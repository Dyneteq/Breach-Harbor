package services

import (
	"time"

	"breach-harbor-core/internal/models"

	"gorm.io/gorm"
)

type DashboardService struct {
	db *gorm.DB
}

type DashboardStats struct {
	TotalIncidents      int64                    `json:"total_incidents"`
	TotalIPAddresses    int64                    `json:"total_ip_addresses"`
	Last24HourIncidents int64                    `json:"last_24_hour_incidents"`
	TotalCollectors     int64                    `json:"total_collectors"`
	IncidentsByCountry  []CountryIncidentCount   `json:"incidents_by_country"`
	HourlyIncidents     []HourlyIncidentCount    `json:"hourly_incidents"`
	RecentIncidents     []models.Incident        `json:"recent_incidents"`
}

type CountryIncidentCount struct {
	CountryName string `json:"country_name"`
	CountryCode string `json:"country_code"`
	Count       int64  `json:"count"`
}

type HourlyIncidentCount struct {
	Hour  int   `json:"hour"`
	Count int64 `json:"count"`
}

func NewDashboardService(db *gorm.DB) *DashboardService {
	return &DashboardService{db: db}
}

func (s *DashboardService) GetDashboardStats(userID uint) (*DashboardStats, error) {
	stats := &DashboardStats{}

	// Total incidents
	s.db.Model(&models.Incident{}).Where("user_id = ?", userID).Count(&stats.TotalIncidents)

	// Total IP addresses (unique IPs from user's incidents)
	s.db.Model(&models.IPAddress{}).
		Joins("JOIN incidents ON ip_addresses.id = incidents.ip_address_id").
		Where("incidents.user_id = ?", userID).
		Distinct("ip_addresses.id").
		Count(&stats.TotalIPAddresses)

	// Last 24 hour incidents
	last24Hours := time.Now().Add(-24 * time.Hour)
	s.db.Model(&models.Incident{}).
		Where("user_id = ? AND created_at > ?", userID, last24Hours).
		Count(&stats.Last24HourIncidents)

	// Total collectors
	s.db.Model(&models.Collector{}).Where("user_id = ?", userID).Count(&stats.TotalCollectors)

	// Incidents by country
	var countryStats []CountryIncidentCount
	s.db.Model(&models.Incident{}).
		Select("locations.country_name, locations.country_code, count(*) as count").
		Joins("JOIN ip_addresses ON incidents.ip_address_id = ip_addresses.id").
		Joins("JOIN locations ON ip_addresses.location_id = locations.id").
		Where("incidents.user_id = ?", userID).
		Group("locations.country_name, locations.country_code").
		Order("count DESC").
		Limit(10).
		Find(&countryStats)
	stats.IncidentsByCountry = countryStats

	// Hourly incidents for last 24 hours
	var hourlyStats []HourlyIncidentCount
	for i := 0; i < 24; i++ {
		hour := time.Now().Add(time.Duration(-i) * time.Hour).Hour()
		hourStart := time.Now().Add(time.Duration(-i) * time.Hour).Truncate(time.Hour)
		hourEnd := hourStart.Add(time.Hour)

		var count int64
		s.db.Model(&models.Incident{}).
			Where("user_id = ? AND created_at >= ? AND created_at < ?", userID, hourStart, hourEnd).
			Count(&count)

		hourlyStats = append(hourlyStats, HourlyIncidentCount{
			Hour:  hour,
			Count: count,
		})
	}
	stats.HourlyIncidents = hourlyStats

	// Recent incidents
	s.db.Preload("Collector").
		Preload("IPAddress").
		Preload("IPAddress.Location").
		Where("user_id = ?", userID).
		Order("created_at DESC").
		Limit(10).
		Find(&stats.RecentIncidents)

	return stats, nil
}

func (s *DashboardService) GetAllIPAddresses(userID uint) ([]models.IPAddress, error) {
	var ipAddresses []models.IPAddress
	err := s.db.Preload("Location").
		Joins("JOIN incidents ON ip_addresses.id = incidents.ip_address_id").
		Where("incidents.user_id = ?", userID).
		Distinct("ip_addresses.*").
		Find(&ipAddresses).Error
	return ipAddresses, err
}

func (s *DashboardService) GetIPAddressDetails(userID uint, ip string) (*models.IPAddress, []models.Incident, error) {
	var ipAddress models.IPAddress
	err := s.db.Preload("Location").Where("ip = ?", ip).First(&ipAddress).Error
	if err != nil {
		return nil, nil, err
	}

	var incidents []models.Incident
	err = s.db.Preload("Collector").
		Where("user_id = ? AND ip_address_id = ?", userID, ipAddress.ID).
		Order("created_at DESC").
		Find(&incidents).Error
	if err != nil {
		return &ipAddress, nil, err
	}

	return &ipAddress, incidents, nil
}