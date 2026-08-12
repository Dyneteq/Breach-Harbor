package services

import (
	"time"

	"github.com/Dyneteq/Breach-Harbor/internal/models"

	"gorm.io/gorm"
)

type DashboardService struct {
	db              *gorm.DB
	locationService *LocationService
}

type DashboardStats struct {
	TotalIncidents      int64                  `json:"total_incidents"`
	TotalIPAddresses    int64                  `json:"total_ip_addresses"`
	Last24HourIncidents int64                  `json:"last_24_hour_incidents"`
	TotalCollectors     int64                  `json:"total_collectors"`
	IncidentsByCountry  []CountryIncidentCount `json:"incidents_by_country"`
	HourlyIncidents     []HourlyIncidentCount  `json:"hourly_incidents"`
	RecentIncidents     []models.Incident      `json:"recent_incidents"`
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

// AttackMapEvent is one plottable arc for the animated attack map: an
// attacker source point (from the incident's IPAddress.Location) and a
// destination point (the collector that observed it, geolocated the same
// way as attacker IPs, via LocationService.GetOrCreateLocation(collector.IP)
// rather than a stored relation — Collector has no LocationID).
type AttackMapEvent struct {
	IncidentID    uint      `json:"incident_id"`
	IncidentType  string    `json:"incident_type"`
	HappenedAt    time.Time `json:"happened_at"`
	SourceIP      string    `json:"source_ip"`
	SourceLat     float64   `json:"source_lat"`
	SourceLon     float64   `json:"source_lon"`
	SourceCity    string    `json:"source_city"`
	SourceCountry string    `json:"source_country"`
	CollectorName string    `json:"collector_name"`
	DestLat       float64   `json:"dest_lat"`
	DestLon       float64   `json:"dest_lon"`
}

func NewDashboardService(db *gorm.DB, locationService *LocationService) *DashboardService {
	return &DashboardService{db: db, locationService: locationService}
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

	hourlyStats, err := s.hourlyIncidentCounts(userID)
	if err != nil {
		return nil, err
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

// hourlyBucketRow is the raw shape of hourlyIncidentCounts' grouped
// query — one row per hour that actually has incidents.
type hourlyBucketRow struct {
	Bucket string
	Count  int64
}

// hourlyIncidentCounts replaces what used to be 24 separate COUNT(*)
// queries (one per hour, in a loop) with a single grouped query, then
// fills in the hours that had zero incidents in Go. created_at is
// stored with an explicit UTC offset (see glebarez/sqlite's default
// time format), so strftime normalizes every row to UTC before
// bucketing — bucket keys below are built the same way for a match.
func (s *DashboardService) hourlyIncidentCounts(userID uint) ([]HourlyIncidentCount, error) {
	now := time.Now().UTC()
	since := now.Add(-24 * time.Hour)

	var rows []hourlyBucketRow
	err := s.db.Model(&models.Incident{}).
		Select("strftime('%Y-%m-%d %H:00:00', created_at) AS bucket, COUNT(*) AS count").
		Where("user_id = ? AND created_at >= ?", userID, since).
		Group("bucket").
		Find(&rows).Error
	if err != nil {
		return nil, err
	}

	counts := make(map[string]int64, len(rows))
	for _, r := range rows {
		counts[r.Bucket] = r.Count
	}

	hourly := make([]HourlyIncidentCount, 0, 24)
	for i := 0; i < 24; i++ {
		bucketStart := now.Add(time.Duration(-i) * time.Hour).Truncate(time.Hour)
		hourly = append(hourly, HourlyIncidentCount{
			Hour:  bucketStart.Hour(),
			Count: counts[bucketStart.Format("2006-01-02 15:00:00")],
		})
	}
	return hourly, nil
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

// GetAttackMapEvents returns the most recent incidents across every
// collector, shaped for the dashboard's attack map (source = attacker IP,
// destination = the collector that observed it).
func (s *DashboardService) GetAttackMapEvents(userID uint, limit int) ([]AttackMapEvent, error) {
	var incidents []models.Incident
	err := s.db.Preload("Collector").
		Preload("IPAddress").
		Preload("IPAddress.Location").
		Where("user_id = ?", userID).
		Order("created_at DESC").
		Limit(limit).
		Find(&incidents).Error
	if err != nil {
		return nil, err
	}

	return s.buildAttackMapEvents(incidents)
}

// GetIPAttackMapEvents returns one IP's incidents shaped for the IP detail
// page's attack map: a fixed source (this IP) with arcs to whichever
// collector(s) observed it.
func (s *DashboardService) GetIPAttackMapEvents(userID uint, ip string, limit int) ([]AttackMapEvent, error) {
	var ipAddress models.IPAddress
	if err := s.db.Preload("Location").Where("ip = ?", ip).First(&ipAddress).Error; err != nil {
		return nil, err
	}

	var incidents []models.Incident
	err := s.db.Preload("Collector").
		Where("user_id = ? AND ip_address_id = ?", userID, ipAddress.ID).
		Order("created_at DESC").
		Limit(limit).
		Find(&incidents).Error
	if err != nil {
		return nil, err
	}

	for i := range incidents {
		incidents[i].IPAddress = ipAddress
	}

	return s.buildAttackMapEvents(incidents)
}

// buildAttackMapEvents resolves each incident's collector location (cached
// per collector ID for the duration of this call, since GetOrCreateLocation
// itself only hits the DB, not the mmdb reader, once a collector's IP has
// been seen once) and skips anything without a usable source point — an
// unenriched or lookup-failed Location comes back as "Unknown"/0,0
// (LocationService.GetOrCreateLocation's documented fallback), which would
// otherwise plot every such incident at 0,0 ("null island").
func (s *DashboardService) buildAttackMapEvents(incidents []models.Incident) ([]AttackMapEvent, error) {
	destCache := make(map[uint]*models.Location, len(incidents))
	events := make([]AttackMapEvent, 0, len(incidents))

	for _, incident := range incidents {
		loc := incident.IPAddress.Location
		if loc.Latitude == 0 && loc.Longitude == 0 {
			continue
		}

		dest, ok := destCache[incident.CollectorID]
		if !ok {
			var err error
			dest, err = s.locationService.GetOrCreateLocation(incident.Collector.IP)
			if err != nil {
				dest = nil
			}
			destCache[incident.CollectorID] = dest
		}
		if dest == nil || (dest.Latitude == 0 && dest.Longitude == 0) {
			continue
		}

		events = append(events, newAttackMapEvent(incident, *dest))
	}

	return events, nil
}

// newAttackMapEvent maps one incident plus its already-resolved destination
// location into the wire shape — split out from buildAttackMapEvents so the
// field mapping is testable without a LocationService/mmdb in the loop.
func newAttackMapEvent(incident models.Incident, dest models.Location) AttackMapEvent {
	loc := incident.IPAddress.Location
	return AttackMapEvent{
		IncidentID:    incident.ID,
		IncidentType:  incident.IncidentType,
		HappenedAt:    incident.HappenedAt,
		SourceIP:      incident.IPAddress.IP,
		SourceLat:     loc.Latitude,
		SourceLon:     loc.Longitude,
		SourceCity:    loc.City,
		SourceCountry: loc.CountryName,
		CollectorName: incident.Collector.Name,
		DestLat:       dest.Latitude,
		DestLon:       dest.Longitude,
	}
}
