package services

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"breach-harbor-core/internal/models"

	"gorm.io/gorm"
)

type CollectorService struct {
	db              *gorm.DB
	locationService *LocationService
}

func NewCollectorService(db *gorm.DB, locationService *LocationService) *CollectorService {
	return &CollectorService{
		db:              db,
		locationService: locationService,
	}
}

func (s *CollectorService) generateToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func (s *CollectorService) CreateCollector(userID uint, name, ip string) (*models.Collector, error) {
	token, err := s.generateToken()
	if err != nil {
		return nil, err
	}

	collector := models.Collector{
		Name:   name,
		IP:     ip,
		Token:  token,
		UserID: userID,
	}

	if err := s.db.Create(&collector).Error; err != nil {
		return nil, err
	}

	return &collector, nil
}

func (s *CollectorService) GetCollectorsByUserID(userID uint) ([]models.Collector, error) {
	var collectors []models.Collector
	err := s.db.Where("user_id = ?", userID).Find(&collectors).Error
	return collectors, err
}

func (s *CollectorService) GetCollectorByName(userID uint, name string) (*models.Collector, error) {
	var collector models.Collector
	err := s.db.Where("user_id = ? AND name = ?", userID, name).First(&collector).Error
	if err != nil {
		return nil, err
	}
	return &collector, nil
}

func (s *CollectorService) ValidateCollectorToken(token string) (*models.Collector, error) {
	var collector models.Collector
	err := s.db.Where("token = ?", token).First(&collector).Error
	if err != nil {
		return nil, err
	}
	return &collector, nil
}

func (s *CollectorService) UpdateLastOnline(collectorID uint) error {
	now := time.Now()
	return s.db.Model(&models.Collector{}).Where("id = ?", collectorID).Update("last_online", &now).Error
}

func (s *CollectorService) CreateIncident(collectorToken, ipAddress, incidentType string, metadata map[string]interface{}) (*models.Incident, error) {
	collector, err := s.ValidateCollectorToken(collectorToken)
	if err != nil {
		return nil, errors.New("invalid collector token")
	}

	var ipAddr models.IPAddress
	err = s.db.Where("ip = ?", ipAddress).First(&ipAddr).Error
	if err == gorm.ErrRecordNotFound {
		location, err := s.locationService.GetOrCreateLocation(ipAddress)
		if err != nil {
			return nil, err
		}

		ipAddr = models.IPAddress{
			IP:         ipAddress,
			LocationID: location.ID,
		}

		if err := s.db.Create(&ipAddr).Error; err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}

	incident := models.Incident{
		IncidentType:  incidentType,
		Metadata:      metadata,
		HappenedAt:    time.Now(),
		CollectorID:   collector.ID,
		UserID:        collector.UserID,
		IPAddressID:   ipAddr.ID,
	}

	if err := s.db.Create(&incident).Error; err != nil {
		return nil, err
	}

	s.UpdateLastOnline(collector.ID)

	return &incident, nil
}

func (s *CollectorService) GetIncidentsByUserID(userID uint) ([]models.Incident, error) {
	var incidents []models.Incident
	err := s.db.Preload("Collector").Preload("IPAddress").Preload("IPAddress.Location").
		Where("user_id = ?", userID).
		Order("created_at DESC").
		Find(&incidents).Error
	return incidents, err
}

func (s *CollectorService) GetIncidentsByCollectorName(userID uint, collectorName string) ([]models.Incident, error) {
	var incidents []models.Incident
	err := s.db.Preload("Collector").Preload("IPAddress").Preload("IPAddress.Location").
		Joins("JOIN collectors ON incidents.collector_id = collectors.id").
		Where("collectors.user_id = ? AND collectors.name = ?", userID, collectorName).
		Order("incidents.created_at DESC").
		Find(&incidents).Error
	return incidents, err
}

func (s *CollectorService) GetIncidentByID(userID uint, incidentID uint) (*models.Incident, error) {
	var incident models.Incident
	err := s.db.Preload("Collector").Preload("IPAddress").Preload("IPAddress.Location").
		Where("id = ? AND user_id = ?", incidentID, userID).
		First(&incident).Error
	if err != nil {
		return nil, err
	}
	return &incident, nil
}