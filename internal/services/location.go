package services

import (
	"log"
	"net"

	"breach-harbor-core/internal/config"
	"breach-harbor-core/internal/models"

	"github.com/oschwald/geoip2-golang"
	"gorm.io/gorm"
)

type LocationService struct {
	db     *gorm.DB
	reader *geoip2.Reader
}

func NewLocationService(db *gorm.DB, cfg *config.Config) (*LocationService, error) {
	// Check if MaxMind database exists and is valid
	reader, err := geoip2.Open(cfg.MaxMind.DBPath)
	if err != nil {
		// If MaxMind database is not available, create service without reader
		// This allows the application to start but geolocation will be limited
		log.Printf("Warning: MaxMind database not available at %s: %v", cfg.MaxMind.DBPath, err)
		log.Printf("IP geolocation will be limited. Download GeoLite2-City.mmdb from MaxMind.")
		
		return &LocationService{
			db:     db,
			reader: nil,
		}, nil
	}

	return &LocationService{
		db:     db,
		reader: reader,
	}, nil
}

func (s *LocationService) Close() error {
	if s.reader != nil {
		return s.reader.Close()
	}
	return nil
}

func (s *LocationService) GetOrCreateLocation(ip string) (*models.Location, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil, gorm.ErrInvalidValue
	}

	// If no MaxMind reader available, create basic location with IP only
	if s.reader == nil {
		location := models.Location{
			CountryName: "Unknown",
			CountryCode: "XX",
			City:        "Unknown",
			Latitude:    0.0,
			Longitude:   0.0,
		}

		if err := s.db.Create(&location).Error; err != nil {
			return nil, err
		}
		return &location, nil
	}

	record, err := s.reader.City(parsedIP)
	if err != nil {
		// If MaxMind lookup fails, create basic location
		location := models.Location{
			CountryName: "Unknown",
			CountryCode: "XX", 
			City:        "Unknown",
			Latitude:    0.0,
			Longitude:   0.0,
		}

		if err := s.db.Create(&location).Error; err != nil {
			return nil, err
		}
		return &location, nil
	}

	var location models.Location
	err = s.db.Where("country_code = ? AND city = ? AND latitude = ? AND longitude = ?",
		record.Country.IsoCode,
		record.City.Names["en"],
		record.Location.Latitude,
		record.Location.Longitude,
	).First(&location).Error

	if err == gorm.ErrRecordNotFound {
		location = models.Location{
			CountryName:         record.Country.Names["en"],
			CountryCode:         record.Country.IsoCode,
			City:                record.City.Names["en"],
			Latitude:            record.Location.Latitude,
			Longitude:           record.Location.Longitude,
			Timezone:            record.Location.TimeZone,
			IsInEuropeanUnion:   record.Country.IsInEuropeanUnion,
			IsAnonymousProxy:    record.Traits.IsAnonymousProxy,
			IsSatelliteProvider: record.Traits.IsSatelliteProvider,
		}

		if len(record.Subdivisions) > 0 {
			// Use subdivision info if available
		}

		if err := s.db.Create(&location).Error; err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}

	return &location, nil
}