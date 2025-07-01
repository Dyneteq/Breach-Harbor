package models

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Email     string    `gorm:"unique;not null" json:"email" validate:"required,email"`
	Password  string    `gorm:"not null" json:"-"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	IsActive  bool      `gorm:"default:true" json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	Collectors    []Collector    `json:"collectors,omitempty"`
	Incidents     []Incident     `json:"incidents,omitempty"`
	Notifications []Notification `json:"notifications,omitempty"`
}

type Location struct {
	ID                 uint    `gorm:"primaryKey" json:"id"`
	CountryName        string  `json:"country_name"`
	CountryCode        string  `json:"country_code"`
	City               string  `json:"city"`
	Latitude           float64 `json:"latitude"`
	Longitude          float64 `json:"longitude"`
	Timezone           string  `json:"timezone"`
	ISP                string  `json:"isp"`
	Organization       string  `json:"organization"`
	AS                 string  `json:"as"`
	ASN                uint    `json:"asn"`
	IsInEuropeanUnion  bool    `json:"is_in_european_union"`
	IsAnonymousProxy   bool    `json:"is_anonymous_proxy"`
	IsSatelliteProvider bool   `json:"is_satellite_provider"`
	IsLegitimateProxy  bool    `json:"is_legitimate_proxy"`
	IsDatacenter       bool    `json:"is_datacenter"`
	IsResidential      bool    `json:"is_residential"`
	IsTorExitNode      bool    `json:"is_tor_exit_node"`
	IsHostingProvider  bool    `json:"is_hosting_provider"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`

	IPAddresses []IPAddress `json:"ip_addresses,omitempty"`
}

type IPAddress struct {
	ID         uint   `gorm:"primaryKey" json:"id"`
	IP         string `gorm:"unique;not null" json:"ip" validate:"required,ip"`
	LocationID uint   `json:"location_id"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`

	Location  Location   `json:"location,omitempty"`
	Incidents []Incident `json:"incidents,omitempty"`
}

type Collector struct {
	ID         uint   `gorm:"primaryKey" json:"id"`
	Name       string `gorm:"unique;not null" json:"name" validate:"required"`
	IP         string `json:"ip" validate:"required,ip"`
	Token      string `gorm:"unique;not null" json:"token"`
	UserID     uint   `json:"user_id"`
	LastOnline *time.Time `json:"last_online"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`

	User      User       `json:"user,omitempty"`
	Incidents []Incident `json:"incidents,omitempty"`
}

type Incident struct {
	ID            uint                   `gorm:"primaryKey" json:"id"`
	IncidentType  string                 `json:"incident_type"`
	Metadata      map[string]interface{} `gorm:"type:text" json:"metadata"`
	HappenedAt    time.Time              `json:"happened_at"`
	CreatedAt     time.Time              `json:"created_at"`
	UpdatedAt     time.Time              `json:"updated_at"`
	CollectorID   uint                   `json:"collector_id"`
	UserID        uint                   `json:"user_id"`
	IPAddressID   uint                   `json:"ip_address_id"`

	Collector               Collector               `json:"collector,omitempty"`
	User                    User                    `json:"user,omitempty"`
	IPAddress               IPAddress               `json:"ip_address,omitempty"`
	IncidentNotifications   []IncidentNotification  `json:"incident_notifications,omitempty"`
}

type Notification struct {
	ID              uint      `gorm:"primaryKey" json:"id"`
	Title           string    `json:"title"`
	Message         string    `json:"message"`
	Severity        string    `json:"severity" validate:"oneof=low medium high critical"`
	IsReadEmail     bool      `gorm:"default:false" json:"is_read_email"`
	IsReadSMS       bool      `gorm:"default:false" json:"is_read_sms"`
	IsReadClient    bool      `gorm:"default:false" json:"is_read_client"`
	UserID          uint      `json:"user_id"`
	NotificationType string   `json:"notification_type"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`

	User                  User                    `json:"user,omitempty"`
	IncidentNotifications []IncidentNotification  `json:"incident_notifications,omitempty"`
}

type IncidentNotification struct {
	ID             uint `gorm:"primaryKey" json:"id"`
	IncidentID     uint `json:"incident_id"`
	NotificationID uint `json:"notification_id"`

	Incident     Incident     `json:"incident,omitempty"`
	Notification Notification `json:"notification,omitempty"`
}

func MigrateDatabase(db *gorm.DB) error {
	return db.AutoMigrate(
		&User{},
		&Location{},
		&IPAddress{},
		&Collector{},
		&Incident{},
		&Notification{},
		&IncidentNotification{},
	)
}