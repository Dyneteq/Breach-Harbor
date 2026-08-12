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
	ID                  uint    `gorm:"primaryKey" json:"id"`
	CountryName         string  `json:"country_name"`
	CountryCode         string  `json:"country_code"`
	City                string  `json:"city"`
	Latitude            float64 `json:"latitude"`
	Longitude           float64 `json:"longitude"`
	Timezone            string  `json:"timezone"`
	ISP                 string  `json:"isp"`
	Organization        string  `json:"organization"`
	AS                  string  `json:"as"`
	ASN                 uint    `json:"asn"`
	IsInEuropeanUnion   bool    `json:"is_in_european_union"`
	IsAnonymousProxy    bool    `json:"is_anonymous_proxy"`
	IsSatelliteProvider bool    `json:"is_satellite_provider"`
	// IsLegitimateProxy was dropped (PLAN.md M2 data model changes): the
	// free GeoLite2-City edition's Traits struct (see
	// github.com/oschwald/geoip2-golang's City type) only ever carries
	// IsAnonymousProxy/IsSatelliteProvider — is_legitimate_proxy is a
	// GeoIP2 Enterprise (paid) field, verified directly against the
	// vendored library source rather than assumed.
	IsDatacenter      bool      `json:"is_datacenter"`
	IsResidential     bool      `json:"is_residential"`
	IsTorExitNode     bool      `json:"is_tor_exit_node"`
	IsHostingProvider bool      `json:"is_hosting_provider"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`

	IPAddresses []IPAddress `json:"ip_addresses,omitempty"`
}

type IPAddress struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	IP         string    `gorm:"unique;not null" json:"ip" validate:"required,ip"`
	LocationID uint      `json:"location_id"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`

	Location  Location   `json:"location,omitempty"`
	Incidents []Incident `json:"incidents,omitempty"`
}

// Collector represents an enrolled agent. The bearer token is never
// stored: only its SHA-256 hash is persisted (TokenHash), and the
// plaintext is returned to the caller exactly once, at creation time
// (GitHub-PAT-style) — see services.CollectorService.CreateCollector.
type Collector struct {
	ID        uint   `gorm:"primaryKey" json:"id"`
	Name      string `gorm:"unique;not null" json:"name" validate:"required"`
	IP        string `json:"ip" validate:"required,ip"`
	TokenHash string `gorm:"uniqueIndex;not null" json:"-"`
	UserID    uint   `json:"user_id"`
	// EnrolledAt is set the moment an agent successfully calls
	// POST /v1/enroll with this collector's token — proof the token
	// works and the server was reachable, independent of whether any
	// data has flowed yet.
	EnrolledAt *time.Time `json:"enrolled_at"`
	// LastOnline moves only when the server has actually ingested a
	// real observation — "this collector has reported an incident,"
	// not "the agent process is alive." Can lag far behind
	// LastHeartbeat on a quiet host, or never move at all.
	LastOnline *time.Time `json:"last_online"`
	// LastHeartbeat moves on every POST /v1/heartbeat, which an
	// enrolled agent sends on its own fixed ticker (see
	// internal/agent's heartbeatInterval) whether or not it has
	// anything to report — this is the presence signal: the process
	// is up and can reach the server right now, independent of
	// whether it's detected anything. The dashboard derives Online/
	// Error/Enrolled/Never-connected from EnrolledAt + LastHeartbeat
	// together (internal/handlers/web.go's collectorStatus).
	LastHeartbeat *time.Time `json:"last_heartbeat"`
	// FirewallBackend is the name of the firewall.Backend ("nftables",
	// "ipset", "iptables-nft", "ufw", "pf", or "none" if unavailable)
	// this collector's agent last reported using — empty until its
	// first POST /v1/firewall-status (internal/agent's
	// sendFirewallStatus).
	FirewallBackend string `json:"firewall_backend"`
	// FirewallEnforcing mirrors the agent's own enforce/dry-run mode at
	// the moment of its last firewall status report — can lag the
	// agent's live state if reporting has stopped (see
	// FirewallUpdatedAt).
	FirewallEnforcing bool `json:"firewall_enforcing"`
	// FirewallBlockedIPs is the agent's own firewall.Backend.List()
	// result at the moment of its last report: the addresses *this*
	// collector's agent currently has blocked in its own rules — not
	// the server's published blocklist, which every enrolled agent
	// merges in and isn't specific to any one collector.
	FirewallBlockedIPs []string `gorm:"type:text;serializer:json" json:"firewall_blocked_ips"`
	// FirewallConfig is the raw dump of the agent's firewall.Backend
	// Status() call at the moment of its last report: the host's whole
	// ruleset (every allow/deny rule, not just FirewallBlockedIPs) as
	// backend-native text (e.g. `ufw status verbose`, `nft list
	// ruleset`) — display-only, truncated agent-side at ~32KB.
	FirewallConfig    string     `gorm:"type:text" json:"firewall_config"`
	FirewallUpdatedAt *time.Time `json:"firewall_updated_at"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`

	User      User       `json:"user,omitempty"`
	Incidents []Incident `json:"incidents,omitempty"`
}

type Incident struct {
	ID           uint                   `gorm:"primaryKey" json:"id"`
	IncidentType string                 `json:"incident_type"`
	Metadata     map[string]interface{} `gorm:"type:text;serializer:json" json:"metadata"`
	HappenedAt   time.Time              `json:"happened_at"`
	CreatedAt    time.Time              `json:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at"`
	CollectorID  uint                   `json:"collector_id"`
	UserID       uint                   `json:"user_id"`
	IPAddressID  uint                   `json:"ip_address_id"`

	Collector             Collector              `json:"collector,omitempty"`
	User                  User                   `json:"user,omitempty"`
	IPAddress             IPAddress              `json:"ip_address,omitempty"`
	IncidentNotifications []IncidentNotification `json:"incident_notifications,omitempty"`
}

type Notification struct {
	ID               uint      `gorm:"primaryKey" json:"id"`
	Title            string    `json:"title"`
	Message          string    `json:"message"`
	Severity         string    `json:"severity" validate:"oneof=low medium high critical"`
	IsReadEmail      bool      `gorm:"default:false" json:"is_read_email"`
	IsReadSMS        bool      `gorm:"default:false" json:"is_read_sms"`
	IsReadClient     bool      `gorm:"default:false" json:"is_read_client"`
	UserID           uint      `json:"user_id"`
	NotificationType string    `json:"notification_type"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`

	User                  User                   `json:"user,omitempty"`
	IncidentNotifications []IncidentNotification `json:"incident_notifications,omitempty"`
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
