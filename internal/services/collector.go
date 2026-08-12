package services

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/Dyneteq/Breach-Harbor/internal/models"

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

func generateToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// hashToken is a fast, deterministic hash — correct here because a
// collector token is a high-entropy 256-bit bearer token, not a
// low-entropy password that needs bcrypt's slow-hash protection.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// CreateCollector generates a new bearer token, persists only its hash,
// and returns the plaintext token alongside the collector record. The
// caller must show the plaintext to the user exactly once — it is
// never recoverable from the database again.
func (s *CollectorService) CreateCollector(userID uint, name, ip string) (*models.Collector, string, error) {
	token, err := generateToken()
	if err != nil {
		return nil, "", err
	}

	collector := models.Collector{
		Name:      name,
		IP:        ip,
		TokenHash: hashToken(token),
		UserID:    userID,
	}

	if err := s.db.Create(&collector).Error; err != nil {
		return nil, "", err
	}

	return &collector, token, nil
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

// GetCollectorByID looks up a collector by primary key with no user
// scoping — used server-side by the /v1/enroll handler, which only
// ever has a collector_id from CollectorAuthMiddleware, never a user.
func (s *CollectorService) GetCollectorByID(id uint) (*models.Collector, error) {
	var collector models.Collector
	if err := s.db.First(&collector, id).Error; err != nil {
		return nil, err
	}
	return &collector, nil
}

// DeleteCollector removes a collector (and, via the FK, orphans none of
// its incidents — incidents are kept for history) scoped to userID so
// one user can never delete another's collector by guessing a name.
func (s *CollectorService) DeleteCollector(userID uint, name string) error {
	res := s.db.Where("user_id = ? AND name = ?", userID, name).Delete(&models.Collector{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

func (s *CollectorService) ValidateCollectorToken(token string) (*models.Collector, error) {
	var collector models.Collector
	err := s.db.Where("token_hash = ?", hashToken(token)).First(&collector).Error
	if err != nil {
		return nil, err
	}
	return &collector, nil
}

func (s *CollectorService) UpdateLastOnline(collectorID uint) error {
	now := time.Now()
	return s.db.Model(&models.Collector{}).Where("id = ?", collectorID).Update("last_online", &now).Error
}

// MarkEnrolled records that an agent successfully completed POST
// /v1/enroll for this collector. Called on every successful enroll,
// not just the first — re-enrolling (e.g. after wiping the agent's
// data directory) refreshes it to "most recently enrolled," which is
// more useful on the dashboard than "first ever."
func (s *CollectorService) MarkEnrolled(collectorID uint) error {
	now := time.Now()
	return s.db.Model(&models.Collector{}).Where("id = ?", collectorID).Update("enrolled_at", &now).Error
}

// RecordHeartbeat updates LastHeartbeat — called on every POST
// /v1/heartbeat, independent of whether the collector has ever
// reported real data (that's UpdateLastOnline's job, above). This is
// the presence signal the dashboard's Online/Error status is derived
// from.
func (s *CollectorService) RecordHeartbeat(collectorID uint) error {
	now := time.Now()
	return s.db.Model(&models.Collector{}).Where("id = ?", collectorID).Update("last_heartbeat", &now).Error
}

// RecordFirewallStatus persists an agent's latest firewall.Backend
// snapshot — called on every POST /v1/firewall-status (or, for the
// in-process local agent, directly from internal/server/localagent.go,
// no HTTP hop). Unlike incidents, this always overwrites in place:
// only the most recent snapshot is kept, there is no history. Select
// forces every listed field to be written even when zero
// (enforcing=false, an empty blockedIPs) — GORM's default Updates(struct)
// silently skips zero-valued fields, which would leave a stale
// "enforcing" or blocked-IP list behind exactly when it flips off.
func (s *CollectorService) RecordFirewallStatus(collectorID uint, backend string, enforcing bool, blockedIPs []string) error {
	now := time.Now()
	update := models.Collector{
		FirewallBackend:    backend,
		FirewallEnforcing:  enforcing,
		FirewallBlockedIPs: blockedIPs,
		FirewallUpdatedAt:  &now,
	}
	return s.db.Model(&models.Collector{}).Where("id = ?", collectorID).
		Select("FirewallBackend", "FirewallEnforcing", "FirewallBlockedIPs", "FirewallUpdatedAt").
		Updates(update).Error
}

// resolveIPAddress returns the IPAddress row for ipAddress, creating it
// (and its Location, via enrichment) on first sight.
func (s *CollectorService) resolveIPAddress(ipAddress string) (*models.IPAddress, error) {
	var ipAddr models.IPAddress
	err := s.db.Where("ip = ?", ipAddress).First(&ipAddr).Error
	if err == nil {
		return &ipAddr, nil
	}
	if err != gorm.ErrRecordNotFound {
		return nil, err
	}

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
	return &ipAddr, nil
}

func (s *CollectorService) CreateIncident(collectorToken, ipAddress, incidentType string, metadata map[string]interface{}) (*models.Incident, error) {
	collector, err := s.ValidateCollectorToken(collectorToken)
	if err != nil {
		return nil, errors.New("invalid collector token")
	}

	ipAddr, err := s.resolveIPAddress(ipAddress)
	if err != nil {
		return nil, err
	}

	incident := models.Incident{
		IncidentType: incidentType,
		Metadata:     metadata,
		HappenedAt:   time.Now(),
		CollectorID:  collector.ID,
		UserID:       collector.UserID,
		IPAddressID:  ipAddr.ID,
	}

	if err := s.db.Create(&incident).Error; err != nil {
		return nil, err
	}

	s.UpdateLastOnline(collector.ID)

	return &incident, nil
}

// ObservationInput is one raw event in a batch POST /v1/observations
// body — the wire shape an enrolled agent uploads, deliberately
// independent of internal/store.Observation (the agent's own local
// queue type) so the two packages don't have to evolve in lockstep.
type ObservationInput struct {
	IP           string
	IncidentType string
	HappenedAt   time.Time
	Metadata     map[string]interface{}
}

// CreateIncidentsBatch ingests a batch of observations from one
// collector in a single CreateInBatches call — the replacement for the
// old one-event-per-request path (PLAN.md M2 item 1/3).
func (s *CollectorService) CreateIncidentsBatch(collectorToken string, observations []ObservationInput) ([]models.Incident, error) {
	collector, err := s.ValidateCollectorToken(collectorToken)
	if err != nil {
		return nil, errors.New("invalid collector token")
	}
	return s.createIncidentsBatch(collector, observations)
}

// CreateIncidentsBatchForCollector is CreateIncidentsBatch's
// token-less counterpart: the caller already knows collectorID is
// authentic because it created the collector itself, in this same
// process, so there is no bearer token to validate. Used only by
// internal/server's in-process local agent (internal/server/
// localagent.go), which has no HTTP hop — and so no token — between
// the agent's own observation queue and this call.
func (s *CollectorService) CreateIncidentsBatchForCollector(collectorID uint, observations []ObservationInput) ([]models.Incident, error) {
	var collector models.Collector
	if err := s.db.First(&collector, collectorID).Error; err != nil {
		return nil, err
	}
	return s.createIncidentsBatch(&collector, observations)
}

func (s *CollectorService) createIncidentsBatch(collector *models.Collector, observations []ObservationInput) ([]models.Incident, error) {
	if len(observations) == 0 {
		return nil, nil
	}

	incidents := make([]models.Incident, 0, len(observations))
	for _, obs := range observations {
		ipAddr, err := s.resolveIPAddress(obs.IP)
		if err != nil {
			return nil, err
		}
		happenedAt := obs.HappenedAt
		if happenedAt.IsZero() {
			happenedAt = time.Now()
		}
		incidents = append(incidents, models.Incident{
			IncidentType: obs.IncidentType,
			Metadata:     obs.Metadata,
			HappenedAt:   happenedAt,
			CollectorID:  collector.ID,
			UserID:       collector.UserID,
			IPAddressID:  ipAddr.ID,
		})
	}

	if err := s.db.CreateInBatches(&incidents, 100).Error; err != nil {
		return nil, err
	}

	s.UpdateLastOnline(collector.ID)

	return incidents, nil
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
