package services

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"

	"github.com/Dyneteq/Breach-Harbor/internal/config"
	"github.com/Dyneteq/Breach-Harbor/internal/feed"
	"github.com/Dyneteq/Breach-Harbor/internal/models"

	"github.com/oschwald/geoip2-golang"
	"gorm.io/gorm"
)

// torIndex is a thread-safe, swappable set of Tor exit node entries.
// UpdateTorEntries is called periodically by internal/server/publisher.go
// (a feed.CachedProvider-backed ticker, mirroring how the agent refreshes
// its own feed union in internal/agent/agent.go) so enrichment never
// blocks an ingest request on a network call.
type torIndex struct {
	mu      sync.RWMutex
	entries []feed.Entry
}

func (t *torIndex) Update(entries []feed.Entry) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.entries = entries
}

func (t *torIndex) Contains(addr netip.Addr) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	for _, e := range t.entries {
		if e.Prefix.Contains(addr) {
			return true
		}
	}
	return false
}

type LocationService struct {
	db         *gorm.DB
	cityReader *geoip2.Reader
	asnReader  *geoip2.Reader
	tor        *torIndex
}

func NewLocationService(db *gorm.DB, cfg *config.Config) (*LocationService, error) {
	svc := &LocationService{db: db, tor: &torIndex{}}

	// Check if MaxMind database exists and is valid
	cityReader, err := geoip2.Open(cfg.MaxMind.DBPath)
	if err != nil {
		// If MaxMind database is not available, create service without reader
		// This allows the application to start but geolocation will be limited
		log.Printf("Warning: MaxMind City database not available at %s: %v", cfg.MaxMind.DBPath, err)
		log.Printf("IP geolocation will be limited. Download GeoLite2-City.mmdb from MaxMind.")
	} else {
		svc.cityReader = cityReader
	}

	asnReader, err := geoip2.Open(cfg.MaxMind.ASNDBPath)
	if err != nil {
		log.Printf("Warning: MaxMind ASN database not available at %s: %v", cfg.MaxMind.ASNDBPath, err)
		log.Printf("ISP/ASN/datacenter enrichment will be limited. Download GeoLite2-ASN.mmdb from MaxMind.")
	} else {
		svc.asnReader = asnReader
	}

	return svc, nil
}

func (s *LocationService) Close() error {
	var err error
	if s.cityReader != nil {
		err = s.cityReader.Close()
	}
	if s.asnReader != nil {
		if aerr := s.asnReader.Close(); err == nil {
			err = aerr
		}
	}
	return err
}

// UpdateTorEntries replaces the in-memory Tor exit node list used for
// IsTorExitNode enrichment. Called by internal/server on a refresh
// ticker; safe to call from any goroutine.
func (s *LocationService) UpdateTorEntries(entries []feed.Entry) {
	s.tor.Update(entries)
}

func (s *LocationService) GetOrCreateLocation(ip string) (*models.Location, error) {
	// Parsed via netip first, not net.ParseIP+To16(): net.IP.To16()
	// always widens an IPv4 address into its IPv4-in-IPv6 form, which
	// produces a netip.Addr that Is4In6() rather than Is4() — that
	// never compares equal to (or matches a Prefix.Contains against)
	// the plain 4-byte netip.Addr values internal/feed's providers
	// parse via netip.ParseAddr, silently breaking IsTorExitNode for
	// every IPv4 address. Deriving net.IP from the netip.Addr instead
	// keeps both forms in agreement.
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, gorm.ErrInvalidValue
	}
	parsedIP := net.IP(addr.AsSlice())

	// If no MaxMind reader available, create basic location with IP only
	if s.cityReader == nil {
		location := s.enrich(models.Location{
			CountryName: "Unknown",
			CountryCode: "XX",
			City:        "Unknown",
			Latitude:    0.0,
			Longitude:   0.0,
		}, parsedIP, addr)

		if err := s.db.Create(&location).Error; err != nil {
			return nil, err
		}
		return &location, nil
	}

	record, err := s.cityReader.City(parsedIP)
	if err != nil {
		// If MaxMind lookup fails, create basic location
		location := s.enrich(models.Location{
			CountryName: "Unknown",
			CountryCode: "XX",
			City:        "Unknown",
			Latitude:    0.0,
			Longitude:   0.0,
		}, parsedIP, addr)

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
		location = s.enrich(models.Location{
			CountryName:         record.Country.Names["en"],
			CountryCode:         record.Country.IsoCode,
			City:                record.City.Names["en"],
			Latitude:            record.Location.Latitude,
			Longitude:           record.Location.Longitude,
			Timezone:            record.Location.TimeZone,
			IsInEuropeanUnion:   record.Country.IsInEuropeanUnion,
			IsAnonymousProxy:    record.Traits.IsAnonymousProxy,
			IsSatelliteProvider: record.Traits.IsSatelliteProvider,
		}, parsedIP, addr)

		if err := s.db.Create(&location).Error; err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}

	return &location, nil
}

// enrich fills in the ASN/ISP/datacenter/residential/Tor fields that
// GetOrCreateLocation's City-database lookup above can never populate
// (PLAN.md M2 data model changes) — done once, here, at server-side
// ingest time, never on the agent's hot path.
func (s *LocationService) enrich(loc models.Location, ip net.IP, addr netip.Addr) models.Location {
	if s.asnReader != nil {
		if record, err := s.asnReader.ASN(ip); err == nil && record.AutonomousSystemNumber != 0 {
			loc.ASN = record.AutonomousSystemNumber
			loc.AS = fmt.Sprintf("AS%d", record.AutonomousSystemNumber)
			loc.Organization = record.AutonomousSystemOrganization
			// GeoLite2-ASN doesn't carry a separate "ISP" field (that's
			// the paid GeoIP2-ISP edition) — the AS organization name
			// is the closest free equivalent.
			loc.ISP = record.AutonomousSystemOrganization
			if name, ok := feed.IsHostingASN(record.AutonomousSystemNumber); ok {
				loc.IsDatacenter = true
				loc.IsHostingProvider = true
				if loc.Organization == "" {
					loc.Organization = name
				}
			}
		}
	}

	if addr.IsValid() {
		loc.IsTorExitNode = s.tor.Contains(addr)
	}

	// No free "this is residential" feed exists — this is the
	// documented heuristic PLAN.md calls for: residential is whatever
	// isn't demonstrably one of the other categories.
	loc.IsResidential = !loc.IsDatacenter && !loc.IsHostingProvider && !loc.IsTorExitNode && !loc.IsAnonymousProxy

	return loc
}
