package server

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"time"

	"github.com/Dyneteq/Breach-Harbor/internal/blocklist"
	"github.com/Dyneteq/Breach-Harbor/internal/feed"
	"github.com/Dyneteq/Breach-Harbor/internal/models"
)

// serverFeedProviders mirrors the free feeds the standalone agent
// already cross-references locally (internal/agent's Feeds field) —
// the server publishes the same coverage so an enrolled agent gets
// equivalent protection even with its own local feeds disabled.
func (s *Server) serverFeedProviders() []feed.Provider {
	return []feed.Provider{
		feed.NewCachedProvider(feed.NewSpamhaus(), s.cfg.DataDir, 15*time.Minute),
		feed.NewCachedProvider(feed.NewFirehol(), s.cfg.DataDir, 15*time.Minute),
		s.torFeed,
	}
}

// consensusIncidentThreshold/-Lookback define the "cross-collector
// consensus" half of the published blocklist: an IP that's generated
// enough incidents across the fleet of enrolled agents recently is
// confirmed-bad, independent of any single agent's own local scoring
// (internal/agent/offender.go). This mirrors, at server scope, the
// same "explainable fixed rule, not ML" posture PLAN.md's offender
// scoring section requires for the agent.
const (
	consensusIncidentThreshold = 3
	consensusLookback          = 24 * time.Hour
)

// blocklistSource is the blocklist.Source the Publisher ticks against:
// the union of free feeds and DB-derived consensus entries.
func (s *Server) blocklistSource(ctx context.Context) ([]blocklist.Entry, error) {
	seen := make(map[string]bool)
	var entries []blocklist.Entry

	for _, p := range s.serverFeedProviders() {
		if needed, configured := p.RequiresKey(); needed && !configured {
			continue
		}
		fetched, err := p.Fetch(ctx)
		if err != nil {
			log.Printf("blocklist source: feed %s: %v", p.Name(), err)
			continue
		}
		for _, e := range fetched {
			key := e.Prefix.String()
			if seen[key] {
				continue
			}
			seen[key] = true
			entries = append(entries, blocklist.Entry{Prefix: e.Prefix, Reason: fmt.Sprintf("%s: %s", e.Provider, e.Reason)})
		}
	}

	consensus, err := s.confirmedFromIncidents(ctx)
	if err != nil {
		log.Printf("blocklist source: incident consensus: %v", err)
	} else {
		for _, e := range consensus {
			key := e.Prefix.String()
			if seen[key] {
				continue
			}
			seen[key] = true
			entries = append(entries, e)
		}
	}

	return entries, nil
}

type incidentCountRow struct {
	IP    string
	Count int64
}

// confirmedFromIncidents finds IPs reported enough times, recently
// enough, across any collector, to treat as confirmed-bad — the
// server-side half of blocklist synthesis that has no agent-side
// equivalent (an agent only ever sees its own observations).
func (s *Server) confirmedFromIncidents(ctx context.Context) ([]blocklist.Entry, error) {
	since := time.Now().Add(-consensusLookback)
	var rows []incidentCountRow
	err := s.db.WithContext(ctx).Model(&models.Incident{}).
		Select("ip_addresses.ip AS ip, COUNT(*) AS count").
		Joins("JOIN ip_addresses ON ip_addresses.id = incidents.ip_address_id").
		Where("incidents.created_at >= ?", since).
		Group("ip_addresses.ip").
		Having("COUNT(*) >= ?", consensusIncidentThreshold).
		Find(&rows).Error
	if err != nil {
		return nil, err
	}

	entries := make([]blocklist.Entry, 0, len(rows))
	for _, r := range rows {
		addr, err := netip.ParseAddr(r.IP)
		if err != nil {
			continue
		}
		entries = append(entries, blocklist.Entry{
			Prefix: netip.PrefixFrom(addr, addr.BitLen()),
			Reason: fmt.Sprintf("%d incidents across enrolled collectors in the last 24h", r.Count),
		})
	}
	return entries, nil
}

// refreshTorLoop keeps the LocationService's in-memory Tor exit index
// current so IsTorExitNode enrichment (internal/services/location.go)
// never blocks an ingest request on a network call.
func (s *Server) refreshTorLoop(ctx context.Context) {
	refresh := func() {
		entries, err := s.torFeed.Fetch(ctx)
		if err != nil {
			log.Printf("tor refresh: %v", err)
			return
		}
		s.locationService.UpdateTorEntries(entries)
	}
	refresh()
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refresh()
		}
	}
}
