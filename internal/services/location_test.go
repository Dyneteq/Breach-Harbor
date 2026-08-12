package services

import (
	"net/netip"
	"testing"

	"github.com/Dyneteq/Breach-Harbor/internal/feed"
)

func TestGetOrCreateLocation_NoMaxMindDB_FallsBackCleanly(t *testing.T) {
	db := openTestDB(t)
	svc := testLocationService(t, db)

	loc, err := svc.GetOrCreateLocation("203.0.113.44")
	if err != nil {
		t.Fatalf("GetOrCreateLocation: %v", err)
	}
	if loc.CountryCode != "XX" {
		t.Errorf("CountryCode = %q, want XX (unknown fallback)", loc.CountryCode)
	}
	// No datacenter/hosting/Tor/anonymous-proxy signal available at
	// all (no MaxMind DBs, no Tor index populated) — the documented
	// heuristic (PLAN.md M2) must still land on "residential."
	if !loc.IsResidential {
		t.Error("expected IsResidential=true with no other enrichment signal available")
	}
}

func TestGetOrCreateLocation_InvalidIP(t *testing.T) {
	db := openTestDB(t)
	svc := testLocationService(t, db)

	if _, err := svc.GetOrCreateLocation("not-an-ip"); err == nil {
		t.Error("expected an error for an unparseable IP")
	}
}

func TestUpdateTorEntries_MarksExitNodeResidentialFalse(t *testing.T) {
	db := openTestDB(t)
	svc := testLocationService(t, db)

	svc.UpdateTorEntries([]feed.Entry{
		{Prefix: netip.MustParsePrefix("203.0.113.44/32"), Reason: "tor exit node", Provider: "tor"},
	})

	loc, err := svc.GetOrCreateLocation("203.0.113.44")
	if err != nil {
		t.Fatalf("GetOrCreateLocation: %v", err)
	}
	if !loc.IsTorExitNode {
		t.Error("expected IsTorExitNode=true for an IP in the Tor index")
	}
	if loc.IsResidential {
		t.Error("expected IsResidential=false for a known Tor exit node")
	}

	// An IP not in the Tor index must be unaffected.
	other, err := svc.GetOrCreateLocation("198.51.100.1")
	if err != nil {
		t.Fatalf("GetOrCreateLocation: %v", err)
	}
	if other.IsTorExitNode {
		t.Error("expected IsTorExitNode=false for an IP not in the Tor index")
	}
}

func TestIsHostingASN(t *testing.T) {
	if name, ok := feed.IsHostingASN(16509); !ok || name == "" {
		t.Errorf("expected AWS's ASN (16509) to be recognized as hosting, got ok=%v name=%q", ok, name)
	}
	if _, ok := feed.IsHostingASN(0); ok {
		t.Error("expected ASN 0 to not be recognized as a known hosting provider")
	}
}
