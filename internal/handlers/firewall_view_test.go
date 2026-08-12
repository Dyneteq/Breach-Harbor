package handlers

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Dyneteq/Breach-Harbor/internal/models"
)

// ufwRow builds one fixed-width row using the same column widths as
// ufwHeader below — mirrors how `ufw status verbose` right-pads To and
// Action so every row lines up under the header.
func ufwRow(to, action, from string) string {
	return fmt.Sprintf("%-28s%-12s%s", to, action, from)
}

func sampleUFWStatusVerbose() string {
	lines := []string{
		"Status: active",
		"Logging: on (low)",
		"Default: deny (incoming), allow (outgoing), disabled (routed)",
		"New profiles: skip",
		"",
		ufwRow("To", "Action", "From"),
		ufwRow("--", "------", "----"),
		ufwRow("Anywhere", "DENY IN", "203.0.113.44"),
		ufwRow("OpenSSH", "ALLOW IN", "Anywhere"),
		ufwRow("80/tcp", "ALLOW IN", "Anywhere"),
		ufwRow("443/tcp", "ALLOW IN", "Anywhere"),
		ufwRow("Anywhere on tailscale0", "ALLOW IN", "Anywhere"),
		ufwRow("41641/udp", "ALLOW IN", "Anywhere"),
		ufwRow("OpenSSH (v6)", "ALLOW IN", "Anywhere (v6)"),
		ufwRow("80/tcp (v6)", "ALLOW IN", "Anywhere (v6)"),
		ufwRow("443/tcp (v6)", "ALLOW IN", "Anywhere (v6)"),
		ufwRow("Anywhere (v6) on tailscale0", "ALLOW IN", "Anywhere (v6)"),
		ufwRow("41641/udp (v6)", "ALLOW IN", "Anywhere (v6)"),
	}
	return strings.Join(lines, "\n")
}

func TestParseUFWStatusVerbose(t *testing.T) {
	rules, status, defaultPolicy, logging := parseUFWStatusVerbose(sampleUFWStatusVerbose(), []string{"203.0.113.44"})

	if status != "active" {
		t.Errorf("status = %q, want active", status)
	}
	if !strings.Contains(defaultPolicy, "deny (incoming)") {
		t.Errorf("defaultPolicy = %q, want it to mention deny (incoming)", defaultPolicy)
	}
	if logging != "on (low)" {
		t.Errorf("logging = %q, want %q", logging, "on (low)")
	}
	if len(rules) != 11 {
		t.Fatalf("got %d rules, want 11: %+v", len(rules), rules)
	}

	var denyCount, allowCount, ownCount, v6Count int
	for _, r := range rules {
		switch r.Class {
		case "deny":
			denyCount++
		case "allow":
			allowCount++
		}
		if r.OwnRule {
			ownCount++
		}
		if r.IPv6 {
			v6Count++
		}
	}
	if denyCount != 1 {
		t.Errorf("denyCount = %d, want 1", denyCount)
	}
	if allowCount != 10 {
		t.Errorf("allowCount = %d, want 10", allowCount)
	}
	if ownCount != 1 {
		t.Errorf("ownCount = %d, want 1 (only the 203.0.113.44 row is breach-harbor's own)", ownCount)
	}
	if v6Count != 5 {
		t.Errorf("v6Count = %d, want 5", v6Count)
	}

	// The breach-harbor-added row must be the one flagged OwnRule, not
	// just any deny row.
	found := false
	for _, r := range rules {
		if r.From == "203.0.113.44" {
			found = true
			if !r.OwnRule {
				t.Error("expected the 203.0.113.44 row to be flagged OwnRule")
			}
			if r.Class != "deny" {
				t.Errorf("Class = %q, want deny", r.Class)
			}
		}
	}
	if !found {
		t.Fatal("expected a rule row for 203.0.113.44")
	}
}

func TestOpenPorts_DedupesV4AndV6_ExcludesAnywhere(t *testing.T) {
	rules, _, _, _ := parseUFWStatusVerbose(sampleUFWStatusVerbose(), nil)
	ports := openPorts(rules)
	want := []string{"41641/udp", "443/tcp", "80/tcp", "OpenSSH"}
	if len(ports) != len(want) {
		t.Fatalf("openPorts = %v, want %v", ports, want)
	}
	for i, p := range want {
		if ports[i] != p {
			t.Errorf("openPorts[%d] = %q, want %q (full: %v)", i, ports[i], p, ports)
		}
	}
	for _, p := range ports {
		if strings.HasPrefix(p, "Anywhere") {
			t.Errorf("openPorts must exclude interface/any rows, got %q", p)
		}
	}
}

func TestBuildFirewallView_UFW_Structured(t *testing.T) {
	now := time.Now()
	c := models.Collector{
		Name:               "web-1",
		FirewallBackend:    "ufw",
		FirewallEnforcing:  true,
		FirewallBlockedIPs: []string{"203.0.113.44"},
		FirewallConfig:     sampleUFWStatusVerbose(),
		FirewallUpdatedAt:  &now,
	}
	view := BuildFirewallView(c)
	if !view.Structured {
		t.Fatal("expected a ufw config to parse as Structured")
	}
	if view.AllowCount != 10 || view.DenyCount != 1 {
		t.Errorf("AllowCount=%d DenyCount=%d, want 10/1", view.AllowCount, view.DenyCount)
	}
	if view.UFWStatus != "active" {
		t.Errorf("UFWStatus = %q, want active", view.UFWStatus)
	}
	if len(view.OpenPorts) == 0 {
		t.Error("expected OpenPorts to be populated")
	}
}

func TestBuildFirewallView_UnsupportedBackend_FallsBackToRaw(t *testing.T) {
	now := time.Now()
	c := models.Collector{
		Name:              "web-2",
		FirewallBackend:   "nftables",
		FirewallConfig:    "table inet breachharbor { ... }",
		FirewallUpdatedAt: &now,
	}
	view := BuildFirewallView(c)
	if view.Structured {
		t.Error("expected an nftables dump not to be parsed as Structured")
	}
	if len(view.Rules) != 0 {
		t.Errorf("expected no Rules for an unsupported backend, got %+v", view.Rules)
	}
}

func TestBuildFirewallView_NoConfig_NotStructured(t *testing.T) {
	c := models.Collector{Name: "web-3", FirewallBackend: "ufw"}
	view := BuildFirewallView(c)
	if view.Structured {
		t.Error("expected an empty config not to be parsed as Structured")
	}
}

func TestSafeSlice_ClampsRaggedLines(t *testing.T) {
	if got := safeSlice("short", 0, 100); got != "short" {
		t.Errorf("safeSlice with an out-of-range end = %q, want %q", got, "short")
	}
	if got := safeSlice("short", 100, 200); got != "" {
		t.Errorf("safeSlice entirely past the string end = %q, want empty", got)
	}
	if got := safeSlice("short", 3, 1); got != "" {
		t.Errorf("safeSlice with end before start = %q, want empty", got)
	}
}
