package agent

import "testing"

func TestDefault_IsSafeAndZeroConfig(t *testing.T) {
	c := Default()
	if c.Enforce {
		t.Error("expected Enforce=false by default — dry run unless the user opts in")
	}
	if c.DataDir == "" {
		t.Error("expected a non-empty default data dir")
	}
	if err := c.Validate(); err != nil {
		t.Errorf("Default() should be valid, got: %v", err)
	}
}

func TestConfig_Validate(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(c *Config)
		wantErr bool
	}{
		{"valid defaults", func(c *Config) {}, false},
		{"empty data dir", func(c *Config) { c.DataDir = "" }, true},
		{"zero refresh", func(c *Config) { c.Refresh = 0 }, true},
		{"negative refresh", func(c *Config) { c.Refresh = -1 }, true},
		{"unknown firewall", func(c *Config) { c.Firewall = "bogus" }, true},
		{"nft firewall ok", func(c *Config) { c.Firewall = "nft" }, false},
		{"ipset firewall ok", func(c *Config) { c.Firewall = "ipset" }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Default()
			tc.mutate(&c)
			err := c.Validate()
			if tc.wantErr && err == nil {
				t.Error("expected an error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}

func TestConfig_FeedEnabled(t *testing.T) {
	c := Default()
	if !c.FeedEnabled("spamhaus") {
		t.Error("expected an unmentioned feed to default to enabled")
	}
	c.Feeds = map[string]bool{"spamhaus": false}
	if c.FeedEnabled("spamhaus") {
		t.Error("expected an explicitly disabled feed to report disabled")
	}
	if !c.FeedEnabled("firehol") {
		t.Error("expected a feed not present in the map to still default to enabled")
	}
}

func TestDefaultDataDir_NonEmpty(t *testing.T) {
	if DefaultDataDir() == "" {
		t.Error("expected a non-empty default data dir")
	}
}
