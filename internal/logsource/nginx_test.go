package logsource

import "testing"

func TestParseNginxAccessLine_SensitivePaths(t *testing.T) {
	events := countEventsInFixture(t, "testdata/nginx_combined.log", parseNginxAccessLine)
	// 4 sensitive-path hits: /wp-login.php, /.env, /xmlrpc.php,
	// /.git/config. The two normal 200s (/index.html, /favicon.ico)
	// must not trigger.
	if len(events) != 4 {
		t.Fatalf("got %d events, want 4: %+v", len(events), events)
	}
	for _, ev := range events {
		if ev.Kind != EventHTTPSuspicious {
			t.Errorf("event kind = %s, want %s", ev.Kind, EventHTTPSuspicious)
		}
	}
	if events[0].IP.String() != "192.0.2.187" {
		t.Errorf("events[0].IP = %s, want 192.0.2.187", events[0].IP)
	}
	if events[0].Fields["path"] != "/wp-login.php" {
		t.Errorf("events[0].path = %q, want /wp-login.php", events[0].Fields["path"])
	}
	if events[0].Time.IsZero() {
		t.Error("expected a parsed timestamp, got zero value")
	}
}

func TestIsSensitivePath(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/wp-login.php", true},
		{"/WP-LOGIN.PHP", true}, // case-insensitive
		{"/wp-admin/edit.php", true},
		{"/.env", true},
		{"/index.html", false},
		{"/favicon.ico", false},
		{"/", false},
	}
	for _, c := range cases {
		_, got := isSensitivePath(c.path)
		if got != c.want {
			t.Errorf("isSensitivePath(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestParseNginxAccessLine_MalformedNeverPanics(t *testing.T) {
	lines := []string{"", "garbage", "not a log line at all [broken"}
	for _, l := range lines {
		if _, ok := parseNginxAccessLine(l); ok {
			t.Errorf("expected malformed line %q to be rejected", l)
		}
	}
}
