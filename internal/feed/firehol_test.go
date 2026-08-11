package feed

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

const fireholFixture = `# FireHOL level1
# aggregated, deduplicated
1.2.3.0/24
198.51.100.9
`

func TestFirehol_Fetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(fireholFixture))
	}))
	defer srv.Close()

	p := &Firehol{URL: srv.URL}
	entries, err := p.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(entries), entries)
	}
	if entries[1].Prefix.String() != "198.51.100.9/32" {
		t.Errorf("entries[1].Prefix = %s, want 198.51.100.9/32 (bare IP treated as /32)", entries[1].Prefix)
	}
}

func TestFirehol_RequiresKey_False(t *testing.T) {
	if needed, configured := NewFirehol().RequiresKey(); needed || !configured {
		t.Errorf("RequiresKey() = %v, %v, want false, true", needed, configured)
	}
}
