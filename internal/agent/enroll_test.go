package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEnroll_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/enroll" {
			t.Errorf("path = %s, want /v1/enroll", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer secrettoken" {
			t.Errorf("Authorization = %q, want Bearer secrettoken", got)
		}
		json.NewEncoder(w).Encode(map[string]any{
			"collector_name": "web-1",
			"collector_ip":   "203.0.113.1",
			"public_key":     []byte{1, 2, 3, 4},
		})
	}))
	defer ts.Close()

	e, err := Enroll(context.Background(), ts.Client(), ts.URL, "secrettoken")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if e.CollectorName != "web-1" {
		t.Errorf("CollectorName = %q, want web-1", e.CollectorName)
	}
	if e.Token != "secrettoken" {
		t.Errorf("Token = %q, want secrettoken", e.Token)
	}
	if len(e.PublicKey) == 0 {
		t.Error("expected a non-empty public key")
	}
}

func TestEnroll_ServerRejectsToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	if _, err := Enroll(context.Background(), ts.Client(), ts.URL, "bad-token"); err == nil {
		t.Error("expected an error when the server rejects the token")
	}
}

func TestEnroll_MissingPublicKey(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"collector_name": "web-1"})
	}))
	defer ts.Close()

	if _, err := Enroll(context.Background(), ts.Client(), ts.URL, "t"); err == nil {
		t.Error("expected an error when the server's response has no signing public key")
	}
}

func TestSaveLoadRemoveEnrollment_RoundTrip(t *testing.T) {
	dir := t.TempDir()

	if _, found, err := LoadEnrollment(dir); err != nil || found {
		t.Fatalf("expected not-found+nil-error for a fresh data dir, got found=%v err=%v", found, err)
	}

	want := Enrollment{ServerURL: "https://example.com", Token: "tok", CollectorName: "web-1", PublicKey: []byte{9, 9}}
	if err := SaveEnrollment(dir, want); err != nil {
		t.Fatalf("SaveEnrollment: %v", err)
	}

	got, found, err := LoadEnrollment(dir)
	if err != nil || !found {
		t.Fatalf("LoadEnrollment: found=%v err=%v", found, err)
	}
	if got.ServerURL != want.ServerURL || got.Token != want.Token || got.CollectorName != want.CollectorName {
		t.Errorf("LoadEnrollment = %+v, want %+v", got, want)
	}

	if err := RemoveEnrollment(dir); err != nil {
		t.Fatalf("RemoveEnrollment: %v", err)
	}
	if _, found, _ := LoadEnrollment(dir); found {
		t.Error("expected LoadEnrollment to report not-found after RemoveEnrollment")
	}
	// Removing again (nothing there) must stay a safe no-op.
	if err := RemoveEnrollment(dir); err != nil {
		t.Errorf("RemoveEnrollment on an already-removed enrollment: %v", err)
	}
}
