package models

import (
	"path/filepath"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// openTestDB verifies the pure-Go glebarez/sqlite (modernc.org/sqlite)
// GORM dialector works as a drop-in replacement for the old CGO
// gorm.io/driver/sqlite: AutoMigrate and basic CRUD against a throwaway
// file, with no CGO involved.
func openTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "breach_harbor_test.db")
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("open sqlite db: %v", err)
	}
	if err := MigrateDatabase(db); err != nil {
		t.Fatalf("migrate database: %v", err)
	}
	return db
}

func TestMigrateDatabase(t *testing.T) {
	db := openTestDB(t)
	for _, model := range []any{&User{}, &Location{}, &IPAddress{}, &Collector{}, &Incident{}, &Notification{}, &IncidentNotification{}} {
		if !db.Migrator().HasTable(model) {
			t.Errorf("expected table for %T to exist after migration", model)
		}
	}
}

func TestUserCRUD(t *testing.T) {
	db := openTestDB(t)

	u := &User{Email: "analyst@example.com", Password: "hashed", FirstName: "A", LastName: "B"}
	if err := db.Create(u).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	if u.ID == 0 {
		t.Fatal("expected user ID to be populated after create")
	}

	var got User
	if err := db.First(&got, u.ID).Error; err != nil {
		t.Fatalf("read back user: %v", err)
	}
	if got.Email != u.Email {
		t.Errorf("email = %q, want %q", got.Email, u.Email)
	}
}

func TestIncidentMetadataRoundTrip(t *testing.T) {
	db := openTestDB(t)

	user := &User{Email: "u@example.com", Password: "x"}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	loc := &Location{CountryName: "Unknown", CountryCode: "XX", City: "Unknown"}
	if err := db.Create(loc).Error; err != nil {
		t.Fatalf("create location: %v", err)
	}
	ip := &IPAddress{IP: "203.0.113.44", LocationID: loc.ID}
	if err := db.Create(ip).Error; err != nil {
		t.Fatalf("create ip address: %v", err)
	}
	collector := &Collector{Name: "test-collector", IP: "203.0.113.1", TokenHash: "deadbeef", UserID: user.ID}
	if err := db.Create(collector).Error; err != nil {
		t.Fatalf("create collector: %v", err)
	}

	want := map[string]interface{}{
		"failed_logins": float64(7),
		"username":      "root",
		"port":          float64(22),
	}
	incident := &Incident{
		IncidentType: "ssh_brute_force",
		Metadata:     want,
		CollectorID:  collector.ID,
		UserID:       user.ID,
		IPAddressID:  ip.ID,
	}
	if err := db.Create(incident).Error; err != nil {
		t.Fatalf("create incident: %v", err)
	}

	var got Incident
	if err := db.First(&got, incident.ID).Error; err != nil {
		t.Fatalf("read back incident: %v", err)
	}
	if len(got.Metadata) != len(want) {
		t.Fatalf("metadata round-trip: got %v, want %v", got.Metadata, want)
	}
	for k, v := range want {
		if got.Metadata[k] != v {
			t.Errorf("metadata[%q] = %v, want %v", k, got.Metadata[k], v)
		}
	}
}
