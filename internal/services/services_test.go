package services

import (
	"path/filepath"
	"testing"

	"github.com/Dyneteq/Breach-Harbor/internal/config"
	"github.com/Dyneteq/Breach-Harbor/internal/models"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// openTestDB mirrors internal/models' own test helper — a throwaway
// file-backed sqlite db via the pure-Go glebarez driver, migrated and
// ready for service-layer tests.
func openTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "breach_harbor_test.db")
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("open sqlite db: %v", err)
	}
	if err := models.MigrateDatabase(db); err != nil {
		t.Fatalf("migrate database: %v", err)
	}
	return db
}

// testLocationService returns a LocationService with no MaxMind
// databases configured (the common case in CI/dev without a
// downloaded .mmdb) — every enrichment falls back to its documented
// "no data available" behavior rather than erroring.
func testLocationService(t *testing.T, db *gorm.DB) *LocationService {
	t.Helper()
	cfg := &config.Config{MaxMind: config.MaxMindConfig{
		DBPath:    filepath.Join(t.TempDir(), "missing-city.mmdb"),
		ASNDBPath: filepath.Join(t.TempDir(), "missing-asn.mmdb"),
	}}
	svc, err := NewLocationService(db, cfg)
	if err != nil {
		t.Fatalf("NewLocationService: %v", err)
	}
	t.Cleanup(func() { svc.Close() })
	return svc
}

func createTestUser(t *testing.T, db *gorm.DB) models.User {
	t.Helper()
	u := models.User{Email: "analyst@example.com", Password: "hashed"}
	if err := db.Create(&u).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	return u
}
