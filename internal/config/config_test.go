package config

import "testing"

func TestLoad_Defaults(t *testing.T) {
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Database.Path != "./breach_harbor.db" {
		t.Errorf("Database.Path = %q, want default", cfg.Database.Path)
	}
	if cfg.Server.Host != "localhost" || cfg.Server.Port != 8080 {
		t.Errorf("Server = %+v, want localhost:8080 defaults", cfg.Server)
	}
	if cfg.JWT.ExpiryMinutes != 60 {
		t.Errorf("JWT.ExpiryMinutes = %d, want 60", cfg.JWT.ExpiryMinutes)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want info", cfg.LogLevel)
	}
}

func TestLoad_EnvOverrides(t *testing.T) {
	t.Setenv("DB_PATH", "/tmp/custom.db")
	t.Setenv("SERVER_HOST", "0.0.0.0")
	t.Setenv("SERVER_PORT", "9090")
	t.Setenv("JWT_EXPIRY_MINUTES", "120")
	t.Setenv("LOG_LEVEL", "debug")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Database.Path != "/tmp/custom.db" {
		t.Errorf("Database.Path = %q, want /tmp/custom.db", cfg.Database.Path)
	}
	if cfg.Server.Host != "0.0.0.0" || cfg.Server.Port != 9090 {
		t.Errorf("Server = %+v, want 0.0.0.0:9090", cfg.Server)
	}
	if cfg.JWT.ExpiryMinutes != 120 {
		t.Errorf("JWT.ExpiryMinutes = %d, want 120", cfg.JWT.ExpiryMinutes)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want debug", cfg.LogLevel)
	}
}

func TestLoad_InvalidPortFallsBackToZero(t *testing.T) {
	t.Setenv("SERVER_PORT", "not-a-number")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// strconv.Atoi failure is currently silently ignored by getEnv's
	// caller, leaving the zero value — documented here so a future
	// change to stricter validation doesn't regress unnoticed.
	if cfg.Server.Port != 0 {
		t.Errorf("Server.Port = %d, want 0 for an invalid SERVER_PORT", cfg.Server.Port)
	}
}
