package config

import (
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	Database   DatabaseConfig
	JWT        JWTConfig
	Server     ServerConfig
	MaxMind    MaxMindConfig
	CORS       CORSConfig
	LogLevel   string
}

type DatabaseConfig struct {
	Path string
}

type JWTConfig struct {
	Secret        string
	ExpiryMinutes int
}

type ServerConfig struct {
	Host string
	Port int
}

type MaxMindConfig struct {
	DBPath string
}

type CORSConfig struct {
	AllowedOrigins []string
}

func Load() (*Config, error) {
	godotenv.Load()

	serverPort, _ := strconv.Atoi(getEnv("SERVER_PORT", "8080"))
	jwtExpiry, _ := strconv.Atoi(getEnv("JWT_EXPIRY_MINUTES", "60"))

	return &Config{
		Database: DatabaseConfig{
			Path: getEnv("DB_PATH", "./breach_harbor.db"),
		},
		JWT: JWTConfig{
			Secret:        getEnv("JWT_SECRET", "your-secret-key-here-make-it-long-and-secure"),
			ExpiryMinutes: jwtExpiry,
		},
		Server: ServerConfig{
			Host: getEnv("SERVER_HOST", "localhost"),
			Port: serverPort,
		},
		MaxMind: MaxMindConfig{
			DBPath: getEnv("MAXMIND_DB_PATH", "./data/GeoLite2-City.mmdb"),
		},
		CORS: CORSConfig{
			AllowedOrigins: []string{getEnv("CORS_ALLOWED_ORIGINS", "http://localhost:3000")},
		},
		LogLevel: getEnv("LOG_LEVEL", "info"),
	}, nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}