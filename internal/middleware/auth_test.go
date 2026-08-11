package middleware

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/Dyneteq/Breach-Harbor/internal/config"
	"github.com/Dyneteq/Breach-Harbor/internal/models"
	"github.com/Dyneteq/Breach-Harbor/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func testAuthService(t *testing.T) *services.AuthService {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "auth_test.db")
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("open sqlite db: %v", err)
	}
	if err := models.MigrateDatabase(db); err != nil {
		t.Fatalf("migrate database: %v", err)
	}
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "test-secret", ExpiryMinutes: 60}}
	return services.NewAuthService(db, cfg)
}

func newTestRouter(mw gin.HandlerFunc) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/protected", mw, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"user_id": c.GetUint("user_id")})
	})
	return r
}

func TestAuthMiddleware_HeaderThenCookie(t *testing.T) {
	authService := testAuthService(t)
	user := &models.User{Email: "u@example.com", Password: "x", IsActive: true}
	// AuthService has no direct "create user" helper that bypasses
	// hashing concerns here — a bare insert is fine, GenerateJWT only
	// needs the ID/Email.
	user.ID = 1
	token, err := authService.GenerateJWT(user)
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}

	r := newTestRouter(AuthMiddleware(authService))

	t.Run("header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("code = %d, want 200; body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("code = %d, want 200 (cookie fallback); body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("neither", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("code = %d, want 401", rec.Code)
		}
	})

	t.Run("bad token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer garbage")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("code = %d, want 401", rec.Code)
		}
	})
}

func TestWebAuthMiddleware_RedirectsInsteadOfJSON(t *testing.T) {
	authService := testAuthService(t)
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/dashboard", WebAuthMiddleware(authService), func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusTemporaryRedirect {
		t.Errorf("code = %d, want 307 redirect", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Errorf("Location = %q, want /login", loc)
	}
}
