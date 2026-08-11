package middleware

import (
	"net/http"
	"strings"

	"github.com/Dyneteq/Breach-Harbor/internal/services"

	"github.com/gin-gonic/gin"
)

// bearerToken extracts a JWT from either the Authorization header (JSON
// API clients, and CollectorAuthMiddleware below) or the auth_token
// cookie the HTMX login flow sets (handlers/web.go's HandleLogin) — the
// previous inconsistency (only the header was ever read) meant every
// browser-side page silently fell through to "unauthenticated".
func bearerToken(c *gin.Context) (string, bool) {
	if authHeader := c.GetHeader("Authorization"); authHeader != "" {
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token != authHeader {
			return token, true
		}
	}
	if cookie, err := c.Cookie("auth_token"); err == nil && cookie != "" {
		return cookie, true
	}
	return "", false
}

// AuthMiddleware protects JSON API routes: header-then-cookie token
// extraction, JSON 401 on failure.
func AuthMiddleware(authService *services.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString, ok := bearerToken(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
			c.Abort()
			return
		}

		claims, err := authService.ValidateJWT(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			c.Abort()
			return
		}

		c.Set("user_id", claims.UserID)
		c.Set("user_email", claims.Email)
		c.Next()
	}
}

// WebAuthMiddleware protects browser-rendered pages: same
// header-then-cookie extraction as AuthMiddleware, but redirects to
// /login on failure instead of returning JSON — the pages behind it
// (handlers/web.go) render full HTML documents, not API responses.
func WebAuthMiddleware(authService *services.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString, ok := bearerToken(c)
		if !ok {
			c.Redirect(http.StatusTemporaryRedirect, "/login")
			c.Abort()
			return
		}

		claims, err := authService.ValidateJWT(tokenString)
		if err != nil {
			c.Redirect(http.StatusTemporaryRedirect, "/login")
			c.Abort()
			return
		}

		c.Set("user_id", claims.UserID)
		c.Set("user_email", claims.Email)
		c.Next()
	}
}

// CollectorAuthMiddleware protects the agent-facing /v1 routes. Agents
// always authenticate via the Authorization header (never a cookie —
// there is no browser session), so this stays header-only.
func CollectorAuthMiddleware(collectorService *services.CollectorService) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Bearer token required"})
			c.Abort()
			return
		}

		collector, err := collectorService.ValidateCollectorToken(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid collector token"})
			c.Abort()
			return
		}

		c.Set("collector_id", collector.ID)
		c.Set("collector_token", tokenString)
		c.Next()
	}
}
