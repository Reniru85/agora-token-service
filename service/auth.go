// service/auth.go
//
// P1-AGORA-1 — Bearer-token auth for the siGo Agora token server.
// Every request must carry `Authorization: Bearer <BUBBLE_AUTH_TOKEN>`,
// except the /ping healthcheck. The expected token is read once from the
// BUBBLE_AUTH_TOKEN env var. If that var is unset, the service REFUSES TO
// START (fail-closed) so it can never run unauthenticated.

package service

import (
	"crypto/subtle"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

// authMiddleware returns a Gin middleware that enforces a static Bearer token
// on every route except /ping. It matches the existing middleware style in
// this package (s.nocache(), s.CORSMiddleware()).
func (s *Service) authMiddleware() gin.HandlerFunc {
	// Read once at startup (NewService calls this during setup).
	expected := os.Getenv("BUBBLE_AUTH_TOKEN")
	if expected == "" {
		// Fail-closed: do not boot a token server with no auth.
		log.Fatal("FATAL ERROR: BUBBLE_AUTH_TOKEN not set — refusing to start without authentication")
	}
	expectedBytes := []byte(expected)

	return func(c *gin.Context) {
		// Railway's healthcheck hits /ping with no auth header — let it through.
		if c.Request.URL.Path == "/ping" {
			c.Next()
			return
		}

		const prefix = "Bearer "
		header := c.GetHeader("Authorization")
		if !strings.HasPrefix(header, prefix) {
			// Note: we never log the header value.
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		got := []byte(strings.TrimPrefix(header, prefix))

		// Constant-time compare avoids timing side-channels on the secret.
		if subtle.ConstantTimeCompare(got, expectedBytes) != 1 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		c.Next()
	}
}
