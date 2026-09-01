package api

import (
	"net/http"
	"strings"
)

const bearerPrefix = "Bearer "

// bearerAuth parses an Authorization header and returns the raw bearer token.
// ok is false when the header is absent, malformed or empty.
func bearerAuth(r *http.Request) (token string, ok bool) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, bearerPrefix) {
		return "", false
	}
	token = strings.TrimSpace(authHeader[len(bearerPrefix):])
	return token, token != ""
}

// hostAuth guards a handler with host token authentication. It requires a
// well-formed "Bearer <token>" header and validates the token against the
// target host (from the "host" query parameter, defaulting to "*"). On
// failure it writes a 401 (missing/malformed token) or 403 (invalid token) and
// returns false without invoking next.
func hostAuth(db interface {
	ValidateHostToken(hostname, rawToken string) bool
}, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerAuth(r)
		if !ok {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}

		targetHost := r.URL.Query().Get("host")
		if targetHost == "" {
			targetHost = "*"
		}

		if !db.ValidateHostToken(targetHost, token) {
			http.Error(w, "invalid host token", http.StatusForbidden)
			return
		}

		next(w, r)
	}
}
