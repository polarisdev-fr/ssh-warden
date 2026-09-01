package api

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
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

// hostAuth guards the key-fetch handler with host token authentication. It
// requires a well-formed "Bearer <token>" header and validates the token
// against the target host (from the "host" query parameter, defaulting to
// "*"). On failure it records a HOST_AUTH_FAILED audit event and writes a 401
// (missing/malformed token) or 403 (invalid token), without invoking next.
func (s *Server) hostAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerAuth(r)
		if !ok {
			s.hostFailed(r, "missing or malformed token")
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}

		targetHost := r.URL.Query().Get("host")
		if targetHost == "" {
			targetHost = "*"
		}

		if !s.db.ValidateHostToken(targetHost, token) {
			s.hostFailed(r, "invalid host token")
			http.Error(w, "invalid host token", http.StatusForbidden)
			return
		}

		next(w, r)
	}
}

// hostFailed logs a HOST_AUTH_FAILED audit event from the username in the URL
// path.
func (s *Server) hostFailed(r *http.Request, reason string) {
	username := chi.URLParam(r, "username")
	if username == "" {
		username = "-"
	}
	targetHost := r.URL.Query().Get("host")
	if targetHost == "" {
		targetHost = "*"
	}
	s.logAudit(r, username, targetHost, actionHostFailed, reason)
}
