package api

import (
	"encoding/json"
	"net/http"
	"time"
)

// tokenTTL is the lifetime of CLI tokens issued via the Web UI approve flow.
const tokenTTL = 30 * 24 * time.Hour

// userTokenAuth is a middleware that validates the CLI user token carried in
// the "Authorization: Bearer <token>" header. Downstream handlers use the
// authenticated username to scope their work.
func (s *Server) userTokenAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerAuth(r)
		if !ok {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		username, valid := s.db.ValidateUserToken(token)
		if !valid {
			http.Error(w, "invalid or expired user token", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(withUserName(r, username)))
	})
}

// requireUserToken wraps a http.HandlerFunc with the user token middleware.
func (s *Server) requireUserToken(next http.HandlerFunc) http.Handler {
	return s.userTokenAuth(next)
}

// handleCreateUserToken mints a new CLI token for the currently authenticated
// UI user and returns it (along with the username) so the /ui/cli-auth page
// can hand it to the CLI. The route is guarded by the same UI auth as /ui.
func (s *Server) handleCreateUserToken(w http.ResponseWriter, r *http.Request) {
	username := s.currentUserName(r)
	if username == "" {
		http.Error(w, "could not determine authenticated user", http.StatusForbidden)
		return
	}

	raw, err := s.db.CreateUserToken(username, tokenTTL)
	if err != nil {
		http.Error(w, "could not create token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"token":    raw,
		"username": username,
	})
}
