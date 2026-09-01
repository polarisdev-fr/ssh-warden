package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

// addKeyRequest is the JSON body accepted by POST /api/v1/keys.
type addKeyRequest struct {
	Username  string `json:"username"`
	PublicKey string `json:"public_key"`
	Comment   string `json:"comment"`
}

// registerKeysRoutes attaches the key-management endpoints to the router.
//
//	GET  /api/v1/keys/{username}  public keys for a user (host bearer auth)
//	POST /api/v1/keys             register a public key for a user
func (s *Server) registerKeysRoutes(r chi.Router) {
	// The AuthorizedKeysCommand on each OpenSSH host invokes the helper,
	// which calls this endpoint with the machine's bearer token and host ID.
	// The token authenticates the machine; the resulting keys are scoped to
	// the machine's leases.
	r.Get("/api/v1/keys/{username}", hostAuth(s.db, s.handleGetUserKeys))

	r.Post("/api/v1/keys", s.handleAddKey)
}

// handleGetUserKeys returns the currently authorized public keys for the
// user in the URL. The response is printed by OpenSSH's AuthorizedKeysCommand.
func (s *Server) handleGetUserKeys(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")

	targetHost := r.URL.Query().Get("host")
	if targetHost == "" {
		targetHost = "*"
	}

	keys, err := s.db.GetValidKeysForUser(username, targetHost)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if len(keys) == 0 {
		http.Error(w, "no active keys found or lease expired", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(strings.Join(keys, "\n") + "\n"))
}

// handleAddKey validates and registers a public key for a user.
func (s *Server) handleAddKey(w http.ResponseWriter, r *http.Request) {
	var req addKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	if req.PublicKey == "" {
		http.Error(w, "public_key is required", http.StatusBadRequest)
		return
	}

	key, err := s.db.AddSSHKey(req.Username, req.PublicKey, req.Comment)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(key)
}
