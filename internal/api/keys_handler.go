// Package api contains HTTP handlers for the SSH-Warden API. Handlers are
// registered against a chi router and share the database via the *DB type
// owned by the server command.
package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/polarisdev-fr/ssh-warden/internal/database"
)

// addKeyRequest is the JSON body accepted by POST /api/v1/keys.
type addKeyRequest struct {
	Username  string `json:"username"`
	PublicKey string `json:"public_key"`
	Comment   string `json:"comment"`
}

// RegisterKeysRoutes attaches the key-management endpoints to the router.
//
//	POST /api/v1/keys  register a public key for a user
func RegisterKeysRoutes(r chi.Router, db *database.DB) {
	r.Post("/api/v1/keys", func(w http.ResponseWriter, r *http.Request) {
		var req addKeyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid payload", http.StatusBadRequest)
			return
		}

		if req.PublicKey == "" {
			http.Error(w, "public_key is required", http.StatusBadRequest)
			return
		}

		key, err := db.AddSSHKey(req.Username, req.PublicKey, req.Comment)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(key)
	})
}
