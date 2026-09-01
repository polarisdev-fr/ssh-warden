// Command server runs the SSH-Warden HTTP API. It exposes the JSON endpoints
// consumed by the CLI and the OpenSSH helper:
//
//   - GET  /api/v1/keys/{username}   public keys for a user (Bearer auth)
//   - GET  /api/v1/leases            list active leases
//   - POST /api/v1/leases            create a temporary lease
//   - DELETE /api/v1/leases/{id}     revoke a lease
package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/polarisdev-fr/ssh-warden/internal/api"
	"github.com/polarisdev-fr/ssh-warden/internal/database"
)

func main() {
	db, err := database.InitDB("warden.db")
	if err != nil {
		log.Fatalf("cannot initialize database: %v", err)
	}

	if err := db.SeedData(); err != nil {
		log.Printf("seed warning: %v", err)
	}

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	api.RegisterKeysRoutes(r, db)

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// The AuthorizedKeysCommand on each OpenSSH host invokes the helper,
	// which calls this endpoint with the machine's bearer token and host ID.
	// The token authenticates the machine; the resulting keys are scoped to
	// the machine's leases.
	r.Get("/api/v1/keys/{username}", func(w http.ResponseWriter, r *http.Request) {
		username := chi.URLParam(r, "username")

		targetHost := r.URL.Query().Get("host")
		if targetHost == "" {
			targetHost = "*"
		}

		// Host authentication: require a well-formed "Bearer <token>".
		const bearerPrefix = "Bearer "
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, bearerPrefix) {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		token := strings.TrimSpace(authHeader[len(bearerPrefix):])
		if token == "" {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}

		if !db.ValidateHostToken(targetHost, token) {
			http.Error(w, "invalid host token", http.StatusForbidden)
			return
		}

		keys, err := db.GetValidKeysForUser(username, targetHost)
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
	})

	r.Get("/api/v1/leases", func(w http.ResponseWriter, r *http.Request) {
		user := r.URL.Query().Get("user")

		leases, err := db.GetActiveLeases(user)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(leases)
	})

	r.Delete("/api/v1/leases/{id}", func(w http.ResponseWriter, r *http.Request) {
		leaseID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
		if err != nil {
			http.Error(w, "invalid lease id", http.StatusBadRequest)
			return
		}

		if err := db.RevokeLease(leaseID); err != nil {
			switch {
			case errors.Is(err, database.ErrLeaseNotFound):
				http.Error(w, err.Error(), http.StatusNotFound)
			case errors.Is(err, database.ErrLeaseAlreadyExpired):
				http.Error(w, err.Error(), http.StatusNotFound)
			default:
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "lease revoked"})
	})

	// CreateLeaseRequest is the JSON body accepted by POST /api/v1/leases.
	// Duration is expressed as a Go duration string (e.g. "30m", "2h").
	type CreateLeaseRequest struct {
		Username   string `json:"username"`
		TargetHost string `json:"target_host"`
		Duration   string `json:"duration"`
		Reason     string `json:"reason"`
	}

	r.Post("/api/v1/leases", func(w http.ResponseWriter, r *http.Request) {
		var req CreateLeaseRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid payload", http.StatusBadRequest)
			return
		}

		duration, err := time.ParseDuration(req.Duration)
		if err != nil {
			http.Error(w, "invalid duration format (e.g. 30m, 2h)", http.StatusBadRequest)
			return
		}

		if req.TargetHost == "" {
			req.TargetHost = "*"
		}

		lease, err := db.CreateLease(req.Username, req.TargetHost, req.Reason, duration)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(lease)
	})

	port := ":8080"
	log.Printf("SSH-Warden API listening on http://localhost%s", port)
	if err := http.ListenAndServe(port, r); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
