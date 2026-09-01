package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/polarisdev-fr/ssh-warden/internal/database"
)

// createLeaseRequest is the JSON body accepted by POST /api/v1/leases.
// Duration is expressed as a Go duration string (e.g. "30m", "2h").
type createLeaseRequest struct {
	Username   string `json:"username"`
	TargetHost string `json:"target_host"`
	Duration   string `json:"duration"`
	Reason     string `json:"reason"`
}

// registerLeasesRoutes attaches the lease-management endpoints to the router.
//
//	POST   /api/v1/leases        create a temporary lease
//	GET    /api/v1/leases        list active leases
//	DELETE /api/v1/leases/{id}   revoke a lease
func (s *Server) registerLeasesRoutes(r chi.Router) {
	r.Get("/api/v1/leases", s.handleListLeases)
	r.Post("/api/v1/leases", s.handleCreateLease)
	r.Delete("/api/v1/leases/{id}", s.handleRevokeLease)
}

// handleListLeases returns active leases, optionally filtered by the "user"
// query parameter.
func (s *Server) handleListLeases(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")

	leases, err := s.db.GetActiveLeases(user)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(leases)
}

// handleCreateLease creates a lease from the JSON body and returns it.
func (s *Server) handleCreateLease(w http.ResponseWriter, r *http.Request) {
	var req createLeaseRequest
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

	lease, err := s.db.CreateLease(req.Username, req.TargetHost, req.Reason, duration)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(lease)
}

// handleRevokeLease revokes a lease by ID and reports the outcome.
func (s *Server) handleRevokeLease(w http.ResponseWriter, r *http.Request) {
	leaseID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid lease id", http.StatusBadRequest)
		return
	}

	if err := s.db.RevokeLease(leaseID); err != nil {
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
}
