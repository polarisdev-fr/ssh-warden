package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/polarisdev-fr/ssh-warden/internal/database"
	"github.com/polarisdev-fr/ssh-warden/internal/models"
)

// createLeaseRequest is the JSON body accepted by POST /api/v1/leases.
// Duration is expressed as a Go duration string (e.g. "30m", "2h").
type createLeaseRequest struct {
	Username   string `json:"username"`
	TargetHost string `json:"target_host"`
	Duration   string `json:"duration"`
	Reason     string `json:"reason"`
	// RequiresApproval, when true, creates the lease in a pending state
	// instead of immediately granting access.
	RequiresApproval bool `json:"requires_approval"`
}

// registerLeasesRoutes attaches the lease-management endpoints to the router.
//
//	POST   /api/v1/leases                create a temporary lease
//	GET    /api/v1/leases                list active (approved) leases
//	GET    /api/v1/leases/pending        list leases awaiting approval
//	POST   /api/v1/leases/{id}/approve   approve a pending lease
//	POST   /api/v1/leases/{id}/reject    reject a pending lease
//	DELETE /api/v1/leases/{id}           revoke a lease
func (s *Server) registerLeasesRoutes(r chi.Router) {
	// Listing endpoints accept an optional Bearer user token to scope a regular
	// user to their own leases (anonymous callers see everything).
	r.With(s.attachActor).Get("/api/v1/leases", s.handleListLeases)
	r.With(s.attachActor).Get("/api/v1/leases/pending", s.handleListPendingLeases)
	// approve and reject additionally require the admin role.
	r.With(s.userTokenAuth).Post("/api/v1/leases", s.handleCreateLease)
	r.With(s.requireAuthActor, s.requireAdmin).Post("/api/v1/leases/{id}/approve", s.handleApproveLease)
	r.With(s.requireAuthActor, s.requireAdmin).Post("/api/v1/leases/{id}/reject", s.handleRejectLease)
	// revoke allows any authenticated user, but a regular user may only revoke
	// their own leases (checked in the handler).
	r.With(s.requireAuthActor).Delete("/api/v1/leases/{id}", s.handleRevokeLease)
}

// handleListLeases returns approved active leases, optionally filtered by the
// "user" query parameter.
func (s *Server) handleListLeases(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	if forced := s.forcedUsername(r); forced != "" {
		// A regular user may only see their own leases regardless of the
		// requested filter.
		user = forced
	}

	leases, err := s.db.GetActiveLeases(user)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if leases == nil {
		leases = []models.LeaseInfo{}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(leases)
}

// handleListPendingLeases returns leases in the pending approval state.
// Regular users only see their own pending leases.
func (s *Server) handleListPendingLeases(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	if forced := s.forcedUsername(r); forced != "" {
		user = forced
	}

	leases, err := s.db.GetPendingLeases(user)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if leases == nil {
		leases = []models.LeaseInfo{}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(leases)
}

// handleCreateLease creates a lease from the JSON body and returns it.
// When requires_approval is true in the request body, the lease is created in
// a pending state instead of immediately granting access.
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

	var lease *models.Lease
	if req.RequiresApproval {
		lease, err = s.db.CreatePendingLease(req.Username, req.TargetHost, req.Reason, duration)
	} else {
		lease, err = s.db.CreateLease(req.Username, req.TargetHost, req.Reason, duration)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(lease)
}

// handleApproveLease approves a pending lease by ID and records the decision.
func (s *Server) handleApproveLease(w http.ResponseWriter, r *http.Request) {
	leaseID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid lease id", http.StatusBadRequest)
		return
	}

	if err := s.db.ApproveLease(leaseID); err != nil {
		switch {
		case errors.Is(err, database.ErrLeaseNotFound):
			http.Error(w, err.Error(), http.StatusNotFound)
		case errors.Is(err, database.ErrLeaseNotPending):
			http.Error(w, err.Error(), http.StatusConflict)
		default:
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
		return
	}

	s.logAudit(r, "-", "*", actionLeaseApproved,
		"Lease #"+strconv.FormatInt(leaseID, 10)+" approved")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "lease approved"})
}

// handleRejectLease rejects a pending lease by ID and records the decision.
func (s *Server) handleRejectLease(w http.ResponseWriter, r *http.Request) {
	leaseID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid lease id", http.StatusBadRequest)
		return
	}

	if err := s.db.RejectLease(leaseID); err != nil {
		switch {
		case errors.Is(err, database.ErrLeaseNotFound):
			http.Error(w, err.Error(), http.StatusNotFound)
		case errors.Is(err, database.ErrLeaseNotPending):
			http.Error(w, err.Error(), http.StatusConflict)
		default:
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
		return
	}

	s.logAudit(r, "-", "*", actionLeaseRejected,
		"Lease #"+strconv.FormatInt(leaseID, 10)+" rejected")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "lease rejected"})
}

// handleRevokeLease revokes a lease by ID and reports the outcome. Admins may
// revoke any lease; a regular user may only revoke their own.
func (s *Server) handleRevokeLease(w http.ResponseWriter, r *http.Request) {
	leaseID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid lease id", http.StatusBadRequest)
		return
	}

	if !s.isAdmin(r) {
		owner, ok := s.db.GetLeaseOwner(leaseID)
		if !ok || owner != s.requesterUser(r) {
			http.Error(w, "forbidden: you may only revoke your own leases", http.StatusForbidden)
			return
		}
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
