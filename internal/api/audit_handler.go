package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/polarisdev-fr/ssh-warden/internal/models"
)

// registerAuditRoutes attaches the audit-log query endpoint to the router.
//
//	GET /api/v1/audit   list authorization audit events
func (s *Server) registerAuditRoutes(r chi.Router) {
	r.With(s.attachActor).Get("/api/v1/audit", s.handleListAudit)
}

// handleListAudit returns audit logs, optionally filtered by the "user" query
// parameter and target host (the "host" parameter), and capped by "limit".
func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("user")
	// A regular user may only see their own audit trail.
	if forced := s.forcedUsername(r); forced != "" {
		username = forced
	}
	targetHost := r.URL.Query().Get("host")

	var limit int
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			http.Error(w, "invalid limit", http.StatusBadRequest)
			return
		}
		limit = parsed
	}

	logs, err := s.db.GetAuditLogs(limit, targetHost, username)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if logs == nil {
		logs = []models.AuditLog{}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(logs)
}
