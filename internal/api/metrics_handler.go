package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/polarisdev-fr/ssh-warden/internal/models"
)

// overviewDays is the number of daily buckets in the activity timeline.
const overviewDays = 7

// handleOverview aggregates analytics for the dashboard Overview view. The
// statistics are scoped to the caller: a regular user sees metrics for their
// own leases and activity, an admin sees the global picture.
func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	user := s.forcedUsername(r)

	active, err := s.db.CountActiveLeases(user)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	pending, err := s.db.CountPendingLeases(user)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	since24h := time.Now().UTC().Add(-24 * time.Hour)
	granted24h, err := s.db.CountAuditDecisionsSince(actionKeyGranted, user, since24h)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	denied24h, err := s.db.CountAuditDecisionsSince(actionKeyDenied, user, since24h)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	timeline, err := s.db.ActivityTimeline(user, overviewDays)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	topHosts, err := s.db.TopHosts(user, 5)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if topHosts == nil {
		topHosts = []models.HostCount{}
	}

	overview := models.Overview{
		ActiveLeasesCount:  active,
		PendingLeasesCount: pending,
		TotalGranted24h:    granted24h,
		TotalDenied24h:     denied24h,
		ActivityTimeline:   timeline,
		TopHosts:           topHosts,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(overview)
}

// handleListHosts returns per-machine access statistics for the dashboard
// "Machines" view. A regular user only sees the machines they accessed; an
// admin (or anonymous caller) sees all machines.
func (s *Server) handleListHosts(w http.ResponseWriter, r *http.Request) {
	user := s.forcedUsername(r)

	hosts, err := s.db.HostStats(user)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if hosts == nil {
		hosts = []models.HostStats{}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(hosts)
}
