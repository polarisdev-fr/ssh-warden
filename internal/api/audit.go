package api

import (
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/polarisdev-fr/ssh-warden/internal/models"
)

// Audit actions recorded to the audit_logs table.
const (
	actionKeyGranted = "KEY_REQUEST_GRANTED"
	actionKeyDenied  = "KEY_REQUEST_DENIED"
	actionHostFailed = "HOST_AUTH_FAILED"
)

// clientIP extracts the real client IP. When X-Forwarded-For is present and
// non-empty its first value is used; otherwise r.RemoteAddr is used with its
// port stripped.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		first := strings.TrimSpace(strings.Split(xff, ",")[0])
		if first != "" {
			return first
		}
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

// logAudit builds an audit entry, persists it to the database and dispatches a
// webhook notification. Recording and notification failures are swallowed (and
// logged by the webhook layer) so they never block an authorization that has
// already been decided.
func (s *Server) logAudit(r *http.Request, username, targetHost, action, reason string) {
	entry := models.AuditLog{
		Username:   username,
		TargetHost: targetHost,
		Action:     action,
		Reason:     reason,
		ClientIP:   clientIP(r),
		CreatedAt:  time.Now().UTC(),
	}

	if err := s.db.RecordAudit(entry.Username, entry.TargetHost, entry.Action, entry.Reason, entry.ClientIP); err != nil {
		return
	}

	s.notifier.Notify(entry)
}
