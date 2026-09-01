package api

import (
	"net"
	"net/http"
	"strings"

	"github.com/polarisdev-fr/ssh-warden/internal/database"
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

// logAudit records an authorization decision. Recording failures are swallowed
// so a logging error never blocks an authorization that has already been
// decided.
func logAudit(db auditWriter, r *http.Request, username, targetHost, action, reason string) {
	db.RecordAudit(username, targetHost, action, reason, clientIP(r))
}

// auditWriter is the minimal persistence surface the API needs for audit
// logging. *database.DB satisfies it.
type auditWriter interface {
	RecordAudit(username, targetHost, action, reason, clientIP string) error
}

// compile-time check that *database.DB implements auditWriter.
var _ auditWriter = (*database.DB)(nil)
