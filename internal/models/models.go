// Package models defines the core data structures shared across the
// server, CLI and helper binaries of SSH-Warden.
package models

import "time"

// Role values describe the permission level of a user. Administrators can
// manage every lease (approve/reject/revoke) and see all activity, whereas a
// regular user can only manage their own leases and see their own activity.
const (
	RoleUser  = "user"
	RoleAdmin = "admin"
)

// User represents a system account that can request temporary SSH access.
type User struct {
	ID        int64     `json:"id"`
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

// SSHKey represents a public key registered for a user. Keys are only
// authorized while an active, unexpired lease exists for the user.
type SSHKey struct {
	ID        int64     `json:"id"`
	UserID    int64     `json:"user_id"`
	PublicKey string    `json:"public_key"`
	Comment   string    `json:"comment"`
	CreatedAt time.Time `json:"created_at"`
}

// Lease status values describe the approval state of a lease. By default
// leases are approved immediately; an approval workflow can instead create
// them in a pending state that requires a second sign-off before taking
// effect.
const (
	// LeaseStatusApproved means the lease is active and grants key access.
	LeaseStatusApproved = "approved"
	// LeaseStatusPending means the lease waits for a second sign-off.
	LeaseStatusPending = "pending"
	// LeaseStatusDenied means the lease was explicitly rejected.
	LeaseStatusDenied = "denied"
)

// Lease is a time-boxed grant of SSH access for a specific user against a
// target host (or "*" for all hosts).
type Lease struct {
	ID         int64     `json:"id"`
	UserID     int64     `json:"user_id"`
	TargetHost string    `json:"target_host"`
	ExpiresAt  time.Time `json:"expires_at"`
	Reason     string    `json:"reason"`
	CreatedAt  time.Time `json:"created_at"`
	Status     string    `json:"status"`
}

// LeaseInfo is a read-only projection of a lease including the username,
// intended for status/listing responses.
type LeaseInfo struct {
	ID         int64     `json:"id"`
	Username   string    `json:"username"`
	TargetHost string    `json:"target_host"`
	Reason     string    `json:"reason"`
	ExpiresAt  time.Time `json:"expires_at"`
	CreatedAt  time.Time `json:"created_at"`
	Status     string    `json:"status"`
}

// Host represents a machine that may request keys via the API. The host is
// authenticated with a raw bearer token whose SHA-256 digest is stored in
// TokenHash at registration time.
type Host struct {
	ID        int64     `json:"id"`
	Hostname  string    `json:"hostname"`
	TokenHash string    `json:"token_hash"`
	CreatedAt time.Time `json:"created_at"`
}

// AuditLog records a single authorization decision made by the API, most
// notably when an OpenSSH host's helper asks for a user's authorized keys.
// Action describes the outcome and Reason provides human-readable detail.
type AuditLog struct {
	ID         int64     `json:"id"`
	Username   string    `json:"username"`
	TargetHost string    `json:"target_host"`
	Action     string    `json:"action"`
	Reason     string    `json:"reason"`
	ClientIP   string    `json:"client_ip"`
	CreatedAt  time.Time `json:"created_at"`
}

// SystemInfo is a read-only snapshot exposed by GET /api/v1/system for the Web
// UI's System view. It reports operational details about the running server.
type SystemInfo struct {
	Version     string `json:"version"`
	AuthMode    string `json:"auth_mode"`
	AuthEnabled bool   `json:"auth_enabled"`
	MTLSEnabled bool   `json:"mtls_enabled"`
	DBPath      string `json:"db_path"`
}

// ActivityPoint aggregates authorization decisions for a single time bucket
// (usually one day) used by the Overview activity chart.
type ActivityPoint struct {
	// Bucket is a short human label for the bucket (e.g. "09-02" or "14:00").
	Bucket  string `json:"bucket"`
	Granted int    `json:"granted"`
	Denied  int    `json:"denied"`
}

// HostCount reports how many times a target host was granted access, used by
// the Overview "top hosts" breakdown.
type HostCount struct {
	Host  string `json:"host"`
	Count int    `json:"count"`
}

// Overview aggregates the metrics shown by the dashboard Overview view.
type Overview struct {
	ActiveLeasesCount  int             `json:"active_leases_count"`
	PendingLeasesCount int             `json:"pending_leases_count"`
	TotalGranted24h    int             `json:"total_granted_24h"`
	TotalDenied24h     int             `json:"total_denied_24h"`
	ActivityTimeline   []ActivityPoint `json:"activity_timeline"`
	TopHosts           []HostCount     `json:"top_hosts"`
}
