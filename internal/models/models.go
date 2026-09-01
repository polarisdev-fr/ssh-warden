// Package models defines the core data structures shared across the
// server, CLI and helper binaries of SSH-Warden.
package models

import "time"

// User represents a system account that can request temporary SSH access.
type User struct {
	ID        int64     `json:"id"`
	Username  string    `json:"username"`
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

// Lease is a time-boxed grant of SSH access for a specific user against a
// target host (or "*" for all hosts).
type Lease struct {
	ID         int64     `json:"id"`
	UserID     int64     `json:"user_id"`
	TargetHost string    `json:"target_host"`
	ExpiresAt  time.Time `json:"expires_at"`
	Reason     string    `json:"reason"`
	CreatedAt  time.Time `json:"created_at"`
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
