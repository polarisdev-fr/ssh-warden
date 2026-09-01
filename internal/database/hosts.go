package database

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
)

// hashToken returns the hex-encoded SHA-256 digest of a raw token. Only the
// digest is ever persisted, so a leaked database does not expose usable
// host tokens.
func hashToken(rawToken string) string {
	sum := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(sum[:])
}

// RegisterHost stores a new host identity, persisting the SHA-256 digest of
// the provided raw token rather than the token itself.
func (db *DB) RegisterHost(hostname, rawToken string) error {
	if hostname == "" || rawToken == "" {
		return fmt.Errorf("hostname and token are required")
	}

	_, err := db.conn.Exec(
		"INSERT INTO hosts (hostname, token_hash) VALUES (?, ?)",
		hostname, hashToken(rawToken),
	)
	if err != nil {
		return fmt.Errorf("cannot register host: %w", err)
	}
	return nil
}

// ValidateHostToken reports whether rawToken matches the digest stored for
// hostname. The comparison uses constant-time logic to avoid leaking
// information about the stored digest via timing, and returns false both when
// the host is unknown and when no token is supplied, without distinguishing
// between the two.
func (db *DB) ValidateHostToken(hostname, rawToken string) bool {
	var storedHash string
	err := db.conn.QueryRow("SELECT token_hash FROM hosts WHERE hostname = ?", hostname).Scan(&storedHash)
	if err != nil || rawToken == "" {
		return false
	}

	computed := hashToken(rawToken)
	return subtle.ConstantTimeCompare([]byte(computed), []byte(storedHash)) == 1
}
