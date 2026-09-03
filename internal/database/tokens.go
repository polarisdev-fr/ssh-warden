package database

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"
)

// userTokenPrefix is the human-recognisable prefix of opaque CLI tokens. The
// full token looks like "wrd_pat_<random hex>"; only its SHA-256 digest is
// stored.
const userTokenPrefix = "wrd_pat_"

// ErrTokenNotFound is returned when no unexpired user token matches.
var ErrTokenNotFound = errors.New("user token not found")

// hashUserToken returns the hex-encoded SHA-256 digest of a raw user token.
func hashUserToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// CreateUserToken generates a new opaque, prefixed token for username, stores
// only its SHA-256 digest (with an expiry and the user's role), and returns the
// raw token so the caller can hand it to the user exactly once. The role is
// frozen at mint time so the token keeps its privilege even if the user's role
// later changes.
func (db *DB) CreateUserToken(username, role string, duration time.Duration) (string, error) {
	if username == "" {
		return "", errors.New("username is required")
	}
	if role == "" {
		role = "user"
	}

	raw := userTokenPrefix + randomHex(48)
	if _, err := db.conn.Exec(
		"INSERT INTO user_tokens (username, role, token_hash, expires_at) VALUES (?, ?, ?, ?)",
		username, role, hashUserToken(raw), time.Now().UTC().Add(duration),
	); err != nil {
		return "", err
	}
	return raw, nil
}

// ValidateUserToken reports whether rawToken matches an unexpired stored
// digest, returning the associated username and role when valid.
func (db *DB) ValidateUserToken(rawToken string) (username, role string, valid bool) {
	if rawToken == "" {
		return "", "", false
	}
	computed := hashUserToken(rawToken)

	var expiresAt time.Time
	err := db.conn.QueryRow(
		"SELECT username, role, expires_at FROM user_tokens WHERE token_hash = ?",
		computed,
	).Scan(&username, &role, &expiresAt)
	if err != nil {
		return "", "", false
	}
	if time.Now().UTC().After(expiresAt) {
		return "", "", false
	}
	return username, role, true
}

// randomHex returns n random bytes hex-encoded.
func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("cannot read from crypto/rand: " + err.Error())
	}
	return hex.EncodeToString(b)
}
