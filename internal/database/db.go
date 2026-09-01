// Package database provides the SQLite-backed persistence layer for
// SSH-Warden. It is responsible for users, SSH keys, leases and host tokens,
// and is the single source of truth used by both the API server and seeding.
package database

import (
	"database/sql"
	"errors"
	"fmt"

	_ "modernc.org/sqlite"
)

var (
	// ErrLeaseNotFound is returned when no lease matches the requested ID.
	ErrLeaseNotFound = errors.New("lease not found")
	// ErrLeaseAlreadyExpired is returned when the lease exists but has
	// already expired, so it cannot be revoked again.
	ErrLeaseAlreadyExpired = errors.New("lease already expired")
)

// DB wraps the underlying *sql.DB connection for SSH-Warden's schema.
type DB struct {
	conn *sql.DB
}

// InitDB opens (or creates) the SQLite database at dbPath, applies the
// required PRAGMA settings and ensures the schema exists.
func InitDB(dbPath string) (*DB, error) {
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("cannot open sqlite: %w", err)
	}

	if _, err := conn.Exec(`
		PRAGMA foreign_keys = ON;
		PRAGMA journal_mode = WAL;
	`); err != nil {
		return nil, fmt.Errorf("cannot configure pragmas: %w", err)
	}

	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS ssh_keys (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		public_key TEXT NOT NULL,
		comment TEXT,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS leases (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		target_host TEXT NOT NULL,
		expires_at DATETIME NOT NULL,
		reason TEXT,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS hosts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		hostname TEXT UNIQUE NOT NULL,
		token_hash TEXT NOT NULL,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
	`
	if _, err := conn.Exec(schema); err != nil {
		return nil, fmt.Errorf("cannot create tables: %w", err)
	}

	return &DB{conn: conn}, nil
}