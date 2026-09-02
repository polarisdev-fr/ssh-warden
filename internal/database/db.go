// Package database provides the SQLite-backed persistence layer for
// SSH-Warden. It is responsible for users, SSH keys, leases and host tokens,
// and is the single source of truth used by both the API server and seeding.
package database

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

var (
	// ErrLeaseNotFound is returned when no lease matches the requested ID.
	ErrLeaseNotFound = errors.New("lease not found")
	// ErrLeaseAlreadyExpired is returned when the lease exists but has
	// already expired, so it cannot be revoked again.
	ErrLeaseAlreadyExpired = errors.New("lease already expired")
	// ErrLeaseNotPending is returned when an approve/reject operation
	// targets a lease that is not in the pending state.
	ErrLeaseNotPending = errors.New("lease is not pending approval")
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
		status TEXT NOT NULL DEFAULT 'approved',
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS hosts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		hostname TEXT UNIQUE NOT NULL,
		token_hash TEXT NOT NULL,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS audit_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL,
		target_host TEXT NOT NULL,
		action TEXT NOT NULL,
		reason TEXT,
		client_ip TEXT NOT NULL,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs (created_at DESC);
	CREATE INDEX IF NOT EXISTS idx_audit_logs_username ON audit_logs (username);
	`
	if _, err := conn.Exec(schema); err != nil {
		return nil, fmt.Errorf("cannot create tables: %w", err)
	}

	// Migration: add status column to existing leases tables that predate
	// the approval workflow.
	var hasStatus int
	if err := conn.QueryRow(
		"SELECT COUNT(*) FROM pragma_table_info('leases') WHERE name = 'status'",
	).Scan(&hasStatus); err == nil && hasStatus == 0 {
		if _, err := conn.Exec(
			"ALTER TABLE leases ADD COLUMN status TEXT NOT NULL DEFAULT 'approved'",
		); err != nil {
			return nil, fmt.Errorf("cannot migrate leases schema: %w", err)
		}
	}

	return &DB{conn: conn}, nil
}

// SeedData injects deterministic development data so the project can be
// exercised immediately: an admin user with a mock key and lease, plus two
// host entries sharing a known test token ("secret-host-token-123"). User
// seeding is a no-op once the users table already contains data, while host
// seeding runs whenever the hosts table is empty so pre-existing databases
// still get usable test hosts.
func (db *DB) SeedData() error {
	var userCount int
	err := db.conn.QueryRow("SELECT COUNT(*) FROM users").Scan(&userCount)
	if err != nil {
		return err
	}
	if userCount == 0 {
		if err := db.seedDemoUser(); err != nil {
			return err
		}
	}

	var hostCount int
	if err := db.conn.QueryRow("SELECT COUNT(*) FROM hosts").Scan(&hostCount); err != nil {
		return err
	}
	if hostCount == 0 {
		if err := db.RegisterHost("srv-test-01", "secret-host-token-123"); err != nil {
			return err
		}
		if err := db.RegisterHost("*", "secret-host-token-123"); err != nil {
			return err
		}
	}

	return nil
}

// seedDemoUser creates the admin user with a mock key and a catch-all active
// lease. It is meant to be called from SeedData only when the users table is
// empty.
func (db *DB) seedDemoUser() error {
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	res, err := tx.Exec("INSERT INTO users (username) VALUES ('admin')")
	if err != nil {
		return err
	}
	userID, _ := res.LastInsertId()

	mockPubKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIValidActiveKeyMockForAdminDevelopment admin@local"
	_, err = tx.Exec("INSERT INTO ssh_keys (user_id, public_key, comment) VALUES (?, ?, 'dev-laptop')", userID, mockPubKey)
	if err != nil {
		return err
	}

	expiresAt := time.Now().UTC().Add(2 * time.Hour)
	_, err = tx.Exec("INSERT INTO leases (user_id, target_host, expires_at, reason, status) VALUES (?, '*', ?, 'Emergency maintenance', ?)", userID, expiresAt, "approved")
	if err != nil {
		return err
	}

	return tx.Commit()
}
