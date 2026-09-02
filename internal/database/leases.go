package database

import (
	"fmt"
	"time"

	"github.com/polarisdev-fr/ssh-warden/internal/models"
)

// CreateLease creates a time-limited, immediately approved access lease for
// the given username against the target host, expiring duration from now. The
// target host may be "*" to cover all hosts.
func (db *DB) CreateLease(username, targetHost, reason string, duration time.Duration) (*models.Lease, error) {
	var userID int64
	err := db.conn.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&userID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	expiresAt := time.Now().UTC().Add(duration)

	res, err := db.conn.Exec(`
		INSERT INTO leases (user_id, target_host, expires_at, reason, status)
		VALUES (?, ?, ?, ?, ?)
	`, userID, targetHost, expiresAt, reason, models.LeaseStatusApproved)
	if err != nil {
		return nil, fmt.Errorf("cannot create lease: %w", err)
	}

	leaseID, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}

	return &models.Lease{
		ID:         leaseID,
		UserID:     userID,
		TargetHost: targetHost,
		ExpiresAt:  expiresAt,
		Reason:     reason,
		CreatedAt:  time.Now().UTC(),
		Status:     models.LeaseStatusApproved,
	}, nil
}

// CreatePendingLease is identical to CreateLease but sets the lease status to
// pending, requiring a second sign-off before the lease takes effect.
func (db *DB) CreatePendingLease(username, targetHost, reason string, duration time.Duration) (*models.Lease, error) {
	var userID int64
	err := db.conn.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&userID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	expiresAt := time.Now().UTC().Add(duration)

	res, err := db.conn.Exec(`
		INSERT INTO leases (user_id, target_host, expires_at, reason, status)
		VALUES (?, ?, ?, ?, ?)
	`, userID, targetHost, expiresAt, reason, models.LeaseStatusPending)
	if err != nil {
		return nil, fmt.Errorf("cannot create lease: %w", err)
	}

	leaseID, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}

	return &models.Lease{
		ID:         leaseID,
		UserID:     userID,
		TargetHost: targetHost,
		ExpiresAt:  expiresAt,
		Reason:     reason,
		CreatedAt:  time.Now().UTC(),
		Status:     models.LeaseStatusPending,
	}, nil
}

// GetActiveLeases lists approved, non-expired leases, sorted by expiry
// ascending so the soonest-to-expire lease comes first. When username is
// non-empty, only that user's leases are returned; otherwise all active leases
// are listed.
func (db *DB) GetActiveLeases(username string) ([]models.LeaseInfo, error) {
	query := `
	SELECT l.id, u.username, l.target_host, l.reason, l.expires_at, l.created_at, l.status
	FROM leases l
	JOIN users u ON u.id = l.user_id
	WHERE l.expires_at > ?
	  AND l.status = ?`
	args := []any{time.Now().UTC(), models.LeaseStatusApproved}

	if username != "" {
		query += " AND u.username = ?"
		args = append(args, username)
	}

	query += " ORDER BY l.expires_at ASC"

	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var leases []models.LeaseInfo
	for rows.Next() {
		var lease models.LeaseInfo
		if err := rows.Scan(&lease.ID, &lease.Username, &lease.TargetHost, &lease.Reason, &lease.ExpiresAt, &lease.CreatedAt, &lease.Status); err != nil {
			return nil, err
		}
		leases = append(leases, lease)
	}

	return leases, rows.Err()
}

// GetPendingLeases lists leases in the pending approval state. When username
// is non-empty only that user's pending leases are returned.
func (db *DB) GetPendingLeases(username string) ([]models.LeaseInfo, error) {
	query := `
	SELECT l.id, u.username, l.target_host, l.reason, l.expires_at, l.created_at, l.status
	FROM leases l
	JOIN users u ON u.id = l.user_id
	WHERE l.status = ?`
	args := []any{models.LeaseStatusPending}

	if username != "" {
		query += " AND u.username = ?"
		args = append(args, username)
	}

	query += " ORDER BY l.created_at DESC"

	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var leases []models.LeaseInfo
	for rows.Next() {
		var lease models.LeaseInfo
		if err := rows.Scan(&lease.ID, &lease.Username, &lease.TargetHost, &lease.Reason, &lease.ExpiresAt, &lease.CreatedAt, &lease.Status); err != nil {
			return nil, err
		}
		leases = append(leases, lease)
	}

	return leases, rows.Err()
}

// ApproveLease transitions a pending lease to approved. It returns
// ErrLeaseNotFound if the lease does not exist or is not in the pending state.
func (db *DB) ApproveLease(leaseID int64) error {
	res, err := db.conn.Exec(
		"UPDATE leases SET status = ? WHERE id = ? AND status = ?",
		models.LeaseStatusApproved, leaseID, models.LeaseStatusPending,
	)
	if err != nil {
		return err
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		var exists bool
		if err := db.conn.QueryRow("SELECT EXISTS(SELECT 1 FROM leases WHERE id = ?)", leaseID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrLeaseNotFound
		}
		return ErrLeaseNotPending
	}
	return nil
}

// RejectLease transitions a pending lease to denied. It returns
// ErrLeaseNotFound if the lease does not exist or ErrLeaseNotPending if the
// lease is not in the pending state.
func (db *DB) RejectLease(leaseID int64) error {
	res, err := db.conn.Exec(
		"UPDATE leases SET status = ? WHERE id = ? AND status = ?",
		models.LeaseStatusDenied, leaseID, models.LeaseStatusPending,
	)
	if err != nil {
		return err
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		var exists bool
		if err := db.conn.QueryRow("SELECT EXISTS(SELECT 1 FROM leases WHERE id = ?)", leaseID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrLeaseNotFound
		}
		return ErrLeaseNotPending
	}
	return nil
}

// RevokeLease revokes a lease immediately by forcing its expiry to the
// current time. The lease row is preserved for audit purposes (soft delete).
// It returns ErrLeaseNotFound if the ID does not exist and
// ErrLeaseAlreadyExpired if the lease had already expired.
func (db *DB) RevokeLease(leaseID int64) error {
	now := time.Now().UTC()

	res, err := db.conn.Exec(
		"UPDATE leases SET expires_at = ? WHERE id = ? AND expires_at > ?",
		now, leaseID, now,
	)
	if err != nil {
		return err
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		var exists bool
		if err := db.conn.QueryRow("SELECT EXISTS(SELECT 1 FROM leases WHERE id = ?)", leaseID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrLeaseNotFound
		}
		return ErrLeaseAlreadyExpired
	}

	return nil
}
