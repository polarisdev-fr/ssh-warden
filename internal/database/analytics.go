package database

import (
	"time"

	"github.com/polarisdev-fr/ssh-warden/internal/models"
)

// CountActiveLeases returns the number of approved, non-expired leases,
// optionally scoped to a single username ("" for all users).
func (db *DB) CountActiveLeases(username string) (int, error) {
	query := `
		SELECT COUNT(*) FROM leases l
		JOIN users u ON u.id = l.user_id
		WHERE l.expires_at > ? AND l.status = ?`
	args := []any{time.Now().UTC(), models.LeaseStatusApproved}
	if username != "" {
		query += " AND u.username = ?"
		args = append(args, username)
	}
	var n int
	err := db.conn.QueryRow(query, args...).Scan(&n)
	return n, err
}

// CountPendingLeases returns the number of leases waiting for approval,
// optionally scoped to a single username ("" for all users).
func (db *DB) CountPendingLeases(username string) (int, error) {
	query := `
		SELECT COUNT(*) FROM leases l
		JOIN users u ON u.id = l.user_id
		WHERE l.status = ?`
	args := []any{models.LeaseStatusPending}
	if username != "" {
		query += " AND u.username = ?"
		args = append(args, username)
	}
	var n int
	err := db.conn.QueryRow(query, args...).Scan(&n)
	return n, err
}

// CountAuditDecisionsSince counts audit events with the given action since a
// point in time, optionally scoped to a username ("" for all users).
func (db *DB) CountAuditDecisionsSince(action string, username string, since time.Time) (int, error) {
	query := `
		SELECT COUNT(*) FROM audit_logs
		WHERE action = ? AND created_at >= ?`
	args := []any{action, since}
	if username != "" {
		query += " AND username = ?"
		args = append(args, username)
	}
	var n int
	err := db.conn.QueryRow(query, args...).Scan(&n)
	return n, err
}

// ActivityTimeline returns per-bucket granted/denied counts over the last
// days, oldest first. Buckets are labeled by calendar day (DD-MM). When
// username is non-empty only that user's activity is included.
func (db *DB) ActivityTimeline(username string, days int) ([]models.ActivityPoint, error) {
	now := time.Now().UTC()
	start := now.AddDate(0, 0, -(days - 1))
	start = time.Date(start.Year(), start.Month(), start.Day(), 0, 0, 0, 0, time.UTC)

	query := `
		SELECT action, created_at FROM audit_logs
		WHERE created_at >= ?`
	args := []any{start}
	if username != "" {
		query += " AND username = ?"
		args = append(args, username)
	}

	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := map[string]*models.ActivityPoint{}
	order := []string{}
	for i := 0; i < days; i++ {
		d := start.AddDate(0, 0, i)
		label := d.Format("02-01")
		counts[label] = &models.ActivityPoint{Bucket: label}
		order = append(order, label)
	}

	for rows.Next() {
		var action string
		var created time.Time
		if err := rows.Scan(&action, &created); err != nil {
			return nil, err
		}
		label := created.UTC().Format("02-01")
		pt, ok := counts[label]
		if !ok {
			continue
		}
		if action == "KEY_REQUEST_GRANTED" {
			pt.Granted++
		} else if action == "KEY_REQUEST_DENIED" {
			pt.Denied++
		}
	}

	out := make([]models.ActivityPoint, 0, days)
	for _, label := range order {
		out = append(out, *counts[label])
	}
	return out, rows.Err()
}

// TopHosts returns the limit most requested target hosts (by granted access
// count) over the whole log, optionally scoped to a username ("" for all).
func (db *DB) TopHosts(username string, limit int) ([]models.HostCount, error) {
	query := `
		SELECT target_host, COUNT(*) AS c FROM audit_logs
		WHERE action = ?`
	args := []any{"KEY_REQUEST_GRANTED"}
	if username != "" {
		query += " AND username = ?"
		args = append(args, username)
	}
	query += " GROUP BY target_host ORDER BY c DESC"
	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}

	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []models.HostCount
	for rows.Next() {
		var hc models.HostCount
		if err := rows.Scan(&hc.Host, &hc.Count); err != nil {
			return nil, err
		}
		out = append(out, hc)
	}
	return out, rows.Err()
}

// GetLeaseOwner returns the username who owns the lease with the given ID.
// The bool is false when no such lease exists.
func (db *DB) GetLeaseOwner(leaseID int64) (string, bool) {
	var username string
	err := db.conn.QueryRow(`
		SELECT u.username FROM leases l
		JOIN users u ON u.id = l.user_id
		WHERE l.id = ?`, leaseID).Scan(&username)
	if err != nil {
		return "", false
	}
	return username, true
}
