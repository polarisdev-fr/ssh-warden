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

	// Overlay the number of approved leases that were active on each day. A
	// lease counts toward a day if its [created_at, expires_at) interval
	// overlaps that calendar day.
	if err := db.fillActiveLeases(counts, order, username); err != nil {
		return nil, err
	}

	return out, rows.Err()
}

// fillActiveLeases populates ActiveLeases for every bucket label in order by
// counting the approved leases whose [CreatedAt, ExpiresAt) interval overlaps
// each calendar day.
func (db *DB) fillActiveLeases(counts map[string]*models.ActivityPoint, order []string, username string) error {
	days := len(order)
	now := time.Now().UTC()

	beginDate := todayStart(now.AddDate(0, 0, -(days - 1)))
	endDate := todayStart(now)

	leases, err := db.activeLeasesOverlap(username, beginDate, endDate.Add(24*time.Hour))
	if err != nil {
		return err
	}
	for _, l := range leases {
		s := dayIndex(order, beginDate, l.CreatedAt.UTC())
		e := dayIndex(order, beginDate, l.ExpiresAt.UTC().Add(-time.Second))
		if s < 0 {
			s = 0
		}
		if e >= days {
			e = days - 1
		}
		if s > e {
			continue
		}
		for i := s; i <= e; i++ {
			counts[order[i]].ActiveLeases++
		}
	}
	return nil
}

// activeLeasesOverlap returns all approved leases whose [created_at, expires_at)
// interval overlaps [begin, end). username scopes to a single user when non-empty.
func (db *DB) activeLeasesOverlap(username string, begin, end time.Time) ([]models.LeaseInfo, error) {
	query := `
		SELECT l.id, u.username, l.target_host, l.reason, l.expires_at, l.created_at, l.status
		FROM leases l
		JOIN users u ON u.id = l.user_id
		WHERE l.status = ?
		  AND l.created_at < ?
		  AND l.expires_at > ?`
	args := []any{models.LeaseStatusApproved, end, begin}
	if username != "" {
		query += " AND u.username = ?"
		args = append(args, username)
	}

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

// todayStart returns the UTC midnight of t's calendar day.
func todayStart(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

// parseDBTime converts a timestamp string as stored by SQLite (either RFC3339
// with a 'T' separator or the space-separated "YYYY-MM-DD HH:MM:SS" produced by
// CURRENT_TIMESTAMP) into a time.Time, in UTC. It returns the zero time for an
// empty/unparseable value.
func parseDBTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// dayIndex returns the offset of the day bucket containing t, where order[0]
// corresponds to base's date. Returns -1 when t falls before base's day.
func dayIndex(order []string, base time.Time, t time.Time) int {
	diff := int(todayStart(t).Sub(todayStart(base)).Hours() / 24)
	if diff < 0 || diff >= len(order) {
		return -1
	}
	return diff
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

// HostStats returns per-machine access statistics derived from the audit
// journal, for the dashboard "Machines" view. When username is non-empty only
// that user's accesses are included. Hosts without any audit entry are absent.
func (db *DB) HostStats(username string) ([]models.HostStats, error) {
	cond := ""
	args := []any{}
	if username != "" {
		cond = "WHERE username = ?"
		args = append(args, username)
	}

	// Aggregate grants/denies and last-seen per host.
	agg := `
		SELECT target_host,
		       SUM(CASE WHEN action = ? THEN 1 ELSE 0 END) AS granted,
		       SUM(CASE WHEN action = ? THEN 1 ELSE 0 END) AS denied,
		       MAX(created_at) AS last_seen
		FROM audit_logs ` + cond + ` GROUP BY target_host`
	aggArgs := []any{"KEY_REQUEST_GRANTED", "KEY_REQUEST_DENIED"}
	aggArgs = append(aggArgs, args...)

	rows, err := db.conn.Query(agg, aggArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type aggRow struct {
		host     string
		granted  int
		denied   int
		lastSeen time.Time
	}
	var aggs []aggRow
	for rows.Next() {
		var r aggRow
		var lastSeen string
		if err := rows.Scan(&r.host, &r.granted, &r.denied, &lastSeen); err != nil {
			return nil, err
		}
		r.lastSeen = parseDBTime(lastSeen)
		aggs = append(aggs, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if len(aggs) == 0 {
		return []models.HostStats{}, nil
	}

	// Collect the distinct usernames per host that accessed it.
	users := map[string]map[string]bool{}
	uRows, err := db.conn.Query(
		`SELECT DISTINCT target_host, username FROM audit_logs `+cond, args...)
	if err != nil {
		return nil, err
	}
	defer uRows.Close()
	for uRows.Next() {
		var host, user string
		if err := uRows.Scan(&host, &user); err != nil {
			return nil, err
		}
		if users[host] == nil {
			users[host] = map[string]bool{}
		}
		users[host][user] = true
	}
	if err := uRows.Err(); err != nil {
		return nil, err
	}

	out := make([]models.HostStats, 0, len(aggs))
	for _, r := range aggs {
		us := make([]string, 0, len(users[r.host]))
		for u := range users[r.host] {
			us = append(us, u)
		}
		out = append(out, models.HostStats{
			Host:     r.host,
			Granted:  r.granted,
			Denied:   r.denied,
			Users:    us,
			LastSeen: r.lastSeen.UTC(),
		})
	}
	return out, nil
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
