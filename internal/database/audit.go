package database

import (
	"github.com/polarisdev-fr/ssh-warden/internal/models"
)

// RecordAudit appends a single authorization event to the audit log. action
// is one of the documented outcomes (e.g. "KEY_REQUEST_GRANTED") and reason
// carries a short human-readable explanation.
func (db *DB) RecordAudit(username, targetHost, action, reason, clientIP string) error {
	_, err := db.conn.Exec(`
		INSERT INTO audit_logs (username, target_host, action, reason, client_ip)
		VALUES (?, ?, ?, ?, ?)
	`, username, targetHost, action, reason, clientIP)
	if err != nil {
		return err
	}
	return nil
}

// GetAuditLogs lists audit events, newest first. A limit of 0 returns all
// events. When targetHost or username is non-empty, the results are filtered
// accordingly.
func (db *DB) GetAuditLogs(limit int, targetHost, username string) ([]models.AuditLog, error) {
	query := `
	SELECT id, username, target_host, action, reason, client_ip, created_at
	FROM audit_logs`
	args := []any{}

	conditions := []string{}
	if targetHost != "" {
		conditions = append(conditions, "target_host = ?")
		args = append(args, targetHost)
	}
	if username != "" {
		conditions = append(conditions, "username = ?")
		args = append(args, username)
	}
	if len(conditions) > 0 {
		query += " WHERE " + joinConditions(conditions)
	}

	query += " ORDER BY created_at DESC, id DESC"
	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}

	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []models.AuditLog
	for rows.Next() {
		var log models.AuditLog
		if err := rows.Scan(&log.ID, &log.Username, &log.TargetHost, &log.Action, &log.Reason, &log.ClientIP, &log.CreatedAt); err != nil {
			return nil, err
		}
		logs = append(logs, log)
	}

	return logs, rows.Err()
}

// joinConditions joins WHERE clauses with " AND ". Kept as a tiny local helper
// to avoid importing strings solely for this query.
func joinConditions(conditions []string) string {
	result := conditions[0]
	for _, c := range conditions[1:] {
		result += " AND " + c
	}
	return result
}
