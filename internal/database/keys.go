package database

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/polarisdev-fr/ssh-warden/internal/models"
	"github.com/polarisdev-fr/ssh-warden/pkg/sshutil"
)

// GetValidKeysForUser returns the distinct public keys authorized for the
// given username. A key is only returned when the user has at least one
// active (non-expired) lease that targets the requested host, or a "*"
// catch-all lease.
func (db *DB) GetValidKeysForUser(username, targetHost string) ([]string, error) {
	query := `
	SELECT DISTINCT k.public_key
	FROM ssh_keys k
	JOIN users u ON u.id = k.user_id
	JOIN leases l ON l.user_id = u.id
	WHERE u.username = ?
	  AND l.expires_at > ?
	  AND (l.target_host = ? OR l.target_host = '*');
	`

	now := time.Now().UTC()
	rows, err := db.conn.Query(query, username, now, targetHost)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []string
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}

	return keys, nil
}

// ensureUser returns the ID of the user with the given username, creating the
// user on the fly if it does not exist yet.
func (db *DB) ensureUser(username string) (int64, error) {
	var userID int64
	err := db.conn.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&userID)
	if err == nil {
		return userID, nil
	}
	if err != sql.ErrNoRows {
		return 0, err
	}

	res, err := db.conn.Exec("INSERT INTO users (username) VALUES (?)", username)
	if err != nil {
		return 0, fmt.Errorf("cannot create user: %w", err)
	}
	return res.LastInsertId()
}

// AddSSHKey validates a raw public key, ensures the owning user exists, and
// stores the normalized key into the ssh_keys table. It returns the created
// SSHKey record.
func (db *DB) AddSSHKey(username, rawPubKey, comment string) (*models.SSHKey, error) {
	if username == "" {
		return nil, fmt.Errorf("username is required")
	}

	cleanKey, parsedComment, err := sshutil.ValidateAndParsePublicKey(rawPubKey)
	if err != nil {
		return nil, err
	}

	if comment == "" {
		comment = parsedComment
	}

	userID, err := db.ensureUser(username)
	if err != nil {
		return nil, err
	}

	res, err := db.conn.Exec(
		"INSERT INTO ssh_keys (user_id, public_key, comment) VALUES (?, ?, ?)",
		userID, cleanKey, comment,
	)
	if err != nil {
		return nil, fmt.Errorf("cannot insert ssh key: %w", err)
	}

	keyID, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}

	return &models.SSHKey{
		ID:        keyID,
		UserID:    userID,
		PublicKey: cleanKey,
		Comment:   comment,
		CreatedAt: time.Now().UTC(),
	}, nil
}