package database

import (
	"database/sql"
	"errors"

	"github.com/polarisdev-fr/ssh-warden/internal/models"
)

// SetUserRole updates the stored permission role of a user (one of
// models.RoleUser or models.RoleAdmin).
func (db *DB) SetUserRole(username, role string) error {
	if username == "" {
		return errors.New("username is required")
	}
	if role != models.RoleAdmin && role != models.RoleUser {
		return errors.New("invalid role: " + role)
	}
	if _, err := db.ensureUser(username); err != nil {
		return err
	}
	_, err := db.conn.Exec("UPDATE users SET role = ? WHERE username = ?", role, username)
	return err
}

// GetUserRole returns the stored role for username, defaulting to models.RoleUser.
// It returns an error only when the user does not exist.
func (db *DB) GetUserRole(username string) (string, error) {
	var role string
	err := db.conn.QueryRow("SELECT role FROM users WHERE username = ?", username).Scan(&role)
	if err == sql.ErrNoRows {
		return "", errors.New("user not found")
	}
	if err != nil {
		return "", err
	}
	return role, nil
}
