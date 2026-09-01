// Package sshutil provides helpers for validating and normalizing SSH
// public keys before they are stored or served to OpenSSH.
package sshutil

import (
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// ValidateAndParsePublicKey parses rawKey as an OpenSSH authorized key line
// (via ssh.ParseAuthorizedKey). It returns the normalized key as a single
// "type base64" string without trailing characters, the parsed key comment,
// and an error if the key is not a valid authorized key.
func ValidateAndParsePublicKey(rawKey string) (cleanKey, comment string, err error) {
	clean, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(rawKey))
	if err != nil {
		return "", "", fmt.Errorf("invalid public key: %w", err)
	}

	// ParseAuthorizedKey returns the remainder of the line (options and
	// comment). The comment, if any, is the final whitespace-separated token
	// that is not an option marker such as "no-passphrase".
	fields := strings.Fields(string(rest))
	if len(fields) > 0 {
		comment = fields[len(fields)-1]
	}

	// Normalize to "type base64" so a consistent form is stored.
	cleanKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(clean)))
	return cleanKey, comment, nil
}
