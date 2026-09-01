// Command helper is the OpenSSH AuthorizedKeysCommand. OpenSSH invokes it
// (once per connection attempt) as `ssh-warden-helper <username>`; it queries
// the Warden API for the user's currently authorized public keys and prints
// them to stdout, which OpenSSH treats as the authorized_keys content.
//
// The machine authenticates itself with a bearer token resolved from the
// WARDEN_HOST_TOKEN environment variable, falling back to the file
// /etc/ssh-warden/token. The target host identity comes from WARDEN_HOST_ID,
// falling back to the system hostname.
package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"
)

// tokenFilePath is the fallback location for the machine host token when the
// WARDEN_HOST_TOKEN environment variable is not set.
const tokenFilePath = "/etc/ssh-warden/token"

// loadHostToken resolves the host bearer token from WARDEN_HOST_TOKEN or, if
// that is unset, from the file at tokenFilePath. It returns an empty string
// when no token is available.
func loadHostToken() string {
	if token := os.Getenv("WARDEN_HOST_TOKEN"); token != "" {
		return strings.TrimSpace(token)
	}

	data, err := os.ReadFile(tokenFilePath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func main() {
	if err := run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

// run orchestrates the helper: parse arguments, resolve config, fetch keys
// and print them. It returns a sentinel-free error for failures.
func run(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: ssh-warden-helper <username>")
	}
	username := args[1]

	apiURL := os.Getenv("WARDEN_API_URL")
	if apiURL == "" {
		apiURL = "http://127.0.0.1:8080"
	}

	hostID := os.Getenv("WARDEN_HOST_ID")
	if hostID == "" {
		hostID, _ = os.Hostname()
	}

	token := loadHostToken()
	if token == "" {
		return fmt.Errorf("error: no host token found (set WARDEN_HOST_TOKEN or create %s)", tokenFilePath)
	}

	body, status, err := fetchKeys(apiURL, username, hostID, token)
	if err != nil {
		return err
	}

	switch status {
	case http.StatusUnauthorized:
		return fmt.Errorf("error: host token missing or malformed (401 Unauthorized)")
	case http.StatusForbidden:
		return fmt.Errorf("error: host token rejected for this host (403 Forbidden)")
	case http.StatusNotFound:
		// No active keys for this user: print nothing so OpenSSH denies the
		// connection cleanly.
		return nil
	}

	if status != http.StatusOK {
		return fmt.Errorf("Warden API returned HTTP %d", status)
	}

	_, err = os.Stdout.Write(body)
	return err
}
