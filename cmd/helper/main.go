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
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
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
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: ssh-warden-helper <username>")
		os.Exit(1)
	}

	username := os.Args[1]

	apiURL := os.Getenv("WARDEN_API_URL")
	if apiURL == "" {
		apiURL = "http://127.0.0.1:8080"
	}

	hostID := os.Getenv("WARDEN_HOST_ID")
	if hostID == "" {
		hostID, _ = os.Hostname()
	}

	u, err := url.Parse(fmt.Sprintf("%s/api/v1/keys/%s", apiURL, url.PathEscape(username)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error building URL: %v\n", err)
		os.Exit(1)
	}

	if hostID != "" {
		q := u.Query()
		q.Set("host", hostID)
		u.RawQuery = q.Encode()
	}

	client := &http.Client{
		Timeout: 3 * time.Second,
	}

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating request: %v\n", err)
		os.Exit(1)
	}

	token := loadHostToken()
	if token == "" {
		fmt.Fprintln(os.Stderr, "Error: no host token found (set WARDEN_HOST_TOKEN or create /etc/ssh-warden/token)")
		os.Exit(1)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error contacting Warden API: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusUnauthorized:
		fmt.Fprintln(os.Stderr, "Error: host token missing or malformed (401 Unauthorized)")
		os.Exit(1)
	case http.StatusForbidden:
		fmt.Fprintln(os.Stderr, "Error: host token rejected for this host (403 Forbidden)")
		os.Exit(1)
	case http.StatusNotFound:
		// No active keys for this user: print nothing so OpenSSH denies the
		// connection cleanly.
		os.Exit(0)
	}

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "Warden API returned HTTP %d\n", resp.StatusCode)
		os.Exit(1)
	}

	if _, err := io.Copy(os.Stdout, resp.Body); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing to stdout: %v\n", err)
		os.Exit(1)
	}
}
