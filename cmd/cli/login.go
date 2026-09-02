package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"time"

	"github.com/spf13/cobra"
)

// newLoginCmd authenticates this CLI against the Warden UI and stores the
// resulting token in the config file. It opens a browser to the guarded
// /ui/cli-auth page, waits on a local callback for the token, and saves it.
func newLoginCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Authenticate the CLI against the Warden API",
		Long: "Authenticate this CLI by approving access in the browser and " +
			"stores the resulting API token in the config file.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runLogin(cmd)
		},
	}
}

func runLogin(cmd *cobra.Command) error {
	base, err := resolveAPIURL()
	if err != nil {
		return err
	}

	// Start a local callback server on an ephemeral port. The browser is sent
	// to /ui/cli-auth?callback=<local>&state=<nonce> and the approve page
	// redirects back here with ?token=...&user=...&state=...
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("cannot open local callback listener: %w", err)
	}
	defer l.Close()

	state, err := randomToken(16)
	if err != nil {
		return err
	}

	done := make(chan struct {
		token string
		user  string
		err   error
	}, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("state") != state {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			done <- struct {
				token string
				user  string
				err   error
			}{err: fmt.Errorf("state mismatch; aborting authentication")}
			return
		}
		token := q.Get("token")
		if token == "" {
			http.Error(w, "missing token", http.StatusBadRequest)
			done <- struct {
				token string
				user  string
				err   error
			}{err: fmt.Errorf("no token returned; authentication failed")}
			return
		}
		user := q.Get("user")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, "<!DOCTYPE html><html><body style=\"font-family:sans-serif;padding:40px;text-align:center\"><h2>Authentication complete</h2><p>You can close this tab and return to your terminal.</p></body></html>")
		done <- struct {
			token string
			user  string
			err   error
		}{token: token, user: user}
	})

	srv := &http.Server{Handler: mux}
	go srv.Serve(l)

	cb := &url.URL{
		Scheme: "http",
		Host:   l.Addr().String(),
		Path:   "/callback",
	}
	approve := &url.URL{
		Scheme:   "https",
		Path:     "/ui/cli-auth",
		RawQuery: url.Values{"callback": {cb.String()}, "state": {state}}.Encode(),
	}
	// Pin the scheme to the configured API URL.
	parsed, err := url.Parse(base)
	if err != nil {
		return fmt.Errorf("invalid API URL %q: %w", base, err)
	}
	approve.Scheme = parsed.Scheme
	approve.Host = parsed.Host

	fmt.Fprintf(cmd.OutOrStdout(), "Opening browser to authorize SSH-Warden CLI...\n")
	fmt.Fprintf(cmd.OutOrStdout(), "If the browser does not open, visit:\n  %s\n", approve.String())
	if err := openBrowser(approve.String()); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "note: could not auto-open browser: %v\n", err)
	}

	select {
	case res := <-done:
		if res.err != nil {
			return res.err
		}
		if err := saveToken(res.token, res.user); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Authenticated as %s. Token stored.\n", res.user)
		return nil
	case <-time.After(2 * time.Minute):
		return fmt.Errorf("timed out waiting for browser approval")
	}
}

// saveToken merges the new token and user into the CLI config and writes it.
func saveToken(token, user string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	cfg.APIToken = token
	if user != "" {
		cfg.DefaultUser = user
	}
	return saveConfig(cfg)
}

// openBrowser attempts to open url in the system browser.
func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}

// randomToken returns n random bytes hex-encoded.
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("cannot generate random value: %w", err)
	}
	return hex.EncodeToString(b), nil
}
