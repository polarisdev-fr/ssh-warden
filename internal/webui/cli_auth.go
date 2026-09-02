package webui

import (
	"embed"
	"net/http"
	"strings"
)

//go:embed cli_auth.html
var cliAuthFS embed.FS

// ServeCLIAuth serves the "Authorize SSH-Warden CLI" approve page, injecting
// the authenticated username. The page is expected to be mounted behind the
// same UI auth (Basic or OIDC) as the dashboard.
func ServeCLIAuth(w http.ResponseWriter, r *http.Request, username string) {
	data, err := cliAuthFS.ReadFile("cli_auth.html")
	if err != nil {
		http.Error(w, "ui unavailable", http.StatusInternalServerError)
		return
	}
	body := strings.ReplaceAll(string(data), "__USERNAME__", username)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Never cache this dynamic page: stale copies could keep showing an old
	// version after a reinstall/upgrade.
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Write([]byte(body))
}
