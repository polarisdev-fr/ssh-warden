package api

import (
	"encoding/json"
	"net/http"

	"github.com/polarisdev-fr/ssh-warden/internal/models"
)

// version is the reported build version. It can be overridden at build time
// with -ldflags "-X 'github.com/polarisdev-fr/ssh-warden/internal/api.version=…'".
var version = "dev"

// actionAuthMode names the authentication modes reported to the UI.
const (
	// authModeOIDC means the dashboard is protected by OpenID Connect.
	authModeOIDC = "oidc"
	// authModeBasic means the dashboard is protected by HTTP Basic Auth.
	authModeBasic = "basic"
	// authModeOpen means the dashboard is served without authentication.
	authModeOpen = "none"
)

// systemHandler writes a JSON snapshot of the running server for the Web UI's
// System view.
type systemHandler struct {
	s *Server
}

func (h systemHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	mode := authModeOpen
	switch {
	case h.s.oidcProvider != nil:
		mode = authModeOIDC
	case h.s.uiUser != "" && h.s.uiPassword != "":
		mode = authModeBasic
	}

	info := models.SystemInfo{
		Version:     version,
		AuthMode:    mode,
		AuthEnabled: mode != authModeOpen,
		MTLSEnabled: h.s.mtlsEnabled,
		DBPath:      h.s.dbPath,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}
