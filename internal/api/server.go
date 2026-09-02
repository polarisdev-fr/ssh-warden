// Package api contains the HTTP layer of SSH-Warden: the router, middleware
// and the request handlers exposed to the CLI and the OpenSSH helper.
package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/polarisdev-fr/ssh-warden/internal/database"
	"github.com/polarisdev-fr/ssh-warden/internal/oidc"
	"github.com/polarisdev-fr/ssh-warden/internal/webhook"
	"github.com/polarisdev-fr/ssh-warden/internal/webui"
)

// Server bundles the dependencies needed by the HTTP handlers and builds the
// chi router.
type Server struct {
	db       *database.DB
	notifier webhook.Notifier
	// uiUser and uiPassword, when both non-empty, are the Basic Auth
	// credentials required to access the /ui dashboard when OIDC is disabled.
	uiUser     string
	uiPassword string
	// oidcProvider, when non-nil, enables OpenID Connect authentication and
	// takes precedence over Basic Auth.
	oidcProvider *oidc.Provider
	// dbPath is the filesystem path of the underlying database, exposed via
	// /api/v1/system. When empty the in-memory SQLite is in use.
	dbPath string
	// mtlsEnabled reports whether the server is serving with mTLS configured.
	mtlsEnabled bool
}

// WithSystemInfo records deployment details used by the /api/v1/system
// endpoint (UI System view). These are informational only.
func (s *Server) WithSystemInfo(dbPath string, mtlsEnabled bool) *Server {
	s.dbPath = dbPath
	s.mtlsEnabled = mtlsEnabled
	return s
}

// NewServer creates an API Server backed by the given database and notifier.
// The notifier is optional; pass webhook.Nil() to disable notifications.
func NewServer(db *database.DB, notifier webhook.Notifier) *Server {
	return NewServerWithUI(db, notifier, "", "")
}

// NewServerWithUI is like NewServer but also configures Basic Auth credentials
// for the /ui dashboard. When both credentials are empty the dashboard is
// served unauthenticated (and shows a warning banner).
func NewServerWithUI(db *database.DB, notifier webhook.Notifier, uiUser, uiPassword string) *Server {
	if notifier == nil {
		notifier = webhook.Nil()
	}
	return &Server{
		db:         db,
		notifier:   notifier,
		uiUser:     uiUser,
		uiPassword: uiPassword,
	}
}

// WithOIDC enables OpenID Connect authentication for the /ui dashboard,
// taking precedence over Basic Auth. When the provider is non-nil, requests
// to /ui are guarded by its session middleware and /auth/* routes are mounted.
func (s *Server) WithOIDC(provider *oidc.Provider) *Server {
	s.oidcProvider = provider
	return s
}

// Handler constructs and returns the fully-configured HTTP router, including
// middleware and all routes. It is safe to call once and reuse.
func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(chimw.Logger)
	r.Use(chimw.Recoverer)

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	s.registerKeysRoutes(r)
	s.registerLeasesRoutes(r)
	s.registerAuditRoutes(r)
	r.Get("/api/v1/system", systemHandler{s: s}.ServeHTTP)
	s.registerUIRoutes(r)

	return r
}

func (s *Server) registerUIRoutes(r chi.Router) {
	auth := webui.UIAuth{Enabled: false}

	if pr := s.oidcProvider; pr != nil {
		r.Get("/auth/login", pr.HandleLogin)
		r.Get("/auth/callback", pr.HandleCallback)
		r.Get("/auth/logout", pr.HandleLogout)
		auth.Enabled = true
		auth.Guard = pr.RequireSession
		auth.Identity = func(r *http.Request) string {
			id, err := pr.CurrentUser(r)
			if err != nil {
				return ""
			}
			return id.Username
		}
	} else {
		auth.Enabled = s.uiUser != "" && s.uiPassword != ""
		auth.BasicUser = s.uiUser
		auth.BasicPassword = s.uiPassword
	}

	webui.RegisterUIRoutes(r, auth)
}
