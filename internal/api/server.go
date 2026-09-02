// Package api contains the HTTP layer of SSH-Warden: the router, middleware
// and the request handlers exposed to the CLI and the OpenSSH helper.
package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/polarisdev-fr/ssh-warden/internal/database"
	"github.com/polarisdev-fr/ssh-warden/internal/webhook"
	"github.com/polarisdev-fr/ssh-warden/internal/webui"
)

// Server bundles the dependencies needed by the HTTP handlers and builds the
// chi router.
type Server struct {
	db       *database.DB
	notifier webhook.Notifier
	// uiUser and uiPassword, when both non-empty, are the Basic Auth
	// credentials required to access the /ui dashboard. When either is empty
	// the dashboard is served without authentication and the UI shows a
	// warning banner.
	uiUser     string
	uiPassword string
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
	webui.RegisterUIRoutes(r, s.uiUser, s.uiPassword)

	return r
}
