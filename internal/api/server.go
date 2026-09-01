// Package api contains the HTTP layer of SSH-Warden: the router, middleware
// and the request handlers exposed to the CLI and the OpenSSH helper.
package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/polarisdev-fr/ssh-warden/internal/database"
	"github.com/polarisdev-fr/ssh-warden/internal/webhook"
)

// Server bundles the dependencies needed by the HTTP handlers and builds the
// chi router.
type Server struct {
	db       *database.DB
	notifier webhook.Notifier
}

// NewServer creates an API Server backed by the given database and notifier.
// The notifier is optional; pass webhook.Nil() to disable notifications.
func NewServer(db *database.DB, notifier webhook.Notifier) *Server {
	if notifier == nil {
		notifier = webhook.Nil()
	}
	return &Server{db: db, notifier: notifier}
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

	return r
}
