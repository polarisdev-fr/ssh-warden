package webui

import (
	"embed"
	"net/http"

	"github.com/go-chi/chi/v5"
)

//go:embed index.html
var static embed.FS

// RegisterUIRoutes registers GET /ui (the dashboard) on the router.
func RegisterUIRoutes(r chi.Router) {
	r.Get("/ui", serveIndex)
}

// serveIndex reads and serves the embedded HTML dashboard.
func serveIndex(w http.ResponseWriter, r *http.Request) {
	data, err := static.ReadFile("index.html")
	if err != nil {
		http.Error(w, "ui unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}
