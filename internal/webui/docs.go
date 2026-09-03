package webui

import (
	"embed"
	"net/http"
)

//go:embed openapi.json
//go:embed swagger.html
//go:embed swagger-ui-bundle.js
//go:embed swagger-ui.css
var docsFS embed.FS

// RegisterDocsRoutes mounts the interactive API documentation. It serves the
// Swagger UI shell on GET /docs, its bundled assets (self-contained, no CDN)
// under /docs/, and the OpenAPI 3.0 specification on GET /api/v1/openapi.json.
func RegisterDocsRoutes(r interface {
	Get(pattern string, handler http.HandlerFunc)
}) {
	r.Get("/docs", serveDocFile("swagger.html", "text/html; charset=utf-8"))
	r.Get("/docs/swagger-ui-bundle.js", serveDocFile("swagger-ui-bundle.js", "application/javascript; charset=utf-8"))
	r.Get("/docs/swagger-ui.css", serveDocFile("swagger-ui.css", "text/css; charset=utf-8"))
	r.Get("/api/v1/openapi.json", serveDocFile("openapi.json", "application/json"))
}

// serveDocFile serves a static embedded documentation file with no-cache
// headers, mirroring the dashboard policy so an upgraded spec is never masked
// by a stale browser copy.
func serveDocFile(name, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := docsFS.ReadFile(name)
		if err != nil {
			http.Error(w, "documentation unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		w.Write(data)
	}
}
