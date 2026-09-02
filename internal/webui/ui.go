package webui

import (
	"crypto/subtle"
	"embed"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

//go:embed index.html
var static embed.FS

// RegisterUIRoutes registers GET /ui (the dashboard) on the router. When both
// uiUser and uiPassword are non-empty the route is protected by HTTP Basic
// Auth; otherwise the dashboard is served unauthenticated (the HTML itself
// shows a warning banner in that case).
func RegisterUIRoutes(r chi.Router, uiUser, uiPassword string) {
	authEnabled := uiUser != "" && uiPassword != ""
	serve := func(w http.ResponseWriter, req *http.Request) {
		serveIndex(w, req, authEnabled)
	}

	if authEnabled {
		r.With(basicAuth(uiUser, uiPassword)).Get("/ui", serve)
		return
	}
	r.Get("/ui", serve)
}

// basicAuth returns a chi middleware that enforces HTTP Basic Auth against
// the given credentials. Failed requests receive a 401 response carrying the
// WWW-Authenticate header so browsers prompt for credentials.
func basicAuth(user, password string) func(http.Handler) http.Handler {
	expectedUser := []byte(user)
	expectedPass := []byte(password)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotUser, gotPass, ok := r.BasicAuth()
			if !ok ||
				subtle.ConstantTimeCompare([]byte(gotUser), expectedUser) != 1 ||
				subtle.ConstantTimeCompare([]byte(gotPass), expectedPass) != 1 {
				w.Header().Set("WWW-Authenticate", `Basic realm="SSH-Warden Dashboard"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// serveIndex reads, injects the auth flag placeholder, and serves the embedded
// HTML dashboard.
func serveIndex(w http.ResponseWriter, r *http.Request, authEnabled bool) {
	data, err := static.ReadFile("index.html")
	if err != nil {
		http.Error(w, "ui unavailable", http.StatusInternalServerError)
		return
	}

	flag := "false"
	if authEnabled {
		flag = "true"
	}
	body := strings.ReplaceAll(string(data), "__AUTH_ENABLED__", flag)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(body))
}
