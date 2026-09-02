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

// UIAuth describes the authentication applied to the /ui dashboard and how to
// report the current user to the page header.
type UIAuth struct {
	// Enabled reports whether the dashboard requires authentication.
	Enabled bool
	// Guard is optional. When non-nil it wraps /ui with a middleware that
	// redirects unauthenticated requests (OIDC). When nil, Basic Auth is used
	// if BasicUser/BasicPassword are set, otherwise the UI is open.
	Guard func(http.Handler) http.Handler
	// BasicUser/BasicPassword, when both non-empty and Guard is nil, enable
	// HTTP Basic Auth (fallback used when OIDC is off).
	BasicUser     string
	BasicPassword string
	// Identity returns the authenticated user ("" when anonymous).
	Identity func(*http.Request) string
}

// RegisterUIRoutes registers GET /ui (and its assets) on the router, applying
// the authentication configured in auth. The returned middleware ordering is:
// Guard (OIDC) if set, else Basic Auth if BasicUser is set, else open.
func RegisterUIRoutes(r chi.Router, auth UIAuth) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		serveIndex(w, req, auth)
	})

	switch {
	case auth.Guard != nil:
		r.With(auth.Guard).Get("/ui", handler.ServeHTTP)
	case auth.BasicUser != "" && auth.BasicPassword != "":
		r.With(basicAuth(auth.BasicUser, auth.BasicPassword)).Get("/ui", handler.ServeHTTP)
	default:
		r.Get("/ui", handler.ServeHTTP)
	}
}

// basicAuth returns a chi middleware that enforces HTTP Basic Auth against
// the given credentials. Failed requests receive a 401 response carrying the
// WWW-Authenticate header so browsers prompt for credentials.
func basicAuth(user, password string) func(http.Handler) http.Handler {
	return BasicAuth(user, password)
}

// BasicAuth exposes basicAuth as an exported middleware factory so the API
// package can guard the same UI surface (cli-auth page, token endpoint).
func BasicAuth(user, password string) func(http.Handler) http.Handler {
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

// serveIndex reads, injects the auth flag, user identity and logout link, then
// serves the embedded HTML dashboard.
func serveIndex(w http.ResponseWriter, r *http.Request, auth UIAuth) {
	data, err := static.ReadFile("index.html")
	if err != nil {
		http.Error(w, "ui unavailable", http.StatusInternalServerError)
		return
	}

	enabled := "false"
	userBar := ""
	if auth.Enabled {
		enabled = "true"
	}
	user := ""
	if auth.Identity != nil {
		user = auth.Identity(r)
	}
	if user != "" {
		userBar = `<span class="username">` + strings.ReplaceAll(user, "&", "&amp;") +
			`</span> <a href="/auth/logout" class="logout">Déconnexion</a>`
	}

	body := string(data)
	body = strings.ReplaceAll(body, "__AUTH_ENABLED__", enabled)
	body = strings.ReplaceAll(body, "__USER_BAR__", userBar)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// The dashboard is a single self-contained HTML document. Never cache it:
	// an upgraded server must not be masked by a stale browser copy (the
	// reason an old UI kept appearing after an uninstall/reinstall).
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Write([]byte(body))
}
