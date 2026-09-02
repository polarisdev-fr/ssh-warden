package api

import (
	"context"
	"net/http"
)

// userNameKey is the context key holding the authenticated CLI username after
// the user-token middleware validates a request.
type ctxKey int

const userNameKey ctxKey = iota

// withUserName stores username in the request context.
func withUserName(r *http.Request, username string) context.Context {
	return context.WithValue(r.Context(), userNameKey, username)
}

// userNameFromContext retrieves the username set by the user-token middleware.
func userNameFromContext(r *http.Request) string {
	if v, ok := r.Context().Value(userNameKey).(string); ok {
		return v
	}
	return ""
}
