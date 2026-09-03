package api

import (
	"context"
	"net/http"
)

// userNameKey is the context key holding the authenticated CLI username after
// the user-token middleware validates a request.
type ctxKey int

const (
	userNameKey ctxKey = iota
	userRoleKey
)

// withUserName stores username and role in the request context.
func withUserName(r *http.Request, username, role string) context.Context {
	ctx := context.WithValue(r.Context(), userNameKey, username)
	return context.WithValue(ctx, userRoleKey, role)
}

// userNameFromContext retrieves the username set by the user-token middleware.
func userNameFromContext(r *http.Request) string {
	if v, ok := r.Context().Value(userNameKey).(string); ok {
		return v
	}
	return ""
}

// userRoleFromContext retrieves the role set by the user-token middleware.
func userRoleFromContext(r *http.Request) string {
	if v, ok := r.Context().Value(userRoleKey).(string); ok {
		return v
	}
	return ""
}
