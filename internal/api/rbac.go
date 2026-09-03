package api

import (
	"net/http"

	"github.com/polarisdev-fr/ssh-warden/internal/models"
)

// defaultAdminGroup is the OIDC group whose members are treated as admins when
// no explicit WARDEN_ADMIN_GROUP is configured.
const defaultAdminGroup = "warden-admins"

// establishActor authenticates the caller and populates the request context
// with the username/role when a CLI Bearer token is supplied. UI callers
// (session or Basic Auth) need no context as their identity is resolved
// directly. It returns 401 when no valid identity can be established.
func (s *Server) establishActor(w http.ResponseWriter, r *http.Request) bool {
	if token, ok := bearerAuth(r); ok {
		username, role, valid := s.db.ValidateUserToken(token)
		if !valid {
			http.Error(w, "invalid or expired user token", http.StatusUnauthorized)
			return false
		}
		*r = *r.WithContext(withUserName(r, username, role))
		return true
	}
	// No bearer token: rely on the UI identity (OIDC session or Basic Auth).
	if s.currentUserName(r) == "" {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return false
	}
	return true
}

// attachActor authenticates a caller when they present a CLI Bearer token,
// populating the request context with username/role. Unlike requireAuthActor
// it does not reject anonymous callers: listing endpoints are public but opt
// into per-user scoping when an identity is supplied.
func (s *Server) attachActor(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token, ok := bearerAuth(r); ok {
			if username, role, valid := s.db.ValidateUserToken(token); valid {
				r = r.WithContext(withUserName(r, username, role))
			}
		}
		next.ServeHTTP(w, r)
	})
}

// requireAuthActor is a middleware that authenticates a caller from either a
// CLI user token or a UI session/Basic identity, populating the request context
// accordingly. Unauthenticated callers receive a 401.
func (s *Server) requireAuthActor(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.establishActor(w, r) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

// roleForUsername returns models.RoleAdmin when user is listed in adminUsers,
// otherwise models.RoleUser. Used in Basic/Local auth mode.
func (s *Server) roleForUsername(user string) string {
	for _, a := range s.adminUsers {
		if a == user {
			return models.RoleAdmin
		}
	}
	return models.RoleUser
}

// roleForGroupList returns models.RoleAdmin when any of the groups equals the
// configured admin group, otherwise models.RoleUser.
func (s *Server) roleForGroupList(groups []string) string {
	if s.adminGroup != "" {
		for _, g := range groups {
			if g == s.adminGroup {
				return models.RoleAdmin
			}
		}
	}
	return models.RoleUser
}

// currentUserRole returns the RBAC role of the currently authenticated UI
// visitor: derived from OIDC groups when OIDC is enabled, otherwise from the
// admin user list against the Basic Auth username. It returns "" when no
// authentication is configured.
func (s *Server) currentUserRole(r *http.Request) string {
	if pr := s.oidcProvider; pr != nil {
		if id, err := pr.CurrentUser(r); err == nil {
			return s.roleForGroupList(id.Groups)
		}
		return ""
	}
	user, _, ok := r.BasicAuth()
	if !ok {
		return ""
	}
	return s.roleForUsername(user)
}

// requesterUser returns the username of the authenticated caller, resolving a
// CLI user token first, then a UI session or Basic Auth identity.
func (s *Server) requesterUser(r *http.Request) string {
	if user := userNameFromContext(r); user != "" {
		return user
	}
	return s.currentUserName(r)
}

// requesterRole returns the RBAC role of the authenticated caller, resolving a
// CLI user token first (frozen at mint time), then a UI session or Basic Auth.
func (s *Server) requesterRole(r *http.Request) string {
	if role := userRoleFromContext(r); role != "" {
		return role
	}
	return s.currentUserRole(r)
}

// isAdmin reports whether the authenticated caller holds the admin role.
func (s *Server) isAdmin(r *http.Request) bool {
	return s.requesterRole(r) == models.RoleAdmin
}

// forcedUsername returns the username that a listing endpoint must restrict
// results to. For a regular user this is their own username (they only see
// their own leases/audit); for admins and anonymous callers it is "" (all).
func (s *Server) forcedUsername(r *http.Request) string {
	if s.requesterRole(r) == models.RoleUser {
		return s.requesterUser(r)
	}
	return ""
}

// requireAdmin is a middleware that rejects non-admin callers with 403. It is
// intended for lease management actions (approve/reject) that only admins may
// perform.
func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.isAdmin(r) {
			http.Error(w, "forbidden: admin role required", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
