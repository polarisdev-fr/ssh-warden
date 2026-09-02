// Package oidc implements optional OpenID Connect authentication for the /ui
// dashboard: the authorization-code flow (login/callback/logout), an
// HMAC-signed session cookie, and a middleware that guards protected routes.
package oidc

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

const sessionCookieName = "warden_session"

var (
	ErrNoSession   = errors.New("oidc: no valid session")
	ErrInvalidCode = errors.New("oidc: invalid session token")
)

// SessionOption configures Session behavior.
type SessionOption func(*Session)

// WithCookiePath overrides the cookie path (default "/").
func WithCookiePath(path string) SessionOption {
	return func(s *Session) { s.cookiePath = path }
}

// WithTTL overrides the session lifetime (default 8h).
func WithTTL(ttl time.Duration) SessionOption {
	return func(s *Session) { s.ttl = ttl }
}

// WithSecure controls the Secure flag on issued cookies. It defaults to true;
// disable it when serving over plain HTTP (e.g. a LAN dashboard without TLS).
func WithSecure(secure bool) SessionOption {
	return func(s *Session) { s.secure = secure }
}

// Session signs and verifies the warden_session cookie with HMAC-SHA256 keyed
// on WARDEN_SESSION_SECRET. It also issues short lived state cookies used by
// the authorization-code flow to prevent CSRF.
type Session struct {
	secret     []byte
	cookieName string
	stateName  string
	cookiePath string
	ttl        time.Duration
	secure     bool
}

// NewSession builds a Session keyed on secret. The secret must be non-empty
// and should be at least 32 random bytes.
func NewSession(secret string, opts ...SessionOption) (*Session, error) {
	if secret == "" {
		return nil, errors.New("oidc: SESSION_SECRET must not be empty")
	}
	s := &Session{
		secret:     []byte(secret),
		cookieName: sessionCookieName,
		stateName:  "warden_oauth_state",
		cookiePath: "/",
		ttl:        8 * time.Hour,
		secure:     true,
	}
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

// payload is the signed, serializable claim carried in the session cookie.
type payload struct {
	Subject   string `json:"sub"`
	Username  string `json:"username"`
	Email     string `json:"email,omitempty"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

// sign produces "<b64(payloadJSON)>.<b64(HMAC-SHA256)>".
func (s *Session) sign(p payload) (string, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	b64 := base64.RawURLEncoding.EncodeToString(raw)
	return b64 + "." + s.mac(b64), nil
}

func (s *Session) mac(data string) string {
	h := hmac.New(sha256.New, s.secret)
	h.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// verify parses and validates a formatted token.
func (s *Session) verify(token string) (payload, error) {
	i := lastIndexByte(token, '.')
	if i < 0 {
		return payload{}, ErrInvalidCode
	}
	b64, mac := token[:i], token[i+1:]
	if !hmac.Equal([]byte(s.mac(b64)), []byte(mac)) {
		return payload{}, ErrInvalidCode
	}
	raw, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		return payload{}, ErrInvalidCode
	}
	var p payload
	if err := json.Unmarshal(raw, &p); err != nil {
		return payload{}, ErrInvalidCode
	}
	if p.ExpiresAt <= time.Now().Unix() {
		return payload{}, ErrNoSession
	}
	return p, nil
}

func lastIndexByte(s string, c byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// Identity is the authenticated user carried by a session.
type Identity struct {
	Subject  string
	Username string
	Email    string
}

// Set issues a fresh session cookie for the given identity.
func (s *Session) Set(w http.ResponseWriter, id Identity) error {
	now := time.Now()
	p := payload{
		Subject:   id.Subject,
		Username:  id.Username,
		Email:     id.Email,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(s.ttl).Unix(),
	}
	tok, err := s.sign(p)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    tok,
		Path:     s.cookiePath,
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(s.ttl.Seconds()),
	})
	return nil
}

// user returns the identity stored in the request's session cookie.
func (s *Session) user(r *http.Request) (Identity, error) {
	c, err := r.Cookie(s.cookieName)
	if err != nil {
		return Identity{}, ErrNoSession
	}
	p, err := s.verify(c.Value)
	if err != nil {
		return Identity{}, err
	}
	return Identity{Subject: p.Subject, Username: p.Username, Email: p.Email}, nil
}

// Clear removes the session cookie.
func (s *Session) Clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: s.cookieName, Value: "", Path: s.cookiePath, HttpOnly: true, MaxAge: -1})
}

// pendState stores a pending login state in a short lived cookie.
func (s *Session) pendState(w http.ResponseWriter, state string) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.stateName,
		Value:    state,
		Path:     s.cookiePath,
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})
}

// checkState verifies and clears the pending state cookie, defeating CSRF.
func (s *Session) checkState(r *http.Request, w http.ResponseWriter, state string) bool {
	c, err := r.Cookie(s.stateName)
	if err != nil || c.Value == "" || c.Value != state {
		return false
	}
	http.SetCookie(w, &http.Cookie{Name: s.stateName, Value: "", Path: s.cookiePath, MaxAge: -1})
	return true
}
