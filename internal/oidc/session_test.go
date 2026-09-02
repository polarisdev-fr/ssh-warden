package oidc

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testSession(t *testing.T) *Session {
	t.Helper()
	s, err := NewSession("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		WithSecure(false))
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	return s
}

func TestSessionRoundTrip(t *testing.T) {
	s := testSession(t)
	rec := httptest.NewRecorder()
	if err := s.Set(rec, Identity{Subject: "sub-1", Username: "alice", Email: "alice@example.com"}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/ui", nil)
	req.AddCookie(rec.Result().Cookies()[0])

	got, err := s.user(req)
	if err != nil {
		t.Fatalf("user: %v", err)
	}
	if got.Subject != "sub-1" || got.Username != "alice" || got.Email != "alice@example.com" {
		t.Fatalf("unexpected identity: %+v", got)
	}

	c := rec.Result().Cookies()[0]
	if c.HttpOnly != true {
		t.Error("session cookie must be HttpOnly")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Error("session cookie must be SameSite=Lax")
	}
	if c.Secure {
		t.Error("WithSecure(false) must not set Secure flag on non-TLS")
	}
}

func TestSessionTamperRejected(t *testing.T) {
	s := testSession(t)
	rec := httptest.NewRecorder()
	if err := s.Set(rec, Identity{Subject: "sub-1", Username: "alice"}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	tok := rec.Result().Cookies()[0].Value

	// Flip a single byte of the payload part to break the HMAC.
	idx := len(tok) - 3
	flip := tok[idx]
	switch flip {
	case 'A':
		flip = 'B'
	default:
		flip = 'A'
	}
	tok = tok[:idx] + string(flip) + tok[idx+1:]

	req := httptest.NewRequest(http.MethodGet, "/ui", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: tok})
	if _, err := s.user(req); err == nil {
		t.Fatal("tampered cookie was accepted")
	}
}

func TestSessionMissingCookie(t *testing.T) {
	s := testSession(t)
	req := httptest.NewRequest(http.MethodGet, "/ui", nil)
	if _, err := s.user(req); err == nil {
		t.Fatal("expected error for missing cookie")
	}
}

func TestSessionExpiry(t *testing.T) {
	s := testSession(t)
	// A valid-looking token whose expiry is already in the past must be
	// refused, not treated as a live session.
	past := payload{Subject: "sub-1", Username: "alice", ExpiresAt: time.Now().Add(-time.Hour).Unix()}
	signed, err := s.sign(past)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/ui", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: signed})
	if _, err := s.user(req); err == nil {
		t.Fatal("expired session was accepted")
	}
}

func TestNewSessionRequiresSecret(t *testing.T) {
	if _, err := NewSession(""); err == nil {
		t.Fatal("expected error for empty secret")
	}
}

func TestSessionClear(t *testing.T) {
	s := testSession(t)
	rec := httptest.NewRecorder()
	s.Clear(rec)
	c := rec.Result().Cookies()[0]
	if c.MaxAge != -1 {
		t.Errorf("clear cookie MaxAge = %d, want -1", c.MaxAge)
	}
}

func TestStateCookie(t *testing.T) {
	s := testSession(t)
	rec := httptest.NewRecorder()
	s.pendState(rec, "abc123")

	req := httptest.NewRequest(http.MethodGet, "/auth/callback", nil)
	req.AddCookie(rec.Result().Cookies()[0])

	if !s.checkState(req, httptest.NewRecorder(), "abc123") {
		t.Error("matching state should validate")
	}
	// Consumed once: re-checking without a cookie must fail.
	rec2 := httptest.NewRecorder()
	if s.checkState(httptest.NewRequest(http.MethodGet, "/auth/callback", nil), rec2, "abc123") {
		t.Error("state cookie should be single use")
	}
}

func TestRandomState(t *testing.T) {
	a, err := randomState()
	if err != nil {
		t.Fatalf("randomState: %v", err)
	}
	b, _ := randomState()
	if a == "" || a == b {
		t.Error("expected random, distinct non-empty states")
	}
	if strings.ContainsRune(a, '/') || strings.ContainsRune(a, '+') || strings.ContainsRune(a, '=') {
		t.Error("state should be URL-safe base64")
	}
}
