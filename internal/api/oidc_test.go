package api

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/polarisdev-fr/ssh-warden/internal/database"
	"github.com/polarisdev-fr/ssh-warden/internal/oidc"
	"github.com/polarisdev-fr/ssh-warden/internal/webhook"
)

// TestUIDRoutingWithOIDC ensures that when an OIDC provider is wired in, the
// /auth/* routes are mounted and an unauthenticated /ui request is redirected
// to /auth/login (rather than served or 401'd by Basic Auth).
func TestUIDRoutingWithOIDC(t *testing.T) {
	stub := stubDiscovery(t)
	sess, err := oidc.NewSession(
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		oidc.WithSecure(false),
	)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	pr, err := oidc.NewProvider(context.Background(), oidc.ProviderConfig{
		IssuerURL:    stub.URL,
		ClientID:     "warden",
		ClientSecret: "secret",
		RedirectURL:  "http://localhost:8080/auth/callback",
	}, sess)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	db, err := database.InitDB(":memory:")
	if err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	s := NewServerWithUI(db, webhook.Nil(), "admin", "s3cret")
	s.WithOIDC(pr)
	handler := s.Handler()

	// Anonymous /ui must redirect to the OIDC login, not hit Basic Auth.
	req := httptest.NewRequest(http.MethodGet, "/ui", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect to /auth/login, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/auth/login" {
		t.Errorf("expected Location=/auth/login, got %q", loc)
	}

	// Auth routes must be reachable.
	for _, path := range []string{"/auth/login", "/auth/logout"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code >= 500 {
			t.Errorf("%s: expected no 5xx (basic handlers), got %d", path, rec.Code)
		}
	}
}

func stubDiscovery(t *testing.T) *httptest.Server {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	n := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
	jwk := map[string]any{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "test-key",
		"n": n, "e": base64.RawURLEncoding.EncodeToString([]byte{0x01, 0x00, 0x01}),
	}
	jwks, _ := json.Marshal(map[string]any{"keys": []any{jwk}})

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		d := map[string]any{
			"issuer":                                "http://" + r.Host,
			"authorization_endpoint":                "http://" + r.Host + "/auth",
			"token_endpoint":                        "http://" + r.Host + "/token",
			"jwks_uri":                              "http://" + r.Host + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(d)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwks)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}
