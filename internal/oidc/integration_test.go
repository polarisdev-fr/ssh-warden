package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func b64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// stubProvider spins up a minimal OIDC discovery server so NewProvider can
// resolve endpoints and build a verifier without a real IdP on the network.
// It serves the discovery document and a (fixed) RSA JWKS.
func stubProvider(t *testing.T) (*httptest.Server, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	discovery := map[string]any{
		"issuer":                                "{base}",
		"authorization_endpoint":                "{base}/auth",
		"token_endpoint":                        "{base}/token",
		"jwks_uri":                              "{base}/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	}
	var jwksPayload []byte

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		host := "http://" + r.Host
		d := map[string]any{}
		for k, v := range discovery {
			if s, ok := v.(string); ok {
				v = replaceAll(s, "{base}", host)
			}
			d[k] = v
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(d)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		if jwksPayload == nil {
			jwksPayload = buildJWKS(t, key)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksPayload)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, key
}

func buildJWKS(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	n := key.PublicKey.N.Bytes()
	jwk := map[string]any{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": "test-key",
		"n":   b64url(n),
		"e":   b64url([]byte{0x01, 0x00, 0x01}),
	}
	payload, _ := json.Marshal(map[string]any{"keys": []any{jwk}})
	return payload
}

func replaceAll(s, old, new string) string {
	out := ""
	for {
		i := indexOf(s, old)
		if i < 0 {
			return out + s
		}
		out += s[:i] + new
		s = s[i+len(old):]
	}
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestRequireSessionRedirectsAnonymous(t *testing.T) {
	stub, _ := stubProvider(t)
	sess, err := NewSession("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		WithSecure(false), WithCookiePath("/"))
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	pr, err := NewProvider(context.Background(), ProviderConfig{
		IssuerURL:    stub.URL,
		ClientID:     "warden",
		ClientSecret: "secret",
		RedirectURL:  "http://localhost:8080/auth/callback",
	}, sess)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	// Anonymous request to a protected route must be redirected to login.
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	route := pr.RequireSession(inner)
	req := httptest.NewRequest(http.MethodGet, "/ui", nil)
	rec := httptest.NewRecorder()
	route.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/auth/login" {
		t.Errorf("expected Location=/auth/login, got %q", loc)
	}

	// With a valid session, the inner handler runs.
	authRec := httptest.NewRecorder()
	if err := sess.Set(authRec, Identity{Subject: "sub", Username: "alice"}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	req = httptest.NewRequest(http.MethodGet, "/ui", nil)
	req.AddCookie(authRec.Result().Cookies()[0])
	rec = httptest.NewRecorder()
	route.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("authenticated request: expected 200, got %d", rec.Code)
	}
}

func TestHandleLoginRedirectsAndSetsState(t *testing.T) {
	stub, _ := stubProvider(t)
	sess, _ := NewSession("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	pr, err := NewProvider(context.Background(), ProviderConfig{
		IssuerURL:    stub.URL,
		ClientID:     "warden",
		ClientSecret: "secret",
		RedirectURL:  "http://localhost:8080/auth/callback",
	}, sess)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	rec := httptest.NewRecorder()
	pr.HandleLogin(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect, got %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if loc == "" {
		t.Fatal("expected Location header pointing at the IdP")
	}
	if !contains(loc, "/auth") {
		t.Errorf("expected redirect to the IdP authorization endpoint, got %q", loc)
	}

	// State cookie must be present and HttpOnly.
	var cookieFound bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == "warden_oauth_state" && c.Value != "" && c.HttpOnly {
			cookieFound = true
		}
	}
	if !cookieFound {
		t.Error("expected a secure, HttpOnly state cookie")
	}
}

func contains(s, sub string) bool {
	return indexOf(s, sub) >= 0
}
