package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"log"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// ProviderConfig holds every value needed to drive the OIDC flow.
type ProviderConfig struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	// Scopes defaults to oidc.ScopeOpenID + "profile" + "email".
	Scopes []string
}

// Provider wraps the verified identity provider and OAuth2 config and exposes
// the login/callback/logout handlers plus the session-guard middleware.
type Provider struct {
	cfg      ProviderConfig
	oidcP    *oidc.Provider
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
	session  *Session
}

// NewProvider discovers the OIDC provider metadata, verifies the issuer and
// builds an ID token verifier and OAuth2 config. It is the caller's job to
// supply a correctly authenticated context (see oidc.ClientContext).
func NewProvider(ctx context.Context, cfg ProviderConfig, session *Session) (*Provider, error) {
	p, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, err
	}
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}
	return &Provider{
		cfg:   cfg,
		oidcP: p,
		oauth: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     p.Endpoint(),
			Scopes:       scopes,
		},
		verifier: p.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		session:  session,
	}, nil
}

// HandleLogin starts the authorization code flow: it generates a random state,
// stashes it in a secure cookie and redirects to the provider.
func (pr *Provider) HandleLogin(w http.ResponseWriter, r *http.Request) {
	state, err := randomState()
	if err != nil {
		http.Error(w, "state generation failed", http.StatusInternalServerError)
		return
	}
	pr.session.pendState(w, state)
	http.Redirect(w, r, pr.oauth.AuthCodeURL(state), http.StatusFound)
}

// HandleCallback validates the state, exchanges the code for tokens, verifies
// the ID token, derives the user identity and issues a session cookie before
// redirecting to /ui.
func (pr *Provider) HandleCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if !pr.session.checkState(r, w, state) {
		http.Error(w, "state mismatch: possible CSRF", http.StatusForbidden)
		return
	}
	if code == "" {
		err := r.URL.Query().Get("error")
		if err != "" {
			http.Error(w, "authentication error: "+err, http.StatusForbidden)
			return
		}
		http.Error(w, "missing authorization code", http.StatusBadRequest)
		return
	}

	tok, err := pr.oauth.Exchange(r.Context(), code)
	if err != nil {
		log.Printf("oidc: token exchange failed: %v", err)
		http.Error(w, "token exchange failed", http.StatusInternalServerError)
		return
	}

	rawID, ok := tok.Extra("id_token").(string)
	if !ok || rawID == "" {
		http.Error(w, "no id_token in exchange response", http.StatusInternalServerError)
		return
	}
	idTok, err := pr.verifier.Verify(r.Context(), rawID)
	if err != nil {
		log.Printf("oidc: id_token verification failed: %v", err)
		http.Error(w, "id_token verification failed", http.StatusInternalServerError)
		return
	}

	// Simple preferred_username/email claims from the verified ID token.
	var claims struct {
		PreferredUsername string `json:"preferred_username"`
		Email             string `json:"email"`
	}
	if err := idTok.Claims(&claims); err != nil {
		log.Printf("oidc: could not decode id_token claims: %v", err)
		http.Error(w, "id_token claim decoding failed", http.StatusInternalServerError)
		return
	}

	username := claims.PreferredUsername
	if username == "" {
		username = idTok.Subject
	}
	id := Identity{
		Subject:  idTok.Subject,
		Username: username,
		Email:    claims.Email,
	}
	if err := pr.session.Set(w, id); err != nil {
		http.Error(w, "session creation failed", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/ui", http.StatusFound)
}

// HandleLogout clears the session cookie and returns to /ui (which will bounce
// back to /auth/login via the middleware).
func (pr *Provider) HandleLogout(w http.ResponseWriter, r *http.Request) {
	pr.session.Clear(w)
	http.Redirect(w, r, "/ui", http.StatusFound)
}

// CurrentUser returns the identity of the authenticated user, or ErrNoSession.
func (pr *Provider) CurrentUser(r *http.Request) (Identity, error) {
	return pr.session.user(r)
}

// RequireSession guards a protected route: an authenticated request proceeds,
// otherwise the user is redirected to /auth/login.
func (pr *Provider) RequireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := pr.session.user(r); err != nil {
			http.Redirect(w, r, "/auth/login", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// randomState returns a 32-byte URL-safe random value.
func randomState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
