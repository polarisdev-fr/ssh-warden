package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/polarisdev-fr/ssh-warden/internal/api"
	"github.com/polarisdev-fr/ssh-warden/internal/database"
	"github.com/polarisdev-fr/ssh-warden/internal/oidc"
	"github.com/polarisdev-fr/ssh-warden/internal/webhook"
)

const (
	defaultAddr     = ":8080"
	shutdownTimeout = 5 * time.Second
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func run() error {
	db, err := database.InitDB("warden.db")
	if err != nil {
		return err
	}

	if err := db.SeedData(); err != nil {
		log.Printf("seed warning: %v", err)
	}

	// Optional mTLS: when WARDEN_TLS_CERT and WARDEN_TLS_KEY are set the
	// server listens on HTTPS. When WARDEN_TLS_CA_CERT is additionally set,
	// client certificates signed by that CA are required.
	tlsCertFile := os.Getenv("WARDEN_TLS_CERT")
	tlsKeyFile := os.Getenv("WARDEN_TLS_KEY")
	tlsCACertFile := os.Getenv("WARDEN_TLS_CA_CERT")
	tlsEnabled := tlsCertFile != "" && tlsKeyFile != ""

	apiServer := api.NewServerWithUI(
		db,
		webhook.New(os.Getenv("WARDEN_WEBHOOK_URL")),
		os.Getenv("WARDEN_UI_USER"),
		os.Getenv("WARDEN_UI_PASSWORD"),
	)

	// Optional OpenID Connect auth for the dashboard. When enabled it takes
	// precedence over Basic Auth and mounts /auth/login, /auth/callback and
	// /auth/logout.
	if os.Getenv("WARDEN_OIDC_ENABLED") == "true" {
		pr, err := newOIDCProvider(tlsEnabled)
		if err != nil {
			return err
		}
		apiServer.WithOIDC(pr)
		log.Printf("OIDC auth enabled for /ui (issuer %s)", os.Getenv("WARDEN_OIDC_ISSUER_URL"))
	}

	var dbPath string
	if p, err := filepath.Abs("warden.db"); err == nil {
		dbPath = p
	} else {
		dbPath = "warden.db"
	}
	apiServer.WithSystemInfo(dbPath, tlsCACertFile != "")

	srv := &http.Server{
		Addr:    defaultAddr,
		Handler: apiServer.Handler(),
	}

	if tlsEnabled {
		tlsCfg := &tls.Config{
			MinVersion: tls.VersionTLS13,
		}

		if tlsCACertFile != "" {
			caCert, err := os.ReadFile(tlsCACertFile)
			if err != nil {
				return fmt.Errorf("cannot read CA certificate: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caCert) {
				return fmt.Errorf("cannot parse CA certificate from %s", tlsCACertFile)
			}
			tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
			tlsCfg.ClientCAs = pool
			log.Println("mTLS enabled: client certificates required")
		}

		srv.TLSConfig = tlsCfg
		log.Printf("SSH-Warden API listening on https://localhost%s", defaultAddr)
		serverErr := make(chan error, 1)
		go func() {
			serverErr <- srv.ListenAndServeTLS(tlsCertFile, tlsKeyFile)
		}()

		quit := make(chan os.Signal, 1)
		signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

		select {
		case err := <-serverErr:
			return err
		case <-quit:
		}
	} else {
		log.Printf("SSH-Warden API listening on http://localhost%s", defaultAddr)
		serverErr := make(chan error, 1)
		go func() {
			serverErr <- srv.ListenAndServe()
		}()

		quit := make(chan os.Signal, 1)
		signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

		select {
		case err := <-serverErr:
			return err
		case <-quit:
		}
	}

	// Gracefully shut down with a timeout.
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		return err
	}
	log.Println("SSH-Warden API stopped")
	return nil
}

// newOIDCProvider builds and verifies the OpenID Connect provider from the
// WARDEN_OIDC_* environment variables. It performs discovery against the
// issuer at startup. sessionSecret must be non-empty.
func newOIDCProvider(tlsEnabled bool) (*oidc.Provider, error) {
	issuer := os.Getenv("WARDEN_OIDC_ISSUER_URL")
	clientID := os.Getenv("WARDEN_OIDC_CLIENT_ID")
	clientSecret := os.Getenv("WARDEN_OIDC_CLIENT_SECRET")
	redirectURL := os.Getenv("WARDEN_OIDC_REDIRECT_URL")
	secret := os.Getenv("WARDEN_SESSION_SECRET")

	if issuer == "" || clientID == "" || clientSecret == "" || redirectURL == "" || secret == "" {
		return nil, fmt.Errorf(
			"WARDEN_OIDC_ENABLED=true requires WARDEN_OIDC_ISSUER_URL, WARDEN_OIDC_CLIENT_ID, " +
				"WARDEN_OIDC_CLIENT_SECRET, WARDEN_OIDC_REDIRECT_URL and WARDEN_SESSION_SECRET to be set",
		)
	}

	// Session cookies are flagged Secure only when serving over TLS.
	sess, err := oidc.NewSession(secret, oidc.WithSecure(tlsEnabled))
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return oidc.NewProvider(ctx, oidc.ProviderConfig{
		IssuerURL:    issuer,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
	}, sess)
}
