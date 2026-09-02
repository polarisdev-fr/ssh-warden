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
	"syscall"
	"time"

	"github.com/polarisdev-fr/ssh-warden/internal/api"
	"github.com/polarisdev-fr/ssh-warden/internal/database"
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

	srv := &http.Server{
		Addr:    defaultAddr,
		Handler: api.NewServer(db, webhook.New(os.Getenv("WARDEN_WEBHOOK_URL"))).Handler(),
	}

	// Optional mTLS: when WARDEN_TLS_CERT and WARDEN_TLS_KEY are set the
	// server listens on HTTPS. When WARDEN_TLS_CA_CERT is additionally set,
	// client certificates signed by that CA are required.
	tlsCertFile := os.Getenv("WARDEN_TLS_CERT")
	tlsKeyFile := os.Getenv("WARDEN_TLS_KEY")
	tlsCACertFile := os.Getenv("WARDEN_TLS_CA_CERT")

	if tlsCertFile != "" && tlsKeyFile != "" {
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
