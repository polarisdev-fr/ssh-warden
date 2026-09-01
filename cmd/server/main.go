// Command server runs the SSH-Warden HTTP API. It loads configuration,
// initializes the database, instantiates the API and serves it until an
// interrupt signal triggers a graceful shutdown.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/polarisdev-fr/ssh-warden/internal/api"
	"github.com/polarisdev-fr/ssh-warden/internal/database"
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
		Handler: api.NewServer(db).Handler(),
	}

	// Run the server in the background and wait for an interrupt.
	serverErr := make(chan error, 1)
	go func() {
		log.Printf("SSH-Warden API listening on http://localhost%s", defaultAddr)
		serverErr <- srv.ListenAndServe()
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErr:
		return err
	case <-quit:
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
