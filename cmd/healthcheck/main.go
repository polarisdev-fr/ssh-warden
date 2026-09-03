// Command healthcheck is a tiny static probe used as the Docker healthcheck
// for the distroless SSH-Warden image, which ships no shell or curl. It issues
// a GET request to the server /health endpoint and exits non-zero on failure.
package main

import (
	"fmt"
	"net/http"
	"os"
	"time"
)

func main() {
	port := os.Getenv("WARDEN_PORT")
	if port == "" {
		port = "8080"
	}
	url := "http://127.0.0.1:" + port + "/health"
	if v := os.Getenv("WARDEN_HEALTHCHECK_URL"); v != "" {
		url = v
	}

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "healthcheck: unexpected status %d\n", resp.StatusCode)
		os.Exit(1)
	}
}
