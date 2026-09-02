package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

// tlsTransport returns an *http.Transport configured to trust the CA
// certificate at the path specified by the WARDEN_TLS_CA_CERT environment
// variable. When the variable is unset or empty, nil is returned and a
// default transport should be used.
func tlsTransport() *http.Transport {
	caPath := os.Getenv("WARDEN_TLS_CA_CERT")
	if caPath == "" {
		return nil
	}

	caCert, err := os.ReadFile(caPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: cannot read CA certificate %s: %v\n", caPath, err)
		return nil
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		fmt.Fprintf(os.Stderr, "warning: cannot parse CA certificate from %s\n", caPath)
		return nil
	}

	return &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: pool,
		},
	}
}

// fetchKeys queries the Warden API for the user's currently authorized public
// keys. The target host identity and the bearer token are supplied explicitly;
// the token is sent as an Authorization header. It returns the raw response
// body and HTTP status code.
func fetchKeys(apiURL, username, hostID, token string) ([]byte, int, error) {
	u, err := url.Parse(fmt.Sprintf("%s/api/v1/keys/%s", apiURL, url.PathEscape(username)))
	if err != nil {
		return nil, 0, fmt.Errorf("error building URL: %w", err)
	}

	if hostID != "" {
		q := u.Query()
		q.Set("host", hostID)
		u.RawQuery = q.Encode()
	}

	client := &http.Client{
		Timeout:   3 * time.Second,
		Transport: tlsTransport(),
	}

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, 0, fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("error contacting Warden API: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("error reading response: %w", err)
	}
	return body, resp.StatusCode, nil
}
