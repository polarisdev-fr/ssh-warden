package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

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
		Timeout: 3 * time.Second,
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
