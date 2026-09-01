package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"time"
)

// wardenClient is a thin HTTP wrapper around the Warden API. It shares the
// base URL, an HTTP client with a timeout, and common request/response
// handling across the CLI subcommands.
type wardenClient struct {
	base   string
	client *http.Client
}

// clientTimeout bounds how long a single API call may take.
const clientTimeout = 10 * time.Second

// newClient returns a wardenClient pointed at the resolved API base URL,
// following the priority: --api flag > WARDEN_API_URL > config file > default.
func newClient() (*wardenClient, error) {
	base, err := resolveAPIURL()
	if err != nil {
		return nil, err
	}
	return &wardenClient{
		base: base,
		client: &http.Client{
			Timeout: clientTimeout,
		},
	}, nil
}

// url joins the base URL with one or more path segments.
func (c *wardenClient) url(segments ...string) (string, error) {
	base, err := url.Parse(c.base)
	if err != nil {
		return "", fmt.Errorf("invalid API URL: %w", err)
	}
	base.Path = path.Join(base.Path, path.Join(segments...))
	return base.String(), nil
}

// do performs a request, reads the response body, and returns the body along
// with the decoded status. Errors from transport-level failures are wrapped.
func (c *wardenClient) do(req *http.Request) ([]byte, int, error) {
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("error contacting API: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("error reading response: %w", err)
	}
	return body, resp.StatusCode, nil
}

// get creates and performs a GET request against the given path with optional
// query parameters.
func (c *wardenClient) get(cmdPath string, params url.Values) ([]byte, int, error) {
	u, err := c.url(cmdPath)
	if err != nil {
		return nil, 0, err
	}
	if len(params) > 0 {
		u += "?" + params.Encode()
	}

	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("request creation error: %w", err)
	}
	return c.do(req)
}

// post creates and performs a JSON POST request against the given path.
func (c *wardenClient) post(cmdPath string, payload any) ([]byte, int, error) {
	u, err := c.url(cmdPath)
	if err != nil {
		return nil, 0, err
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, 0, fmt.Errorf("serialization error: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return nil, 0, fmt.Errorf("request creation error: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req)
}

// delete creates and performs a DELETE request against the given path.
func (c *wardenClient) delete(cmdPath string) ([]byte, int, error) {
	u, err := c.url(cmdPath)
	if err != nil {
		return nil, 0, err
	}

	req, err := http.NewRequest(http.MethodDelete, u, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("request creation error: %w", err)
	}
	return c.do(req)
}

// decodeJSON unmarshals a response body into out, wrapping any parse error.
func decodeJSON(body []byte, out any) error {
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("unexpected response: %w", err)
	}
	return nil
}
