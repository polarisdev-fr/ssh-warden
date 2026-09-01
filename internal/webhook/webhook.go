// Package webhook provides asynchronous outbound notifications for critical
// SSH-Warden events. It supports Discord webhooks (embed payloads) and generic
// JSON webhooks compatible with Slack, Gotify, Ntfy and similar services.
//
// Notifications are fire-and-forget: Notify never blocks the caller and never
// affects the API response latency. A 3-second timeout bounds every outbound
// HTTP POST.
package webhook

import (
	"bytes"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/polarisdev-fr/ssh-warden/internal/models"
)

// defaultTimeout bounds a single webhook POST to prevent it from impacting
// API responsiveness.
const defaultTimeout = 3 * time.Second

// Notifier delivers audit events to an external webhook. Implementations MUST
// be non-blocking from the caller's perspective. The no-op nilNotifier is a
// safe instance when notifications are disabled.
type Notifier interface {
	Notify(event models.AuditLog)
}

// nilNotifier is a Notifier that discards every event. It is used when no
// webhook is configured, letting callers stay uniform and null-safe.
type nilNotifier struct{}

// Compile-time guarantee that nilNotifier satisfies Notifier.
var _ Notifier = (*nilNotifier)(nil)

// Nil returns a Notifier that silently ignores all events.
func Nil() Notifier {
	return &nilNotifier{}
}

// Notify is a no-op for the disabled notifier.
func (n *nilNotifier) Notify(event models.AuditLog) {}

// notifier is a Notifier backed by a configured webhook URL.
type notifier struct {
	url       string
	client    *http.Client
	formatter func(models.AuditLog) ([]byte, error)
}

// Compile-time guarantee that notifier satisfies Notifier.
var _ Notifier = (*notifier)(nil)

// New returns a Notifier that POSTs audit events to the webhook at url. The
// payload format is chosen automatically: an embed for Discord webhook URLs, a
// generic JSON payload otherwise. An empty url returns the disabled notifier.
func New(url string) Notifier {
	if url == "" {
		return Nil()
	}
	return &notifier{
		url:       url,
		client:    &http.Client{Timeout: defaultTimeout},
		formatter: formatterFor(isDiscord(url)),
	}
}

// formatterFor returns the payload formatter matching the target service.
func formatterFor(discord bool) func(models.AuditLog) ([]byte, error) {
	if discord {
		return formatDiscord
	}
	return formatGeneric
}

// isDiscord reports whether the URL targets a Discord webhook endpoint.
func isDiscord(url string) bool {
	return strings.Contains(url, "discord.com/api/webhooks")
}

// Notify posts the audit event to the webhook in the background. The method
// returns immediately; delivery runs in a goroutine with a strict timeout.
func (n *notifier) Notify(event models.AuditLog) {
	go n.send(event)
}

// send performs the HTTP POST of the formatted payload. Errors are logged and
// otherwise ignored so they never surface to the API caller.
func (n *notifier) send(event models.AuditLog) {
	payload, err := n.formatter(event)
	if err != nil {
		log.Printf("webhook: failed to format payload: %v", err)
		return
	}

	req, err := http.NewRequest(http.MethodPost, n.url, bytes.NewReader(payload))
	if err != nil {
		log.Printf("webhook: error building request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.client.Do(req)
	if err != nil {
		log.Printf("webhook: POST failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("webhook: unexpected status %d", resp.StatusCode)
	}
}
