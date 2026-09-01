package webhook

import (
	"encoding/json"
	"time"

	"github.com/polarisdev-fr/ssh-warden/internal/models"
)

// genericPayload is the slack/gotify/ntfy-compatible payload shape.
type genericPayload struct {
	Event      string    `json:"event"`
	Username   string    `json:"username"`
	TargetHost string    `json:"target_host"`
	Reason     string    `json:"reason"`
	ClientIP   string    `json:"client_ip"`
	CreatedAt  time.Time `json:"created_at"`
}

// formatGeneric renders a generic JSON payload, dropping the empty CreatedAt
// when the event lacks one.
func formatGeneric(event models.AuditLog) ([]byte, error) {
	payload := genericPayload{
		Event:      event.Action,
		Username:   event.Username,
		TargetHost: event.TargetHost,
		Reason:     event.Reason,
		ClientIP:   event.ClientIP,
		CreatedAt:  event.CreatedAt,
	}
	return json.Marshal(payload)
}
