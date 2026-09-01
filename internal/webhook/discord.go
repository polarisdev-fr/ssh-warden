package webhook

import (
	"encoding/json"
	"time"

	"github.com/polarisdev-fr/ssh-warden/internal/models"
)

// Discord embed colors keyed by audit action.
const (
	colorGranted  = 0x2ECC71 // green
	colorDenied   = 0xE67E22 // orange
	colorHostFail = 0xE74C3C // red
)

// discordStyle carries the embed color and title for an audit action.
type discordStyle struct {
	color int
	title string
}

// discordPalette maps audit actions to their embed presentation.
func discordPalette() map[string]discordStyle {
	return map[string]discordStyle{
		"KEY_REQUEST_GRANTED": {colorGranted, "SSH Access Granted"},
		"KEY_REQUEST_DENIED":  {colorDenied, "SSH Access Denied"},
		"HOST_AUTH_FAILED":    {colorHostFail, "Unauthorized Host Connection Attempt"},
	}
}

// discordPayload is the JSON structure accepted by Discord webhooks.
type discordPayload struct {
	Embeds []discordEmbed `json:"embeds"`
}

// discordEmbed is a single embed object within a Discord webhook payload.
type discordEmbed struct {
	Title       string         `json:"title"`
	Color       int            `json:"color"`
	Timestamp   string         `json:"timestamp"`
	Description string         `json:"description,omitempty"`
	Fields      []discordField `json:"fields"`
}

// discordField is a single name/value row inside a Discord embed.
type discordField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

// formatDiscord renders an audit event as a Discord embed payload.
func formatDiscord(event models.AuditLog) ([]byte, error) {
	style := discordStyle{color: colorGranted, title: "SSH Access"}
	if s, ok := discordPalette()[event.Action]; ok {
		style = s
	}

	payload := discordPayload{
		Embeds: []discordEmbed{
			{
				Title:       style.title,
				Color:       style.color,
				Timestamp:   event.CreatedAt.UTC().Format(time.RFC3339),
				Description: event.Reason,
				Fields: []discordField{
					{Name: "User", Value: event.Username, Inline: true},
					{Name: "Target Host", Value: event.TargetHost, Inline: true},
					{Name: "Client IP", Value: event.ClientIP, Inline: true},
				},
			},
		},
	}

	return json.Marshal(payload)
}
