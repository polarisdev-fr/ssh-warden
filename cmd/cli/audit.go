package main

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

var (
	auditLimit  int
	auditUser   string
	auditTarget string
)

// newAuditCmd builds the "warden audit" command that lists authorization
// audit events recorded by the API.
func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "List authorization audit events",
		Args:  cobra.NoArgs,
		RunE:  runAudit,
	}

	cmd.Flags().IntVarP(&auditLimit, "limit", "n", 20, "Maximum number of events to show")
	cmd.Flags().StringVarP(&auditUser, "user", "u", "", "Filter by username")
	cmd.Flags().StringVarP(&auditTarget, "target", "t", "", "Filter by target host")
	return cmd
}

// runAudit fetches and renders the audit log as an aligned table, separating
// granted, denied and host-auth-failure statuses.
func runAudit(cmd *cobra.Command, args []string) error {
	params := url.Values{}
	params.Set("limit", strconv.Itoa(auditLimit))
	if auditUser != "" {
		params.Set("user", auditUser)
	}
	if auditTarget != "" {
		params.Set("host", auditTarget)
	}

	client, err := newClient()
	if err != nil {
		return err
	}
	body, status, err := client.get("/api/v1/audit", params)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("unexpected response (%d): %s", status, string(body))
	}

	var logs []struct {
		ID         int64     `json:"id"`
		Username   string    `json:"username"`
		TargetHost string    `json:"target_host"`
		Action     string    `json:"action"`
		Reason     string    `json:"reason"`
		ClientIP   string    `json:"client_ip"`
		CreatedAt  time.Time `json:"created_at"`
	}
	if err := decodeJSON(body, &logs); err != nil {
		return err
	}

	if len(logs) == 0 {
		fmt.Println("No audit events recorded.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "DATE\tIP\tHÔTE\tUTILISATEUR\tRÉSULTAT\tDÉTAILS")

	for _, l := range logs {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			l.CreatedAt.Local().Format("15:04:05 02/01/2006"),
			l.ClientIP,
			l.TargetHost,
			l.Username,
			actionLabel(l.Action),
			l.Reason,
		)
	}

	return w.Flush()
}

// actionLabel maps an audit action to a short human-readable status.
func actionLabel(action string) string {
	switch action {
	case "KEY_REQUEST_GRANTED":
		return "ALLOWED"
	case "KEY_REQUEST_DENIED":
		return "DENIED"
	case "HOST_AUTH_FAILED":
		return "AUTH FAILED"
	default:
		return action
	}
}
