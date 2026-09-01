package main

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

var statusUser string

// newStatusCmd builds the "warden status" command that lists active leases.
func newStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "List active leases",
		RunE:  runStatus,
	}

	cmd.Flags().StringVarP(&statusUser, "user", "u", "", "Filter by username")
	return cmd
}

// runStatus lists active leases from the API, optionally filtered by user,
// and renders them as an aligned table.
func runStatus(cmd *cobra.Command, args []string) error {
	var params url.Values
	if statusUser != "" {
		params = url.Values{}
		params.Set("user", statusUser)
	}

	client, err := newClient()
	if err != nil {
		return err
	}
	body, status, err := client.get("/api/v1/leases", params)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("unexpected response (%d): %s", status, string(body))
	}

	var leases []struct {
		ID         int64     `json:"id"`
		Username   string    `json:"username"`
		TargetHost string    `json:"target_host"`
		Reason     string    `json:"reason"`
		ExpiresAt  time.Time `json:"expires_at"`
	}
	if err := decodeJSON(body, &leases); err != nil {
		return err
	}

	if len(leases) == 0 {
		fmt.Println("No active leases found.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "ID\tUSER\tTARGET\tREASON\tTIME LEFT\tEXPIRES")

	for _, lease := range leases {
		remaining := time.Until(lease.ExpiresAt)
		remaining = remaining.Round(time.Second)
		if remaining < 0 {
			remaining = 0
		}

		days := int(remaining.Hours()) / 24
		hours := int(remaining.Hours()) % 24
		mins := int(remaining.Minutes()) % 60
		secs := int(remaining.Seconds()) % 60

		var remainingStr string
		switch {
		case days > 0:
			remainingStr = fmt.Sprintf("%dd %dh %dm", days, hours, mins)
		case hours > 0:
			remainingStr = fmt.Sprintf("%dh %dm", hours, mins)
		default:
			remainingStr = fmt.Sprintf("%dm %ds", mins, secs)
		}

		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\n",
			lease.ID,
			lease.Username,
			lease.TargetHost,
			lease.Reason,
			remainingStr,
			lease.ExpiresAt.Local().Format("15:04:05 02/01/2006"),
		)
	}

	return w.Flush()
}
