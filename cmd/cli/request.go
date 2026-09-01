package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/spf13/cobra"
)

var (
	requestUser     string
	requestTarget   string
	requestDuration string
	requestReason   string
)

// newRequestCmd builds the "warden request" command that asks for a
// time-limited lease from the Warden API.
func newRequestCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "request",
		Short: "Request temporary access to a server",
		RunE:  runRequest,
	}

	cmd.Flags().StringVarP(&requestUser, "user", "u", "", "Username (required)")
	cmd.Flags().StringVarP(&requestTarget, "target", "t", "*", "Target host (e.g. srv-prod-01 or *)")
	cmd.Flags().StringVarP(&requestDuration, "duration", "d", "1h", "Lease duration (e.g. 30m, 2h)")
	cmd.Flags().StringVarP(&requestReason, "reason", "r", "", "Reason for the request")

	return cmd
}

// runRequest requests a new lease from the API and prints a confirmation.
func runRequest(cmd *cobra.Command, args []string) error {
	user, err := resolveUsername(requestUser)
	if err != nil {
		return err
	}

	payload := map[string]string{
		"username":    user,
		"target_host": requestTarget,
		"duration":    requestDuration,
		"reason":      requestReason,
	}

	client, err := newClient()
	if err != nil {
		return err
	}
	body, status, err := client.post("/api/v1/leases", payload)
	if err != nil {
		return err
	}
	if status != http.StatusCreated {
		return fmt.Errorf("request rejected (%d): %s", status, string(body))
	}

	var res struct {
		ID         int64     `json:"id"`
		TargetHost string    `json:"target_host"`
		ExpiresAt  time.Time `json:"expires_at"`
		Reason     string    `json:"reason"`
	}
	if err := decodeJSON(body, &res); err != nil {
		return err
	}

	fmt.Println("Access granted!")
	fmt.Printf("Lease ID     : %d\n", res.ID)
	fmt.Printf("Target host  : %s\n", res.TargetHost)
	fmt.Printf("Expires at   : %s (in %s)\n", res.ExpiresAt.Local().Format("15:04:05 02/01/2006"), requestDuration)
	if res.Reason != "" {
		fmt.Printf("Reason       : %s\n", res.Reason)
	}

	return nil
}
