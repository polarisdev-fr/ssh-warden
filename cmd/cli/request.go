package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/spf13/cobra"
)

var (
	requestUser        string
	requestTarget      string
	requestDuration    string
	requestReason      string
	requestInteractive bool
)

// newRequestCmd builds the "warden request" command that asks for a
// time-limited lease from the Warden API. It runs an interactive wizard when
// the required flags are missing or --interactive is given.
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
	cmd.Flags().BoolVarP(&requestInteractive, "interactive", "i", false, "Run the interactive wizard to fill the request")

	return cmd
}

// runRequest requests a new lease, either via the interactive wizard (default
// when no -u flag or -i given) or directly from command line flags.
func runRequest(cmd *cobra.Command, args []string) error {
	var user, target, duration, reason string

	// Launch the interactive wizard only when --interactive is explicitly
	// set, or when the command is invoked bare (no flags at all). Any flag
	// provided on the command line (-u, -t, -d, -r) means the user expects
	// a direct, non-interactive request.
	noFlagsChanged := !cmd.Flags().Changed("user") &&
		!cmd.Flags().Changed("target") &&
		!cmd.Flags().Changed("duration") &&
		!cmd.Flags().Changed("reason")

	if requestInteractive || noFlagsChanged {
		// Interactive wizard: pre-fill the username from local config.
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		result, err := runWizard(cfg.DefaultUser)
		if err != nil {
			return fmt.Errorf("interactive request failed: %w", err)
		}
		if result.Canceled() {
			fmt.Println("Request cancelled.")
			return nil
		}
		user, target, duration, reason = result.Username, result.Target, result.Duration, result.Reason
	} else {
		var err error
		user, err = resolveUsername(requestUser)
		if err != nil {
			return err
		}
		target, duration, reason = requestTarget, requestDuration, requestReason
	}

	if user == "" {
		return fmt.Errorf("no username provided: set it with -u/--user or run 'warden config set default_user <name>'")
	}
	if target == "" {
		target = "*"
	}
	if duration == "" {
		duration = "1h"
	}

	return submitLease(user, target, duration, reason)
}

// submitLease posts a new lease to the API and prints the outcome.
func submitLease(user, target, duration, reason string) error {
	payload := map[string]string{
		"username":    user,
		"target_host": target,
		"duration":    duration,
		"reason":      reason,
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
	fmt.Printf("Expires at   : %s (in %s)\n", res.ExpiresAt.Local().Format("15:04:05 02/01/2006"), duration)
	if res.Reason != "" {
		fmt.Printf("Reason       : %s\n", res.Reason)
	}

	return nil
}
