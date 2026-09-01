// Command cli is the SSH-Warden user CLI. It talks to the Warden API to
// request temporary leases, inspect active leases and revoke them:
//
//	warden request -u <user> -t <host> -d <duration> -r "<reason>"
//	warden status [ -u <user> ]
//	warden revoke <lease_id>
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

var (
	apiURL     string
	username   string
	targetHost string
	duration   string
	reason     string
	statusUser string
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "warden",
		Short: "Manage temporary SSH access",
	}

	// Global persistent flag pointing at the Warden API.
	rootCmd.PersistentFlags().StringVar(&apiURL, "api", "http://localhost:8080", "Warden API URL")

	// "request" subcommand: ask for a time-limited lease.
	var requestCmd = &cobra.Command{
		Use:   "request",
		Short: "Request temporary access to a server",
		RunE:  runRequest,
	}

	requestCmd.Flags().StringVarP(&username, "user", "u", "", "Username (required)")
	requestCmd.Flags().StringVarP(&targetHost, "target", "t", "*", "Target host (e.g. srv-prod-01 or *)")
	requestCmd.Flags().StringVarP(&duration, "duration", "d", "1h", "Lease duration (e.g. 30m, 2h)")
	requestCmd.Flags().StringVarP(&reason, "reason", "r", "", "Reason for the request")

	requestCmd.MarkFlagRequired("user")

	// "status" subcommand: list active leases.
	var statusCmd = &cobra.Command{
		Use:   "status",
		Short: "List active leases",
		RunE:  runStatus,
	}

	statusCmd.Flags().StringVarP(&statusUser, "user", "u", "", "Filter by username")

	// "revoke" subcommand: immediately cut an active lease.
	var revokeCmd = &cobra.Command{
		Use:   "revoke <lease_id>",
		Short: "Revoke an active lease immediately",
		Args:  cobra.ExactArgs(1),
		RunE:  runRevoke,
	}

	rootCmd.AddCommand(requestCmd, statusCmd, revokeCmd, newKeyCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// runRequest requests a new lease from the API and prints a confirmation.
func runRequest(cmd *cobra.Command, args []string) error {
	payload := map[string]string{
		"username":    username,
		"target_host": targetHost,
		"duration":    duration,
		"reason":      reason,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("serialization error: %w", err)
	}

	endpoint := fmt.Sprintf("%s/api/v1/leases", apiURL)
	resp, err := http.Post(endpoint, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("error contacting API: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("request rejected (%d): %s", resp.StatusCode, string(respBody))
	}

	var res struct {
		ID         int64     `json:"id"`
		TargetHost string    `json:"target_host"`
		ExpiresAt  time.Time `json:"expires_at"`
		Reason     string    `json:"reason"`
	}

	if err := json.Unmarshal(respBody, &res); err != nil {
		return fmt.Errorf("unexpected response: %w", err)
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

// runStatus lists active leases from the API, optionally filtered by user,
// and renders them as an aligned table.
func runStatus(cmd *cobra.Command, args []string) error {
	endpoint, err := url.Parse(fmt.Sprintf("%s/api/v1/leases", apiURL))
	if err != nil {
		return fmt.Errorf("URL construction error: %w", err)
	}

	if statusUser != "" {
		q := endpoint.Query()
		q.Set("user", statusUser)
		endpoint.RawQuery = q.Encode()
	}

	resp, err := http.Get(endpoint.String())
	if err != nil {
		return fmt.Errorf("error contacting API: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected response (%d): %s", resp.StatusCode, string(respBody))
	}

	var leases []struct {
		ID         int64     `json:"id"`
		Username   string    `json:"username"`
		TargetHost string    `json:"target_host"`
		Reason     string    `json:"reason"`
		ExpiresAt  time.Time `json:"expires_at"`
	}

	if err := json.Unmarshal(respBody, &leases); err != nil {
		return fmt.Errorf("unexpected response: %w", err)
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

// runRevoke revokes a lease by ID and confirms the SSH access has been cut.
func runRevoke(cmd *cobra.Command, args []string) error {
	leaseID, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid lease id: %q", args[0])
	}

	endpoint := fmt.Sprintf("%s/api/v1/leases/%d", apiURL, leaseID)

	req, err := http.NewRequest(http.MethodDelete, endpoint, nil)
	if err != nil {
		return fmt.Errorf("request creation error: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("error contacting API: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("revocation refused (%d): %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	fmt.Printf("Lease #%d revoked. SSH access has been cut immediately.\n", leaseID)
	return nil
}
