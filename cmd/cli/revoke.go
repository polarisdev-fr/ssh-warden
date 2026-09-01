package main

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/spf13/cobra"
)

// newRevokeCmd builds the "warden revoke" command that immediately cuts an
// active lease.
func newRevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <lease_id>",
		Short: "Revoke an active lease immediately",
		Args:  cobra.ExactArgs(1),
		RunE:  runRevoke,
	}
}

// runRevoke revokes a lease by ID and confirms the SSH access has been cut.
func runRevoke(cmd *cobra.Command, args []string) error {
	leaseID, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid lease id: %q", args[0])
	}

	client, err := newClient()
	if err != nil {
		return err
	}
	body, status, err := client.delete(fmt.Sprintf("/api/v1/leases/%d", leaseID))
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("revocation refused (%d): %s", status, string(body))
	}

	fmt.Printf("Lease #%d revoked. SSH access has been cut immediately.\n", leaseID)
	return nil
}
