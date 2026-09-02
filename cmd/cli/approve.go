package main

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/spf13/cobra"
)

// newApproveCmd builds the "warden approve" command that approves a pending
// lease, granting the user SSH access.
func newApproveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "approve <lease_id>",
		Short: "Approve a pending lease",
		Args:  cobra.ExactArgs(1),
		RunE:  runApprove,
	}
}

// runApprove sends an approval request for the given lease ID and confirms
// the access grant.
func runApprove(cmd *cobra.Command, args []string) error {
	leaseID, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid lease id: %q", args[0])
	}

	client, err := newClient()
	if err != nil {
		return err
	}

	body, status, err := client.post(fmt.Sprintf("/api/v1/leases/%d/approve", leaseID), nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("approval refused (%d): %s", status, string(body))
	}

	fmt.Printf("Lease #%d approved. SSH access has been granted.\n", leaseID)
	return nil
}
