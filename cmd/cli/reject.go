package main

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/spf13/cobra"
)

// newRejectCmd builds the "warden reject" command that rejects a pending
// lease, denying the user SSH access.
func newRejectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reject <lease_id>",
		Short: "Reject a pending lease",
		Args:  cobra.ExactArgs(1),
		RunE:  runReject,
	}
}

// runReject sends a rejection request for the given lease ID and confirms
// the access denial.
func runReject(cmd *cobra.Command, args []string) error {
	leaseID, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid lease id: %q", args[0])
	}

	client, err := newClient()
	if err != nil {
		return err
	}

	body, status, err := client.post(fmt.Sprintf("/api/v1/leases/%d/reject", leaseID), nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("rejection refused (%d): %s", status, string(body))
	}

	fmt.Printf("Lease #%d rejected. SSH access has been denied.\n", leaseID)
	return nil
}
