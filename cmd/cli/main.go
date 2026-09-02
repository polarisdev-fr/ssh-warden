// Command cli is the SSH-Warden user CLI. It talks to the Warden API to
// register keys, request temporary leases, inspect active leases and revoke
// them:
//
//	warden key add <key.pub> -u <user>
//	warden request -u <user> -t <host> -d <duration> -r "<reason>"
//	warden status [ -u <user> ]
//	warden revoke <lease_id>
package main

import (
	"os"

	"github.com/spf13/cobra"
)

// apiURL is the global base URL for the Warden API, set by the --api flag.
var apiURL string

func main() {
	rootCmd := &cobra.Command{
		Use:   "warden",
		Short: "Manage temporary SSH access",
	}

	// Global persistent flag pointing at the Warden API. Leaving it empty
	// lets the config file or WARDEN_API_URL provide the value.
	rootCmd.PersistentFlags().StringVar(&apiURL, "api", "", "Warden API URL (overrides config)")

	rootCmd.AddCommand(
		newRequestCmd(),
		newStatusCmd(),
		newRevokeCmd(),
		newApproveCmd(),
		newRejectCmd(),
		newKeyCmd(),
		newConfigCmd(),
		newAuditCmd(),
		newLoginCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
