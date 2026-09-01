package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var (
	addKeyUser    string
	addKeyComment string
)

// newKeyCmd builds the "warden key" command group with its subcommands,
// currently "warden key add".
func newKeyCmd() *cobra.Command {
	keyCmd := &cobra.Command{
		Use:   "key",
		Short: "Manage public keys",
	}

	addCmd := &cobra.Command{
		Use:   "add <path/to/key.pub>",
		Short: "Register a public key for a user",
		Args:  cobra.ExactArgs(1),
		RunE:  runKeyAdd,
	}

	addCmd.Flags().StringVarP(&addKeyUser, "user", "u", "", "Username to associate with the key (required)")
	addCmd.Flags().StringVarP(&addKeyComment, "comment", "c", "", "Custom label/comment for the key")

	keyCmd.AddCommand(addCmd)
	return keyCmd
}

// runKeyAdd reads a local public key file, POSTs it to the API and prints a
// confirmation.
func runKeyAdd(cmd *cobra.Command, args []string) error {
	user, err := resolveUsername(addKeyUser)
	if err != nil {
		return err
	}

	keyFile := args[0]

	data, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("failed to read key file %s: %w", keyFile, err)
	}

	payload := map[string]string{
		"username":   user,
		"public_key": string(data),
		"comment":    addKeyComment,
	}

	client, err := newClient()
	if err != nil {
		return err
	}
	body, status, err := client.post("/api/v1/keys", payload)
	if err != nil {
		return err
	}
	if status != http.StatusCreated {
		return fmt.Errorf("key registration rejected (%d): %s", status, string(body))
	}

	var created struct {
		ID        int64  `json:"id"`
		PublicKey string `json:"public_key"`
		Comment   string `json:"comment"`
	}
	if err := decodeJSON(body, &created); err != nil {
		return err
	}

	if created.Comment == "" {
		created.Comment = "no comment"
	}
	fmt.Printf("✓ Public key successfully registered for user %s\n", user)
	fmt.Printf("  Key ID     : %d\n", created.ID)
	fmt.Printf("  Key        : %s\n", created.PublicKey)
	fmt.Printf("  Comment    : %s\n", created.Comment)
	fmt.Printf("  Source file: %s\n", filepath.Clean(keyFile))

	return nil
}
