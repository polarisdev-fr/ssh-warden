package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var (
	addKeyUser    string
	addKeyComment string
)

// newKeyCmd builds the "warden key add" command that registers a local public
// key file with the Warden API for a given user.
func newKeyCmd() *cobra.Command {
	var keyCmd = &cobra.Command{
		Use:   "key",
		Short: "Manage public keys",
	}

	var addCmd = &cobra.Command{
		Use:   "add <path/to/key.pub>",
		Short: "Register a public key for a user",
		Args:  cobra.ExactArgs(1),
		RunE:  runKeyAdd,
	}

	addCmd.Flags().StringVarP(&addKeyUser, "user", "u", "", "Username to associate with the key (required)")
	addCmd.Flags().StringVarP(&addKeyComment, "comment", "c", "", "Custom label/comment for the key")
	addCmd.MarkFlagRequired("user")

	keyCmd.AddCommand(addCmd)
	return keyCmd
}

// runKeyAdd reads a local public key file, POSTs it to the API and prints a
// confirmation.
func runKeyAdd(cmd *cobra.Command, args []string) error {
	keyFile := args[0]

	data, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("failed to read key file %s: %w", keyFile, err)
	}

	payload := map[string]string{
		"username":   addKeyUser,
		"public_key": string(data),
		"comment":    addKeyComment,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("serialization error: %w", err)
	}

	endpoint := fmt.Sprintf("%s/api/v1/keys", apiURL)
	resp, err := http.Post(endpoint, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("error contacting API: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("key registration rejected (%d): %s", resp.StatusCode, string(respBody))
	}

	var created struct {
		ID        int64  `json:"id"`
		PublicKey string `json:"public_key"`
		Comment   string `json:"comment"`
	}
	if err := json.Unmarshal(respBody, &created); err != nil {
		return fmt.Errorf("unexpected response: %w", err)
	}

	if created.Comment == "" {
		created.Comment = "no comment"
	}
	fmt.Printf("✓ Public key successfully registered for user %s\n", addKeyUser)
	fmt.Printf("  Key ID     : %d\n", created.ID)
	fmt.Printf("  Key        : %s\n", created.PublicKey)
	fmt.Printf("  Comment    : %s\n", created.Comment)
	fmt.Printf("  Source file: %s\n", filepath.Clean(keyFile))

	return nil
}
