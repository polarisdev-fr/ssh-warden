package sshutil

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// genEd25519Key returns a public key line (type base64 comment) for a freshly
// generated Ed25519 keypair.
func genEd25519Key(t *testing.T, comment string) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("new ssh public key: %v", err)
	}
	line := string(ssh.MarshalAuthorizedKey(sshPub))
	if comment != "" {
		line += " " + comment
	}
	return line
}

// genRSAKey returns a public key line (type base64 comment) for a freshly
// generated RSA keypair.
func genRSAKey(t *testing.T, comment string) string {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("new ssh public key: %v", err)
	}
	line := string(ssh.MarshalAuthorizedKey(sshPub))
	if comment != "" {
		line += " " + comment
	}
	return line
}

func TestValidateAndParsePublicKey_Ed25519(t *testing.T) {
	raw := genEd25519Key(t, "alice@laptop")
	clean, comment, err := ValidateAndParsePublicKey(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(clean, "ssh-ed25519 ") {
		t.Errorf("expected ssh-ed25519 key, got %q", clean)
	}
	if comment != "alice@laptop" {
		t.Errorf("expected comment alice@laptop, got %q", comment)
	}
	// The re-marshalled key must be stable (no trailing data).
	first, firstRest := splitTwo(clean)
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(first + " " + firstRest)); err != nil {
		t.Errorf("normalized key does not re-parse: %v", err)
	}
}

func TestValidateAndParsePublicKey_RSA(t *testing.T) {
	raw := genRSAKey(t, "ci-build")
	clean, comment, err := ValidateAndParsePublicKey(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(clean, "ssh-rsa ") {
		t.Errorf("expected ssh-rsa key, got %q", clean)
	}
	if comment != "ci-build" {
		t.Errorf("expected comment ci-build, got %q", comment)
	}
}

func TestValidateAndParsePublicKey_Malformed(t *testing.T) {
	raw := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI trunc" // truncated base64
	if _, _, err := ValidateAndParsePublicKey(raw); err == nil {
		t.Error("expected error for malformed key, got nil")
	}
}

func TestValidateAndParsePublicKey_Garbage(t *testing.T) {
	raw := "this is not an ssh key at all"
	if _, _, err := ValidateAndParsePublicKey(raw); err == nil {
		t.Error("expected error for garbage input, got nil")
	}
}

func TestValidateAndParsePublicKey_TrimWhitespace(t *testing.T) {
	raw := genEd25519Key(t, "dev")
	// Leading/trailing spaces and newlines must be tolerated.
	withNoise := "  \n  " + raw + "  \t\n  "
	clean, comment, err := ValidateAndParsePublicKey(withNoise)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if comment != "dev" {
		t.Errorf("expected comment dev, got %q", comment)
	}
	// clean must be a single trimmed line without surrounding blanks.
	if strings.TrimSpace(clean) != clean {
		t.Errorf("clean key still has surrounding whitespace: %q", clean)
	}
	if strings.ContainsAny(clean, "\n") {
		t.Errorf("clean key contains newline: %q", clean)
	}
}

// splitTwo splits a normalized "type base64" line into its two tokens.
func splitTwo(s string) (string, string) {
	fields := strings.Fields(s)
	if len(fields) != 2 {
		return s, ""
	}
	return fields[0], fields[1]
}
