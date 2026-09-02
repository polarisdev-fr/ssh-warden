package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/polarisdev-fr/ssh-warden/internal/database"
	"github.com/polarisdev-fr/ssh-warden/internal/webhook"
	"golang.org/x/crypto/ssh"
)

const testHostName = "srv-web-01"
const testRawToken = "host-token-abc"

// validUserKey returns a freshly-generated valid public key line.
func validUserKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("new public key: %v", err)
	}
	return string(ssh.MarshalAuthorizedKey(sshPub))
}

// newTestServer builds an API server backed by an in-memory DB seeded with a
// known host token, plus optional user/lease fixtures.
func newTestServer(t *testing.T) (*Server, *database.DB) {
	t.Helper()
	db, err := database.InitDB(":memory:")
	if err != nil {
		t.Fatalf("InitDB: %v", err)
	}

	if err := db.RegisterHost(testHostName, testRawToken); err != nil {
		t.Fatalf("RegisterHost: %v", err)
	}
	if err := db.RegisterHost("*", testRawToken); err != nil {
		t.Fatalf("RegisterHost(*): %v", err)
	}

	return NewServer(db, webhook.Nil()), db
}

// seedKeyAndLease registers a key and an active lease for user against host.
func seedKeyAndLease(t *testing.T, db *database.DB, user, host string) {
	t.Helper()
	if _, err := db.AddSSHKey(user, validUserKey(t), "dev"); err != nil {
		t.Fatalf("AddSSHKey: %v", err)
	}
	if _, err := db.CreateLease(user, host, "on call", 1*time.Hour); err != nil {
		t.Fatalf("CreateLease: %v", err)
	}
}

// countAudit returns the number of audit rows for the given action.
func countAudit(t *testing.T, db *database.DB, action string) int {
	t.Helper()
	logs, err := db.GetAuditLogs(0, "", "")
	if err != nil {
		t.Fatalf("GetAuditLogs: %v", err)
	}
	n := 0
	for _, l := range logs {
		if l.Action == action {
			n++
		}
	}
	return n
}

func TestHealth(t *testing.T) {
	srv, _ := newTestServer(t)
	handler := srv.Handler()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if rec.Body.String() != "OK" {
		t.Errorf("expected body OK, got %q", rec.Body.String())
	}
}

func TestGetUserKeys_NoAuth(t *testing.T) {
	srv, db := newTestServer(t)
	handler := srv.Handler()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/alice?host="+testHostName, nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
	if n := countAudit(t, db, actionHostFailed); n != 1 {
		t.Errorf("expected 1 HOST_AUTH_FAILED audit entry, got %d", n)
	}
}

func TestGetUserKeys_BadToken(t *testing.T) {
	srv, db := newTestServer(t)
	handler := srv.Handler()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/alice?host="+testHostName, nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
	if n := countAudit(t, db, actionHostFailed); n != 1 {
		t.Errorf("expected 1 HOST_AUTH_FAILED audit entry, got %d", n)
	}
}

func TestGetUserKeys_Valid(t *testing.T) {
	srv, db := newTestServer(t)
	handler := srv.Handler()
	seedKeyAndLease(t, db, "alice", testHostName)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/alice?host="+testHostName, nil)
	req.Header.Set("Authorization", "Bearer "+testRawToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, string(rec.Body.String()))
	}
	body := strings.TrimSpace(rec.Body.String())
	if !strings.HasPrefix(body, "ssh-ed25519 ") {
		t.Errorf("expected raw ssh key, got %q", body)
	}
	// The body must equal the canonical key stored in the DB.
	if expected := validKeyBody(db); body != expected {
		t.Errorf("served key mismatch: got %q, want %q", body, expected)
	}
	if n := countAudit(t, db, actionKeyGranted); n != 1 {
		t.Errorf("expected 1 KEY_REQUEST_GRANTED audit entry, got %d", n)
	}
}

// validKeyBody re-reads the single key stored for alice from the DB.
func validKeyBody(db *database.DB) string {
	logs, err := db.GetValidKeysForUser("alice", testHostName)
	if err != nil {
		return ""
	}
	if len(logs) == 0 {
		return ""
	}
	return strings.TrimSpace(logs[0])
}

func TestGetUserKeys_NoLease(t *testing.T) {
	srv, db := newTestServer(t)
	handler := srv.Handler()
	// A registered key but NO active lease.
	if _, err := db.AddSSHKey("bob", validUserKey(t), "dev"); err != nil {
		t.Fatalf("AddSSHKey: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/bob?host="+testHostName, nil)
	req.Header.Set("Authorization", "Bearer "+testRawToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
	if n := countAudit(t, db, actionKeyDenied); n != 1 {
		t.Errorf("expected 1 KEY_REQUEST_DENIED audit entry, got %d", n)
	}
}

func TestCreateLease(t *testing.T) {
	srv, db := newTestServer(t)
	handler := srv.Handler()

	// User must exist to receive a lease.
	if _, err := db.AddSSHKey("alice", validUserKey(t), "dev"); err != nil {
		t.Fatalf("AddSSHKey: %v", err)
	}

	body := `{"username":"alice","target_host":"srv-web-01","duration":"30m","reason":"testing"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/leases", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var lease struct {
		ID         int64  `json:"id"`
		TargetHost string `json:"target_host"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &lease); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if lease.ID == 0 {
		t.Error("expected a lease ID")
	}
	if lease.TargetHost != "srv-web-01" {
		t.Errorf("expected target srv-web-01, got %q", lease.TargetHost)
	}
}

func TestCreateLease_InvalidDuration(t *testing.T) {
	srv, _ := newTestServer(t)
	handler := srv.Handler()

	body := `{"username":"alice","duration":"not-a-duration"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/leases", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestCreateLease_UnknownUser(t *testing.T) {
	srv, _ := newTestServer(t)
	handler := srv.Handler()

	body := `{"username":"ghost","target_host":"srv-web-01","duration":"30m"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/leases", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for unknown user, got %d", rec.Code)
	}
}
