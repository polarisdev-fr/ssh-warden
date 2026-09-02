package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/polarisdev-fr/ssh-warden/internal/database"
	"github.com/polarisdev-fr/ssh-warden/internal/models"
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

func TestSystemInfo(t *testing.T) {
	srv, _ := newTestServer(t)
	srv.WithSystemInfo("/var/lib/warden.db", true)
	handler := srv.Handler()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var info models.SystemInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if info.AuthMode != authModeOpen {
		t.Errorf("expected auth_mode none, got %q", info.AuthMode)
	}
	if info.AuthEnabled {
		t.Error("expected AuthEnabled=false for open server")
	}
	if !info.MTLSEnabled {
		t.Error("expected MTLSEnabled=true from WithSystemInfo")
	}
	if info.DBPath != "/var/lib/warden.db" {
		t.Errorf("expected db_path=%q, got %q", "/var/lib/warden.db", info.DBPath)
	}
	if info.Version == "" {
		t.Error("expected a non-empty version")
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

func TestCreateLease_RequiresApproval(t *testing.T) {
	srv, db := newTestServer(t)
	handler := srv.Handler()

	if _, err := db.AddSSHKey("alice", validUserKey(t), "dev"); err != nil {
		t.Fatalf("AddSSHKey: %v", err)
	}

	body := `{"username":"alice","target_host":"srv-web-01","duration":"30m","reason":"approval test","requires_approval":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/leases", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var lease struct {
		ID     int64  `json:"id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &lease); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if lease.ID == 0 {
		t.Error("expected a lease ID")
	}
	if lease.Status != "pending" {
		t.Errorf("expected status pending, got %q", lease.Status)
	}
}

func TestGetPendingLeases(t *testing.T) {
	srv, db := newTestServer(t)
	handler := srv.Handler()

	if _, err := db.AddSSHKey("alice", validUserKey(t), "dev"); err != nil {
		t.Fatalf("AddSSHKey: %v", err)
	}
	if _, err := db.CreatePendingLease("alice", "srv-web-01", "waiting", 1*time.Hour); err != nil {
		t.Fatalf("CreatePendingLease: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/leases/pending", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var leases []struct {
		ID     int64  `json:"id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &leases); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(leases) != 1 {
		t.Fatalf("expected 1 pending lease, got %d", len(leases))
	}
	if leases[0].Status != "pending" {
		t.Errorf("expected status pending, got %q", leases[0].Status)
	}
}

func TestEmptyListsReturnJSONArrays(t *testing.T) {
	srv, _ := newTestServer(t)
	handler := srv.Handler()

	// Each empty-list endpoint must return "[]" (a JSON array), never "null",
	// so the dashboard's table renderers always receive an array.
	for _, path := range []string{"/api/v1/leases", "/api/v1/leases/pending", "/api/v1/audit?limit=10"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 for %s, got %d", path, rec.Code)
		}
		if body := strings.TrimSpace(rec.Body.String()); body != "[]" {
			t.Errorf("expected [] for %s, got %q", path, body)
		}
	}
}

func TestApproveLease(t *testing.T) {
	srv, db := newTestServer(t)
	handler := srv.Handler()

	if _, err := db.AddSSHKey("alice", validUserKey(t), "dev"); err != nil {
		t.Fatalf("AddSSHKey: %v", err)
	}
	lease, err := db.CreatePendingLease("alice", "srv-web-01", "need access", 1*time.Hour)
	if err != nil {
		t.Fatalf("CreatePendingLease: %v", err)
	}

	body := ""
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/leases/%d/approve", lease.ID), strings.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// The lease must now grant keys.
	keys, err := db.GetValidKeysForUser("alice", "srv-web-01")
	if err != nil {
		t.Fatalf("GetValidKeysForUser: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("expected 1 key after approve, got %v", keys)
	}
}

func TestRejectLease(t *testing.T) {
	srv, db := newTestServer(t)
	handler := srv.Handler()

	if _, err := db.AddSSHKey("bob", validUserKey(t), "dev"); err != nil {
		t.Fatalf("AddSSHKey: %v", err)
	}
	lease, err := db.CreatePendingLease("bob", "srv-web-01", "need access", 1*time.Hour)
	if err != nil {
		t.Fatalf("CreatePendingLease: %v", err)
	}

	body := ""
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/leases/%d/reject", lease.ID), strings.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// The lease must not grant keys.
	keys, err := db.GetValidKeysForUser("bob", "srv-web-01")
	if err != nil {
		t.Fatalf("GetValidKeysForUser: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("expected 0 keys after reject, got %v", keys)
	}
}

func TestApproveAlreadyApprovedLease(t *testing.T) {
	srv, db := newTestServer(t)
	handler := srv.Handler()

	if _, err := db.AddSSHKey("alice", validUserKey(t), "dev"); err != nil {
		t.Fatalf("AddSSHKey: %v", err)
	}
	lease, err := db.CreateLease("alice", "srv-web-01", "approved", 1*time.Hour)
	if err != nil {
		t.Fatalf("CreateLease: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/leases/%d/approve", lease.ID), strings.NewReader(""))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("expected 409 for non-pending lease, got %d", rec.Code)
	}
}

func TestApproveNonExistentLease(t *testing.T) {
	srv, _ := newTestServer(t)
	handler := srv.Handler()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/leases/9999/approve", strings.NewReader(""))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestWebUI(t *testing.T) {
	srv, _ := newTestServer(t)
	handler := srv.Handler()

	req := httptest.NewRequest(http.MethodGet, "/ui", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("expected text/html content-type, got %q", ct)
	}
	if !strings.Contains(rec.Body.String(), "SSH-Warden") {
		t.Error("expected HTML body to contain 'SSH-Warden'")
	}
	if !strings.Contains(rec.Body.String(), "UI_AUTH_ENABLED = false") {
		t.Error("expected auth flag to be false when no credentials configured")
	}
}

func TestWebUI_RequiresAuth(t *testing.T) {
	db, err := database.InitDB(":memory:")
	if err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	handler := NewServerWithUI(db, webhook.Nil(), "admin", "s3cret").Handler()

	// Without credentials -> 401 + WWW-Authenticate.
	req := httptest.NewRequest(http.MethodGet, "/ui", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); !strings.Contains(got, `Basic realm="SSH-Warden Dashboard"`) {
		t.Errorf("expected WWW-Authenticate Basic realm header, got %q", got)
	}

	// Wrong password -> 401.
	req = httptest.NewRequest(http.MethodGet, "/ui", nil)
	req.SetBasicAuth("admin", "wrong")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for bad password, got %d", rec.Code)
	}

	// Correct credentials -> 200 with auth flag true.
	req = httptest.NewRequest(http.MethodGet, "/ui", nil)
	req.SetBasicAuth("admin", "s3cret")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for valid credentials, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "UI_AUTH_ENABLED = true") {
		t.Error("expected auth flag to be true when credentials configured")
	}
}

func TestWebUI_OnlyOneCredentialDisablesAuth(t *testing.T) {
	db, err := database.InitDB(":memory:")
	if err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	// Only user set (no password) -> auth disabled, banner path active.
	handler := NewServerWithUI(db, webhook.Nil(), "admin", "").Handler()

	req := httptest.NewRequest(http.MethodGet, "/ui", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 when only one credential is set, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "UI_AUTH_ENABLED = false") {
		t.Error("expected auth flag false when only one credential set")
	}
}
