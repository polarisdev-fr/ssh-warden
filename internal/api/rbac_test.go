package api

import (
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
)

// TestApproveRejectRequiresAdmin verifies that a regular user token cannot
// approve or reject a lease (403), while an admin token can.
func TestApproveRejectRequiresAdmin(t *testing.T) {
	srv, db := newTestServer(t)
	handler := srv.Handler()

	if _, err := db.AddSSHKey("alice", validUserKey(t), "dev"); err != nil {
		t.Fatalf("AddSSHKey: %v", err)
	}
	lease, err := db.CreatePendingLease("alice", "srv-web-01", "need access", 1*time.Hour)
	if err != nil {
		t.Fatalf("CreatePendingLease: %v", err)
	}

	// A plain (non-admin) user token is rejected with 403.
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/leases/%d/approve", lease.ID), strings.NewReader(""))
	req.Header.Set("Authorization", cliAuthHeader(t, db, "alice"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-admin approve, got %d", rec.Code)
	}

	// An admin token succeeds.
	req = httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/leases/%d/approve", lease.ID), strings.NewReader(""))
	req.Header.Set("Authorization", cliAdminAuthHeader(t, db, "admin"))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for admin approve, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestUserLeasesAreScoped verifies that a regular user only sees their own
// active leases.
func TestUserLeasesAreScoped(t *testing.T) {
	srv, db := newTestServer(t)
	handler := srv.Handler()

	if _, err := db.AddSSHKey("alice", validUserKey(t), "dev"); err != nil {
		t.Fatalf("AddSSHKey: %v", err)
	}
	if _, err := db.AddSSHKey("bob", validUserKey(t), "dev"); err != nil {
		t.Fatalf("AddSSHKey: %v", err)
	}
	if _, err := db.CreateLease("alice", "srv-web-01", "approved", 1*time.Hour); err != nil {
		t.Fatalf("CreateLease alice: %v", err)
	}
	if _, err := db.CreateLease("bob", "srv-db-01", "approved", 1*time.Hour); err != nil {
		t.Fatalf("CreateLease bob: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/leases", nil)
	req.Header.Set("Authorization", cliAuthHeader(t, db, "alice"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var leases []models.LeaseInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &leases); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(leases) != 1 || leases[0].Username != "alice" {
		t.Errorf("expected only alice's lease, got %+v", leases)
	}
}

// TestUserCannotRevokeOthersLease verifies that a regular user may only revoke
// their own lease (403 otherwise), while an admin may revoke any.
func TestUserCannotRevokeOthersLease(t *testing.T) {
	srv, db := newTestServer(t)
	handler := srv.Handler()

	if _, err := db.AddSSHKey("alice", validUserKey(t), "dev"); err != nil {
		t.Fatalf("AddSSHKey: %v", err)
	}
	if _, err := db.AddSSHKey("bob", validUserKey(t), "dev"); err != nil {
		t.Fatalf("AddSSHKey: %v", err)
	}
	lease, err := db.CreateLease("alice", "srv-web-01", "approved", 1*time.Hour)
	if err != nil {
		t.Fatalf("CreateLease: %v", err)
	}

	// bob (not the owner, non-admin) is refused.
	req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/v1/leases/%d", lease.ID), nil)
	req.Header.Set("Authorization", cliAuthHeader(t, db, "bob"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-owner revoke, got %d", rec.Code)
	}

	// admin can revoke any lease.
	req = httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/v1/leases/%d", lease.ID), nil)
	req.Header.Set("Authorization", cliAdminAuthHeader(t, db, "admin"))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for admin revoke, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHostsEndpoint verifies the machines view returns per-host statistics and
// scopes a regular user to the machines they accessed.
func TestHostsEndpoint(t *testing.T) {
	srv, db := newTestServer(t)
	handler := srv.Handler()

	if err := db.RecordAudit("alice", "srv-web-01", "KEY_REQUEST_GRANTED", "ok", "1.2.3.4"); err != nil {
		t.Fatalf("RecordAudit: %v", err)
	}
	if err := db.RecordAudit("bob", "srv-db-01", "KEY_REQUEST_GRANTED", "ok", "5.6.7.8"); err != nil {
		t.Fatalf("RecordAudit: %v", err)
	}

	// Anonymous sees all hosts.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/hosts", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var all []models.HostStats
	if err := json.Unmarshal(rec.Body.Bytes(), &all); err != nil {
		t.Fatalf("decode hosts: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 hosts, got %d", len(all))
	}

	// A regular user only sees the machines they accessed.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/hosts", nil)
	req.Header.Set("Authorization", cliAuthHeader(t, db, "alice"))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var mine []models.HostStats
	if err := json.Unmarshal(rec.Body.Bytes(), &mine); err != nil {
		t.Fatalf("decode hosts: %v", err)
	}
	if len(mine) != 1 || mine[0].Host != "srv-web-01" {
		t.Errorf("expected only srv-web-01 for alice, got %+v", mine)
	}
	if mine[0].Granted != 1 {
		t.Errorf("expected 1 grant, got %d", mine[0].Granted)
	}
}

// TestOverviewAvailable verifies the overview endpoint responds with expected
// aggregation fields.
func TestOverviewAvailable(t *testing.T) {
	srv, db := newTestServer(t)
	handler := srv.Handler()

	if _, err := db.AddSSHKey("alice", validUserKey(t), "dev"); err != nil {
		t.Fatalf("AddSSHKey: %v", err)
	}
	if _, err := db.CreateLease("alice", "srv-web-01", "approved", 1*time.Hour); err != nil {
		t.Fatalf("CreateLease: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/overview", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var ov models.Overview
	if err := json.Unmarshal(rec.Body.Bytes(), &ov); err != nil {
		t.Fatalf("decode overview: %v", err)
	}
	if ov.ActiveLeasesCount != 1 {
		t.Errorf("expected 1 active lease, got %d", ov.ActiveLeasesCount)
	}
}

// TestCLIToken_OpenDashboard verifies that with no UI auth configured, the
// token endpoint still works and falls back to the seeded local admin.
func TestCLIToken_OpenDashboard(t *testing.T) {
	db, err := database.InitDB(":memory:")
	if err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	handler := NewServer(db, webhook.Nil()).Handler()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/user-tokens", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on open dashboard, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Token    string `json:"token"`
		Username string `json:"username"`
		Role     string `json:"role"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if resp.Username != localAdminUser || resp.Token == "" {
		t.Errorf("expected local admin fallback token, got username=%q token=%q", resp.Username, resp.Token)
	}
	if resp.Role != models.RoleAdmin {
		t.Errorf("expected admin role for open dashboard token, got %q", resp.Role)
	}

	// The minted token must validate as an admin token.
	user, role, valid := db.ValidateUserToken(resp.Token)
	if !valid || user != localAdminUser || role != models.RoleAdmin {
		t.Errorf("expected valid admin token for %s, got user=%q role=%q valid=%v", localAdminUser, user, role, valid)
	}
}

// TestWebUI_OverviewAndRoleBadge verifies the dashboard renders the Overview
// nav item and injects the RBAC role for an admin user.
func TestWebUI_OverviewAndRoleBadge(t *testing.T) {
	db, err := database.InitDB(":memory:")
	if err != nil {
		t.Fatalf("InitDB: %v", err)
	}

	srv := NewServerWithUI(db, webhook.Nil(), "admin", "s3cret").
		WithRBAC([]string{"admin"}, "warden-admins")

	req := httptest.NewRequest(http.MethodGet, "/ui", nil)
	req.SetBasicAuth("admin", "s3cret")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "nav-overview") {
		t.Error("expected Overview nav item in the dashboard")
	}
	if strings.Contains(body, "__USER_ROLE__") {
		t.Error("expected the USER_ROLE placeholder to be substituted away")
	}
	if !strings.Contains(body, "USER_ROLE = 'admin'") {
		t.Error("expected admin role injected for an admin user, got: " + body)
	}
	if !strings.Contains(body, `role-badge role-admin">admin`) {
		t.Error("expected an admin role badge in the sidebar user area")
	}
}
