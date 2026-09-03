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
