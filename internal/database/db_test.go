package database

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/polarisdev-fr/ssh-warden/internal/models"
	"golang.org/x/crypto/ssh"
)

// validTestKey returns a freshly-generated, valid public key line.
func validTestKey(t *testing.T) string {
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

// mustOpen returns a fresh in-memory DB, failing the test on error.
func mustOpen(t *testing.T) *DB {
	t.Helper()
	db, err := InitDB(":memory:")
	if err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	return db
}

// closeDB closes the underlying connection (in-memory DBs are dropped on
// close).
func closeDB(t *testing.T, db *DB) {
	t.Helper()
	if err := db.conn.Close(); err != nil {
		t.Errorf("close db: %v", err)
	}
}

// mustAddKey registers a key for user, returning its owner id via ensureUser.
func mustAddKey(t *testing.T, db *DB, user string) {
	t.Helper()
	if _, err := db.AddSSHKey(user, validTestKey(t), "test"); err != nil {
		t.Fatalf("AddSSHKey(%s): %v", user, err)
	}
}

func TestInitDB(t *testing.T) {
	db := mustOpen(t)
	defer closeDB(t, db)

	// Schema must contain all core tables.
	for _, table := range []string{"users", "ssh_keys", "leases", "hosts", "audit_logs"} {
		var n int
		err := db.conn.QueryRow(
			"SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?", table,
		).Scan(&n)
		if err != nil {
			t.Fatalf("query table %s: %v", table, err)
		}
		if n != 1 {
			t.Errorf("table %s not created", table)
		}
	}

	// foreign_keys pragma must be enabled.
	var fk int
	if err := db.conn.QueryRow("PRAGMA foreign_keys").Scan(&fk); err != nil {
		t.Fatalf("read foreign_keys: %v", err)
	}
	if fk != 1 {
		t.Errorf("expected foreign_keys=1, got %d", fk)
	}
}

func TestLeaseLifecycle(t *testing.T) {
	db := mustOpen(t)
	defer closeDB(t, db)

	mustAddKey(t, db, "alice")

	// Create a lease.
	lease, err := db.CreateLease("alice", "srv-web-01", "on call", 1*time.Hour)
	if err != nil {
		t.Fatalf("CreateLease: %v", err)
	}
	if lease.ID == 0 {
		t.Error("expected a lease ID")
	}

	// Must appear in active leases.
	active, err := db.GetActiveLeases("")
	if err != nil {
		t.Fatalf("GetActiveLeases: %v", err)
	}
	if len(active) != 1 || active[0].Username != "alice" {
		t.Fatalf("expected 1 active lease for alice, got %+v", active)
	}

	// Filter by user.
	byUser, err := db.GetActiveLeases("alice")
	if err != nil {
		t.Fatalf("GetActiveLeases(alice): %v", err)
	}
	if len(byUser) != 1 {
		t.Errorf("expected 1 lease for alice, got %d", len(byUser))
	}

	// Revoke -> expires_at forced to now -> disappears from active.
	if err := db.RevokeLease(lease.ID); err != nil {
		t.Fatalf("RevokeLease: %v", err)
	}
	after, err := db.GetActiveLeases("")
	if err != nil {
		t.Fatalf("GetActiveLeases after revoke: %v", err)
	}
	if len(after) != 0 {
		t.Errorf("expected 0 active leases after revoke, got %d", len(after))
	}

	// Revoking again -> already expired error.
	if err := db.RevokeLease(lease.ID); err != ErrLeaseAlreadyExpired {
		t.Errorf("expected ErrLeaseAlreadyExpired, got %v", err)
	}

	// Revoking a non-existent lease -> not found.
	if err := db.RevokeLease(lease.ID + 1000); err != ErrLeaseNotFound {
		t.Errorf("expected ErrLeaseNotFound, got %v", err)
	}
}

func TestLeaseExpiryReturnsNoKey(t *testing.T) {
	db := mustOpen(t)
	defer closeDB(t, db)

	mustAddKey(t, db, "bob")

	// Lease already expired.
	if _, err := db.CreateLease("bob", "srv-web-01", "short", -1*time.Minute); err != nil {
		t.Fatalf("CreateLease(expired): %v", err)
	}

	keys, err := db.GetValidKeysForUser("bob", "srv-web-01")
	if err != nil {
		t.Fatalf("GetValidKeysForUser: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("expected no keys for expired lease, got %v", keys)
	}
}

func TestGetValidKeysForUser(t *testing.T) {
	db := mustOpen(t)
	defer closeDB(t, db)

	mustAddKey(t, db, "alice")

	// Active lease on srv-web-01 returns the key for that host...
	if _, err := db.CreateLease("alice", "srv-web-01", "work", 1*time.Hour); err != nil {
		t.Fatalf("CreateLease: %v", err)
	}
	keys, err := db.GetValidKeysForUser("alice", "srv-web-01")
	if err != nil {
		t.Fatalf("GetValidKeysForUser: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key for matching host, got %v", keys)
	}

	// ... but NOT for a different host.
	elseKeys, err := db.GetValidKeysForUser("alice", "srv-db-01")
	if err != nil {
		t.Fatalf("GetValidKeysForUser other host: %v", err)
	}
	if len(elseKeys) != 0 {
		t.Errorf("expected no key for different host, got %v", elseKeys)
	}

	// A "*" catch-all lease grants keys on any host.
	if _, err := db.CreateLease("alice", "*", "catch all", 1*time.Hour); err != nil {
		t.Fatalf("CreateLease(*): %v", err)
	}
	wild, err := db.GetValidKeysForUser("alice", "srv-db-01")
	if err != nil {
		t.Fatalf("GetValidKeysForUser wildcard: %v", err)
	}
	if len(wild) != 1 {
		t.Errorf("expected key via wildcard lease, got %v", wild)
	}
}

func TestHostValidation(t *testing.T) {
	db := mustOpen(t)
	defer closeDB(t, db)

	const rawToken = "super-secret-token"
	if err := db.RegisterHost("srv-prod-01", rawToken); err != nil {
		t.Fatalf("RegisterHost: %v", err)
	}

	// Correct token validates.
	if !db.ValidateHostToken("srv-prod-01", rawToken) {
		t.Error("valid token should be accepted")
	}

	// Wrong token rejected.
	if db.ValidateHostToken("srv-prod-01", "wrong-token") {
		t.Error("invalid token should be rejected")
	}

	// Empty token rejected.
	if db.ValidateHostToken("srv-prod-01", "") {
		t.Error("empty token should be rejected")
	}

	// Unknown host rejected regardless of token.
	if db.ValidateHostToken("unknown-host", rawToken) {
		t.Error("unknown host should be rejected")
	}
}

// TestHostValidationWildcard verifies that a "*" host acts as a fallback for
// any unregistered hostname carrying the same token.
func TestHostValidationWildcard(t *testing.T) {
	db := mustOpen(t)
	defer closeDB(t, db)

	const wildToken = "wildcard-secret"
	if err := db.RegisterHost("*", wildToken); err != nil {
		t.Fatalf("RegisterHost(*): %v", err)
	}

	// An arbitrary host with the wildcard token is accepted.
	if !db.ValidateHostToken("any-random-host", wildToken) {
		t.Error("wildcard host should accept any hostname with the matching token")
	}

	// A specific host with a different token is still rejected.
	if db.ValidateHostToken("any-random-host", "other-token") {
		t.Error("wildcard host should reject a non-matching token")
	}
}

func TestPendingLeaseWorkflow(t *testing.T) {
	db := mustOpen(t)
	defer closeDB(t, db)

	mustAddKey(t, db, "alice")

	// Create a pending lease — should NOT grant keys.
	lease, err := db.CreatePendingLease("alice", "srv-web-01", "pending work", 1*time.Hour)
	if err != nil {
		t.Fatalf("CreatePendingLease: %v", err)
	}
	if lease.Status != "pending" {
		t.Errorf("expected status pending, got %q", lease.Status)
	}

	keys, err := db.GetValidKeysForUser("alice", "srv-web-01")
	if err != nil {
		t.Fatalf("GetValidKeysForUser: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("pending lease should not grant keys, got %v", keys)
	}

	// Pending lease must appear in GetPendingLeases.
	pending, err := db.GetPendingLeases("")
	if err != nil {
		t.Fatalf("GetPendingLeases: %v", err)
	}
	if len(pending) != 1 || pending[0].ID != lease.ID {
		t.Fatalf("expected 1 pending lease with ID %d, got %+v", lease.ID, pending)
	}

	// Approve the lease — now it should grant keys.
	if err := db.ApproveLease(lease.ID); err != nil {
		t.Fatalf("ApproveLease: %v", err)
	}
	keys, err = db.GetValidKeysForUser("alice", "srv-web-01")
	if err != nil {
		t.Fatalf("GetValidKeysForUser after approve: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("approved lease should grant 1 key, got %v", keys)
	}

	// Approved lease must not appear in pending list.
	pending, err = db.GetPendingLeases("")
	if err != nil {
		t.Fatalf("GetPendingLeases after approve: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("expected 0 pending leases after approve, got %d", len(pending))
	}
}

func TestRejectLeaseWorkflow(t *testing.T) {
	db := mustOpen(t)
	defer closeDB(t, db)

	mustAddKey(t, db, "bob")

	lease, err := db.CreatePendingLease("bob", "srv-db-01", "need access", 1*time.Hour)
	if err != nil {
		t.Fatalf("CreatePendingLease: %v", err)
	}

	// Reject the lease.
	if err := db.RejectLease(lease.ID); err != nil {
		t.Fatalf("RejectLease: %v", err)
	}

	// Denied lease must not grant keys.
	keys, err := db.GetValidKeysForUser("bob", "srv-db-01")
	if err != nil {
		t.Fatalf("GetValidKeysForUser after reject: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("denied lease should not grant keys, got %v", keys)
	}

	// Denied lease must not appear in pending list.
	pending, err := db.GetPendingLeases("")
	if err != nil {
		t.Fatalf("GetPendingLeases after reject: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("expected 0 pending after reject, got %d", len(pending))
	}
}

func TestApproveNonPendingLease(t *testing.T) {
	db := mustOpen(t)
	defer closeDB(t, db)

	mustAddKey(t, db, "alice")

	// Approving an already-approved lease must return ErrLeaseNotPending.
	lease, err := db.CreateLease("alice", "srv-web-01", "approved", 1*time.Hour)
	if err != nil {
		t.Fatalf("CreateLease: %v", err)
	}
	if err := db.ApproveLease(lease.ID); err != ErrLeaseNotPending {
		t.Errorf("expected ErrLeaseNotPending, got %v", err)
	}
}

func TestApproveNonExistentLease(t *testing.T) {
	db := mustOpen(t)
	defer closeDB(t, db)

	if err := db.ApproveLease(9999); err != ErrLeaseNotFound {
		t.Errorf("expected ErrLeaseNotFound, got %v", err)
	}
}

func TestUserTokenLifecycle(t *testing.T) {
	db := mustOpen(t)
	defer closeDB(t, db)

	raw, err := db.CreateUserToken("alice", "", time.Hour)
	if err != nil {
		t.Fatalf("CreateUserToken: %v", err)
	}
	if len(raw) < len(userTokenPrefix)+12 {
		t.Errorf("token too short: %q", raw)
	}

	// Valid token resolves to the username; empty role defaults to "user".
	if user, role, valid := db.ValidateUserToken(raw); !valid || user != "alice" || role != "user" {
		t.Errorf("expected valid token for alice/user, got user=%q role=%q valid=%v", user, role, valid)
	}

	// A token minted with an explicit role preserves that role.
	adminRaw, err := db.CreateUserToken("bob", "admin", time.Hour)
	if err != nil {
		t.Fatalf("CreateUserToken admin: %v", err)
	}
	if _, role, valid := db.ValidateUserToken(adminRaw); !valid || role != "admin" {
		t.Errorf("expected admin role on token, got role=%q valid=%v", role, valid)
	}

	// Unknown / empty / tampered tokens are rejected.
	if _, _, valid := db.ValidateUserToken("wrd_pat_tampered"); valid {
		t.Error("expected invalid for tampered token")
	}
	if _, _, valid := db.ValidateUserToken(""); valid {
		t.Error("expected invalid for empty token")
	}

	// Empty username is refused.
	if _, err := db.CreateUserToken("", "", time.Hour); err == nil {
		t.Error("expected error for empty username")
	}
}

func TestUserTokenExpired(t *testing.T) {
	db := mustOpen(t)
	defer closeDB(t, db)

	raw, err := db.CreateUserToken("alice", "", -time.Minute)
	if err != nil {
		t.Fatalf("CreateUserToken: %v", err)
	}
	if _, _, valid := db.ValidateUserToken(raw); valid {
		t.Error("expected expired token to be invalid")
	}
}

func TestHostStats(t *testing.T) {
	db := mustOpen(t)
	defer closeDB(t, db)

	if err := db.RecordAudit("alice", "srv-web-01", "KEY_REQUEST_GRANTED", "ok", "1.2.3.4"); err != nil {
		t.Fatalf("RecordAudit grant: %v", err)
	}
	if err := db.RecordAudit("bob", "srv-web-01", "KEY_REQUEST_GRANTED", "ok", "5.6.7.8"); err != nil {
		t.Fatalf("RecordAudit grant: %v", err)
	}
	if err := db.RecordAudit("alice", "srv-web-01", "KEY_REQUEST_DENIED", "no", "1.2.3.4"); err != nil {
		t.Fatalf("RecordAudit deny: %v", err)
	}
	if err := db.RecordAudit("alice", "srv-db-01", "KEY_REQUEST_GRANTED", "ok", "1.2.3.4"); err != nil {
		t.Fatalf("RecordAudit grant: %v", err)
	}

	all, err := db.HostStats("")
	if err != nil {
		t.Fatalf("HostStats: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 hosts, got %d", len(all))
	}

	var web, dbh *models.HostStats
	for i := range all {
		if all[i].Host == "srv-web-01" {
			web = &all[i]
		}
		if all[i].Host == "srv-db-01" {
			dbh = &all[i]
		}
	}
	if web == nil || dbh == nil {
		t.Fatalf("missing expected hosts, got %+v", all)
	}
	if web.Granted != 2 || web.Denied != 1 {
		t.Errorf("srv-web-01: expected granted=2 denied=1, got %d/%d", web.Granted, web.Denied)
	}
	if len(web.Users) != 2 {
		t.Errorf("srv-web-01: expected 2 distinct users, got %v", web.Users)
	}
	if dbh.Granted != 1 || dbh.Denied != 0 {
		t.Errorf("srv-db-01: expected granted=1 denied=0, got %d/%d", dbh.Granted, dbh.Denied)
	}
	if web.LastSeen.IsZero() {
		t.Error("expected LastSeen to be set")
	}

	// Scoped to a single user.
	mine, err := db.HostStats("alice")
	if err != nil {
		t.Fatalf("HostStats(alice): %v", err)
	}
	if len(mine) != 2 {
		t.Fatalf("expected alice to have 2 hosts, got %d", len(mine))
	}
	for _, h := range mine {
		if len(h.Users) > 1 && h.Host == "srv-web-01" {
			// alice and bob both hit srv-web-01, but scoped to alice only alice appears.
			t.Errorf("expected only alice in scoped users for %s, got %v", h.Host, h.Users)
		}
	}
}
