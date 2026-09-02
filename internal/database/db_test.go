package database

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

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
