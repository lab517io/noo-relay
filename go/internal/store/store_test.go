package store

import (
	"context"
	"path/filepath"
	"testing"
)

// openTemp gives each test a private database file.
func openTemp(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "relay.db")
	st, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st, path
}

func seedUser(t *testing.T, st *Store) int64 {
	t.Helper()
	id, err := st.CreateUser(context.Background(), "user", "hash", Now())
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return id
}

func TestInsertPacketRecordsContentHash(t *testing.T) {
	ctx := context.Background()
	st, _ := openTemp(t)
	user := seedUser(t, st)

	payload := []byte("encrypted-packet")
	if _, _, err := st.InsertPacket(ctx, user, "device-a", 1, payload, false, nil); err != nil {
		t.Fatalf("insert: %v", err)
	}

	hashes, err := st.StreamHashes(ctx, user, "device-a", 1, 1)
	if err != nil {
		t.Fatalf("stream hashes: %v", err)
	}
	if hashes[1] != PayloadHash(payload) {
		t.Fatalf("hash = %q, want %q", hashes[1], PayloadHash(payload))
	}
}

// The migration path that runs against a relay already holding data: rows
// written before the column existed carry no hash, and a partially hashed
// store cannot answer the only question the column is for. Reopening must
// fill them all in.
func TestBackfillHashesExistingPackets(t *testing.T) {
	ctx := context.Background()
	st, path := openTemp(t)
	user := seedUser(t, st)

	payload := []byte("packet-written-before-the-column")
	if _, _, err := st.InsertPacket(ctx, user, "device-a", 1, payload, false, nil); err != nil {
		t.Fatalf("insert: %v", err)
	}
	// Put the row back into its pre-migration state.
	if _, err := st.DB().ExecContext(ctx, "UPDATE packets SET payload_hash = ''"); err != nil {
		t.Fatalf("clear hash: %v", err)
	}
	hashes, err := st.StreamHashes(ctx, user, "device-a", 1, 1)
	if err != nil {
		t.Fatalf("stream hashes: %v", err)
	}
	if len(hashes) != 0 {
		t.Fatalf("hashes = %v, want an unhashed row to say nothing", hashes)
	}
	st.Close()

	// Reopening runs the migration, which backfills.
	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()

	hashes, err = reopened.StreamHashes(ctx, user, "device-a", 1, 1)
	if err != nil {
		t.Fatalf("stream hashes after reopen: %v", err)
	}
	if hashes[1] != PayloadHash(payload) {
		t.Fatalf("hash = %q, want %q", hashes[1], PayloadHash(payload))
	}
}

// Compaction deletes low counters. A pruned range must read as "cannot say",
// never as a mismatch, or every compacted stream would look forked.
func TestStreamHashesSkipPrunedCounters(t *testing.T) {
	ctx := context.Background()
	st, _ := openTemp(t)
	user := seedUser(t, st)

	for counter := int64(1); counter <= 3; counter++ {
		if _, _, err := st.InsertPacket(ctx, user, "device-a", counter, []byte{byte(counter)}, false, nil); err != nil {
			t.Fatalf("insert %d: %v", counter, err)
		}
	}
	if _, err := st.PruneCovered(ctx, user, map[string]int64{"device-a": 2}, "device-a", 3); err != nil {
		t.Fatalf("prune: %v", err)
	}

	hashes, err := st.StreamHashes(ctx, user, "device-a", 1, 3)
	if err != nil {
		t.Fatalf("stream hashes: %v", err)
	}
	if len(hashes) != 1 || hashes[3] == "" {
		t.Fatalf("hashes = %v, want only the unpruned counter 3", hashes)
	}
}
