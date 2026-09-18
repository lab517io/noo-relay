// Package store owns the SQLite schema and every query the relay runs.
//
// Sync protocol v2 (docs/P2P_SYNC.md in the client repository): the relay
// stores opaque encrypted packets keyed by (user, origin device, counter) —
// per-device streams with client-assigned contiguous counters. There is no
// server-assigned global sequence; a user's sync state is the version vector
// derived from max(counter) per origin device.
package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// TimeFormat matches the SQLite column defaults
// (strftime('%Y-%m-%dT%H:%M:%SZ')) and the Python implementation, so rows
// written by either service are indistinguishable.
const TimeFormat = "2006-01-02T15:04:05Z"

func Now() string { return time.Now().UTC().Format(TimeFormat) }

const schemaSQL = `
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    device_name TEXT NOT NULL,
    platform TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    last_seen TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE(user_id, device_id)
);

CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    origin_device_id TEXT NOT NULL,
    counter INTEGER NOT NULL,
    payload BLOB NOT NULL,
    -- SHA-256 of payload, lowercase hex: the packet's content identity, as
    -- opposed to the (origin device, counter) slot it occupies. The relay
    -- cannot read a payload, but it can say whether the bytes it holds under
    -- an identity are the bytes a client holds under the same one -- which is
    -- what separates a duplicate from a forked stream (docs/P2P_SYNC.md 3.3).
    payload_hash TEXT NOT NULL DEFAULT '',
    stored_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE(user_id, origin_device_id, counter)
);

CREATE INDEX IF NOT EXISTS idx_packets_user_device
    ON packets(user_id, origin_device_id, counter);

-- Attachment blobs (docs/P2P_SYNC.md 3.5): encrypted bytes stored once per
-- account under their content id, referenced from packets by that id rather
-- than carried inside them. The relay cannot read a blob any more than a
-- packet; blob_id is a hash the client computed over plaintext it never sees.
CREATE TABLE IF NOT EXISTS blobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    blob_id TEXT NOT NULL,
    payload BLOB NOT NULL,
    stored_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE(user_id, blob_id)
);

-- Which blobs each stored packet declared on upload. The relay's only
-- knowledge of what a packet references, and what keeps a blob alive: a
-- blob no stored packet declares is collected when packets are pruned.
CREATE TABLE IF NOT EXISTS packet_blobs (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    origin_device_id TEXT NOT NULL,
    counter INTEGER NOT NULL,
    blob_id TEXT NOT NULL,
    PRIMARY KEY (user_id, origin_device_id, counter, blob_id)
);
CREATE INDEX IF NOT EXISTS idx_packet_blobs_blob ON packet_blobs(user_id, blob_id);
CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id);

-- Per-device high-water marks, kept independently of the packets themselves.
-- Compaction (docs/P2P_SYNC_COMPACTION.md §4.3) deletes low counters, so
-- MAX(counter) is no longer a safe source for "what comes next": a stream
-- pruned to nothing would restart at 1 and re-issue identities that already
-- exist elsewhere — the §3.3 fork, caused by the server.
CREATE TABLE IF NOT EXISTS stream_marks (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    origin_device_id TEXT NOT NULL,
    high_water INTEGER NOT NULL,
    PRIMARY KEY (user_id, origin_device_id)
);
`

// v1 leftovers. The v1->v2 migration is a clean epoch break: v1 blobs are
// undecryptable under the v2 key derivation, and clients re-announce their
// full current state as fresh v2 streams, so the old global-sequence log and
// server-side cursors are dropped rather than converted.
const dropV1SQL = `
DROP TABLE IF EXISTS changes;
DROP TABLE IF EXISTS device_cursors;
`

type Store struct {
	db *sql.DB
	// dir is the directory holding the database file, whose filesystem
	// FreeBytes reports on.
	dir string
}

// Open connects to the SQLite file and applies the schema.
func Open(ctx context.Context, path string) (*Store, error) {
	// WAL and foreign keys mirror the PRAGMAs the Python service sets per
	// connection; busy_timeout covers the pool's writers queueing behind
	// SQLite's single write lock instead of failing with SQLITE_BUSY.
	dsn := path + "?" + url.Values{"_pragma": {
		"journal_mode(WAL)", "foreign_keys(1)", "busy_timeout(5000)",
	}}.Encode()

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	s := &Store{db: db, dir: filepath.Dir(path)}
	if err := s.init(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) init(ctx context.Context) error {
	for _, script := range []string{dropV1SQL, schemaSQL} {
		if _, err := s.db.ExecContext(ctx, script); err != nil {
			return fmt.Errorf("initialise schema: %w", err)
		}
	}
	return s.migrate(ctx)
}

// migrate brings a database written by an older build up to the current
// schema. Both steps are idempotent, so this runs on every start.
func (s *Store) migrate(ctx context.Context) error {
	// A packet uploaded with the snapshot header is flagged, so pulls can put
	// snapshots before packets a requester could not otherwise accept
	// (docs/P2P_SYNC_COMPACTION.md §4.2). The relay still cannot read a
	// payload — this is the uploader's out-of-band declaration, nothing more.
	var hasColumn int
	err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM pragma_table_info('packets') WHERE name = 'is_snapshot'",
	).Scan(&hasColumn)
	if err != nil {
		return fmt.Errorf("inspect packets schema: %w", err)
	}
	if hasColumn == 0 {
		if _, err := s.db.ExecContext(ctx,
			"ALTER TABLE packets ADD COLUMN is_snapshot INTEGER NOT NULL DEFAULT 0",
		); err != nil {
			return fmt.Errorf("add packets.is_snapshot: %w", err)
		}
	}

	// Content hashes, added alongside the client's schema v10. Backfilled in
	// full rather than lazily: a hash only some rows carry cannot answer "do we
	// hold the same stream", which is the only question the column exists for.
	if err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM pragma_table_info('packets') WHERE name = 'payload_hash'",
	).Scan(&hasColumn); err != nil {
		return fmt.Errorf("inspect packets schema: %w", err)
	}
	if hasColumn == 0 {
		if _, err := s.db.ExecContext(ctx,
			"ALTER TABLE packets ADD COLUMN payload_hash TEXT NOT NULL DEFAULT ''",
		); err != nil {
			return fmt.Errorf("add packets.payload_hash: %w", err)
		}
	}
	if err := s.backfillHashes(ctx); err != nil {
		return err
	}

	// Seed the marks from what is stored. Only meaningful once, for a database
	// that predates the table; afterwards the marks are already at or above
	// MAX(counter) and the upsert is a no-op.
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO stream_marks (user_id, origin_device_id, high_water)
		SELECT user_id, origin_device_id, MAX(counter) FROM packets
		GROUP BY user_id, origin_device_id
		ON CONFLICT(user_id, origin_device_id)
		DO UPDATE SET high_water = MAX(high_water, excluded.high_water)`,
	); err != nil {
		return fmt.Errorf("seed stream marks: %w", err)
	}
	return nil
}

// backfillHashes fills in payload_hash wherever it is still empty. Batched:
// payloads carry attachments, and the whole table will not fit in memory.
func (s *Store) backfillHashes(ctx context.Context) error {
	const batch = 100
	for {
		rows, err := s.db.QueryContext(ctx,
			`SELECT id, payload FROM packets WHERE payload_hash = '' LIMIT ?`, batch)
		if err != nil {
			return fmt.Errorf("scan packets for hashing: %w", err)
		}
		type row struct {
			id   int64
			hash string
		}
		var pending []row
		for rows.Next() {
			var id int64
			var payload []byte
			if err := rows.Scan(&id, &payload); err != nil {
				rows.Close()
				return fmt.Errorf("scan packet for hashing: %w", err)
			}
			pending = append(pending, row{id: id, hash: PayloadHash(payload)})
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("scan packets for hashing: %w", err)
		}
		rows.Close()
		if len(pending) == 0 {
			return nil
		}
		for _, p := range pending {
			if _, err := s.db.ExecContext(ctx,
				"UPDATE packets SET payload_hash = ? WHERE id = ?", p.hash, p.id,
			); err != nil {
				return fmt.Errorf("backfill packet hash: %w", err)
			}
		}
	}
}

// PayloadHash is a packet's content identity: SHA-256 of the wire blob,
// lowercase hex. Computed over the stored ciphertext, which every node holds
// verbatim, so the relay and its clients always hash identical bytes.
func PayloadHash(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// StreamHashes returns the content hashes the relay holds for one device's
// stream over the inclusive counter range [from, to].
//
// Sparse by design: counters pruned by compaction are simply absent, which a
// client reads as "cannot say" rather than as a mismatch. Nothing here
// discloses payload content -- these are hashes of ciphertext the caller is
// already entitled to pull.
func (s *Store) StreamHashes(ctx context.Context, userID int64, origin string, from, to int64) (map[int64]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT counter, payload_hash FROM packets
		 WHERE user_id = ? AND origin_device_id = ? AND counter >= ? AND counter <= ?
		   AND payload_hash != ''
		 ORDER BY counter`,
		userID, origin, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	hashes := map[int64]string{}
	for rows.Next() {
		var counter int64
		var hash string
		if err := rows.Scan(&counter, &hash); err != nil {
			return nil, err
		}
		hashes[counter] = hash
	}
	return hashes, rows.Err()
}

func (s *Store) Close() error { return s.db.Close() }

// DB exposes the handle for tests and health probes.
func (s *Store) DB() *sql.DB { return s.db }

type User struct {
	ID           int64
	Username     string
	PasswordHash string
	CreatedAt    string
}

type Device struct {
	DeviceID   string `json:"device_id"`
	DeviceName string `json:"device_name"`
	Platform   string `json:"platform"`
	CreatedAt  string `json:"created_at"`
	LastSeen   string `json:"last_seen"`
}

type Packet struct {
	OriginDeviceID string
	Counter        int64
	Payload        []byte
	StoredAt       string
}

var ErrUsernameTaken = fmt.Errorf("username already exists")

// CreateUser inserts a user, reporting ErrUsernameTaken on a duplicate.
func (s *Store) CreateUser(ctx context.Context, username, passwordHash, now string) (int64, error) {
	var exists int
	err := s.db.QueryRowContext(ctx, "SELECT 1 FROM users WHERE username = ?", username).Scan(&exists)
	if err == nil {
		return 0, ErrUsernameTaken
	}
	if err != sql.ErrNoRows {
		return 0, err
	}

	res, err := s.db.ExecContext(ctx,
		"INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
		username, passwordHash, now)
	if err != nil {
		// The UNIQUE index backstops a race between the check and the insert.
		if isUniqueViolation(err) {
			return 0, ErrUsernameTaken
		}
		return 0, err
	}
	return res.LastInsertId()
}

// UserByUsername returns nil without error when there is no such user.
func (s *Store) UserByUsername(ctx context.Context, username string) (*User, error) {
	var u User
	err := s.db.QueryRowContext(ctx,
		"SELECT id, username, password_hash FROM users WHERE username = ?", username,
	).Scan(&u.ID, &u.Username, &u.PasswordHash)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// DeviceBelongsToUser is the check that makes device deletion an effective
// token revocation: once the row is gone, tokens naming it stop working.
func (s *Store) DeviceBelongsToUser(ctx context.Context, userID int64, deviceID string) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx,
		"SELECT 1 FROM users u JOIN devices d ON d.user_id = u.id AND d.device_id = ? WHERE u.id = ?",
		deviceID, userID,
	).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// UpsertDevice registers the device on login, or refreshes its name, platform
// and last_seen if it is already known.
func (s *Store) UpsertDevice(ctx context.Context, userID int64, deviceID, name, platform, now string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO devices (user_id, device_id, device_name, platform, created_at, last_seen)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(user_id, device_id) DO UPDATE SET
		     device_name = excluded.device_name,
		     platform    = excluded.platform,
		     last_seen   = excluded.last_seen`,
		userID, deviceID, name, platform, now, now)
	return err
}

// InsertDevice adds a device explicitly, reporting whether it already existed.
func (s *Store) InsertDevice(ctx context.Context, userID int64, deviceID, name, platform, now string) (created bool, err error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO devices (user_id, device_id, device_name, platform, created_at, last_seen)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		userID, deviceID, name, platform, now, now)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

func (s *Store) TouchDevice(ctx context.Context, userID int64, deviceID, now string) error {
	_, err := s.db.ExecContext(ctx,
		"UPDATE devices SET last_seen = ? WHERE user_id = ? AND device_id = ?",
		now, userID, deviceID)
	return err
}

func (s *Store) ListDevices(ctx context.Context, userID int64) ([]Device, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT device_id, device_name, platform, created_at, last_seen FROM devices WHERE user_id = ?",
		userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	devices := []Device{}
	for rows.Next() {
		var d Device
		if err := rows.Scan(&d.DeviceID, &d.DeviceName, &d.Platform, &d.CreatedAt, &d.LastSeen); err != nil {
			return nil, err
		}
		devices = append(devices, d)
	}
	return devices, rows.Err()
}

// DeleteDevice reports whether a row was removed.
func (s *Store) DeleteDevice(ctx context.Context, userID int64, deviceID string) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		"DELETE FROM devices WHERE user_id = ? AND device_id = ?", userID, deviceID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// UserVector is the relay's version vector for a user: origin device to the
// highest counter it has ever accepted.
//
// Marks are part of the answer, not just stored packets: after a prune a
// stream can be empty and still have a top (docs/P2P_SYNC_COMPACTION.md §4.3).
// Reporting only what is stored would send clients back to re-upload packets
// the relay deliberately discarded, on every sync.
func (s *Store) UserVector(ctx context.Context, userID int64) (map[string]int64, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT origin_device_id, MAX(counter) FROM (
			SELECT origin_device_id, MAX(counter) AS counter FROM packets
			WHERE user_id = ? GROUP BY origin_device_id
			UNION ALL
			SELECT origin_device_id, high_water FROM stream_marks WHERE user_id = ?
		) GROUP BY origin_device_id`,
		userID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	vector := map[string]int64{}
	for rows.Next() {
		var device string
		var counter int64
		if err := rows.Scan(&device, &counter); err != nil {
			return nil, err
		}
		vector[device] = counter
	}
	return vector, rows.Err()
}

// StreamMark is the next-counter authority for one device's stream: the
// highest counter ever accepted, whether or not that packet is still stored.
// Compaction deletes low counters, so MAX(counter) alone would let a fully
// pruned stream restart at 1.
func (s *Store) StreamMark(ctx context.Context, userID int64, origin string) (int64, error) {
	var mark int64
	err := s.db.QueryRowContext(ctx, streamMarkSQL, userID, origin, userID, origin).Scan(&mark)
	return mark, err
}

// The mark as a scalar subquery: the greater of what is stored and what is
// remembered. Takes (user, device) twice.
const streamMarkSQL = `SELECT COALESCE(MAX(m), 0) FROM (
	SELECT COALESCE(MAX(counter), 0) AS m FROM packets
	WHERE user_id = ? AND origin_device_id = ?
	UNION ALL
	SELECT high_water FROM stream_marks WHERE user_id = ? AND origin_device_id = ?
)`

// InsertPacket stores one packet under its (origin device, counter) identity.
//
// The uploader is not required to be the origin device: clients also carry
// packets for their user's other devices (gossip). The relay never inspects
// payloads — clients verify origin via the AEAD AAD. [isSnapshot] is the
// uploader's declaration that this packet is a full-state snapshot; it only
// affects pull ordering.
//
// Insertion rule (docs/P2P_SYNC.md §5.2): a packet is accepted only as the
// next contiguous counter of its device's stream, where "next" comes from the
// persisted mark rather than from MAX(counter) — see [StreamMark]. An
// already-held slot is a no-op (200); a counter beyond the next one is a
// protocol violation (409).
//
// The insert carries its own contiguity guard: the row lands only when the
// counter is exactly one past the mark. SQLite serialises writers, so the
// guard is evaluated under the write lock and two concurrent uploads of the
// same slot cannot both succeed — no explicit transaction needed, and the
// UNIQUE constraint remains as a backstop.
//
// When nothing was inserted, held is the stream's mark so the caller can tell
// an already-held slot (a no-op) from a gap (a protocol violation).
//
// [blobIDs] is the uploader's declaration of the attachment blobs the packet
// references (docs/P2P_SYNC.md §3.5). Recorded whether the packet is new or
// already held — a carrier may deliver a packet before its origin, and the
// origin's later declaration must still count. Callers check the blobs exist
// first; this only records the association.
func (s *Store) InsertPacket(ctx context.Context, userID int64, origin string, counter int64, payload []byte, isSnapshot bool, blobIDs []string) (inserted bool, held int64, err error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO packets (user_id, origin_device_id, counter, payload, payload_hash, is_snapshot)
		 SELECT ?, ?, ?, ?, ?, ?
		 WHERE (`+streamMarkSQL+`) = ? - 1`,
		userID, origin, counter, payload, PayloadHash(payload), boolToInt(isSnapshot),
		userID, origin, userID, origin, counter)
	if err == nil {
		var n int64
		if n, err = res.RowsAffected(); err != nil {
			return false, 0, err
		}
		if n == 1 {
			// Persist the mark so a later prune cannot lower what comes next.
			// A crash between the two statements is harmless: the packet is
			// still stored, so MAX(counter) answers for it until it is pruned,
			// and a prune re-asserts the mark before deleting anything.
			if err := s.raiseMark(ctx, userID, origin, counter); err != nil {
				return true, counter, err
			}
			if err := s.recordPacketBlobs(ctx, userID, origin, counter, blobIDs); err != nil {
				return true, counter, err
			}
			return true, counter, nil
		}
	} else if !isUniqueViolation(err) {
		return false, 0, err
	}
	// Nothing was inserted: either the slot is already filled (a no-op) or the
	// counter is past the end of the stream (a gap the caller reports as 409).

	held, err = s.StreamMark(ctx, userID, origin)
	if err != nil {
		return false, 0, err
	}
	if counter <= held {
		if err := s.recordPacketBlobs(ctx, userID, origin, counter, blobIDs); err != nil {
			return false, held, err
		}
	}
	if isSnapshot && counter <= held {
		// The slot is already filled, and this upload declares it a snapshot.
		// The row may well have been stored unflagged: under gossip a peer
		// carries the packet for its origin device, and a carrier has no
		// coverage declaration of its own to send. The flag is what pull
		// ordering keys on, so adopt the stronger claim rather than leaving
		// the snapshot indistinguishable from an ordinary packet.
		if err := s.flagSnapshot(ctx, userID, origin, counter); err != nil {
			return false, held, err
		}
	}
	return false, held, nil
}

// recordPacketBlobs stores the packet → blob references. Additive and
// idempotent: a declaration is only ever added to, never revoked.
func (s *Store) recordPacketBlobs(ctx context.Context, userID int64, origin string, counter int64, blobIDs []string) error {
	for _, id := range blobIDs {
		if _, err := s.db.ExecContext(ctx,
			`INSERT OR IGNORE INTO packet_blobs (user_id, origin_device_id, counter, blob_id)
			 VALUES (?, ?, ?, ?)`,
			userID, origin, counter, id); err != nil {
			return err
		}
	}
	return nil
}

// PutBlob stores an encrypted attachment blob under its content id. A blob
// already held is left as it is: two devices encrypting the same plaintext
// produce different ciphertexts (fresh nonces), and either decrypts to the
// bytes the id names, so the first to arrive is as good as any.
func (s *Store) PutBlob(ctx context.Context, userID int64, blobID string, payload []byte) (inserted bool, err error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO blobs (user_id, blob_id, payload) VALUES (?, ?, ?)`,
		userID, blobID, payload)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// GetBlob returns the stored ciphertext for blobID, or nil when not held.
func (s *Store) GetBlob(ctx context.Context, userID int64, blobID string) ([]byte, error) {
	var payload []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT payload FROM blobs WHERE user_id = ? AND blob_id = ?`,
		userID, blobID).Scan(&payload)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return payload, err
}

// HasBlob reports whether blobID is held, without reading it.
func (s *Store) HasBlob(ctx context.Context, userID int64, blobID string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM blobs WHERE user_id = ? AND blob_id = ?`,
		userID, blobID).Scan(&n)
	return n > 0, err
}

// MissingBlobs returns which of ids the relay does not hold for this user —
// what an upload declaring them must supply first.
func (s *Store) MissingBlobs(ctx context.Context, userID int64, ids []string) ([]string, error) {
	var missing []string
	for _, id := range ids {
		held, err := s.HasBlob(ctx, userID, id)
		if err != nil {
			return nil, err
		}
		if !held {
			missing = append(missing, id)
		}
	}
	return missing, nil
}

// collectBlobs deletes every blob of the user that no stored packet declares.
// Returns how many blobs and bytes went.
func (s *Store) collectBlobs(ctx context.Context, userID int64) (blobs, bytes int64, err error) {
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(SUM(LENGTH(payload)), 0) FROM blobs b
		 WHERE b.user_id = ?
		   AND NOT EXISTS (SELECT 1 FROM packet_blobs r
		                   WHERE r.user_id = b.user_id AND r.blob_id = b.blob_id)`,
		userID).Scan(&blobs, &bytes); err != nil {
		return 0, 0, err
	}
	if blobs == 0 {
		return 0, 0, nil
	}
	_, err = s.db.ExecContext(ctx,
		`DELETE FROM blobs
		 WHERE user_id = ?
		   AND NOT EXISTS (SELECT 1 FROM packet_blobs r
		                   WHERE r.user_id = blobs.user_id AND r.blob_id = blobs.blob_id)`,
		userID)
	return blobs, bytes, err
}

// flagSnapshot marks an already-stored packet as a snapshot. It never clears
// the flag: a declaration is only ever added to.
func (s *Store) flagSnapshot(ctx context.Context, userID int64, origin string, counter int64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE packets SET is_snapshot = 1
		 WHERE user_id = ? AND origin_device_id = ? AND counter = ? AND is_snapshot = 0`,
		userID, origin, counter)
	return err
}

// raiseMark records that (user, device) has reached counter, never lowering an
// existing mark.
func (s *Store) raiseMark(ctx context.Context, userID int64, origin string, counter int64) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO stream_marks (user_id, origin_device_id, high_water)
		 VALUES (?, ?, ?)
		 ON CONFLICT(user_id, origin_device_id)
		 DO UPDATE SET high_water = MAX(high_water, excluded.high_water)`,
		userID, origin, counter)
	return err
}

// PruneResult reports what a prune reclaimed.
type PruneResult struct {
	Packets int64 `json:"pruned_packets"`
	Bytes   int64 `json:"pruned_bytes"`
	// Attachment blobs that nothing referenced once the packets were gone.
	Blobs     int64 `json:"pruned_blobs"`
	BlobBytes int64 `json:"pruned_blob_bytes"`
}

// PruneCovered deletes every packet a snapshot has made redundant
// (docs/P2P_SYNC_COMPACTION.md §4.3): for each (device, counter) in covers,
// the packets of that device at or below that counter.
//
// The relay cannot read payloads, so it cannot check the claim — it trusts the
// uploading client, which can already corrupt its own user's stream by lying
// about counters. What it does enforce is the blast radius: nothing above the
// declared coverage is touched, nothing above what it actually holds, and
// never the snapshot packet itself — keepOrigin/keepCounter identify the
// upload that authorised the prune.
func (s *Store) PruneCovered(ctx context.Context, userID int64, covers map[string]int64, keepOrigin string, keepCounter int64) (PruneResult, error) {
	var result PruneResult

	for device, upTo := range covers {
		if device == keepOrigin && upTo >= keepCounter {
			upTo = keepCounter - 1
		}
		if upTo < 1 {
			continue
		}
		mark, err := s.StreamMark(ctx, userID, device)
		if err != nil {
			return result, err
		}
		if mark == 0 {
			// Nothing was ever held for this device; a claim about it prunes
			// nothing and must not seed a mark.
			continue
		}
		if upTo > mark {
			upTo = mark
		}
		// Re-assert the mark before deleting: after this, the stream's next
		// counter no longer depends on any stored row.
		if err := s.raiseMark(ctx, userID, device, mark); err != nil {
			return result, err
		}

		var packets, bytes int64
		if err := s.db.QueryRowContext(ctx,
			`SELECT COUNT(*), COALESCE(SUM(LENGTH(payload)), 0) FROM packets
			 WHERE user_id = ? AND origin_device_id = ? AND counter <= ?`,
			userID, device, upTo).Scan(&packets, &bytes); err != nil {
			return result, err
		}
		if packets == 0 {
			continue
		}
		if _, err := s.db.ExecContext(ctx,
			"DELETE FROM packets WHERE user_id = ? AND origin_device_id = ? AND counter <= ?",
			userID, device, upTo); err != nil {
			return result, err
		}
		// A pruned packet releases its blob references; the snapshot that
		// authorised the prune has declared its own, so live blobs survive.
		if _, err := s.db.ExecContext(ctx,
			"DELETE FROM packet_blobs WHERE user_id = ? AND origin_device_id = ? AND counter <= ?",
			userID, device, upTo); err != nil {
			return result, err
		}
		result.Packets += packets
		result.Bytes += bytes
	}
	if result.Packets > 0 {
		blobs, bytes, err := s.collectBlobs(ctx, userID)
		if err != nil {
			return result, err
		}
		result.Blobs, result.BlobBytes = blobs, bytes
	}
	return result, nil
}

// DeviceUsage is one origin device's share of a user's stored packets.
type DeviceUsage struct {
	DeviceID     string `json:"device_id"`
	DeviceName   string `json:"device_name"`
	Packets      int64  `json:"packets"`
	Bytes        int64  `json:"bytes"`
	FirstCounter int64  `json:"first_counter"`
	LastCounter  int64  `json:"last_counter"`
	Snapshots    int64  `json:"snapshots"`
	LastStoredAt string `json:"last_stored_at"`
}

// Usage is what one account occupies on the relay, which is the only storage
// figure a client can ask about — the dashboard's global totals are admin-only.
type Usage struct {
	Packets int64         `json:"packets"`
	Bytes   int64         `json:"bytes"`
	Devices []DeviceUsage `json:"devices"`
	// Attachment blobs, account-wide: they belong to content, not to a device.
	Blobs     int64 `json:"blobs"`
	BlobBytes int64 `json:"blob_bytes"`
	// The account's storage limit in bytes, packets and blobs together;
	// 0 when there is none. Set by the handler, from configuration.
	QuotaBytes int64 `json:"quota_bytes"`
}

// UserUsage totals a user's stored packets, broken down per origin device and
// ordered largest first — the order the client displays them in.
func (s *Store) UserUsage(ctx context.Context, userID int64) (*Usage, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT p.origin_device_id,
		       COALESCE(d.device_name, ''),
		       COUNT(*),
		       COALESCE(SUM(LENGTH(p.payload)), 0),
		       MIN(p.counter),
		       MAX(p.counter),
		       COALESCE(SUM(p.is_snapshot), 0),
		       MAX(p.stored_at)
		FROM packets p
		LEFT JOIN devices d
		       ON d.user_id = p.user_id AND d.device_id = p.origin_device_id
		WHERE p.user_id = ?
		GROUP BY p.origin_device_id
		ORDER BY SUM(LENGTH(p.payload)) DESC, p.origin_device_id ASC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	usage := &Usage{Devices: []DeviceUsage{}}
	for rows.Next() {
		var d DeviceUsage
		if err := rows.Scan(&d.DeviceID, &d.DeviceName, &d.Packets, &d.Bytes,
			&d.FirstCounter, &d.LastCounter, &d.Snapshots, &d.LastStoredAt); err != nil {
			return nil, err
		}
		usage.Packets += d.Packets
		usage.Bytes += d.Bytes
		usage.Devices = append(usage.Devices, d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(SUM(LENGTH(payload)), 0) FROM blobs WHERE user_id = ?`,
		userID).Scan(&usage.Blobs, &usage.BlobBytes); err != nil {
		return nil, err
	}
	return usage, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Pull returns every packet the relay holds above the caller's vector,
// ascending by counter within each origin device (required by the protocol so
// receiver holdings stay contiguous), plus whether more remain beyond the page.
//
// A page ends at limit packets or once their payloads reach maxBytes,
// whichever comes first — but always holds at least one packet, so a single
// packet larger than the budget still gets through. Without the byte bound a
// page of 1000 maximum-size packets would be buffered, then base64-encoded
// into one JSON body: gigabytes for one request. Cutting a page short keeps
// the order a prefix of the full order, so has_more and the caller's advanced
// vector pick up exactly where it stopped.
func (s *Store) Pull(ctx context.Context, userID int64, have map[string]int64, limit int, maxBytes int64) ([]Packet, bool, error) {
	serverVector, err := s.UserVector(ctx, userID)
	if err != nil {
		return nil, false, err
	}

	var conditions []string
	args := []any{userID}
	for device, held := range serverVector {
		if after := have[device]; held > after {
			conditions = append(conditions, "(origin_device_id = ? AND counter > ?)")
			args = append(args, device, after)
		}
	}
	if len(conditions) == 0 {
		return []Packet{}, false, nil
	}
	args = append(args, limit+1)

	rows, err := s.db.QueryContext(ctx,
		"SELECT origin_device_id, counter, payload, stored_at FROM packets "+
			"WHERE user_id = ? AND ("+strings.Join(conditions, " OR ")+") "+
			// Snapshot-bearing streams first (docs/P2P_SYNC_COMPACTION.md
			// §4.2): a requester starting above a pruned range can only accept
			// the rest of a stream after adopting a snapshot's coverage, so a
			// device holding one must not queue behind another device's
			// packets — or behind a page boundary.
			//
			// The hoist is per stream, not per row. Sorting rows by
			// is_snapshot would lift a snapshot above the lower counters of
			// its own device, breaking the ascending-within-a-device order
			// this pull promises: a client that advanced its vector to the
			// snapshot's counter could never ask for the packets below it
			// again. After a prune a snapshot is already its stream's lowest
			// stored counter, so counter ASC puts it first on its own.
			"ORDER BY MAX(is_snapshot) OVER (PARTITION BY origin_device_id) DESC, "+
			"origin_device_id ASC, counter ASC LIMIT ?",
		args...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()

	packets := []Packet{}
	var bytes int64
	for rows.Next() {
		if len(packets) == limit || (len(packets) > 0 && bytes >= maxBytes) {
			// A row exists beyond the page; that is all has_more needs, so
			// it is not scanned into the page.
			return packets, true, nil
		}
		var p Packet
		if err := rows.Scan(&p.OriginDeviceID, &p.Counter, &p.Payload, &p.StoredAt); err != nil {
			return nil, false, err
		}
		packets = append(packets, p)
		bytes += int64(len(p.Payload))
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	return packets, false, nil
}

func isUniqueViolation(err error) bool {
	// modernc's driver reports constraint failures in the message; matching on
	// it keeps the store free of a driver-specific error type.
	return err != nil && strings.Contains(strings.ToUpper(err.Error()), "UNIQUE CONSTRAINT FAILED")
}
