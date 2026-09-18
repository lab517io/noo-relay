package store

import "context"

// Queries behind the relay's storage limits. They answer "how much" and never
// look inside a payload: sizes are all the relay can know, and all it needs.

// UserStorageBytes is what one account occupies: packet payloads plus blobs.
// Computed rather than kept as a running total, so it cannot drift from the
// rows it describes. LENGTH() on a BLOB reads the record header, not the
// payload, so this costs one index walk per account.
func (s *Store) UserStorageBytes(ctx context.Context, userID int64) (int64, error) {
	var total int64
	err := s.db.QueryRowContext(ctx, `
		SELECT
			(SELECT COALESCE(SUM(LENGTH(payload)), 0) FROM packets WHERE user_id = ?) +
			(SELECT COALESCE(SUM(LENGTH(payload)), 0) FROM blobs WHERE user_id = ?)`,
		userID, userID).Scan(&total)
	return total, err
}

// CoveredBytes is how many packet bytes PruneCovered would free for the same
// declaration: the stored packets at or below each declared counter, never
// the uploading snapshot itself. Blobs a prune would orphan are not counted,
// so this errs low — a snapshot is never let through on space it will not
// actually free.
func (s *Store) CoveredBytes(ctx context.Context, userID int64, covers map[string]int64, keepOrigin string, keepCounter int64) (int64, error) {
	var total int64
	for device, upTo := range covers {
		if device == keepOrigin && upTo >= keepCounter {
			upTo = keepCounter - 1
		}
		if upTo < 1 {
			continue
		}
		var bytes int64
		if err := s.db.QueryRowContext(ctx,
			`SELECT COALESCE(SUM(LENGTH(payload)), 0) FROM packets
			 WHERE user_id = ? AND origin_device_id = ? AND counter <= ?`,
			userID, device, upTo).Scan(&bytes); err != nil {
			return 0, err
		}
		total += bytes
	}
	return total, nil
}

// StreamCount is how many origin-device streams an account has ever had.
// stream_marks holds one row per stream from its first accepted packet on,
// and outlives pruning, so a stream emptied by compaction still counts: it
// still has a top, and a client may continue it.
func (s *Store) StreamCount(ctx context.Context, userID int64) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM (
			SELECT origin_device_id FROM stream_marks WHERE user_id = ?
			UNION
			SELECT origin_device_id FROM packets WHERE user_id = ?
		)`, userID, userID).Scan(&n)
	return n, err
}

// FreeBytes reports the space available to the relay on the database's
// filesystem, or -1 where the platform cannot say.
func (s *Store) FreeBytes() (int64, error) {
	return freeBytes(s.dir)
}
