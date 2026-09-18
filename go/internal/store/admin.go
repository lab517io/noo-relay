package store

import (
	"context"
	"database/sql"
)

// Stats is the global dashboard summary. The field names keep the v1
// vocabulary (change_count, last_change_at) because static/index.html reads
// them directly.
type Stats struct {
	UserCount    int64   `json:"user_count"`
	DeviceCount  int64   `json:"device_count"`
	ChangeCount  int64   `json:"change_count"`
	StorageBytes int64   `json:"storage_bytes"`
	LastChangeAt *string `json:"last_change_at"`
	ServerTime   string  `json:"server_time"`
}

func (s *Store) Stats(ctx context.Context) (*Stats, error) {
	var st Stats
	row := s.db.QueryRowContext(ctx, `
		SELECT
			(SELECT COUNT(*) FROM users),
			(SELECT COUNT(*) FROM devices),
			(SELECT COUNT(*) FROM packets),
			(SELECT COALESCE(SUM(LENGTH(payload)), 0) FROM packets),
			(SELECT stored_at FROM packets ORDER BY id DESC LIMIT 1)`)

	var lastChange sql.NullString
	if err := row.Scan(&st.UserCount, &st.DeviceCount, &st.ChangeCount, &st.StorageBytes, &lastChange); err != nil {
		return nil, err
	}
	if lastChange.Valid {
		st.LastChangeAt = &lastChange.String
	}
	st.ServerTime = Now()
	return &st, nil
}

type AdminUser struct {
	ID           int64  `json:"id"`
	Username     string `json:"username"`
	CreatedAt    string `json:"created_at"`
	TotalChanges int64  `json:"total_changes"`
	DeviceCount  int64  `json:"device_count"`
	StorageBytes int64  `json:"storage_bytes"`
}

func (s *Store) ListUsers(ctx context.Context) ([]AdminUser, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT
			u.id,
			u.username,
			u.created_at,
			(SELECT COUNT(*) FROM packets p WHERE p.user_id = u.id),
			(SELECT COUNT(*) FROM devices d WHERE d.user_id = u.id),
			(SELECT COALESCE(SUM(LENGTH(p.payload)), 0) FROM packets p WHERE p.user_id = u.id)
		FROM users u
		-- created_at has one-second resolution, so users registered in the
		-- same second tie. id breaks the tie so the dashboard's ordering is
		-- stable across requests rather than left to the query plan.
		ORDER BY u.created_at DESC, u.id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	users := []AdminUser{}
	for rows.Next() {
		var u AdminUser
		if err := rows.Scan(&u.ID, &u.Username, &u.CreatedAt, &u.TotalChanges, &u.DeviceCount, &u.StorageBytes); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

type AdminDevice struct {
	DeviceID      string `json:"device_id"`
	DeviceName    string `json:"device_name"`
	Platform      string `json:"platform"`
	CreatedAt     string `json:"created_at"`
	LastSeen      string `json:"last_seen"`
	StreamCounter int64  `json:"stream_counter"`
}

func (s *Store) ListUserDevices(ctx context.Context, userID int64) ([]AdminDevice, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT
			d.device_id,
			d.device_name,
			d.platform,
			d.created_at,
			d.last_seen,
			-- The stream's mark, not MAX(counter): compaction deletes low
			-- counters, and a stream pruned to its snapshot (or to nothing)
			-- still stands at its high-water mark. Same rule as streamMarkSQL.
			(SELECT MAX(m) FROM (
				SELECT COALESCE(MAX(p.counter), 0) AS m FROM packets p
				WHERE p.user_id = d.user_id AND p.origin_device_id = d.device_id
				UNION ALL
				SELECT sm.high_water FROM stream_marks sm
				WHERE sm.user_id = d.user_id AND sm.origin_device_id = d.device_id))
		FROM devices d
		WHERE d.user_id = ?
		ORDER BY d.last_seen DESC, d.id DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	devices := []AdminDevice{}
	for rows.Next() {
		var d AdminDevice
		if err := rows.Scan(&d.DeviceID, &d.DeviceName, &d.Platform, &d.CreatedAt, &d.LastSeen, &d.StreamCounter); err != nil {
			return nil, err
		}
		devices = append(devices, d)
	}
	return devices, rows.Err()
}

// AdminChange is packet metadata only — never the payload. The relay is
// zero-knowledge, and the dashboard has no business holding ciphertext.
type AdminChange struct {
	OriginDeviceID string `json:"origin_device_id"`
	Counter        int64  `json:"counter"`
	StoredAt       string `json:"stored_at"`
	PayloadSize    int64  `json:"payload_size"`
}

func (s *Store) ListUserChanges(ctx context.Context, userID int64, limit int) ([]AdminChange, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT origin_device_id, counter, stored_at, LENGTH(payload)
		FROM packets
		WHERE user_id = ?
		ORDER BY id DESC
		LIMIT ?`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	changes := []AdminChange{}
	for rows.Next() {
		var c AdminChange
		if err := rows.Scan(&c.OriginDeviceID, &c.Counter, &c.StoredAt, &c.PayloadSize); err != nil {
			return nil, err
		}
		changes = append(changes, c)
	}
	return changes, rows.Err()
}

// DeleteUser removes the user and everything belonging to them. The deletes
// are explicit rather than left to ON DELETE CASCADE so the behaviour does not
// depend on the foreign_keys pragma being on.
func (s *Store) DeleteUser(ctx context.Context, userID int64) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	var one int
	err = tx.QueryRowContext(ctx, "SELECT 1 FROM users WHERE id = ?", userID).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	for _, stmt := range []string{
		"DELETE FROM packets WHERE user_id = ?",
		// The marks outlive the packets they describe, so they need deleting
		// in their own right — leaving them to ON DELETE CASCADE is the one
		// thing this loop exists to avoid.
		"DELETE FROM stream_marks WHERE user_id = ?",
		"DELETE FROM devices WHERE user_id = ?",
		"DELETE FROM users WHERE id = ?",
	} {
		if _, err := tx.ExecContext(ctx, stmt, userID); err != nil {
			return false, err
		}
	}
	return true, tx.Commit()
}
