package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	_ "modernc.org/sqlite"
)

// Identical to the Python server's schema so an existing luksmith.db drops in.
const schema = `
CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    machine_id TEXT UNIQUE NOT NULL,
    token_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_seen INTEGER,
    last_report TEXT,
    rotate_requested INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS keys (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id),
    ciphertext TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    retired_at INTEGER
);
CREATE TABLE IF NOT EXISTS audit (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    device_id TEXT,
    detail TEXT
);
`

type Store struct{ db *sql.DB }

func OpenStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// ponytail: one connection serializes all writes, same as the Python
	// server's single conn + lock; raise if fleet size ever makes it hurt.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}
	return &Store{db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func sha256hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func randHex8() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func randToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Store) Audit(actor, action, deviceID, detail string) error {
	var did, det any
	if deviceID != "" {
		did = deviceID
	}
	if detail != "" {
		det = detail
	}
	_, err := s.db.Exec(
		"INSERT INTO audit (ts, actor, action, device_id, detail) VALUES (?,?,?,?,?)",
		time.Now().Unix(), actor, action, did, det)
	return err
}

// Enroll upserts by machine_id; re-enrolling rotates the token.
func (s *Store) Enroll(hostname, machineID string) (deviceID, token string, err error) {
	token = randToken()
	err = s.db.QueryRow("SELECT id FROM devices WHERE machine_id=?", machineID).Scan(&deviceID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		deviceID = randHex8()
		_, err = s.db.Exec(
			"INSERT INTO devices (id, hostname, machine_id, token_hash, created_at) VALUES (?,?,?,?,?)",
			deviceID, hostname, machineID, sha256hex(token), time.Now().Unix())
	case err == nil:
		_, err = s.db.Exec("UPDATE devices SET token_hash=?, hostname=? WHERE id=?",
			sha256hex(token), hostname, deviceID)
	}
	return deviceID, token, err
}

// DeviceByToken scans all rows and compares hashes constant-time, like the
// Python server.
func (s *Store) DeviceByToken(token string) (string, bool, error) {
	want := []byte(sha256hex(token))
	rows, err := s.db.Query("SELECT id, token_hash FROM devices")
	if err != nil {
		return "", false, err
	}
	defer rows.Close()
	var found string
	var ok bool
	for rows.Next() {
		var id, th string
		if err := rows.Scan(&id, &th); err != nil {
			return "", false, err
		}
		if hmac.Equal([]byte(th), want) {
			found, ok = id, true
		}
	}
	return found, ok, rows.Err()
}

// Escrow retires the previous active key, inserts the new one and clears the
// rotate flag, atomically.
func (s *Store) Escrow(deviceID, ciphertext string) (string, error) {
	keyID := randHex8()
	now := time.Now().Unix()
	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("UPDATE keys SET retired_at=? WHERE device_id=? AND retired_at IS NULL",
		now, deviceID); err != nil {
		return "", err
	}
	if _, err := tx.Exec("INSERT INTO keys (id, device_id, ciphertext, created_at) VALUES (?,?,?,?)",
		keyID, deviceID, ciphertext, now); err != nil {
		return "", err
	}
	if _, err := tx.Exec("UPDATE devices SET rotate_requested=0 WHERE id=?", deviceID); err != nil {
		return "", err
	}
	return keyID, tx.Commit()
}

func (s *Store) Checkin(deviceID, reportJSON string) (bool, error) {
	if _, err := s.db.Exec("UPDATE devices SET last_seen=?, last_report=? WHERE id=?",
		time.Now().Unix(), reportJSON, deviceID); err != nil {
		return false, err
	}
	var rot sql.NullInt64
	err := s.db.QueryRow("SELECT rotate_requested FROM devices WHERE id=?", deviceID).Scan(&rot)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return rot.Valid && rot.Int64 != 0, err
}

type Device struct {
	ID              string
	Hostname        string
	LastSeen        sql.NullInt64
	LastReport      sql.NullString
	RotateRequested int64
	ActiveKeys      int64
}

func (s *Store) Devices() ([]Device, error) {
	rows, err := s.db.Query(
		"SELECT d.id, d.hostname, d.last_seen, d.last_report, d.rotate_requested," +
			" (SELECT COUNT(*) FROM keys k WHERE k.device_id=d.id AND k.retired_at IS NULL)" +
			" AS active_keys FROM devices d ORDER BY hostname")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		var d Device
		var rot sql.NullInt64
		if err := rows.Scan(&d.ID, &d.Hostname, &d.LastSeen, &d.LastReport, &rot, &d.ActiveKeys); err != nil {
			return nil, err
		}
		d.RotateRequested = rot.Int64
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) ActiveKey(deviceID string) (keyID, ciphertext string, createdAt int64, ok bool, err error) {
	err = s.db.QueryRow(
		"SELECT id, ciphertext, created_at FROM keys WHERE device_id=? AND retired_at IS NULL"+
			" ORDER BY created_at DESC LIMIT 1", deviceID).Scan(&keyID, &ciphertext, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", 0, false, nil
	}
	return keyID, ciphertext, createdAt, err == nil, err
}

func (s *Store) RequestRotate(deviceID string) error {
	_, err := s.db.Exec("UPDATE devices SET rotate_requested=1 WHERE id=?", deviceID)
	return err
}

type AuditRow struct {
	Seq      int64   `json:"seq"`
	Ts       int64   `json:"ts"`
	Actor    string  `json:"actor"`
	Action   string  `json:"action"`
	DeviceID *string `json:"device_id"`
	Detail   *string `json:"detail"`
}

func (s *Store) AuditLog(limit int) ([]AuditRow, error) {
	rows, err := s.db.Query("SELECT seq, ts, actor, action, device_id, detail FROM audit"+
		" ORDER BY seq DESC LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditRow{}
	for rows.Next() {
		var a AuditRow
		if err := rows.Scan(&a.Seq, &a.Ts, &a.Actor, &a.Action, &a.DeviceID, &a.Detail); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
