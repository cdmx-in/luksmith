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
CREATE TABLE IF NOT EXISTS admins (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT,
    role TEXT NOT NULL,
    sso_subject TEXT UNIQUE,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    role TEXT NOT NULL,
    expires INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS reveal_requests (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    key_id TEXT,
    requester TEXT NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL,
    approver TEXT,
    created_at INTEGER NOT NULL,
    decided_at INTEGER
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

// ------------------------------------------------------------------- admins

type AdminRow struct {
	ID       string
	Username string
	Role     string
	SSO      bool
}

// AdminByUsername returns the stored hash ("" for SSO-only rows), role and role.
func (s *Store) AdminByUsername(username string) (id, passwordHash, role string, ok bool, err error) {
	var ph sql.NullString
	err = s.db.QueryRow("SELECT id, password_hash, role FROM admins WHERE username=?",
		username).Scan(&id, &ph, &role)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", "", false, nil
	}
	if err != nil {
		return "", "", "", false, err
	}
	return id, ph.String, role, true, nil
}

func (s *Store) Admins() ([]AdminRow, error) {
	rows, err := s.db.Query("SELECT id, username, role, sso_subject FROM admins ORDER BY username")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AdminRow{}
	for rows.Next() {
		var a AdminRow
		var sub sql.NullString
		if err := rows.Scan(&a.ID, &a.Username, &a.Role, &sub); err != nil {
			return nil, err
		}
		a.SSO = sub.Valid
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) CreateAdmin(username, passwordHash, role string) error {
	_, err := s.db.Exec(
		"INSERT INTO admins (id, username, password_hash, role, sso_subject, created_at)"+
			" VALUES (?,?,?,?,NULL,?)",
		randHex8(), username, passwordHash, role, time.Now().Unix())
	return err
}

func (s *Store) DeleteAdmin(username string) (bool, error) {
	res, err := s.db.Exec("DELETE FROM admins WHERE username=?", username)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *Store) CountOwners() (int, error) {
	var n int
	err := s.db.QueryRow("SELECT COUNT(*) FROM admins WHERE role=?", roleOwner).Scan(&n)
	return n, err
}

// UpsertSSOAdmin upserts a proxy-asserted identity by sso_subject.
func (s *Store) UpsertSSOAdmin(subject, role string) (*principal, error) {
	_, err := s.db.Exec(
		"INSERT INTO admins (id, username, password_hash, role, sso_subject, created_at)"+
			" VALUES (?,?,NULL,?,?,?)"+
			" ON CONFLICT(sso_subject) DO UPDATE SET role=excluded.role",
		randHex8(), subject, role, subject, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	return &principal{username: subject, role: role, sso: true}, nil
}

// ------------------------------------------------------------------ sessions

func (s *Store) CreateSession(username, role string, ttl time.Duration) (token string, expires int64, err error) {
	token = randToken()
	expires = time.Now().Add(ttl).Unix()
	_, err = s.db.Exec("INSERT INTO sessions (token_hash, username, role, expires) VALUES (?,?,?,?)",
		sha256hex(token), username, role, expires)
	return token, expires, err
}

func (s *Store) SessionByToken(token string) (*principal, bool, error) {
	th := sha256hex(token)
	var username, role string
	var expires int64
	err := s.db.QueryRow("SELECT username, role, expires FROM sessions WHERE token_hash=?",
		th).Scan(&username, &role, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if expires <= time.Now().Unix() {
		s.db.Exec("DELETE FROM sessions WHERE token_hash=?", th) // GC on read
		return nil, false, nil
	}
	return &principal{username: username, role: role}, true, nil
}

func (s *Store) DeleteSession(token string) error {
	_, err := s.db.Exec("DELETE FROM sessions WHERE token_hash=?", sha256hex(token))
	return err
}

// ------------------------------------------------------------ reveal requests

type RevealRequest struct {
	ID        string
	DeviceID  string
	KeyID     sql.NullString
	Requester string
	Reason    string
	Status    string
	Approver  sql.NullString
	CreatedAt int64
	DecidedAt sql.NullInt64
}

var (
	errNotPending  = errors.New("request is not pending")
	errNotApproved = errors.New("request is not approved")
	errNoActiveKey = errors.New("no active key")
)

func (s *Store) CreateRevealRequest(deviceID, requester, reason string) (string, error) {
	id := randHex8()
	_, err := s.db.Exec(
		"INSERT INTO reveal_requests (id, device_id, key_id, requester, reason, status,"+
			" approver, created_at, decided_at) VALUES (?,?,NULL,?,?,'pending',NULL,?,NULL)",
		id, deviceID, requester, reason, time.Now().Unix())
	return id, err
}

const revealCols = "id, device_id, key_id, requester, reason, status, approver, created_at, decided_at"

func scanRevealRequest(sc interface{ Scan(...any) error }) (RevealRequest, error) {
	var r RevealRequest
	err := sc.Scan(&r.ID, &r.DeviceID, &r.KeyID, &r.Requester, &r.Reason, &r.Status,
		&r.Approver, &r.CreatedAt, &r.DecidedAt)
	return r, err
}

func (s *Store) RevealRequest(id string) (*RevealRequest, bool, error) {
	r, err := scanRevealRequest(s.db.QueryRow("SELECT "+revealCols+" FROM reveal_requests WHERE id=?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return &r, true, nil
}

func (s *Store) ListRevealRequests(pendingOnly bool) ([]RevealRequest, error) {
	q := "SELECT " + revealCols + " FROM reveal_requests"
	if pendingOnly {
		q += " WHERE status='pending'"
	}
	q += " ORDER BY created_at DESC"
	rows, err := s.db.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RevealRequest{}
	for rows.Next() {
		r, err := scanRevealRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DecideRevealRequest transitions pending -> approved|denied atomically.
func (s *Store) DecideRevealRequest(id, approver, status string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var cur string
	if err := tx.QueryRow("SELECT status FROM reveal_requests WHERE id=?", id).Scan(&cur); err != nil {
		return err
	}
	if cur != "pending" {
		return errNotPending
	}
	if _, err := tx.Exec("UPDATE reveal_requests SET status=?, approver=?, decided_at=? WHERE id=?",
		status, approver, time.Now().Unix(), id); err != nil {
		return err
	}
	return tx.Commit()
}

// ConsumeRevealRequest transitions approved -> consumed, returning the active
// key. The status guard and update are atomic so a request reveals at most once.
func (s *Store) ConsumeRevealRequest(id string) (keyID, ciphertext string, createdAt int64, err error) {
	tx, err := s.db.Begin()
	if err != nil {
		return "", "", 0, err
	}
	defer tx.Rollback()
	var status, deviceID string
	if err = tx.QueryRow("SELECT status, device_id FROM reveal_requests WHERE id=?", id).
		Scan(&status, &deviceID); err != nil {
		return "", "", 0, err
	}
	if status != "approved" {
		return "", "", 0, errNotApproved
	}
	err = tx.QueryRow("SELECT id, ciphertext, created_at FROM keys WHERE device_id=?"+
		" AND retired_at IS NULL ORDER BY created_at DESC LIMIT 1", deviceID).
		Scan(&keyID, &ciphertext, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", 0, errNoActiveKey
	}
	if err != nil {
		return "", "", 0, err
	}
	if _, err = tx.Exec("UPDATE reveal_requests SET status='consumed', key_id=? WHERE id=?",
		keyID, id); err != nil {
		return "", "", 0, err
	}
	return keyID, ciphertext, createdAt, tx.Commit()
}
