package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

const decryptHint = "base64 -d ciphertext.b64 | openssl pkeyutl -decrypt " +
	"-inkey org_private.pem -pkeyopt rsa_padding_mode:oaep " +
	"-pkeyopt rsa_oaep_md:sha256"

type server struct {
	store        *Store
	adminToken   string
	enrollSecret string
	uiDir        string // "" -> minimal built-in dashboard

	requireApproval bool
	trustProxy      bool
	proxySecret     string
	groupMap        map[string]string
}

// adminConfig carries the RBAC/SSO/two-person flags into newHandler.
type adminConfig struct {
	requireApproval bool
	trustProxy      bool
	proxySecret     string
	ssoGroupMap     string // raw "group:role,..."
}

func newHandler(store *Store, adminToken, enrollSecret, uiDir string, cfg adminConfig) http.Handler {
	if uiDir != "" {
		if st, err := os.Stat(uiDir); err != nil || !st.IsDir() {
			fmt.Fprintf(os.Stderr, "WARNING: --ui-dir %q missing; serving built-in dashboard\n", uiDir)
			uiDir = ""
		}
	}
	s := &server{
		store: store, adminToken: adminToken, enrollSecret: enrollSecret, uiDir: uiDir,
		requireApproval: cfg.requireApproval, trustProxy: cfg.trustProxy,
		proxySecret: cfg.proxySecret, groupMap: parseGroupMap(cfg.ssoGroupMap),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		jsonResp(w, 200, map[string]any{"ok": true})
	})
	mux.HandleFunc("POST /api/v1/devices/enroll", s.enroll)
	mux.HandleFunc("POST /api/v1/keys", s.escrow)
	mux.HandleFunc("POST /api/v1/devices/{id}/checkin", s.checkin)
	mux.HandleFunc("POST /api/v1/keys/{id}/rotate", s.rotate)
	mux.HandleFunc("POST /api/v1/keys/{id}/reveal", s.reveal)
	mux.HandleFunc("POST /keys/{id}/reveal", s.revealDirect)
	mux.HandleFunc("GET /api/v1/devices", s.listDevices)
	mux.HandleFunc("GET /api/v1/audit", s.auditLog)

	// Admin identity layer.
	mux.HandleFunc("POST /api/v1/auth/login", s.login)
	mux.HandleFunc("POST /api/v1/auth/logout", s.logout)
	mux.HandleFunc("GET /api/v1/me", s.me)
	mux.HandleFunc("GET /api/v1/admins", s.listAdmins)
	mux.HandleFunc("POST /api/v1/admins", s.createAdmin)
	mux.HandleFunc("DELETE /api/v1/admins/{username}", s.deleteAdmin)
	mux.HandleFunc("GET /api/v1/reveal-requests", s.listRevealRequests)
	mux.HandleFunc("POST /api/v1/reveal-requests/{id}/approve", s.decideReveal("approved"))
	mux.HandleFunc("POST /api/v1/reveal-requests/{id}/deny", s.decideReveal("denied"))
	mux.HandleFunc("POST /api/v1/reveal-requests/{id}/reveal", s.revealConsume)

	mux.HandleFunc("/", s.root) // catch-all: static UI / dashboard / 404
	return mux
}

// ------------------------------------------------------------------ helpers

func jsonResp(w http.ResponseWriter, code int, v any) {
	b, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(b)
}

func jsonErr(w http.ResponseWriter, code int, msg string) {
	jsonResp(w, code, map[string]string{"error": msg})
}

func fail(w http.ResponseWriter, err error) {
	log.Printf("internal error: %v", err)
	jsonErr(w, 500, "internal error")
}

// ctEq compares secrets constant-time via hashes (no length leak).
func ctEq(a, b string) bool {
	ha, hb := sha256.Sum256([]byte(a)), sha256.Sum256([]byte(b))
	return hmac.Equal(ha[:], hb[:])
}

func bearer(r *http.Request) string {
	if tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
		return tok
	}
	return ""
}

// resolve applies the auth order from the contract, returning the caller's
// principal or nil (unauthenticated). Only DB failures return an error.
func (s *server) resolve(r *http.Request) (*principal, error) {
	if tok := bearer(r); tok != "" {
		if ctEq(tok, s.adminToken) { // 1. master token
			return &principal{username: "root-token", role: roleOwner}, nil
		}
		p, ok, err := s.store.SessionByToken(tok) // 2. live session
		if err != nil {
			return nil, err
		}
		if ok {
			return p, nil
		}
	}
	if _, pw, ok := r.BasicAuth(); ok && ctEq(pw, s.adminToken) { // 3. basic master
		return &principal{username: "root-token", role: roleOwner}, nil
	}
	// 4. trusted proxy — headers are ignored unless the shared secret matches.
	if s.trustProxy && s.proxySecret != "" && ctEq(r.Header.Get("X-Proxy-Secret"), s.proxySecret) {
		if email := strings.TrimSpace(r.Header.Get("X-Auth-Request-Email")); email != "" {
			role := mapGroups(s.groupMap, r.Header.Get("X-Auth-Request-Groups"))
			return s.store.UpsertSSOAdmin(email, role)
		}
	}
	return nil, nil
}

// authed resolves the caller or writes 401; view-level (any valid role).
func (s *server) authed(w http.ResponseWriter, r *http.Request) (*principal, bool) {
	p, err := s.resolve(r)
	if err != nil {
		fail(w, err)
		return nil, false
	}
	if p == nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="luksmith"`)
		w.WriteHeader(401)
		return nil, false
	}
	return p, true
}

func (s *server) needAdmin(w http.ResponseWriter, r *http.Request) bool {
	_, ok := s.authed(w, r)
	return ok
}

// agentDevice returns the device id for a valid Bearer device token.
func (s *server) agentDevice(w http.ResponseWriter, r *http.Request) (string, bool) {
	tok := bearer(r)
	if tok != "" {
		id, ok, err := s.store.DeviceByToken(tok)
		if err != nil {
			fail(w, err)
			return "", false
		}
		if ok {
			return id, true
		}
	}
	jsonErr(w, 401, "bad device token")
	return "", false
}

func bodyJSON(r *http.Request) map[string]any {
	b, err := io.ReadAll(io.LimitReader(r.Body, 1_000_001))
	if err != nil || len(b) > 1_000_000 {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	return m
}

func truncRunes(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

// ------------------------------------------------------------------- routes

func (s *server) enroll(w http.ResponseWriter, r *http.Request) {
	if !ctEq(r.Header.Get("X-Enroll-Secret"), s.enrollSecret) {
		jsonErr(w, 403, "bad enroll secret")
		return
	}
	body := bodyJSON(r)
	hostname, _ := body["hostname"].(string)
	machineID, _ := body["machine_id"].(string)
	if hostname == "" || machineID == "" {
		jsonErr(w, 400, "hostname and machine_id required")
		return
	}
	deviceID, token, err := s.store.Enroll(truncRunes(hostname, 255), truncRunes(machineID, 64))
	if err != nil {
		fail(w, err)
		return
	}
	if err := s.store.Audit("agent", "device_enrolled", deviceID, ""); err != nil {
		fail(w, err)
		return
	}
	jsonResp(w, 200, map[string]string{"device_id": deviceID, "device_token": token})
}

func (s *server) escrow(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := s.agentDevice(w, r)
	if !ok {
		return
	}
	body := bodyJSON(r)
	ct, _ := body["ciphertext"].(string)
	if _, err := base64.StdEncoding.DecodeString(ct); err != nil {
		jsonErr(w, 400, "ciphertext must be base64")
		return
	}
	keyID, err := s.store.Escrow(deviceID, ct)
	if err != nil {
		fail(w, err)
		return
	}
	if err := s.store.Audit("agent", "key_escrowed", deviceID, "key_id="+keyID); err != nil {
		fail(w, err)
		return
	}
	jsonResp(w, 200, map[string]string{"key_id": keyID})
}

func (s *server) checkin(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := s.agentDevice(w, r)
	if !ok {
		return
	}
	report := bodyJSON(r)
	if report == nil {
		report = map[string]any{}
	}
	js, _ := json.Marshal(report)
	rotate, err := s.store.Checkin(deviceID, string(js))
	if err != nil {
		fail(w, err)
		return
	}
	jsonResp(w, 200, map[string]bool{"rotate_requested": rotate})
}

func (s *server) rotate(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authed(w, r)
	if !ok {
		return
	}
	if !canRotate(p.role) {
		jsonErr(w, 403, "forbidden")
		return
	}
	deviceID := r.PathValue("id")
	if err := s.store.RequestRotate(deviceID); err != nil {
		fail(w, err)
		return
	}
	if err := s.store.Audit(p.username, "rotate_requested", deviceID, ""); err != nil {
		fail(w, err)
		return
	}
	jsonResp(w, 200, map[string]bool{"rotate_requested": true})
}

// revealReason reads the mandatory reason from ?reason= or a form body.
func revealReason(r *http.Request) string {
	reason := strings.TrimSpace(r.URL.Query().Get("reason"))
	if reason == "" {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1_000_000))
		if form, err := url.ParseQuery(string(b)); err == nil {
			reason = strings.TrimSpace(form.Get("reason"))
		}
	}
	return reason
}

// revealPrep authenticates, checks the "request" permission and the mandatory
// reason shared by both reveal entry points.
func (s *server) revealPrep(w http.ResponseWriter, r *http.Request) (p *principal, deviceID, reason string, ok bool) {
	p, ok = s.authed(w, r)
	if !ok {
		return nil, "", "", false
	}
	if !canRequest(p.role) {
		jsonErr(w, 403, "forbidden")
		return nil, "", "", false
	}
	deviceID = r.PathValue("id")
	reason = revealReason(r)
	if reason == "" {
		jsonErr(w, 400, "a reason is required and audited")
		return nil, "", "", false
	}
	return p, deviceID, reason, true
}

// reveal — the JSON API path /api/v1/keys/{id}/reveal. With --require-approval
// off it returns the ciphertext immediately (back-compat); with it on it files
// a pending two-person request (202) instead.
func (s *server) reveal(w http.ResponseWriter, r *http.Request) {
	p, deviceID, reason, ok := s.revealPrep(w, r)
	if !ok {
		return
	}
	if s.requireApproval {
		reqID, err := s.store.CreateRevealRequest(deviceID, p.username, truncRunes(reason, 500))
		if err != nil {
			fail(w, err)
			return
		}
		if err := s.store.Audit(p.username, "reveal_requested", deviceID,
			"reason="+truncRunes(reason, 500)); err != nil {
			fail(w, err)
			return
		}
		jsonResp(w, 202, map[string]any{"request_id": reqID, "status": "pending"})
		return
	}
	s.revealImmediate(w, p, deviceID, reason)
}

// revealDirect — the dashboard path /keys/{id}/reveal. Always immediate, even
// with --require-approval on (a Basic-auth owner viewing the built-in dashboard).
func (s *server) revealDirect(w http.ResponseWriter, r *http.Request) {
	p, deviceID, reason, ok := s.revealPrep(w, r)
	if !ok {
		return
	}
	s.revealImmediate(w, p, deviceID, reason)
}

func (s *server) revealImmediate(w http.ResponseWriter, p *principal, deviceID, reason string) {
	keyID, ciphertext, createdAt, found, err := s.store.ActiveKey(deviceID)
	if err != nil {
		fail(w, err)
		return
	}
	action := "key_reveal_miss"
	if found {
		action = "key_revealed"
	}
	if err := s.store.Audit(p.username, action, deviceID, "reason="+truncRunes(reason, 500)); err != nil {
		fail(w, err)
		return
	}
	if !found {
		jsonErr(w, 404, "no active key for device")
		return
	}
	jsonResp(w, 200, map[string]any{
		"key_id": keyID, "ciphertext": ciphertext,
		"created_at": createdAt, "decrypt_hint": decryptHint})
}

func (s *server) listDevices(w http.ResponseWriter, r *http.Request) {
	if !s.needAdmin(w, r) {
		return
	}
	devs, err := s.store.Devices()
	if err != nil {
		fail(w, err)
		return
	}
	type deviceOut struct {
		ID              string `json:"id"`
		Hostname        string `json:"hostname"`
		LastSeen        *int64 `json:"last_seen"`
		RotateRequested int64  `json:"rotate_requested"`
		ActiveKeys      int64  `json:"active_keys"`
		LastReport      any    `json:"last_report"`
	}
	out := make([]deviceOut, 0, len(devs))
	for _, d := range devs {
		o := deviceOut{ID: d.ID, Hostname: d.Hostname,
			RotateRequested: d.RotateRequested, ActiveKeys: d.ActiveKeys}
		if d.LastSeen.Valid {
			v := d.LastSeen.Int64
			o.LastSeen = &v
		}
		if d.LastReport.Valid {
			json.Unmarshal([]byte(d.LastReport.String), &o.LastReport)
		}
		out = append(out, o)
	}
	jsonResp(w, 200, map[string]any{"devices": out})
}

func (s *server) auditLog(w http.ResponseWriter, r *http.Request) {
	if !s.needAdmin(w, r) {
		return
	}
	rows, err := s.store.AuditLog(200)
	if err != nil {
		fail(w, err)
		return
	}
	jsonResp(w, 200, map[string]any{"audit": rows})
}

// -------------------------------------------------------------- admin identity

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	body := bodyJSON(r)
	username, _ := body["username"].(string)
	password, _ := body["password"].(string)
	_, hash, role, found, err := s.store.AdminByUsername(username)
	if err != nil {
		fail(w, err)
		return
	}
	// Always run one pbkdf2 verify (against a dummy hash for unknown/SSO-only
	// users) so timing does not reveal whether the username exists.
	stored := dummyHash
	if found && hash != "" {
		stored = hash
	}
	if !verifyPassword(password, stored) || !found || hash == "" {
		jsonErr(w, 401, "invalid credentials")
		return
	}
	token, expires, err := s.store.CreateSession(username, role, 12*time.Hour)
	if err != nil {
		fail(w, err)
		return
	}
	jsonResp(w, 200, map[string]any{
		"token": token, "username": username, "role": role, "expires": expires})
}

func (s *server) logout(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authed(w, r); !ok {
		return
	}
	if tok := bearer(r); tok != "" {
		if err := s.store.DeleteSession(tok); err != nil {
			fail(w, err)
			return
		}
	}
	jsonResp(w, 200, map[string]any{"ok": true})
}

func (s *server) me(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authed(w, r)
	if !ok {
		return
	}
	jsonResp(w, 200, map[string]any{"username": p.username, "role": p.role, "sso": p.sso})
}

func (s *server) listAdmins(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authed(w, r)
	if !ok {
		return
	}
	if !canManageAdmins(p.role) {
		jsonErr(w, 403, "forbidden")
		return
	}
	rows, err := s.store.Admins()
	if err != nil {
		fail(w, err)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, a := range rows {
		out = append(out, map[string]any{
			"id": a.ID, "username": a.Username, "role": a.Role, "sso": a.SSO})
	}
	jsonResp(w, 200, map[string]any{"admins": out})
}

func (s *server) createAdmin(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authed(w, r)
	if !ok {
		return
	}
	if !canManageAdmins(p.role) {
		jsonErr(w, 403, "forbidden")
		return
	}
	body := bodyJSON(r)
	username, _ := body["username"].(string)
	password, _ := body["password"].(string)
	role, _ := body["role"].(string)
	username = strings.TrimSpace(username)
	if username == "" || password == "" || !validRole(role) {
		jsonErr(w, 400, "username, password and a valid role are required")
		return
	}
	if username == "root-token" {
		jsonErr(w, 409, "username is reserved")
		return
	}
	if _, _, _, exists, err := s.store.AdminByUsername(username); err != nil {
		fail(w, err)
		return
	} else if exists {
		jsonErr(w, 409, "username already exists")
		return
	}
	if err := s.store.CreateAdmin(username, hashPassword(password), role); err != nil {
		fail(w, err)
		return
	}
	if err := s.store.Audit(p.username, "admin_created", "",
		"username="+username+" role="+role); err != nil {
		fail(w, err)
		return
	}
	jsonResp(w, 200, map[string]any{"username": username, "role": role})
}

func (s *server) deleteAdmin(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authed(w, r)
	if !ok {
		return
	}
	if !canManageAdmins(p.role) {
		jsonErr(w, 403, "forbidden")
		return
	}
	username := r.PathValue("username")
	if username == "root-token" {
		jsonErr(w, 403, "cannot remove the built-in root-token")
		return
	}
	_, _, role, found, err := s.store.AdminByUsername(username)
	if err != nil {
		fail(w, err)
		return
	}
	if !found {
		jsonErr(w, 404, "no such admin")
		return
	}
	if role == roleOwner {
		n, err := s.store.CountOwners()
		if err != nil {
			fail(w, err)
			return
		}
		if n <= 1 {
			jsonErr(w, 409, "cannot remove the last owner")
			return
		}
	}
	if _, err := s.store.DeleteAdmin(username); err != nil {
		fail(w, err)
		return
	}
	if err := s.store.Audit(p.username, "admin_deleted", "", "username="+username); err != nil {
		fail(w, err)
		return
	}
	jsonResp(w, 200, map[string]any{"deleted": username})
}

// -------------------------------------------------------------- reveal requests

func revealRequestJSON(r RevealRequest) map[string]any {
	m := map[string]any{
		"id": r.ID, "device_id": r.DeviceID, "requester": r.Requester,
		"reason": r.Reason, "status": r.Status, "created_at": r.CreatedAt,
		"key_id": nil, "approver": nil, "decided_at": nil,
	}
	if r.KeyID.Valid {
		m["key_id"] = r.KeyID.String
	}
	if r.Approver.Valid {
		m["approver"] = r.Approver.String
	}
	if r.DecidedAt.Valid {
		m["decided_at"] = r.DecidedAt.Int64
	}
	return m
}

func (s *server) listRevealRequests(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authed(w, r); !ok {
		return
	}
	// Parity with the Python server: default (no param) and ?status=all list
	// every request; only ?status=pending narrows to pending.
	pendingOnly := r.URL.Query().Get("status") == "pending"
	rows, err := s.store.ListRevealRequests(pendingOnly)
	if err != nil {
		fail(w, err)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, rq := range rows {
		out = append(out, revealRequestJSON(rq))
	}
	jsonResp(w, 200, map[string]any{"requests": out})
}

// decideReveal handles approve/deny: owner/admin, never the requester.
func (s *server) decideReveal(status string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := s.authed(w, r)
		if !ok {
			return
		}
		if !canApprove(p.role) {
			jsonErr(w, 403, "forbidden")
			return
		}
		id := r.PathValue("id")
		rq, found, err := s.store.RevealRequest(id)
		if err != nil {
			fail(w, err)
			return
		}
		if !found {
			jsonErr(w, 404, "no such request")
			return
		}
		if rq.Requester == p.username {
			jsonErr(w, 403, "a request may not be decided by its requester")
			return
		}
		if err := s.store.DecideRevealRequest(id, p.username, status); err != nil {
			if errors.Is(err, errNotPending) {
				jsonErr(w, 409, "request is not pending")
				return
			}
			fail(w, err)
			return
		}
		action := "reveal_approved"
		if status == "denied" {
			action = "reveal_denied"
		}
		if err := s.store.Audit(p.username, action, rq.DeviceID,
			"request="+id+" requester="+rq.Requester); err != nil {
			fail(w, err)
			return
		}
		jsonResp(w, 200, map[string]any{"request_id": id, "status": status})
	}
}

// revealConsume returns the ciphertext for an approved request; only the
// requester may call it, and only once.
func (s *server) revealConsume(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authed(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	rq, found, err := s.store.RevealRequest(id)
	if err != nil {
		fail(w, err)
		return
	}
	if !found {
		jsonErr(w, 404, "no such request")
		return
	}
	if rq.Requester != p.username {
		jsonErr(w, 403, "only the requester may reveal")
		return
	}
	keyID, ciphertext, createdAt, err := s.store.ConsumeRevealRequest(id)
	if err != nil {
		switch {
		case errors.Is(err, errNotApproved):
			jsonErr(w, 409, "request is not approved")
		case errors.Is(err, errNoActiveKey):
			s.store.Audit(p.username, "key_reveal_miss", rq.DeviceID, "request_id="+id)
			jsonErr(w, 404, "no active key for device")
		default:
			fail(w, err)
		}
		return
	}
	detail := fmt.Sprintf("request=%s requester=%s approver=%s",
		id, rq.Requester, rq.Approver.String)
	if err := s.store.Audit(p.username, "key_revealed", rq.DeviceID, detail); err != nil {
		fail(w, err)
		return
	}
	jsonResp(w, 200, map[string]any{
		"key_id": keyID, "ciphertext": ciphertext,
		"created_at": createdAt, "decrypt_hint": decryptHint})
}

// root is the catch-all: static SPA (with index.html fallback) when --ui-dir
// is set, else a minimal admin dashboard at /; 404 JSON for everything else.
func (s *server) root(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || strings.HasPrefix(r.URL.Path, "/api/") {
		jsonErr(w, 404, "not found")
		return
	}
	if s.uiDir != "" {
		// path.Clean on a rooted path cannot escape uiDir.
		p := path.Clean("/" + r.URL.Path)
		f := filepath.Join(s.uiDir, filepath.FromSlash(p))
		if st, err := os.Stat(f); err == nil && !st.IsDir() {
			http.ServeFile(w, r, f)
			return
		}
		http.ServeFile(w, r, filepath.Join(s.uiDir, "index.html")) // SPA fallback
		return
	}
	if r.URL.Path != "/" {
		jsonErr(w, 404, "not found")
		return
	}
	if !s.needAdmin(w, r) {
		return
	}
	s.dashboard(w)
}

// ponytail: bare device table; the React UI is the real dashboard.
func (s *server) dashboard(w http.ResponseWriter) {
	devs, err := s.store.Devices()
	if err != nil {
		fail(w, err)
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "<!doctype html><meta charset=\"utf-8\"><title>luksmith</title>"+
		"<h1>luksmith</h1><p>%d device(s) enrolled.</p>"+
		"<table><tr><th>Host</th><th>Device ID</th><th>Last seen</th><th>Active keys</th></tr>", len(devs))
	for _, d := range devs {
		seen := "never"
		if d.LastSeen.Valid {
			seen = time.Unix(d.LastSeen.Int64, 0).UTC().Format("2006-01-02 15:04")
		}
		fmt.Fprintf(&b, "<tr><td>%s</td><td><code>%s</code></td><td>%s</td><td>%d</td></tr>",
			html.EscapeString(d.Hostname), html.EscapeString(d.ID), seen, d.ActiveKeys)
	}
	b.WriteString("</table>")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(b.String()))
}
