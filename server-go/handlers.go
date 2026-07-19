package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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
}

func newHandler(store *Store, adminToken, enrollSecret, uiDir string) http.Handler {
	if uiDir != "" {
		if st, err := os.Stat(uiDir); err != nil || !st.IsDir() {
			fmt.Fprintf(os.Stderr, "WARNING: --ui-dir %q missing; serving built-in dashboard\n", uiDir)
			uiDir = ""
		}
	}
	s := &server{store: store, adminToken: adminToken, enrollSecret: enrollSecret, uiDir: uiDir}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		jsonResp(w, 200, map[string]any{"ok": true})
	})
	mux.HandleFunc("POST /api/v1/devices/enroll", s.enroll)
	mux.HandleFunc("POST /api/v1/keys", s.escrow)
	mux.HandleFunc("POST /api/v1/devices/{id}/checkin", s.checkin)
	mux.HandleFunc("POST /api/v1/keys/{id}/rotate", s.rotate)
	mux.HandleFunc("POST /api/v1/keys/{id}/reveal", s.reveal)
	mux.HandleFunc("POST /keys/{id}/reveal", s.reveal)
	mux.HandleFunc("GET /api/v1/devices", s.listDevices)
	mux.HandleFunc("GET /api/v1/audit", s.auditLog)
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

func (s *server) isAdmin(r *http.Request) bool {
	if tok := bearer(r); tok != "" && ctEq(tok, s.adminToken) {
		return true
	}
	if _, pw, ok := r.BasicAuth(); ok && ctEq(pw, s.adminToken) {
		return true
	}
	return false
}

func (s *server) needAdmin(w http.ResponseWriter, r *http.Request) bool {
	if s.isAdmin(r) {
		return true
	}
	w.Header().Set("WWW-Authenticate", `Basic realm="luksmith"`)
	w.WriteHeader(401)
	return false
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
	if !s.needAdmin(w, r) {
		return
	}
	deviceID := r.PathValue("id")
	if err := s.store.RequestRotate(deviceID); err != nil {
		fail(w, err)
		return
	}
	if err := s.store.Audit("admin", "rotate_requested", deviceID, ""); err != nil {
		fail(w, err)
		return
	}
	jsonResp(w, 200, map[string]bool{"rotate_requested": true})
}

// reveal — admin only, reason mandatory, always audited. Serves both
// /api/v1/keys/{id}/reveal and /keys/{id}/reveal (React UI displays it now).
func (s *server) reveal(w http.ResponseWriter, r *http.Request) {
	if !s.needAdmin(w, r) {
		return
	}
	deviceID := r.PathValue("id")
	reason := strings.TrimSpace(r.URL.Query().Get("reason"))
	if reason == "" {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1_000_000))
		if form, err := url.ParseQuery(string(b)); err == nil {
			reason = strings.TrimSpace(form.Get("reason"))
		}
	}
	if reason == "" {
		jsonErr(w, 400, "a reason is required and audited")
		return
	}
	keyID, ciphertext, createdAt, found, err := s.store.ActiveKey(deviceID)
	if err != nil {
		fail(w, err)
		return
	}
	action := "key_reveal_miss"
	if found {
		action = "key_revealed"
	}
	if err := s.store.Audit("admin", action, deviceID, "reason="+truncRunes(reason, 500)); err != nil {
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
