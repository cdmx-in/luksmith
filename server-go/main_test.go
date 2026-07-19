package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testAdmin  = "test-admin-token"
	testEnroll = "test-enroll-secret"
)

func newTestServer(t *testing.T, uiDir string) *httptest.Server {
	t.Helper()
	store, err := OpenStore(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(newHandler(store, testAdmin, testEnroll, uiDir))
	t.Cleanup(func() { ts.Close(); store.Close() })
	return ts
}

// call issues a request; payload (if non-nil) is sent as JSON, token as Bearer.
func call(t *testing.T, ts *httptest.Server, method, path string, payload any,
	token string, headers map[string]string) (int, map[string]any) {
	t.Helper()
	var body io.Reader
	if payload != nil {
		b, _ := json.Marshal(payload)
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, ts.URL+path, body)
	if err != nil {
		t.Fatal(err)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	json.Unmarshal(raw, &m)
	return resp.StatusCode, m
}

func enroll(t *testing.T, ts *httptest.Server) (deviceID, token string) {
	t.Helper()
	status, body := call(t, ts, "POST", "/api/v1/devices/enroll",
		map[string]string{"hostname": "laptop-1", "machine_id": strings.Repeat("m", 32)},
		"", map[string]string{"X-Enroll-Secret": testEnroll})
	if status != 200 {
		t.Fatalf("enroll: status %d, body %v", status, body)
	}
	return body["device_id"].(string), body["device_token"].(string)
}

func TestHealth(t *testing.T) {
	ts := newTestServer(t, "")
	status, body := call(t, ts, "GET", "/healthz", nil, "", nil)
	if status != 200 || body["ok"] != true {
		t.Fatalf("healthz: status %d, body %v", status, body)
	}
}

func TestEnrollRequiresSecret(t *testing.T) {
	ts := newTestServer(t, "")
	status, _ := call(t, ts, "POST", "/api/v1/devices/enroll",
		map[string]string{"hostname": "x", "machine_id": "y"},
		"", map[string]string{"X-Enroll-Secret": "wrong"})
	if status != 403 {
		t.Fatalf("expected 403, got %d", status)
	}
}

func TestFullEscrowAndRevealFlow(t *testing.T) {
	ts := newTestServer(t, "")
	deviceID, token := enroll(t, ts)
	ct := base64.StdEncoding.EncodeToString([]byte("rsa-ciphertext-blob"))

	status, body := call(t, ts, "POST", "/api/v1/keys",
		map[string]string{"device_id": deviceID, "ciphertext": ct}, token, nil)
	if status != 200 {
		t.Fatalf("escrow: status %d, body %v", status, body)
	}
	keyID := body["key_id"].(string)

	// Reveal without a reason is refused.
	status, _ = call(t, ts, "POST", "/api/v1/keys/"+deviceID+"/reveal", nil, testAdmin, nil)
	if status != 400 {
		t.Fatalf("reveal without reason: expected 400, got %d", status)
	}

	// Reveal with a reason returns the ciphertext and is audited.
	status, body = call(t, ts, "POST",
		"/api/v1/keys/"+deviceID+"/reveal?reason=helpdesk+ticket+42", nil, testAdmin, nil)
	if status != 200 {
		t.Fatalf("reveal: status %d, body %v", status, body)
	}
	if body["ciphertext"] != ct || body["key_id"] != keyID {
		t.Fatalf("reveal payload mismatch: %v", body)
	}
	if body["decrypt_hint"] == nil || body["created_at"] == nil {
		t.Fatalf("reveal payload missing fields: %v", body)
	}

	// Form-body reveal on the /keys/ path works too.
	req, _ := http.NewRequest("POST", ts.URL+"/keys/"+deviceID+"/reveal",
		strings.NewReader("reason=form+test"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+testAdmin)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("form reveal: status %d", resp.StatusCode)
	}
	var formBody map[string]any
	json.NewDecoder(resp.Body).Decode(&formBody)
	if formBody["ciphertext"] != ct {
		t.Fatalf("form reveal payload mismatch: %v", formBody)
	}

	// Audit trail records the reveal with the decoded reason.
	status, body = call(t, ts, "GET", "/api/v1/audit", nil, testAdmin, nil)
	if status != 200 {
		t.Fatalf("audit: status %d", status)
	}
	var revealed map[string]any
	for _, a := range body["audit"].([]any) {
		row := a.(map[string]any)
		if row["action"] == "key_revealed" {
			revealed = row
		}
	}
	if revealed == nil {
		t.Fatal("no key_revealed audit entry")
	}
	if !strings.Contains(revealed["detail"].(string), "helpdesk ticket 42") &&
		!strings.Contains(revealed["detail"].(string), "form test") {
		t.Fatalf("audit detail missing reason: %v", revealed)
	}
}

func TestRevealRequiresAdmin(t *testing.T) {
	ts := newTestServer(t, "")
	deviceID, token := enroll(t, ts)
	status, _ := call(t, ts, "POST", "/api/v1/keys/"+deviceID+"/reveal?reason=x",
		nil, token, nil) // device token is not admin
	if status != 401 {
		t.Fatalf("expected 401, got %d", status)
	}
}

func TestEscrowRequiresValidDeviceToken(t *testing.T) {
	ts := newTestServer(t, "")
	status, _ := call(t, ts, "POST", "/api/v1/keys",
		map[string]string{"ciphertext": "aGk="}, "bogus", nil)
	if status != 401 {
		t.Fatalf("expected 401, got %d", status)
	}
}

func TestCiphertextMustBeBase64(t *testing.T) {
	ts := newTestServer(t, "")
	_, token := enroll(t, ts)
	status, _ := call(t, ts, "POST", "/api/v1/keys",
		map[string]string{"ciphertext": "not base64!!"}, token, nil)
	if status != 400 {
		t.Fatalf("expected 400, got %d", status)
	}
}

func TestRotationRoundtrip(t *testing.T) {
	ts := newTestServer(t, "")
	deviceID, token := enroll(t, ts)
	ct := base64.StdEncoding.EncodeToString([]byte("key-v1"))
	call(t, ts, "POST", "/api/v1/keys", map[string]string{"ciphertext": ct}, token, nil)

	status, _ := call(t, ts, "POST", "/api/v1/keys/"+deviceID+"/rotate", nil, testAdmin, nil)
	if status != 200 {
		t.Fatalf("rotate: expected 200, got %d", status)
	}

	// Agent check-in sees the pending rotate request...
	status, body := call(t, ts, "POST", "/api/v1/devices/"+deviceID+"/checkin",
		map[string]string{"boot_class": "tpm_unlock_ok"}, token, nil)
	if status != 200 || body["rotate_requested"] != true {
		t.Fatalf("checkin: status %d, body %v", status, body)
	}

	// ...and a fresh escrow clears it and retires the old key.
	ct2 := base64.StdEncoding.EncodeToString([]byte("key-v2"))
	call(t, ts, "POST", "/api/v1/keys", map[string]string{"ciphertext": ct2}, token, nil)
	_, body = call(t, ts, "POST", "/api/v1/devices/"+deviceID+"/checkin",
		map[string]string{"boot_class": "tpm_unlock_ok"}, token, nil)
	if body["rotate_requested"] != false {
		t.Fatalf("rotate flag not cleared: %v", body)
	}
	_, body = call(t, ts, "POST", "/api/v1/keys/"+deviceID+"/reveal?reason=verify",
		nil, testAdmin, nil)
	if body["ciphertext"] != ct2 {
		t.Fatalf("expected new ciphertext, got %v", body)
	}
}

func TestDashboardRequiresAuthAndRenders(t *testing.T) {
	ts := newTestServer(t, "")
	resp, err := ts.Client().Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("WWW-Authenticate"), `Basic realm="luksmith"`) {
		t.Fatalf("missing WWW-Authenticate header: %q", resp.Header.Get("WWW-Authenticate"))
	}

	req, _ := http.NewRequest("GET", ts.URL+"/", nil)
	req.SetBasicAuth("admin", testAdmin)
	resp, err = ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(raw), "luksmith") {
		t.Fatalf("dashboard: status %d, body %q", resp.StatusCode, raw)
	}
}

func TestStaticUIAndTraversalRefusal(t *testing.T) {
	base := t.TempDir()
	uiDir := filepath.Join(base, "ui")
	if err := os.Mkdir(uiDir, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(uiDir, "index.html"), []byte("SPA-INDEX"), 0o644)
	os.WriteFile(filepath.Join(base, "secret.txt"), []byte("TOP-SECRET"), 0o644)

	ts := newTestServer(t, uiDir)

	// index.html served at / without auth (SPA handles login).
	resp, err := ts.Client().Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(raw), "SPA-INDEX") {
		t.Fatalf("index: status %d, body %q", resp.StatusCode, raw)
	}

	// Unknown non-API GET path falls back to index.html.
	resp, err = ts.Client().Get(ts.URL + "/devices/abc123")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(raw), "SPA-INDEX") {
		t.Fatalf("SPA fallback: status %d, body %q", resp.StatusCode, raw)
	}

	// Traversal never yields the file outside the UI dir — over the wire...
	resp, err = ts.Client().Get(ts.URL + "/../secret.txt")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.Contains(string(raw), "TOP-SECRET") {
		t.Fatal("path traversal leaked file contents")
	}

	// ...and against the handler directly with an encoded dot-dot path.
	store, err := OpenStore(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	h := newHandler(store, testAdmin, testEnroll, uiDir)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/..%2Fsecret.txt", nil))
	if strings.Contains(rec.Body.String(), "TOP-SECRET") {
		t.Fatal("encoded path traversal leaked file contents")
	}
}
