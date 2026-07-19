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
	return newTestServerCfg(t, uiDir, adminConfig{})
}

func newTestServerCfg(t *testing.T, uiDir string, cfg adminConfig) *httptest.Server {
	t.Helper()
	store, err := OpenStore(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(newHandler(store, testAdmin, testEnroll, uiDir, cfg))
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
	h := newHandler(store, testAdmin, testEnroll, uiDir, adminConfig{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/..%2Fsecret.txt", nil))
	if strings.Contains(rec.Body.String(), "TOP-SECRET") {
		t.Fatal("encoded path traversal leaked file contents")
	}
}

// ---------------------------------------------------- admin RBAC / SSO / 2-person

func makeAdmin(t *testing.T, ts *httptest.Server, username, password, role string) {
	t.Helper()
	status, body := call(t, ts, "POST", "/api/v1/admins",
		map[string]string{"username": username, "password": password, "role": role}, testAdmin, nil)
	if status != 200 {
		t.Fatalf("create admin %s: status %d, body %v", username, status, body)
	}
}

func loginAs(t *testing.T, ts *httptest.Server, username, password string) string {
	t.Helper()
	status, body := call(t, ts, "POST", "/api/v1/auth/login",
		map[string]string{"username": username, "password": password}, "", nil)
	if status != 200 {
		t.Fatalf("login %s: status %d, body %v", username, status, body)
	}
	return body["token"].(string)
}

func TestLoginSessionAndMe(t *testing.T) {
	ts := newTestServer(t, "")
	makeAdmin(t, ts, "alice", "pw-alice-123", roleAdmin)

	// Wrong password is rejected.
	if status, _ := call(t, ts, "POST", "/api/v1/auth/login",
		map[string]string{"username": "alice", "password": "nope"}, "", nil); status != 401 {
		t.Fatalf("bad login: expected 401, got %d", status)
	}
	// Unknown user is rejected too.
	if status, _ := call(t, ts, "POST", "/api/v1/auth/login",
		map[string]string{"username": "ghost", "password": "x"}, "", nil); status != 401 {
		t.Fatalf("unknown-user login: expected 401, got %d", status)
	}

	tok := loginAs(t, ts, "alice", "pw-alice-123")
	status, body := call(t, ts, "GET", "/api/v1/me", nil, tok, nil)
	if status != 200 || body["username"] != "alice" || body["role"] != "admin" || body["sso"] != false {
		t.Fatalf("/me: status %d, body %v", status, body)
	}

	// Logout kills the session.
	if status, _ := call(t, ts, "POST", "/api/v1/auth/logout", nil, tok, nil); status != 200 {
		t.Fatalf("logout: status %d", status)
	}
	if status, _ := call(t, ts, "GET", "/api/v1/me", nil, tok, nil); status != 401 {
		t.Fatalf("/me after logout: expected 401, got %d", status)
	}

	// The master token authenticates as owner/root-token.
	_, body = call(t, ts, "GET", "/api/v1/me", nil, testAdmin, nil)
	if body["username"] != "root-token" || body["role"] != "owner" {
		t.Fatalf("master token /me: %v", body)
	}
}

func TestRoleEnforcement(t *testing.T) {
	ts := newTestServer(t, "")
	deviceID, dtoken := enroll(t, ts)
	ct := base64.StdEncoding.EncodeToString([]byte("blob"))
	call(t, ts, "POST", "/api/v1/keys", map[string]string{"ciphertext": ct}, dtoken, nil)

	makeAdmin(t, ts, "helpdesk1", "pw-help-1234", roleHelpdesk)
	makeAdmin(t, ts, "auditor1", "pw-audit-1234", roleAuditor)
	hTok := loginAs(t, ts, "helpdesk1", "pw-help-1234")
	aTok := loginAs(t, ts, "auditor1", "pw-audit-1234")

	// Auditor can view devices...
	if status, _ := call(t, ts, "GET", "/api/v1/devices", nil, aTok, nil); status != 200 {
		t.Fatalf("auditor view devices: %d", status)
	}
	// ...but may not request a reveal.
	if status, _ := call(t, ts, "POST", "/api/v1/keys/"+deviceID+"/reveal?reason=x", nil, aTok, nil); status != 403 {
		t.Fatalf("auditor reveal: expected 403, got %d", status)
	}
	// Helpdesk can reveal directly (approval off)...
	if status, _ := call(t, ts, "POST", "/api/v1/keys/"+deviceID+"/reveal?reason=ticket", nil, hTok, nil); status != 200 {
		t.Fatalf("helpdesk reveal: expected 200, got %d", status)
	}
	// ...but cannot rotate or manage admins.
	if status, _ := call(t, ts, "POST", "/api/v1/keys/"+deviceID+"/rotate", nil, hTok, nil); status != 403 {
		t.Fatalf("helpdesk rotate: expected 403, got %d", status)
	}
	if status, _ := call(t, ts, "GET", "/api/v1/admins", nil, hTok, nil); status != 403 {
		t.Fatalf("helpdesk list admins: expected 403, got %d", status)
	}

	// Approval OFF creates no reveal requests.
	_, lb := call(t, ts, "GET", "/api/v1/reveal-requests?status=all", nil, testAdmin, nil)
	if n := len(lb["requests"].([]any)); n != 0 {
		t.Fatalf("approval-off should not file requests, got %d", n)
	}
}

func TestAdminCRUDGating(t *testing.T) {
	ts := newTestServer(t, "")
	makeAdmin(t, ts, "bob", "pw-bob-12345", roleAdmin)

	// A non-owner cannot manage admins.
	bobTok := loginAs(t, ts, "bob", "pw-bob-12345")
	if status, _ := call(t, ts, "POST", "/api/v1/admins",
		map[string]string{"username": "x", "password": "pwpwpwpw", "role": "admin"}, bobTok, nil); status != 403 {
		t.Fatalf("create by non-owner: expected 403, got %d", status)
	}

	// Duplicate username -> 409; bad role -> 400.
	if status, _ := call(t, ts, "POST", "/api/v1/admins",
		map[string]string{"username": "bob", "password": "pwpwpwpw", "role": "admin"}, testAdmin, nil); status != 409 {
		t.Fatalf("duplicate: expected 409, got %d", status)
	}
	if status, _ := call(t, ts, "POST", "/api/v1/admins",
		map[string]string{"username": "z", "password": "pwpwpwpw", "role": "superuser"}, testAdmin, nil); status != 400 {
		t.Fatalf("bad role: expected 400, got %d", status)
	}

	// Listing never leaks password hashes.
	_, lb := call(t, ts, "GET", "/api/v1/admins", nil, testAdmin, nil)
	for _, a := range lb["admins"].([]any) {
		if _, leaked := a.(map[string]any)["password_hash"]; leaked {
			t.Fatalf("admins listing leaked password_hash: %v", a)
		}
	}

	// root-token can never be deleted.
	if status, _ := call(t, ts, "DELETE", "/api/v1/admins/root-token", nil, testAdmin, nil); status != 403 {
		t.Fatalf("delete root-token: expected 403, got %d", status)
	}

	// Last-owner guard: two owner rows, delete one ok, second blocked.
	makeAdmin(t, ts, "owner2", "pw-owner2-12", roleOwner)
	makeAdmin(t, ts, "owner3", "pw-owner3-12", roleOwner)
	if status, _ := call(t, ts, "DELETE", "/api/v1/admins/owner2", nil, testAdmin, nil); status != 200 {
		t.Fatalf("delete owner2: expected 200, got %d", status)
	}
	if status, _ := call(t, ts, "DELETE", "/api/v1/admins/owner3", nil, testAdmin, nil); status != 409 {
		t.Fatalf("delete last owner: expected 409, got %d", status)
	}

	// Deleting a normal admin works; a missing one is 404.
	if status, _ := call(t, ts, "DELETE", "/api/v1/admins/bob", nil, testAdmin, nil); status != 200 {
		t.Fatalf("delete bob: expected 200, got %d", status)
	}
	if status, _ := call(t, ts, "DELETE", "/api/v1/admins/ghost", nil, testAdmin, nil); status != 404 {
		t.Fatalf("delete ghost: expected 404, got %d", status)
	}
}

func TestProxyHeaderAuth(t *testing.T) {
	ts := newTestServerCfg(t, "", adminConfig{trustProxy: true, proxySecret: "proxy-secret-xyz"})
	hdr := func(secret, email, groups string) map[string]string {
		return map[string]string{"X-Proxy-Secret": secret,
			"X-Auth-Request-Email": email, "X-Auth-Request-Groups": groups}
	}

	// Proxy headers are ignored without the shared secret.
	if status, _ := call(t, ts, "GET", "/api/v1/me", nil, "",
		map[string]string{"X-Auth-Request-Email": "e@x.io", "X-Auth-Request-Groups": "luksmith-admins"}); status != 401 {
		t.Fatalf("proxy without secret: expected 401, got %d", status)
	}
	// Wrong secret -> ignored.
	if status, _ := call(t, ts, "GET", "/api/v1/me", nil, "", hdr("wrong", "e@x.io", "luksmith-admins")); status != 401 {
		t.Fatalf("proxy wrong secret: expected 401, got %d", status)
	}
	// Correct secret + owners group -> owner, sso true, username = email.
	status, body := call(t, ts, "GET", "/api/v1/me", nil, "",
		hdr("proxy-secret-xyz", "boss@x.io", "luksmith-owners,other"))
	if status != 200 || body["role"] != "owner" || body["sso"] != true || body["username"] != "boss@x.io" {
		t.Fatalf("proxy owner: status %d, body %v", status, body)
	}
	// Unknown group -> helpdesk default.
	if _, body := call(t, ts, "GET", "/api/v1/me", nil, "",
		hdr("proxy-secret-xyz", "h@x.io", "random-team")); body["role"] != "helpdesk" {
		t.Fatalf("proxy default role: %v", body)
	}

	// Custom --sso-group-map entry wins.
	ts2 := newTestServerCfg(t, "", adminConfig{trustProxy: true, proxySecret: "s", ssoGroupMap: "eng-leads:owner"})
	if _, body := call(t, ts2, "GET", "/api/v1/me", nil, "",
		hdr2("s", "lead@x.io", "eng-leads")); body["role"] != "owner" {
		t.Fatalf("custom group map: %v", body)
	}
}

func hdr2(secret, email, groups string) map[string]string {
	return map[string]string{"X-Proxy-Secret": secret,
		"X-Auth-Request-Email": email, "X-Auth-Request-Groups": groups}
}

func TestTwoPersonRevealFlow(t *testing.T) {
	ts := newTestServerCfg(t, "", adminConfig{requireApproval: true})
	deviceID, dtoken := enroll(t, ts)
	ct := base64.StdEncoding.EncodeToString([]byte("secret-key-blob"))
	call(t, ts, "POST", "/api/v1/keys", map[string]string{"ciphertext": ct}, dtoken, nil)

	makeAdmin(t, ts, "req", "pw-req-12345", roleHelpdesk)
	makeAdmin(t, ts, "appr", "pw-appr-1234", roleAdmin)
	reqTok := loginAs(t, ts, "req", "pw-req-12345")
	apprTok := loginAs(t, ts, "appr", "pw-appr-1234")

	// Reason is still mandatory.
	if status, _ := call(t, ts, "POST", "/api/v1/keys/"+deviceID+"/reveal", nil, reqTok, nil); status != 400 {
		t.Fatalf("no reason: expected 400, got %d", status)
	}
	// With approval ON, the reveal files a pending request (202), no ciphertext.
	status, body := call(t, ts, "POST", "/api/v1/keys/"+deviceID+"/reveal?reason=incident+7", nil, reqTok, nil)
	if status != 202 || body["status"] != "pending" || body["ciphertext"] != nil {
		t.Fatalf("request: status %d, body %v", status, body)
	}
	reqID := body["request_id"].(string)

	// Cannot reveal before approval.
	if status, _ := call(t, ts, "POST", "/api/v1/reveal-requests/"+reqID+"/reveal", nil, reqTok, nil); status != 409 {
		t.Fatalf("reveal before approve: expected 409, got %d", status)
	}
	// Self-approval is forbidden.
	if status, _ := call(t, ts, "POST", "/api/v1/reveal-requests/"+reqID+"/approve", nil, reqTok, nil); status != 403 {
		t.Fatalf("self-approve: expected 403, got %d", status)
	}
	// A different admin approves.
	if status, _ := call(t, ts, "POST", "/api/v1/reveal-requests/"+reqID+"/approve", nil, apprTok, nil); status != 200 {
		t.Fatalf("approve: expected 200, got %d", status)
	}
	// A non-requester cannot consume the approval.
	if status, _ := call(t, ts, "POST", "/api/v1/reveal-requests/"+reqID+"/reveal", nil, apprTok, nil); status != 403 {
		t.Fatalf("non-requester reveal: expected 403, got %d", status)
	}
	// The requester reveals -> ciphertext, request consumed.
	status, body = call(t, ts, "POST", "/api/v1/reveal-requests/"+reqID+"/reveal", nil, reqTok, nil)
	if status != 200 || body["ciphertext"] != ct {
		t.Fatalf("consume: status %d, body %v", status, body)
	}
	// Re-reveal is blocked.
	if status, _ := call(t, ts, "POST", "/api/v1/reveal-requests/"+reqID+"/reveal", nil, reqTok, nil); status != 409 {
		t.Fatalf("re-reveal: expected 409, got %d", status)
	}

	// Audit trail carries the three-step flow.
	_, ab := call(t, ts, "GET", "/api/v1/audit", nil, testAdmin, nil)
	seen := map[string]bool{}
	for _, a := range ab["audit"].([]any) {
		seen[a.(map[string]any)["action"].(string)] = true
	}
	for _, want := range []string{"reveal_requested", "reveal_approved", "key_revealed"} {
		if !seen[want] {
			t.Fatalf("missing audit action %q in %v", want, seen)
		}
	}

	// Deny path: a fresh request denied cannot be revealed.
	_, body = call(t, ts, "POST", "/api/v1/keys/"+deviceID+"/reveal?reason=incident+8", nil, reqTok, nil)
	reqID2 := body["request_id"].(string)
	if status, _ := call(t, ts, "POST", "/api/v1/reveal-requests/"+reqID2+"/deny", nil, apprTok, nil); status != 200 {
		t.Fatalf("deny: expected 200, got %d", status)
	}
	if status, _ := call(t, ts, "POST", "/api/v1/reveal-requests/"+reqID2+"/reveal", nil, reqTok, nil); status != 409 {
		t.Fatalf("reveal after deny: expected 409, got %d", status)
	}

	// Listing: none pending now, two total.
	if _, lb := call(t, ts, "GET", "/api/v1/reveal-requests?status=pending", nil, apprTok, nil); len(lb["requests"].([]any)) != 0 {
		t.Fatalf("pending list should be empty: %v", lb["requests"])
	}
	if _, lb := call(t, ts, "GET", "/api/v1/reveal-requests?status=all", nil, apprTok, nil); len(lb["requests"].([]any)) != 2 {
		t.Fatalf("all list expected 2: %v", lb["requests"])
	}

	// The dashboard path /keys/{id}/reveal stays immediate even with approval ON.
	status, body = call(t, ts, "POST", "/keys/"+deviceID+"/reveal?reason=dashboard", nil, testAdmin, nil)
	if status != 200 || body["ciphertext"] != ct {
		t.Fatalf("dashboard direct reveal under approval: status %d, body %v", status, body)
	}
}
