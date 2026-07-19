"""E2E tests for luksmith-server: real HTTP against a real sqlite store."""

import base64
import http.client
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "server"))
import luksmith_server  # noqa: E402

ADMIN = "test-admin-token"
ENROLL = "test-enroll-secret"


class ServerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        luksmith_server.Handler.store = luksmith_server.Store(
            os.path.join(cls.tmp, "test.db"))
        luksmith_server.Handler.admin_token = ADMIN
        luksmith_server.Handler.enroll_secret = ENROLL
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), luksmith_server.Handler)
        cls.base = "http://127.0.0.1:%d" % cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def call(self, method, path, payload=None, token=None, headers=None, raw=None):
        data = raw if raw is not None else (
            json.dumps(payload).encode() if payload is not None else None)
        req = urllib.request.Request(self.base + path, data=data, method=method)
        if raw is None and data is not None:
            req.add_header("Content-Type", "application/json")
        if token:
            req.add_header("Authorization", "Bearer " + token)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode() or "{}")
        except urllib.error.HTTPError as e:
            body = e.read().decode()
            try:
                return e.code, json.loads(body)
            except ValueError:
                return e.code, body

    def enroll(self):
        status, body = self.call("POST", "/api/v1/devices/enroll",
                                 {"hostname": "laptop-1", "machine_id": "m" * 32},
                                 headers={"X-Enroll-Secret": ENROLL})
        self.assertEqual(status, 200)
        return body["device_id"], body["device_token"]

    def test_health(self):
        self.assertEqual(self.call("GET", "/healthz")[0], 200)

    def test_enroll_requires_secret(self):
        status, _ = self.call("POST", "/api/v1/devices/enroll",
                              {"hostname": "x", "machine_id": "y"},
                              headers={"X-Enroll-Secret": "wrong"})
        self.assertEqual(status, 403)

    def test_full_escrow_and_reveal_flow(self):
        device_id, token = self.enroll()
        ct = base64.b64encode(b"rsa-ciphertext-blob").decode()

        status, body = self.call("POST", "/api/v1/keys",
                                 {"device_id": device_id, "ciphertext": ct}, token=token)
        self.assertEqual(status, 200)
        key_id = body["key_id"]

        # Reveal without a reason is refused.
        status, body = self.call("POST", f"/api/v1/keys/{device_id}/reveal",
                                 token=ADMIN, raw=b"")
        self.assertEqual(status, 400)

        # Reveal with a reason returns the ciphertext and is audited.
        status, body = self.call(
            "POST", f"/api/v1/keys/{device_id}/reveal?reason=helpdesk+ticket+42",
            token=ADMIN, raw=b"")
        self.assertEqual(status, 200)
        self.assertEqual(body["ciphertext"], ct)
        self.assertEqual(body["key_id"], key_id)

        status, body = self.call("GET", "/api/v1/audit", token=ADMIN)
        actions = [a["action"] for a in body["audit"]]
        self.assertIn("key_revealed", actions)
        revealed = next(a for a in body["audit"] if a["action"] == "key_revealed")
        self.assertIn("helpdesk ticket 42", revealed["detail"])

    def test_reveal_requires_admin(self):
        device_id, token = self.enroll()
        status, _ = self.call("POST", f"/api/v1/keys/{device_id}/reveal?reason=x",
                              token=token, raw=b"")  # device token is not admin
        self.assertEqual(status, 401)

    def test_escrow_requires_valid_device_token(self):
        status, _ = self.call("POST", "/api/v1/keys",
                              {"ciphertext": "aGk="}, token="bogus")
        self.assertEqual(status, 401)

    def test_ciphertext_must_be_base64(self):
        _, token = self.enroll()
        status, _ = self.call("POST", "/api/v1/keys",
                              {"ciphertext": "not base64!!"}, token=token)
        self.assertEqual(status, 400)

    def test_rotation_roundtrip(self):
        device_id, token = self.enroll()
        ct = base64.b64encode(b"key-v1").decode()
        self.call("POST", "/api/v1/keys", {"ciphertext": ct}, token=token)

        status, _ = self.call("POST", f"/api/v1/keys/{device_id}/rotate", token=ADMIN)
        self.assertEqual(status, 200)

        # Agent check-in sees the pending rotate request...
        status, body = self.call("POST", f"/api/v1/devices/{device_id}/checkin",
                                 {"boot_class": "tpm_unlock_ok"}, token=token)
        self.assertEqual(status, 200)
        self.assertTrue(body["rotate_requested"])

        # ...and a fresh escrow clears it and retires the old key.
        ct2 = base64.b64encode(b"key-v2").decode()
        self.call("POST", "/api/v1/keys", {"ciphertext": ct2}, token=token)
        status, body = self.call("POST", f"/api/v1/devices/{device_id}/checkin",
                                 {"boot_class": "tpm_unlock_ok"}, token=token)
        self.assertFalse(body["rotate_requested"])
        status, body = self.call(
            "POST", f"/api/v1/keys/{device_id}/reveal?reason=verify", token=ADMIN, raw=b"")
        self.assertEqual(body["ciphertext"], ct2)

    def test_dashboard_requires_auth_and_renders(self):
        status, _ = self.call("GET", "/")
        self.assertEqual(status, 401)
        req = urllib.request.Request(self.base + "/")
        req.add_header("Authorization", "Basic " +
                       base64.b64encode(b"admin:" + ADMIN.encode()).decode())
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("luksmith", resp.read().decode())

    def test_static_refuses_path_traversal(self):
        ui = os.path.join(self.tmp, "dist")
        os.makedirs(ui, exist_ok=True)
        with open(os.path.join(ui, "index.html"), "w") as f:
            f.write("<title>luksmith ui</title>")
        with open(os.path.join(self.tmp, "secret.txt"), "w") as f:
            f.write("org-private-material")
        luksmith_server.Handler.ui_dir = ui
        try:
            host, port = self.httpd.server_address
            # http.client sends the path verbatim (urllib would normalize ..)
            for evil in ("/../secret.txt", "/%2e%2e/secret.txt",
                         "/assets/../../secret.txt"):
                conn = http.client.HTTPConnection(host, port)
                conn.request("GET", evil)
                resp = conn.getresponse()
                body = resp.read()
                self.assertEqual(resp.status, 404, evil)
                self.assertNotIn(b"org-private-material", body)
                conn.close()
            # sanity: index.html is served from inside ui_dir
            with urllib.request.urlopen(self.base + "/") as resp:
                self.assertEqual(resp.status, 200)
                self.assertIn("luksmith ui", resp.read().decode())
        finally:
            luksmith_server.Handler.ui_dir = None


class RbacServerTest(unittest.TestCase):
    """Admin RBAC / SSO / two-person-reveal layer (docs/rbac-contract.md)."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        H = luksmith_server.Handler
        cls.store = luksmith_server.Store(os.path.join(cls.tmp, "rbac.db"))
        H.store = cls.store
        H.admin_token = ADMIN
        H.enroll_secret = ENROLL
        H.ui_dir = None
        H.require_approval = False
        H.trust_proxy = False
        H.proxy_secret = None
        cls.store.create_admin("admin1", "pw-admin", "admin")
        cls.store.create_admin("helpdesk1", "pw-helpdesk", "helpdesk")
        cls.store.create_admin("auditor1", "pw-auditor", "auditor")
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        cls.base = "http://127.0.0.1:%d" % cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        luksmith_server.Handler.require_approval = False

    # copy of ServerTest.call (self-contained; different server instance/config)
    def call(self, method, path, payload=None, token=None, headers=None, raw=None):
        data = raw if raw is not None else (
            json.dumps(payload).encode() if payload is not None else None)
        req = urllib.request.Request(self.base + path, data=data, method=method)
        if raw is None and data is not None:
            req.add_header("Content-Type", "application/json")
        if token:
            req.add_header("Authorization", "Bearer " + token)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode() or "{}")
        except urllib.error.HTTPError as e:
            body = e.read().decode()
            try:
                return e.code, json.loads(body)
            except ValueError:
                return e.code, body

    def login(self, username, password):
        return self.call("POST", "/api/v1/auth/login",
                         {"username": username, "password": password})

    def device_with_key(self):
        _, body = self.call("POST", "/api/v1/devices/enroll",
                            {"hostname": "h", "machine_id": os.urandom(16).hex()},
                            headers={"X-Enroll-Secret": ENROLL})
        did, dtok = body["device_id"], body["device_token"]
        ct = base64.b64encode(os.urandom(24)).decode()
        self.call("POST", "/api/v1/keys", {"ciphertext": ct}, token=dtok)
        return did, ct

    # --- login / session ---
    def test_login_success_and_session_bearer(self):
        status, body = self.login("admin1", "pw-admin")
        self.assertEqual(status, 200)
        self.assertEqual(body["role"], "admin")
        status, me = self.call("GET", "/api/v1/me", token=body["token"])
        self.assertEqual(status, 200)
        self.assertEqual(me["username"], "admin1")
        self.assertEqual(me["role"], "admin")
        self.assertFalse(me["sso"])

    def test_login_failure(self):
        self.assertEqual(self.login("admin1", "wrong")[0], 401)
        self.assertEqual(self.login("ghost", "whatever")[0], 401)

    def test_logout_kills_session(self):
        _, body = self.login("admin1", "pw-admin")
        token = body["token"]
        self.assertEqual(self.call("POST", "/api/v1/auth/logout", token=token, raw=b"")[0], 200)
        self.assertEqual(self.call("GET", "/api/v1/me", token=token)[0], 401)

    # --- role enforcement ---
    def test_auditor_cannot_request_reveal(self):
        did, _ = self.device_with_key()
        _, body = self.login("auditor1", "pw-auditor")
        status, _ = self.call("POST", f"/api/v1/keys/{did}/reveal?reason=x",
                              token=body["token"], raw=b"")
        self.assertEqual(status, 403)

    # --- admin CRUD (owner only) ---
    def test_admin_crud_owner_gated(self):
        _, hb = self.login("helpdesk1", "pw-helpdesk")
        self.assertEqual(self.call("GET", "/api/v1/admins", token=hb["token"])[0], 403)
        self.assertEqual(self.call("POST", "/api/v1/admins",
                         {"username": "temp1", "password": "pw", "role": "helpdesk"},
                         token=hb["token"])[0], 403)

        status, _ = self.call("POST", "/api/v1/admins",
                             {"username": "temp1", "password": "pw", "role": "helpdesk"},
                             token=ADMIN)
        self.assertEqual(status, 200)
        status, body = self.call("GET", "/api/v1/admins", token=ADMIN)
        self.assertIn("temp1", [a["username"] for a in body["admins"]])
        self.assertTrue(all("password_hash" not in a for a in body["admins"]))
        self.assertEqual(self.call("DELETE", "/api/v1/admins/temp1", token=ADMIN)[0], 200)

    def test_cannot_delete_last_owner_or_root_token(self):
        self.assertEqual(self.call("DELETE", "/api/v1/admins/root-token", token=ADMIN)[0], 403)
        self.call("POST", "/api/v1/admins",
                  {"username": "solo-owner", "password": "pw", "role": "owner"}, token=ADMIN)
        self.assertEqual(self.call("DELETE", "/api/v1/admins/solo-owner", token=ADMIN)[0], 409)

    # --- trusted proxy ---
    def test_trusted_proxy_auth(self):
        H = luksmith_server.Handler
        H.trust_proxy, H.proxy_secret = True, "proxy-secret-123"
        try:
            good = {"X-Proxy-Secret": "proxy-secret-123",
                    "X-Auth-Request-Email": "jane@corp.example",
                    "X-Auth-Request-Groups": "luksmith-admins"}
            status, me = self.call("GET", "/api/v1/me", headers=good)
            self.assertEqual(status, 200)
            self.assertEqual(me["username"], "jane@corp.example")
            self.assertEqual(me["role"], "admin")
            self.assertTrue(me["sso"])
            # wrong secret -> headers ignored -> 401
            bad = dict(good, **{"X-Proxy-Secret": "nope"})
            self.assertEqual(self.call("GET", "/api/v1/me", headers=bad)[0], 401)
            # no secret header at all -> 401
            nohdr = {"X-Auth-Request-Email": "jane@corp.example"}
            self.assertEqual(self.call("GET", "/api/v1/me", headers=nohdr)[0], 401)
        finally:
            H.trust_proxy, H.proxy_secret = False, None

    # --- reveal flows ---
    def test_two_person_reveal_flow(self):
        H = luksmith_server.Handler
        H.require_approval = True
        try:
            did, ct = self.device_with_key()
            _, ab = self.login("admin1", "pw-admin")
            atok = ab["token"]

            status, body = self.call("POST", f"/api/v1/keys/{did}/reveal?reason=ticket9",
                                     token=atok, raw=b"")
            self.assertEqual(status, 202)
            self.assertEqual(body["status"], "pending")
            rid = body["request_id"]

            # requester cannot approve their own request
            self.assertEqual(self.call("POST", f"/api/v1/reveal-requests/{rid}/approve",
                             token=atok, raw=b"")[0], 403)
            # helpdesk lacks the approve capability
            _, hb = self.login("helpdesk1", "pw-helpdesk")
            self.assertEqual(self.call("POST", f"/api/v1/reveal-requests/{rid}/approve",
                             token=hb["token"], raw=b"")[0], 403)
            # a different admin (owner via master token) approves
            status, body = self.call("POST", f"/api/v1/reveal-requests/{rid}/approve",
                                     token=ADMIN, raw=b"")
            self.assertEqual(status, 200)
            self.assertEqual(body["status"], "approved")
            # only the requester may reveal
            self.assertEqual(self.call("POST", f"/api/v1/reveal-requests/{rid}/reveal",
                             token=hb["token"], raw=b"")[0], 403)
            # requester reveals -> ciphertext, status consumed
            status, body = self.call("POST", f"/api/v1/reveal-requests/{rid}/reveal",
                                     token=atok, raw=b"")
            self.assertEqual(status, 200)
            self.assertEqual(body["ciphertext"], ct)
            self.assertEqual(self.store.get_reveal_request(rid)["status"], "consumed")
            # re-reveal is refused
            self.assertEqual(self.call("POST", f"/api/v1/reveal-requests/{rid}/reveal",
                             token=atok, raw=b"")[0], 409)
        finally:
            H.require_approval = False

    def test_approval_off_reveals_directly(self):
        self.assertFalse(luksmith_server.Handler.require_approval)
        did, ct = self.device_with_key()
        _, ab = self.login("admin1", "pw-admin")
        status, body = self.call("POST", f"/api/v1/keys/{did}/reveal?reason=direct",
                                 token=ab["token"], raw=b"")
        self.assertEqual(status, 200)
        self.assertEqual(body["ciphertext"], ct)


if __name__ == "__main__":
    unittest.main()
