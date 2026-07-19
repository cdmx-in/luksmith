"""E2E tests for luksmith-server: real HTTP against a real sqlite store."""

import base64
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


if __name__ == "__main__":
    unittest.main()
