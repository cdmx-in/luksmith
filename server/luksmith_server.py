#!/usr/bin/env python3
"""luksmith-server — self-hosted escrow portal for luksmith agents.

Stores RSA-encrypted LUKS recovery keys (ciphertext only — the org private
key never touches this server), device inventory, and an append-only audit
log of every key retrieval, Crypt-Server style: a reason is mandatory.

Stdlib only: ThreadingHTTPServer + sqlite3.

Auth model:
  - X-Enroll-Secret header       -> device enrollment
  - Bearer <device_token>        -> agent check-ins / key escrow
  - Bearer <admin_token>         -> admin API; HTTP Basic (any user + admin
                                    token as password) for the dashboard
"""

import argparse
import base64
import hashlib
import hmac
import html
import json
import mimetypes
import os
import secrets
import sqlite3
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

SCHEMA = """
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
"""

ROLES = ("owner", "admin", "helpdesk", "auditor")
# Capability -> roles that hold it. "view" (any authenticated admin) is implicit.
PERMS = {
    "request": {"owner", "admin", "helpdesk"},
    "approve": {"owner", "admin"},
    "rotate": {"owner", "admin"},
    "manage": {"owner"},
}
ROLE_RANK = {"owner": 3, "admin": 2, "helpdesk": 1, "auditor": 0}
PBKDF2_ITERS = 600000
SESSION_TTL = 12 * 3600
DECRYPT_HINT = ("base64 -d ciphertext.b64 | openssl pkeyutl -decrypt "
                "-inkey org_private.pem -pkeyopt rsa_padding_mode:oaep "
                "-pkeyopt rsa_oaep_md:sha256")


def sha256(s):
    return hashlib.sha256(s.encode()).hexdigest()


def hash_password(pw, iters=PBKDF2_ITERS):
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, iters)
    return f"pbkdf2_sha256${iters}${salt.hex()}${dk.hex()}"


def verify_password(pw, stored):
    try:
        _algo, iters, salt_hex, hash_hex = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt_hex), int(iters))
    except (ValueError, AttributeError):
        return False
    return hmac.compare_digest(dk.hex(), hash_hex)


# One fixed hash so login runs pbkdf2 even for unknown users (timing/enumeration).
DUMMY_HASH = hash_password("luksmith-nobody")


def locked(method):
    def wrapper(self, *args, **kwargs):
        with self.lock:
            return method(self, *args, **kwargs)
    return wrapper


class Store:
    # ponytail: one connection + one lock serializes everything; move to a
    # connection pool if fleet size ever makes this a bottleneck.
    def __init__(self, path):
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    @locked
    def audit(self, actor, action, device_id=None, detail=None):
        self.db.execute(
            "INSERT INTO audit (ts, actor, action, device_id, detail) VALUES (?,?,?,?,?)",
            (int(time.time()), actor, action, device_id, detail))
        self.db.commit()

    @locked
    def enroll_device(self, hostname, machine_id):
        row = self.db.execute(
            "SELECT id FROM devices WHERE machine_id=?", (machine_id,)).fetchone()
        token = secrets.token_urlsafe(32)
        if row:
            device_id = row["id"]
            self.db.execute("UPDATE devices SET token_hash=?, hostname=? WHERE id=?",
                            (sha256(token), hostname, device_id))
        else:
            device_id = secrets.token_hex(8)
            self.db.execute(
                "INSERT INTO devices (id, hostname, machine_id, token_hash, created_at)"
                " VALUES (?,?,?,?,?)",
                (device_id, hostname, machine_id, sha256(token), int(time.time())))
        self.db.commit()
        return device_id, token

    @locked
    def device_by_token(self, token):
        h = sha256(token)
        for row in self.db.execute("SELECT * FROM devices"):
            if hmac.compare_digest(row["token_hash"], h):
                return row
        return None

    @locked
    def escrow(self, device_id, ciphertext):
        key_id = secrets.token_hex(8)
        now = int(time.time())
        self.db.execute(
            "UPDATE keys SET retired_at=? WHERE device_id=? AND retired_at IS NULL",
            (now, device_id))
        self.db.execute(
            "INSERT INTO keys (id, device_id, ciphertext, created_at) VALUES (?,?,?,?)",
            (key_id, device_id, ciphertext, now))
        self.db.execute(
            "UPDATE devices SET rotate_requested=0 WHERE id=?", (device_id,))
        self.db.commit()
        return key_id

    @locked
    def checkin(self, device_id, report):
        self.db.execute("UPDATE devices SET last_seen=?, last_report=? WHERE id=?",
                        (int(time.time()), json.dumps(report), device_id))
        self.db.commit()
        row = self.db.execute("SELECT rotate_requested FROM devices WHERE id=?",
                              (device_id,)).fetchone()
        return bool(row and row["rotate_requested"])

    @locked
    def devices(self):
        return self.db.execute(
            "SELECT d.*, (SELECT COUNT(*) FROM keys k WHERE k.device_id=d.id"
            " AND k.retired_at IS NULL) AS active_keys FROM devices d"
            " ORDER BY hostname").fetchall()

    @locked
    def active_key(self, device_id):
        return self.db.execute(
            "SELECT * FROM keys WHERE device_id=? AND retired_at IS NULL"
            " ORDER BY created_at DESC LIMIT 1", (device_id,)).fetchone()

    @locked
    def request_rotate(self, device_id):
        self.db.execute("UPDATE devices SET rotate_requested=1 WHERE id=?", (device_id,))
        self.db.commit()

    @locked
    def audit_log(self, limit=200):
        return self.db.execute(
            "SELECT * FROM audit ORDER BY seq DESC LIMIT ?", (limit,)).fetchall()

    # ------------------------------------------------------- admins / RBAC
    @locked
    def get_admin(self, username):
        return self.db.execute(
            "SELECT * FROM admins WHERE username=?", (username,)).fetchone()

    @locked
    def create_admin(self, username, password, role):
        self.db.execute(
            "INSERT INTO admins (id, username, password_hash, role, created_at)"
            " VALUES (?,?,?,?,?)",
            (secrets.token_hex(8), username, hash_password(password), role,
             int(time.time())))
        self.db.commit()

    @locked
    def list_admins(self):  # no password hashes
        return self.db.execute(
            "SELECT id, username, role, sso_subject, created_at FROM admins"
            " ORDER BY username").fetchall()

    @locked
    def delete_admin(self, username):
        row = self.db.execute(
            "SELECT role FROM admins WHERE username=?", (username,)).fetchone()
        if not row:
            return False, "not found"
        if row["role"] == "owner":
            n = self.db.execute(
                "SELECT COUNT(*) c FROM admins WHERE role='owner'").fetchone()["c"]
            if n <= 1:
                return False, "cannot remove the last owner"
        self.db.execute("DELETE FROM admins WHERE username=?", (username,))
        self.db.commit()
        return True, None

    @locked
    def upsert_sso(self, email, role):
        # ponytail: keyed on sso_subject; a username collision with a local
        # admin of the same name is left to raise — SSO subjects are emails.
        self.db.execute(
            "INSERT INTO admins (id, username, password_hash, role, sso_subject, created_at)"
            " VALUES (?,?,NULL,?,?,?)"
            " ON CONFLICT(sso_subject) DO UPDATE SET role=excluded.role",
            (secrets.token_hex(8), email, role, email, int(time.time())))
        self.db.commit()

    # ------------------------------------------------------- sessions
    @locked
    def create_session(self, username, role):
        token = secrets.token_urlsafe(32)
        expires = int(time.time()) + SESSION_TTL
        self.db.execute(
            "INSERT INTO sessions (token_hash, username, role, expires) VALUES (?,?,?,?)",
            (sha256(token), username, role, expires))
        self.db.commit()
        return token, expires

    @locked
    def session(self, token):
        row = self.db.execute(
            "SELECT * FROM sessions WHERE token_hash=?", (sha256(token),)).fetchone()
        return row if row and row["expires"] > int(time.time()) else None

    @locked
    def delete_session(self, token):
        self.db.execute("DELETE FROM sessions WHERE token_hash=?", (sha256(token),))
        self.db.commit()

    # ------------------------------------------------------- reveal requests
    @locked
    def create_reveal_request(self, device_id, requester, reason):
        rid = secrets.token_hex(8)
        self.db.execute(
            "INSERT INTO reveal_requests (id, device_id, requester, reason, status, created_at)"
            " VALUES (?,?,?,?,'pending',?)",
            (rid, device_id, requester, reason, int(time.time())))
        self.db.commit()
        return rid

    @locked
    def get_reveal_request(self, rid):
        return self.db.execute(
            "SELECT * FROM reveal_requests WHERE id=?", (rid,)).fetchone()

    @locked
    def list_reveal_requests(self, status=None):
        if status and status != "all":
            return self.db.execute(
                "SELECT * FROM reveal_requests WHERE status=? ORDER BY created_at DESC",
                (status,)).fetchall()
        return self.db.execute(
            "SELECT * FROM reveal_requests ORDER BY created_at DESC").fetchall()

    @locked
    def decide_reveal_request(self, rid, approver, status):
        cur = self.db.execute(
            "UPDATE reveal_requests SET status=?, approver=?, decided_at=?"
            " WHERE id=? AND status='pending'",
            (status, approver, int(time.time()), rid))
        self.db.commit()
        return cur.rowcount > 0

    @locked
    def consume_reveal_request(self, rid, key_id):
        cur = self.db.execute(
            "UPDATE reveal_requests SET status='consumed', key_id=?"
            " WHERE id=? AND status='approved'", (key_id, rid))
        self.db.commit()
        return cur.rowcount > 0


DASHBOARD = """<!doctype html><meta charset="utf-8">
<title>luksmith</title>
<style>
 body{{font:15px/1.5 system-ui;margin:2rem auto;max-width:60rem;padding:0 1rem;color:#1a1a2e}}
 table{{border-collapse:collapse;width:100%;margin:1rem 0}}
 th,td{{text-align:left;padding:.4rem .6rem;border-bottom:1px solid #ddd}}
 .ok{{color:#0a7d33}}.warn{{color:#b3261e}}
 code{{background:#f1f1f4;padding:.1rem .3rem;border-radius:4px}}
 form{{display:inline}} input[type=text]{{width:14rem}}
</style>
<h1>&#128273; luksmith</h1>
<p>{ndev} device(s) enrolled. Every key retrieval below is audited.</p>
<table><tr><th>Host</th><th>Device ID</th><th>Last seen</th><th>Boot</th>
<th>Escrow</th><th>Recovery key</th></tr>{rows}</table>
<h2>Recent audit log</h2>
<table><tr><th>When</th><th>Actor</th><th>Action</th><th>Device</th><th>Detail</th></tr>{audit}</table>
"""

ROW = """<tr><td>{host}</td><td><code>{id}</code></td><td>{seen}</td>
<td class="{bootcls}">{boot}</td><td class="{esccls}">{escrow}</td>
<td><form method="post" action="/keys/{id}/reveal">
<input type="text" name="reason" placeholder="reason (required, audited)" required>
<button>Reveal ciphertext</button></form></td></tr>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "luksmith"
    store = None
    admin_token = None
    enroll_secret = None
    ui_dir = None  # built React UI (ui/dist); None -> inline dashboard fallback
    require_approval = False
    trust_proxy = False
    proxy_secret = None
    sso_group_map = {"luksmith-owners": "owner", "luksmith-admins": "admin",
                     "luksmith-auditors": "auditor"}

    # ------------------------------------------------------------- helpers
    def send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else \
            (body if isinstance(body, str) else json.dumps(body)).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def body_json(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length > 1_000_000:
            return None
        try:
            return json.loads(self.rfile.read(length).decode() or "{}")
        except ValueError:
            return None

    def bearer(self):
        auth = self.headers.get("Authorization", "")
        return auth[7:] if auth.startswith("Bearer ") else None

    def map_role(self, groups_header):
        matched = [self.sso_group_map[g.strip()] for g in groups_header.split(",")
                   if g.strip() in self.sso_group_map]
        return max(matched, key=ROLE_RANK.get) if matched else "helpdesk"

    def identity(self):
        """Resolve the caller per the contract's auth order; None -> 401."""
        auth = self.headers.get("Authorization", "")
        tok = self.bearer()
        if tok and hmac.compare_digest(tok, self.admin_token):
            return {"username": "root-token", "role": "owner", "sso": False}
        if tok:
            sess = self.store.session(tok)
            if sess:
                return {"username": sess["username"], "role": sess["role"], "sso": False}
        if auth.startswith("Basic "):
            try:
                _, _, pw = base64.b64decode(auth[6:]).decode().partition(":")
            except Exception:
                pw = ""
            if pw and hmac.compare_digest(pw, self.admin_token):
                return {"username": "root-token", "role": "owner", "sso": False}
        if self.trust_proxy and self.proxy_secret:
            sent = self.headers.get("X-Proxy-Secret", "")
            if hmac.compare_digest(sent, self.proxy_secret):
                email = self.headers.get("X-Auth-Request-Email", "").strip()
                if email:
                    role = self.map_role(self.headers.get("X-Auth-Request-Groups", ""))
                    self.store.upsert_sso(email, role)
                    return {"username": email, "role": role, "sso": True}
        return None

    def need_admin(self):
        ident = self.identity()
        if ident:
            return ident
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="luksmith"')
        self.end_headers()
        return None

    def require(self, cap):
        """need_admin plus a capability gate (cap=None -> any authenticated)."""
        ident = self.need_admin()
        if not ident:
            return None
        if cap and ident["role"] not in PERMS[cap]:
            self.send(403, {"error": "forbidden: role %s lacks %s" % (ident["role"], cap)})
            return None
        return ident

    def agent_device(self):
        tok = self.bearer()
        return self.store.device_by_token(tok) if tok else None

    def log_message(self, fmt, *args):  # quiet default request logging
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    # ------------------------------------------------------------- routes
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/healthz":
            return self.send(200, {"ok": True})
        if path == "/":
            # Static SPA (if built) is public: it is useless without an admin
            # token and the API stays Bearer-protected. Inline fallback keeps
            # its Basic-auth gate.
            if self.serve_ui("/index.html"):
                return
            if not self.need_admin():
                return
            return self.dashboard()
        if path == "/api/v1/devices":
            if not self.need_admin():
                return
            devs = [{k: d[k] for k in ("id", "hostname", "last_seen", "rotate_requested")}
                    | {"active_keys": d["active_keys"],
                       "last_report": json.loads(d["last_report"] or "null")}
                    for d in self.store.devices()]
            return self.send(200, {"devices": devs})
        if path == "/api/v1/audit":
            if not self.need_admin():
                return
            return self.send(200, {"audit": [dict(r) for r in self.store.audit_log()]})
        if path == "/api/v1/me":
            ident = self.need_admin()
            if not ident:
                return
            return self.send(200, ident)
        if path == "/api/v1/admins":
            if not self.require("manage"):
                return
            return self.send(200, {"admins": [dict(r) for r in self.store.list_admins()]})
        if path == "/api/v1/reveal-requests":
            if not self.require(None):
                return
            status = parse_qs(urlparse(self.path).query).get("status", ["all"])[0]
            return self.send(200, {"requests":
                                   [dict(r) for r in self.store.list_reveal_requests(status)]})
        if self.serve_ui(path):
            return
        self.send(404, {"error": "not found"})

    def serve_ui(self, path):
        """Serve a static file from ui_dir; False if absent or path escapes it."""
        if not self.ui_dir:
            return False
        root = os.path.realpath(self.ui_dir)
        full = os.path.realpath(os.path.join(root, unquote(path).lstrip("/")))
        if full != root and not full.startswith(root + os.sep):
            return False  # path traversal attempt -> 404
        if not os.path.isfile(full):
            return False
        ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
        with open(full, "rb") as f:
            self.send(200, f.read(), ctype)
        return True

    def do_POST(self):
        path = urlparse(self.path).path

        if path == "/api/v1/devices/enroll":
            sent = self.headers.get("X-Enroll-Secret", "")
            if not hmac.compare_digest(sent, self.enroll_secret):
                return self.send(403, {"error": "bad enroll secret"})
            body = self.body_json() or {}
            if not body.get("hostname") or not body.get("machine_id"):
                return self.send(400, {"error": "hostname and machine_id required"})
            device_id, token = self.store.enroll_device(
                str(body["hostname"])[:255], str(body["machine_id"])[:64])
            self.store.audit("agent", "device_enrolled", device_id)
            return self.send(200, {"device_id": device_id, "device_token": token})

        if path == "/api/v1/keys":
            dev = self.agent_device()
            if not dev:
                return self.send(401, {"error": "bad device token"})
            body = self.body_json() or {}
            ct = body.get("ciphertext", "")
            try:
                base64.b64decode(ct, validate=True)
            except Exception:
                return self.send(400, {"error": "ciphertext must be base64"})
            key_id = self.store.escrow(dev["id"], ct)
            self.store.audit("agent", "key_escrowed", dev["id"], f"key_id={key_id}")
            return self.send(200, {"key_id": key_id})

        if path.startswith("/api/v1/devices/") and path.endswith("/checkin"):
            dev = self.agent_device()
            if not dev:
                return self.send(401, {"error": "bad device token"})
            rotate = self.store.checkin(dev["id"], self.body_json() or {})
            return self.send(200, {"rotate_requested": rotate})

        if path == "/api/v1/auth/login":
            body = self.body_json() or {}
            username = str(body.get("username", ""))
            password = str(body.get("password", ""))
            row = self.store.get_admin(username)
            stored = row["password_hash"] if row and row["password_hash"] else DUMMY_HASH
            if not verify_password(password, stored) or not (row and row["password_hash"]):
                return self.send(401, {"error": "bad credentials"})
            token, expires = self.store.create_session(row["username"], row["role"])
            return self.send(200, {"token": token, "username": row["username"],
                                   "role": row["role"], "expires": expires})

        if path == "/api/v1/auth/logout":
            tok = self.bearer()
            if tok:
                self.store.delete_session(tok)
            return self.send(200, {"ok": True})

        if path == "/api/v1/admins":
            ident = self.require("manage")
            if not ident:
                return
            body = self.body_json() or {}
            username = str(body.get("username", "")).strip()
            password = str(body.get("password", ""))
            role = str(body.get("role", ""))
            if not username or not password or role not in ROLES:
                return self.send(400, {"error": "username, password, and valid role required"})
            try:
                self.store.create_admin(username, password, role)
            except sqlite3.IntegrityError:
                return self.send(409, {"error": "username already exists"})
            self.store.audit(ident["username"], "admin_created", None,
                             "username=%s role=%s" % (username, role))
            return self.send(200, {"username": username, "role": role})

        if path.startswith("/api/v1/reveal-requests/"):
            parts = path.split("/")
            if len(parts) == 6:
                return self.reveal_request_action(parts[4], parts[5])

        if path.startswith("/api/v1/keys/") and path.endswith("/rotate"):
            ident = self.require("rotate")
            if not ident:
                return
            device_id = path.split("/")[4]
            self.store.request_rotate(device_id)
            self.store.audit(ident["username"], "rotate_requested", device_id)
            return self.send(200, {"rotate_requested": True})

        if path.endswith("/reveal") and \
                (path.startswith("/api/v1/keys/") or path.startswith("/keys/")):
            return self.reveal(path)

        self.send(404, {"error": "not found"})

    def reveal(self, path):
        """Key retrieval — reason mandatory, always audited.

        Needs the "request" capability. With --require-approval the JSON API
        path creates a pending request (202) instead of returning ciphertext;
        the dashboard (/keys/…) path stays immediate for the basic-auth owner.
        """
        ident = self.require("request")
        if not ident:
            return
        device_id = path.split("/")[2] if path.startswith("/keys/") else \
            path.split("/")[4]
        qs = parse_qs(urlparse(self.path).query)
        length = int(self.headers.get("Content-Length") or 0)
        form = parse_qs(self.rfile.read(length).decode()) if length else {}
        reason = (qs.get("reason") or form.get("reason") or [""])[0].strip()
        if not reason:
            return self.send(400, {"error": "a reason is required and audited"})
        if self.require_approval and path.startswith("/api/v1/keys/"):
            rid = self.store.create_reveal_request(device_id, ident["username"], reason)
            self.store.audit(ident["username"], "reveal_requested", device_id,
                             f"reason={reason[:500]}")
            return self.send(202, {"request_id": rid, "status": "pending"})
        row = self.store.active_key(device_id)
        self.store.audit(ident["username"], "key_revealed" if row else "key_reveal_miss",
                         device_id, f"reason={reason[:500]}")
        if not row:
            return self.send(404, {"error": "no active key for device"})
        payload = {"key_id": row["id"], "ciphertext": row["ciphertext"],
                   "created_at": row["created_at"], "decrypt_hint": DECRYPT_HINT}
        if path.startswith("/keys/"):  # dashboard form -> human-readable page
            body = ("<!doctype html><meta charset='utf-8'><body style='font:15px system-ui;"
                    "margin:2rem'><h2>Escrowed ciphertext for %s</h2><p>Retrieval audited "
                    "(reason: %s).</p><textarea rows=6 cols=80 readonly>%s</textarea>"
                    "<p>Decrypt on an admin workstation:</p><pre>%s</pre>"
                    "<p><a href='/'>&larr; back</a></p>"
                    % (html.escape(device_id), html.escape(reason),
                       html.escape(row["ciphertext"]), html.escape(payload["decrypt_hint"])))
            return self.send(200, body, "text/html; charset=utf-8")
        return self.send(200, payload)

    def reveal_request_action(self, rid, action):
        ident = self.need_admin()
        if not ident:
            return
        req = self.store.get_reveal_request(rid)
        if not req:
            return self.send(404, {"error": "no such request"})
        if action in ("approve", "deny"):
            if ident["role"] not in PERMS["approve"]:
                return self.send(403, {"error": "forbidden: role %s lacks approve"
                                       % ident["role"]})
            if req["requester"] == ident["username"]:
                return self.send(403, {"error": "cannot approve your own request"})
            status = "approved" if action == "approve" else "denied"
            if not self.store.decide_reveal_request(rid, ident["username"], status):
                return self.send(409, {"error": "request is not pending"})
            self.store.audit(ident["username"], "reveal_" + status, req["device_id"],
                             "request=%s requester=%s" % (rid, req["requester"]))
            return self.send(200, {"id": rid, "status": status})
        if action == "reveal":
            if req["requester"] != ident["username"]:
                return self.send(403, {"error": "only the requester may reveal"})
            if req["status"] != "approved":
                return self.send(409, {"error": "request is not approved"})
            row = self.store.active_key(req["device_id"])
            if not row:
                return self.send(404, {"error": "no active key for device"})
            if not self.store.consume_reveal_request(rid, row["id"]):
                return self.send(409, {"error": "request is not approved"})
            self.store.audit(ident["username"], "key_revealed", req["device_id"],
                             "request=%s requester=%s approver=%s"
                             % (rid, req["requester"], req["approver"]))
            return self.send(200, {"key_id": row["id"], "ciphertext": row["ciphertext"],
                                   "created_at": row["created_at"],
                                   "decrypt_hint": DECRYPT_HINT})
        return self.send(404, {"error": "not found"})

    def do_DELETE(self):
        path = urlparse(self.path).path
        if path.startswith("/api/v1/admins/"):
            ident = self.require("manage")
            if not ident:
                return
            username = unquote(path.split("/")[4])
            if username == "root-token":
                return self.send(403, {"error": "cannot remove the built-in root-token"})
            ok, err = self.store.delete_admin(username)
            if not ok:
                return self.send(404 if err == "not found" else 409, {"error": err})
            self.store.audit(ident["username"], "admin_deleted", None, "username=%s" % username)
            return self.send(200, {"deleted": username})
        self.send(404, {"error": "not found"})

    def dashboard(self):
        rows = []
        for d in self.store.devices():
            report = json.loads(d["last_report"] or "{}")
            boot = report.get("boot_class") or "—"
            seen = time.strftime("%Y-%m-%d %H:%M", time.gmtime(d["last_seen"])) \
                if d["last_seen"] else "never"
            rows.append(ROW.format(
                host=html.escape(d["hostname"]), id=html.escape(d["id"]), seen=seen,
                boot=html.escape(boot),
                bootcls="ok" if boot == "tpm_unlock_ok" else "warn",
                escrow="escrowed" if d["active_keys"] else "MISSING",
                esccls="ok" if d["active_keys"] else "warn"))
        audit = "".join(
            "<tr><td>%s</td><td>%s</td><td>%s</td><td><code>%s</code></td><td>%s</td></tr>"
            % (time.strftime("%Y-%m-%d %H:%M", time.gmtime(a["ts"])),
               html.escape(a["actor"]), html.escape(a["action"]),
               html.escape(a["device_id"] or ""), html.escape(a["detail"] or ""))
            for a in self.store.audit_log(50))
        self.send(200, DASHBOARD.format(ndev=len(rows), rows="".join(rows), audit=audit),
                  "text/html; charset=utf-8")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="luksmith-server", description=__doc__)
    ap.add_argument("--db", default="luksmith.db")
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--admin-token", default=os.environ.get("LUKSMITH_ADMIN_TOKEN"),
                    help="admin bearer token (or env LUKSMITH_ADMIN_TOKEN)")
    ap.add_argument("--enroll-secret", default=os.environ.get("LUKSMITH_ENROLL_SECRET"),
                    help="shared device-enrollment secret (or env LUKSMITH_ENROLL_SECRET)")
    ap.add_argument("--tls-cert", help="TLS certificate (PEM); omit only behind a reverse proxy")
    ap.add_argument("--tls-key", help="TLS private key (PEM)")
    ap.add_argument("--ui-dir",
                    help="built UI assets to serve (default: ui/dist next to this "
                         "script, if present; else the inline dashboard)")
    ap.add_argument("--require-approval", action="store_true",
                    default=os.environ.get("LUKSMITH_REQUIRE_APPROVAL") in ("1", "true", "yes"),
                    help="two-person reveal: requests need a different admin's approval")
    ap.add_argument("--trust-proxy", action="store_true",
                    help="honour X-Auth-Request-* headers when X-Proxy-Secret matches")
    ap.add_argument("--proxy-shared-secret", default=os.environ.get("LUKSMITH_PROXY_SECRET"),
                    help="shared secret a trusted reverse proxy sends in X-Proxy-Secret")
    ap.add_argument("--sso-group-map", default=os.environ.get("LUKSMITH_SSO_GROUP_MAP"),
                    help="group:role,... overrides added to the built-in defaults")
    args = ap.parse_args(argv)

    if not args.admin_token or not args.enroll_secret:
        ap.error("--admin-token and --enroll-secret are required (flags or env)")

    Handler.store = Store(args.db)
    Handler.admin_token = args.admin_token
    Handler.enroll_secret = args.enroll_secret
    ui_dir = args.ui_dir or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "ui", "dist")
    Handler.ui_dir = ui_dir if os.path.isdir(ui_dir) else None
    Handler.require_approval = args.require_approval
    Handler.trust_proxy = args.trust_proxy
    Handler.proxy_secret = args.proxy_shared_secret
    if args.sso_group_map:
        gmap = dict(Handler.sso_group_map)
        for pair in args.sso_group_map.split(","):
            group, _, role = pair.partition(":")
            if group.strip() and role.strip() in ROLES:
                gmap[group.strip()] = role.strip()
        Handler.sso_group_map = gmap

    httpd = ThreadingHTTPServer((args.bind, args.port), Handler)
    scheme = "http"
    if args.tls_cert and args.tls_key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(args.tls_cert, args.tls_key)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"
    elif args.bind not in ("127.0.0.1", "::1", "localhost"):
        print("WARNING: serving plain HTTP on a non-loopback address; "
              "use --tls-cert/--tls-key or a TLS reverse proxy.", file=sys.stderr)
    print(f"luksmith-server on {scheme}://{args.bind}:{args.port} (db: {args.db})")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
