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
"""


def sha256(s):
    return hashlib.sha256(s.encode()).hexdigest()


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

    def is_admin(self):
        tok = self.bearer()
        if tok and hmac.compare_digest(tok, self.admin_token):
            return True
        basic = self.headers.get("Authorization", "")
        if basic.startswith("Basic "):
            try:
                _, _, pw = base64.b64decode(basic[6:]).decode().partition(":")
                return hmac.compare_digest(pw, self.admin_token)
            except Exception:
                return False
        return False

    def need_admin(self):
        if self.is_admin():
            return True
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="luksmith"')
        self.end_headers()
        return False

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

        if path.startswith("/api/v1/keys/") and path.endswith("/rotate"):
            if not self.need_admin():
                return
            device_id = path.split("/")[4]
            self.store.request_rotate(device_id)
            self.store.audit("admin", "rotate_requested", device_id)
            return self.send(200, {"rotate_requested": True})

        if path.endswith("/reveal") and \
                (path.startswith("/api/v1/keys/") or path.startswith("/keys/")):
            return self.reveal(path)

        self.send(404, {"error": "not found"})

    def reveal(self, path):
        """Key retrieval — admin only, reason mandatory, always audited."""
        if not self.need_admin():
            return
        device_id = path.split("/")[2] if path.startswith("/keys/") else \
            path.split("/")[4]
        qs = parse_qs(urlparse(self.path).query)
        length = int(self.headers.get("Content-Length") or 0)
        form = parse_qs(self.rfile.read(length).decode()) if length else {}
        reason = (qs.get("reason") or form.get("reason") or [""])[0].strip()
        if not reason:
            return self.send(400, {"error": "a reason is required and audited"})
        row = self.store.active_key(device_id)
        self.store.audit("admin", "key_revealed" if row else "key_reveal_miss",
                         device_id, f"reason={reason[:500]}")
        if not row:
            return self.send(404, {"error": "no active key for device"})
        payload = {"key_id": row["id"], "ciphertext": row["ciphertext"],
                   "created_at": row["created_at"],
                   "decrypt_hint": "base64 -d ciphertext.b64 | openssl pkeyutl -decrypt "
                                   "-inkey org_private.pem -pkeyopt rsa_padding_mode:oaep "
                                   "-pkeyopt rsa_oaep_md:sha256"}
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
    args = ap.parse_args(argv)

    if not args.admin_token or not args.enroll_secret:
        ap.error("--admin-token and --enroll-secret are required (flags or env)")

    Handler.store = Store(args.db)
    Handler.admin_token = args.admin_token
    Handler.enroll_secret = args.enroll_secret
    ui_dir = args.ui_dir or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "ui", "dist")
    Handler.ui_dir = ui_dir if os.path.isdir(ui_dir) else None

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
