# luksmith portal — admin RBAC / SSO / two-person reveal contract

Both server implementations (`server/luksmith_server.py`, `server-go/`) and the
UI (`ui/`) build to THIS spec so they stay interchangeable. Device/agent
endpoints (enroll, key escrow, checkin) are **unchanged** — this only adds an
admin identity layer on top.

## Backward compatibility (must not break v0.3.0 deploys)

- `--admin-token` / `LUKSMITH_ADMIN_TOKEN` still works exactly as before and is
  treated as a built-in superuser: username `root-token`, role `owner`. Every
  existing admin API call authenticated with the master token keeps working.
- HTTP Basic with the master token as password still works (dashboard).
- If no admin accounts exist and `--require-approval` is off, behaviour is
  identical to today.

## Roles & permissions

| Capability                    | owner | admin | helpdesk | auditor |
|-------------------------------|:---:|:---:|:---:|:---:|
| View devices & audit log      |  ✔  |  ✔  |    ✔     |    ✔    |
| Request a key reveal          |  ✔  |  ✔  |    ✔     |         |
| Approve a reveal request      |  ✔  |  ✔  |          |         |
| Rotate a device key           |  ✔  |  ✔  |          |         |
| Manage admin accounts         |  ✔  |     |          |         |

A reveal request may never be approved by its own requester (self-approval →
403), regardless of role.

## Data model (identical schema in both servers; additive to existing tables)

```sql
CREATE TABLE IF NOT EXISTS admins (
    id TEXT PRIMARY KEY,              -- hex(8)
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT,              -- pbkdf2_sha256$<iters>$<salt_hex>$<hash_hex>; NULL for SSO-only
    role TEXT NOT NULL,              -- owner|admin|helpdesk|auditor
    sso_subject TEXT UNIQUE,         -- proxy-asserted email/sub; NULL for local-only
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,     -- sha256 hex of the bearer session token
    username TEXT NOT NULL,
    role TEXT NOT NULL,
    expires INTEGER NOT NULL         -- unix; TTL 12h
);
CREATE TABLE IF NOT EXISTS reveal_requests (
    id TEXT PRIMARY KEY,             -- hex(8)
    device_id TEXT NOT NULL,
    key_id TEXT,                     -- resolved at reveal time
    requester TEXT NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL,            -- pending|approved|denied|consumed
    approver TEXT,
    created_at INTEGER NOT NULL,
    decided_at INTEGER
);
```

## Password hashing

`pbkdf2_sha256$600000$<salt_hex>$<hash_hex>`, 16-byte random salt, 600000
iterations, SHA-256, 32-byte derived key. Python: `hashlib.pbkdf2_hmac`. Go:
`crypto/pbkdf2` (stdlib as of Go 1.24). Constant-time compare on the derived key.

## Auth resolution order (per request, admin endpoints)

1. `Authorization: Bearer <t>` where `<t>` == master admin token → owner/root-token.
2. `Authorization: Bearer <t>` matching a live (unexpired) session → that session's role.
3. HTTP Basic, password == master admin token → owner.
4. If `--trust-proxy` is set AND `X-Proxy-Secret` matches `--proxy-shared-secret`
   (constant-time): read `X-Auth-Request-Email` (identity) and
   `X-Auth-Request-Groups` (comma list). Map to a role via `--sso-group-map`
   (`group:role,...`, default: any authenticated proxy user → `helpdesk`; a
   group named `luksmith-owners`/`-admins`/`-auditors` maps to that role). An
   `admins` row is upserted by `sso_subject`. Proxy headers are IGNORED unless
   the shared secret matches — never trust them raw.
5. Otherwise 401 (`WWW-Authenticate: Basic realm="luksmith"`).

## Endpoints (all admin-authed unless noted)

- `POST /api/v1/auth/login` {username,password} → {token, username, role, expires}. No auth. 401 on bad creds. Rate-limit-friendly constant-time.
- `POST /api/v1/auth/logout` → deletes the caller's session.
- `GET  /api/v1/me` → {username, role, sso: bool} for the current caller.
- `GET  /api/v1/admins` (owner) → list (no hashes).
- `POST /api/v1/admins` (owner) {username, password, role} → creates local admin.
- `DELETE /api/v1/admins/{username}` (owner) → removes (cannot remove the last owner; cannot remove root-token).

### Reveal — behaviour depends on `--require-approval`

Requires role with "request" permission (owner/admin/helpdesk).

- **Approval OFF (default, back-compat):** `POST /api/v1/keys/{device_id}/reveal?reason=...`
  returns `{key_id, ciphertext, created_at, decrypt_hint}` immediately, audited
  `key_revealed` (actor = caller). Exactly today's behaviour.
- **Approval ON:** the same POST instead creates a request and returns
  `{request_id, status:"pending"}` (HTTP 202), audited `reveal_requested`. No ciphertext yet.
  - `GET  /api/v1/reveal-requests?status=pending|all` → list.
  - `POST /api/v1/reveal-requests/{id}/approve` (owner/admin, not the requester) → status `approved`, audited `reveal_approved`.
  - `POST /api/v1/reveal-requests/{id}/deny` (owner/admin, not the requester) → status `denied`, audited `reveal_denied`.
  - `POST /api/v1/reveal-requests/{id}/reveal` (the requester, once approved) → `{key_id, ciphertext, created_at, decrypt_hint}`, status→`consumed`, audited `key_revealed` with detail naming requester+approver. 409 if not approved.

Reason is still mandatory everywhere (400 without it). Every audit row keeps the
existing shape (actor, action, device_id, detail).

## Flags (both servers)

`--require-approval` (env `LUKSMITH_REQUIRE_APPROVAL=1`), `--trust-proxy`,
`--proxy-shared-secret` (env `LUKSMITH_PROXY_SECRET`), `--sso-group-map`.
Existing flags unchanged.

## What CI already guarantees

The escrow-chain parity integration test hits only device/agent + basic reveal
endpoints, so it must keep passing unchanged with approval OFF. Add per-server
unit tests for the new surface.
