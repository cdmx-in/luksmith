import { useCallback, useEffect, useRef, useState } from "react";

// ---------------------------------------------------------------- api types

type Report = {
  boot_class?: string | null;
  pcr7_drift?: boolean;
  rebound?: boolean;
};

type Device = {
  id: string;
  hostname: string;
  last_seen: number | null;
  rotate_requested: number;
  active_keys: number;
  last_report: Report | null;
};

type AuditEntry = {
  seq: number;
  ts: number;
  actor: string;
  action: string;
  device_id: string | null;
  detail: string | null;
};

type Reveal = {
  key_id: string;
  ciphertext: string;
  created_at: number;
  decrypt_hint: string;
};

type Role = "owner" | "admin" | "helpdesk" | "auditor";

type Me = { username: string; role: Role; sso?: boolean };

type ReqStatus = "pending" | "approved" | "denied" | "consumed";

type RevealRequest = {
  id: string;
  device_id: string;
  key_id?: string | null;
  requester: string;
  reason: string;
  status: ReqStatus;
  approver?: string | null;
  created_at: number;
  decided_at?: number | null;
};

type Admin = { username: string; role: Role; sso?: boolean };

type Pending = { request_id: string; status: string };

const TOKEN_KEY = "luksmith_token";
const ROLE_KEY = "luksmith_role";

class AuthError extends Error {}

// token === null → rely on trusted-proxy / SSO session (no Authorization header).
async function api<T>(token: string | null, path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = { ...(init?.headers as Record<string, string> | undefined) };
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(path, { ...init, headers });
  if (res.status === 401) throw new AuthError("session expired");
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try {
      msg = (await res.json()).error ?? msg;
    } catch {
      /* non-JSON error body */
    }
    throw new Error(msg);
  }
  return res.json() as Promise<T>;
}

// ponytail: list endpoints may return {key:[...]} or a bare array — accept either.
function asList<T>(body: unknown, key: string): T[] {
  if (Array.isArray(body)) return body as T[];
  return ((body as Record<string, T[]>)?.[key] as T[]) ?? [];
}

// ---------------------------------------------------------------- helpers

function relTime(ts: number | null | undefined): string {
  if (!ts) return "never";
  const s = Math.floor(Date.now() / 1000 - ts);
  if (s < 60) return "just now";
  const units: [number, string][] = [
    [31536000, "y"],
    [2592000, "mo"],
    [86400, "d"],
    [3600, "h"],
    [60, "m"],
  ];
  for (const [secs, label] of units)
    if (s >= secs) return `${Math.floor(s / secs)}${label} ago`;
  return "just now";
}

function fmtTime(ts: number): string {
  return new Date(ts * 1000).toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false; // clipboard unavailable (non-secure context)
  }
}

type Tone = "ok" | "bad" | "muted" | "warn";

const REQ_TONE: Record<ReqStatus, Tone> = {
  pending: "warn",
  approved: "ok",
  denied: "bad",
  consumed: "muted",
};

function roleTone(role: Role): Tone {
  return role === "owner" ? "ok" : "muted";
}

function bootBadge(r: Report | null): { label: string; tone: Tone } {
  const bc = r?.boot_class;
  if (bc === "tpm_unlock_ok") return { label: "TPM unlock", tone: "ok" };
  if (bc === "fallback_used" || bc === "tpm_binding_missing")
    return { label: "Fallback used", tone: "bad" };
  return { label: "No TPM", tone: "muted" };
}

function Badge({ label, tone, title }: { label: string; tone: Tone; title?: string }) {
  return (
    <span className={`badge badge-${tone}`} title={title}>
      {label}
    </span>
  );
}

function Logomark({ size = 22 }: { size?: number }) {
  return (
    <svg
      className="logomark"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <circle cx="7.5" cy="16.5" r="4.5" />
      <path d="M10.7 13.3 21 3" />
      <path d="m17.5 6.5 3 3" />
      <path d="m14.5 9.5 2 2" />
    </svg>
  );
}

function Wordmark() {
  return (
    <div className="wordmark">
      <Logomark />
      <span>luksmith</span>
    </div>
  );
}

// ---------------------------------------------------------------- login

function Login({ onAuthed }: { onAuthed: (token: string | null, me: Me) => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [tokenVal, setTokenVal] = useState("");
  const [showTok, setShowTok] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function fail(err: unknown, authMsg: string) {
    setError(err instanceof AuthError ? authMsg : String(err instanceof Error ? err.message : err));
  }

  async function creds(e: React.FormEvent) {
    e.preventDefault();
    if (!username.trim() || !password) return;
    setBusy(true);
    setError(null);
    try {
      const r = await api<{ token: string }>(null, "api/v1/auth/login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username: username.trim(), password }),
      });
      const me = await api<Me>(r.token, "api/v1/me");
      onAuthed(r.token, me);
    } catch (err) {
      fail(err, "Invalid username or password.");
    } finally {
      setBusy(false);
    }
  }

  async function tokenLogin(e: React.FormEvent) {
    e.preventDefault();
    const t = tokenVal.trim();
    if (!t) return;
    setBusy(true);
    setError(null);
    try {
      const me = await api<Me>(t, "api/v1/me");
      onAuthed(t, me);
    } catch (err) {
      fail(err, "Invalid admin token.");
    } finally {
      setBusy(false);
    }
  }

  async function sso() {
    setBusy(true);
    setError(null);
    try {
      const me = await api<Me>(null, "api/v1/me");
      onAuthed(null, me);
    } catch (err) {
      fail(err, "No active SSO session. Sign in above, or authenticate with your identity provider first.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-wrap">
      <div className="login-card">
        <Wordmark />
        <p className="login-sub">
          LUKS key escrow for managed fleets. Every key retrieval is audited.
        </p>

        <form onSubmit={creds}>
          <label className="field-label" htmlFor="username">
            Username
          </label>
          <input
            id="username"
            type="text"
            autoFocus
            autoComplete="username"
            spellCheck={false}
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="admin"
          />
          <label className="field-label" htmlFor="password">
            Password
          </label>
          <input
            id="password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="••••••••"
          />
          <button
            type="submit"
            className="btn btn-primary login-submit"
            disabled={busy || !username.trim() || !password}
          >
            {busy ? "Signing in…" : "Sign in"}
          </button>
        </form>

        <div className="login-divider">or admin token</div>

        <form onSubmit={tokenLogin}>
          <div className="token-field">
            <input
              id="token"
              type={showTok ? "text" : "password"}
              autoComplete="off"
              spellCheck={false}
              value={tokenVal}
              onChange={(e) => setTokenVal(e.target.value)}
              placeholder="Bearer token"
            />
            <button
              type="button"
              className="btn btn-ghost token-toggle"
              aria-label={showTok ? "Hide token" : "Show token"}
              aria-pressed={showTok}
              onClick={() => setShowTok((s) => !s)}
            >
              {showTok ? "Hide" : "Show"}
            </button>
          </div>
          <button type="submit" className="btn login-submit" disabled={busy || !tokenVal.trim()}>
            Use token
          </button>
        </form>

        {error && <p className="form-error" role="alert">{error}</p>}

        <div className="login-sso">
          <button type="button" className="btn btn-ghost" onClick={sso} disabled={busy}>
            Sign in with SSO
          </button>
          <p className="login-sso-hint">
            If a trusted proxy has already authenticated you, <code className="mono">GET /api/v1/me</code>{" "}
            signs you in automatically — no token needed.
          </p>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- reveal modal

// Two modes: `device` → start a reveal (may be gated to approval); `request` →
// complete an already-approved request. Both surface ciphertext in this modal.
function RevealModal({
  token,
  device,
  request,
  onClose,
  onAuthError,
  showToast,
}: {
  token: string | null;
  device?: Device;
  request?: RevealRequest;
  onClose: () => void;
  onAuthError: () => void;
  showToast: (msg: string) => void;
}) {
  const completion = !!request;
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(completion);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<Reveal | null>(null);

  const targetId = device ? device.id : request!.device_id;
  const targetHost = device ? device.hostname : request!.device_id;

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  // Completion mode: fetch ciphertext immediately (request is already approved).
  useEffect(() => {
    if (!request) return;
    (async () => {
      try {
        const data = await api<Reveal>(
          token,
          `api/v1/reveal-requests/${encodeURIComponent(request.id)}/reveal`,
          { method: "POST" },
        );
        setResult(data);
      } catch (err) {
        if (err instanceof AuthError) return onAuthError();
        setError(String(err instanceof Error ? err.message : err));
      } finally {
        setBusy(false);
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [request]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    const r = reason.trim();
    if (!r) return;
    setBusy(true);
    setError(null);
    try {
      const data = await api<Reveal | Pending>(
        token,
        `api/v1/keys/${encodeURIComponent(device!.id)}/reveal?reason=${encodeURIComponent(r)}`,
        { method: "POST" },
      );
      if ("ciphertext" in data) {
        setResult(data);
      } else {
        showToast("Request submitted for approval");
        onClose();
      }
    } catch (err) {
      if (err instanceof AuthError) return onAuthError();
      setError(String(err instanceof Error ? err.message : err));
    } finally {
      setBusy(false);
    }
  }

  async function copy(text: string, what: string) {
    if (await copyText(text)) showToast(`${what} copied to clipboard`);
  }

  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal" role="dialog" aria-modal="true" aria-label="Reveal recovery key">
        <div className="modal-head">
          <h2>
            {completion ? "Reveal approved key" : "Reveal recovery key"}{" "}
            <span className="mono dim">{targetHost}</span>
          </h2>
          <button className="btn btn-ghost btn-icon" onClick={onClose} aria-label="Close dialog">
            <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" aria-hidden="true">
              <path d="M1 1l12 12M13 1L1 13" />
            </svg>
          </button>
        </div>

        {result ? (
          <div className="modal-body">
            <p className="modal-copy">
              Escrowed ciphertext for <code className="mono">{targetId}</code>{" "}
              — key <code className="mono">{result.key_id}</code>, created{" "}
              <span title={fmtTime(result.created_at)}>{relTime(result.created_at)}</span>.
              This retrieval has been audited.
            </p>
            <p className="field-label">Ciphertext</p>
            <div className="code-card">
              <pre className="mono code-card-text">{result.ciphertext}</pre>
              <button
                className="btn btn-small copy-btn"
                onClick={() => copy(result.ciphertext, "Ciphertext")}
              >
                Copy
              </button>
            </div>
            <p className="field-label">Decrypt on an admin workstation</p>
            <div className="code-card">
              <pre className="mono code-card-text">{result.decrypt_hint}</pre>
              <button
                className="btn btn-small copy-btn"
                onClick={() => copy(result.decrypt_hint, "Command")}
              >
                Copy
              </button>
            </div>
            <div className="modal-actions">
              <button className="btn btn-primary" onClick={onClose}>
                Done
              </button>
            </div>
          </div>
        ) : completion ? (
          <div className="modal-body">
            {error ? (
              <p className="form-error" role="alert">{error}</p>
            ) : (
              <p className="modal-copy">Retrieving approved ciphertext…</p>
            )}
            <div className="modal-actions">
              <button className="btn" onClick={onClose}>
                Close
              </button>
            </div>
          </div>
        ) : (
          <form onSubmit={submit} className="modal-body">
            <div className="callout callout-warn" role="note">
              <strong>This action is recorded.</strong> Revealing the escrowed
              ciphertext for <code className="mono">{targetId}</code> writes a
              permanent entry to the append-only audit log — your identity,
              timestamp, and the reason below are all retained.
            </div>
            <label className="field-label" htmlFor="reason">
              Reason <span className="req">(required, audited)</span>
            </label>
            <textarea
              id="reason"
              autoFocus
              rows={3}
              required
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="e.g. helpdesk ticket #4211 — user locked out after firmware update"
            />
            {error && <p className="form-error" role="alert">{error}</p>}
            <div className="modal-actions">
              <button type="button" className="btn" onClick={onClose}>
                Cancel
              </button>
              <button type="submit" className="btn btn-danger" disabled={busy || !reason.trim()}>
                {busy ? "Revealing…" : "Reveal ciphertext"}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- fleet stats

function StatTiles({ devices }: { devices: Device[] }) {
  const total = devices.length;
  const escrowed = devices.filter((d) => d.active_keys > 0).length;
  const tpm = devices.filter((d) => d.last_report?.boot_class === "tpm_unlock_ok").length;
  const fallback = devices.filter(
    (d) =>
      d.last_report?.boot_class === "fallback_used" ||
      d.last_report?.boot_class === "tpm_binding_missing",
  ).length;
  const unescrowed = total - escrowed;

  return (
    <div className="stat-tiles">
      <div className="stat-tile">
        <span className="stat-label">Total devices</span>
        <span className="stat-value">{total}</span>
      </div>
      <div className={`stat-tile ${unescrowed > 0 ? "stat-tile-bad" : ""}`}>
        <span className="stat-label">Escrowed</span>
        <span className="stat-value">
          {escrowed}
          <span className="stat-denom">/{total}</span>
        </span>
        <div
          className="stat-progress"
          role="progressbar"
          aria-label="Escrow coverage"
          aria-valuemin={0}
          aria-valuemax={total}
          aria-valuenow={escrowed}
        >
          <div
            className="stat-progress-fill"
            style={{ width: total > 0 ? `${(escrowed / total) * 100}%` : "0%" }}
          />
        </div>
      </div>
      <div className="stat-tile">
        <span className="stat-label">TPM-bound</span>
        <span className="stat-value">{tpm}</span>
      </div>
      <div className={`stat-tile ${fallback > 0 ? "stat-tile-warn" : ""}`}>
        <span className="stat-label">Fallback boots</span>
        <span className="stat-value">{fallback}</span>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- tables

function EmptyDevices({ showToast }: { showToast: (msg: string) => void }) {
  const cmd = "luksmith enroll";
  return (
    <div className="empty-state">
      <Logomark size={28} />
      <h3>No devices enrolled yet</h3>
      <p>Run the agent on a managed host to enroll it and escrow its recovery key.</p>
      <div className="code-card empty-cmd">
        <pre className="mono code-card-text">{cmd}</pre>
        <button
          className="btn btn-small copy-btn"
          onClick={async () => {
            if (await copyText(cmd)) showToast("Command copied to clipboard");
          }}
        >
          Copy
        </button>
      </div>
    </div>
  );
}

function DevicesTable({
  devices,
  onReveal,
  onRotate,
  rotating,
  canReveal,
  canRotate,
}: {
  devices: Device[];
  onReveal: (d: Device) => void;
  onRotate: (d: Device) => void;
  rotating: string | null;
  canReveal: boolean;
  canRotate: boolean;
}) {
  const readOnly = !canReveal && !canRotate;
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Hostname</th>
            <th>Device ID</th>
            <th>Last seen</th>
            <th>Boot</th>
            <th>Escrow</th>
            <th className="th-actions">Actions</th>
          </tr>
        </thead>
        <tbody>
          {devices.map((d) => {
            const boot = bootBadge(d.last_report);
            return (
              <tr key={d.id}>
                <td className="td-host">
                  {d.hostname}
                  {d.last_report?.pcr7_drift && (
                    <Badge label="PCR7 drift" tone="warn" title="PCR7 measurement drift detected" />
                  )}
                </td>
                <td className="mono dim">{d.id}</td>
                <td className="td-num" title={d.last_seen ? fmtTime(d.last_seen) : undefined}>
                  {relTime(d.last_seen)}
                </td>
                <td>
                  <Badge {...boot} />
                </td>
                <td>
                  {d.active_keys > 0 ? (
                    <Badge label="Escrowed" tone="ok" />
                  ) : (
                    <Badge label="Missing" tone="bad" />
                  )}
                  {!!d.rotate_requested && (
                    <Badge
                      label="Rotation pending"
                      tone="warn"
                      title="Rotation requested; awaiting agent check-in"
                    />
                  )}
                </td>
                <td className="td-actions">
                  {readOnly && <span className="dim">Read-only</span>}
                  {canReveal && (
                    <button
                      className="btn btn-small"
                      onClick={() => onReveal(d)}
                      disabled={d.active_keys === 0}
                      title={
                        d.active_keys === 0
                          ? "No active key escrowed"
                          : "Reveal recovery key (audited)"
                      }
                    >
                      Reveal key
                    </button>
                  )}
                  {canRotate && (
                    <button
                      className="btn btn-small"
                      onClick={() => onRotate(d)}
                      disabled={rotating === d.id || !!d.rotate_requested}
                    >
                      {rotating === d.id ? "Requesting…" : "Request rotation"}
                    </button>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function ApprovalsTable({
  requests,
  me,
  canApprove,
  onDecide,
  onComplete,
  busyId,
}: {
  requests: RevealRequest[];
  me: Me;
  canApprove: boolean;
  onDecide: (r: RevealRequest, action: "approve" | "deny") => void;
  onComplete: (r: RevealRequest) => void;
  busyId: string | null;
}) {
  if (requests.length === 0)
    return (
      <div className="empty-state">
        <h3>No reveal requests</h3>
        <p>Approval-gated key reveals appear here for review, with their status.</p>
      </div>
    );
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Requested</th>
            <th>Device</th>
            <th>Requester</th>
            <th>Reason</th>
            <th>Status</th>
            <th className="th-actions">Actions</th>
          </tr>
        </thead>
        <tbody>
          {requests.map((r) => {
            const self = r.requester === me.username;
            return (
              <tr key={r.id}>
                <td className="td-num" title={fmtTime(r.created_at)}>
                  {relTime(r.created_at)}
                </td>
                <td className="mono dim">{r.device_id}</td>
                <td>{r.requester}</td>
                <td className="td-detail">{r.reason}</td>
                <td>
                  <Badge label={r.status} tone={REQ_TONE[r.status] ?? "muted"} />
                  {r.approver && <span className="dim"> · {r.approver}</span>}
                </td>
                <td className="td-actions">
                  {r.status === "pending" && canApprove && (
                    <>
                      <button
                        className="btn btn-small"
                        disabled={self || busyId === r.id}
                        title={self ? "You can't approve your own request" : undefined}
                        onClick={() => onDecide(r, "approve")}
                      >
                        Approve
                      </button>
                      <button
                        className="btn btn-small btn-danger"
                        disabled={self || busyId === r.id}
                        title={self ? "You can't deny your own request" : undefined}
                        onClick={() => onDecide(r, "deny")}
                      >
                        Deny
                      </button>
                    </>
                  )}
                  {r.status === "approved" && self && (
                    <button className="btn btn-small btn-primary" onClick={() => onComplete(r)}>
                      Reveal key
                    </button>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function AdminsPanel({
  admins,
  onAdd,
  onDelete,
  busyUser,
}: {
  admins: Admin[];
  onAdd: (username: string, password: string, role: Role) => Promise<string | null>;
  onDelete: (username: string) => void;
  busyUser: string | null;
}) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<Role>("helpdesk");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const owners = admins.filter((a) => a.role === "owner").length;

  async function add(e: React.FormEvent) {
    e.preventDefault();
    if (!username.trim() || !password) return;
    setBusy(true);
    setError(null);
    const err = await onAdd(username.trim(), password, role);
    setBusy(false);
    if (err) {
      setError(err);
    } else {
      setUsername("");
      setPassword("");
      setRole("helpdesk");
    }
  }

  return (
    <>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Username</th>
              <th>Role</th>
              <th>Type</th>
              <th className="th-actions">Actions</th>
            </tr>
          </thead>
          <tbody>
            {admins.map((a) => {
              const lastOwner = a.role === "owner" && owners <= 1;
              const rootToken = a.username === "root-token";
              const guarded = lastOwner || rootToken;
              return (
                <tr key={a.username}>
                  <td className="td-host">{a.username}</td>
                  <td>
                    <Badge label={a.role} tone={roleTone(a.role)} />
                  </td>
                  <td>
                    <Badge label={a.sso ? "SSO" : "Local"} tone={a.sso ? "ok" : "muted"} />
                  </td>
                  <td className="td-actions">
                    <button
                      className="btn btn-small btn-danger"
                      disabled={guarded || busyUser === a.username}
                      title={
                        rootToken
                          ? "The master token account cannot be removed"
                          : lastOwner
                            ? "Cannot remove the last owner"
                            : undefined
                      }
                      onClick={() => onDelete(a.username)}
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <form className="admin-add" onSubmit={add}>
        <h3>Add local admin</h3>
        <div className="admin-add-row">
          <div className="admin-add-field">
            <label className="field-label" htmlFor="new-admin-user">
              Username
            </label>
            <input
              id="new-admin-user"
              type="text"
              autoComplete="off"
              spellCheck={false}
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="jane.doe"
            />
          </div>
          <div className="admin-add-field">
            <label className="field-label" htmlFor="new-admin-pass">
              Password
            </label>
            <input
              id="new-admin-pass"
              type="password"
              autoComplete="new-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
            />
          </div>
          <div className="admin-add-field">
            <label className="field-label" htmlFor="new-admin-role">
              Role
            </label>
            <select id="new-admin-role" value={role} onChange={(e) => setRole(e.target.value as Role)}>
              <option value="owner">owner</option>
              <option value="admin">admin</option>
              <option value="helpdesk">helpdesk</option>
              <option value="auditor">auditor</option>
            </select>
          </div>
          <button
            type="submit"
            className="btn btn-primary"
            disabled={busy || !username.trim() || !password}
          >
            {busy ? "Adding…" : "Add admin"}
          </button>
        </div>
        {error && <p className="form-error" role="alert">{error}</p>}
      </form>
    </>
  );
}

function AuditTable({ entries }: { entries: AuditEntry[] }) {
  if (entries.length === 0)
    return (
      <div className="empty-state">
        <h3>No audit events yet</h3>
        <p>Key reveals, rotation requests, and agent check-ins will appear here.</p>
      </div>
    );
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Actor</th>
            <th>Action</th>
            <th>Device</th>
            <th>Detail</th>
          </tr>
        </thead>
        <tbody>
          {entries.map((a) => (
            <tr key={a.seq}>
              <td className="td-num" title={fmtTime(a.ts)}>
                {relTime(a.ts)}
              </td>
              <td>{a.actor}</td>
              <td>
                <code className="mono action-code">{a.action}</code>
              </td>
              <td className="mono dim">{a.device_id ?? ""}</td>
              <td className="td-detail">{a.detail ?? ""}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function SkeletonTable({ cols }: { cols: number }) {
  return (
    <div className="table-wrap" aria-hidden="true">
      <table>
        <thead>
          <tr>
            {Array.from({ length: cols }, (_, i) => (
              <th key={i}>
                <span className="skel skel-th" />
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {Array.from({ length: 5 }, (_, r) => (
            <tr key={r}>
              {Array.from({ length: cols }, (_, c) => (
                <td key={c}>
                  <span className="skel" style={{ width: `${55 + ((r * 7 + c * 13) % 40)}%` }} />
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ---------------------------------------------------------------- portal

type Tab = "devices" | "audit" | "approvals" | "admins";

function Portal({ token, me, onLogout }: { token: string | null; me: Me; onLogout: () => void }) {
  const canReveal = me.role !== "auditor";
  const canRotate = me.role === "owner" || me.role === "admin";
  const canApprove = me.role === "owner" || me.role === "admin";
  const isOwner = me.role === "owner";
  const showApprovals = canApprove || canReveal; // participants in the reveal flow

  const [devices, setDevices] = useState<Device[] | null>(null);
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [requests, setRequests] = useState<RevealRequest[]>([]);
  const [admins, setAdmins] = useState<Admin[]>([]);
  const [tab, setTab] = useState<Tab>("devices");
  const [error, setError] = useState<string | null>(null);
  const [revealFor, setRevealFor] = useState<Device | null>(null);
  const [completeReq, setCompleteReq] = useState<RevealRequest | null>(null);
  const [rotating, setRotating] = useState<string | null>(null);
  const [reqBusy, setReqBusy] = useState<string | null>(null);
  const [toast, setToast] = useState<string | null>(null);
  const toastTimer = useRef<number | undefined>(undefined);

  const showToast = useCallback((msg: string) => {
    setToast(msg);
    window.clearTimeout(toastTimer.current);
    toastTimer.current = window.setTimeout(() => setToast(null), 2200);
  }, []);

  const refresh = useCallback(async () => {
    try {
      const [d, a] = await Promise.all([
        api<{ devices: Device[] }>(token, "api/v1/devices"),
        api<{ audit: AuditEntry[] }>(token, "api/v1/audit"),
      ]);
      setDevices(d.devices);
      setAudit(a.audit); // server already returns newest first
      if (showApprovals) {
        const r = await api<unknown>(token, "api/v1/reveal-requests?status=all");
        setRequests(asList<RevealRequest>(r, "requests"));
      }
      if (isOwner) {
        const ad = await api<unknown>(token, "api/v1/admins");
        setAdmins(asList<Admin>(ad, "admins"));
      }
      setError(null);
    } catch (err) {
      if (err instanceof AuthError) return onLogout();
      setError(String(err instanceof Error ? err.message : err));
    }
  }, [token, onLogout, showApprovals, isOwner]);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 30_000);
    return () => clearInterval(t);
  }, [refresh]);

  async function rotate(d: Device) {
    setRotating(d.id);
    try {
      await api(token, `api/v1/keys/${encodeURIComponent(d.id)}/rotate`, { method: "POST" });
      showToast(`Rotation requested for ${d.hostname}`);
      await refresh();
    } catch (err) {
      if (err instanceof AuthError) return onLogout();
      setError(String(err instanceof Error ? err.message : err));
    } finally {
      setRotating(null);
    }
  }

  async function decide(r: RevealRequest, action: "approve" | "deny") {
    setReqBusy(r.id);
    try {
      await api(token, `api/v1/reveal-requests/${encodeURIComponent(r.id)}/${action}`, {
        method: "POST",
      });
      showToast(action === "approve" ? "Request approved" : "Request denied");
      await refresh();
    } catch (err) {
      if (err instanceof AuthError) return onLogout();
      setError(String(err instanceof Error ? err.message : err));
    } finally {
      setReqBusy(null);
    }
  }

  async function addAdmin(username: string, password: string, role: Role): Promise<string | null> {
    try {
      await api(token, "api/v1/admins", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username, password, role }),
      });
      showToast(`Admin ${username} added`);
      await refresh();
      return null;
    } catch (err) {
      if (err instanceof AuthError) {
        onLogout();
        return null;
      }
      return String(err instanceof Error ? err.message : err);
    }
  }

  async function deleteAdmin(username: string) {
    setReqBusy(username);
    try {
      await api(token, `api/v1/admins/${encodeURIComponent(username)}`, { method: "DELETE" });
      showToast(`Removed ${username}`);
      await refresh();
    } catch (err) {
      if (err instanceof AuthError) return onLogout();
      setError(String(err instanceof Error ? err.message : err));
    } finally {
      setReqBusy(null);
    }
  }

  const pendingCount = requests.filter((r) => r.status === "pending").length;
  const colsFor = tab === "devices" ? 6 : tab === "approvals" ? 6 : tab === "admins" ? 4 : 5;

  return (
    <div className="portal">
      <header className="topbar">
        <Wordmark />
        <span className="topbar-spacer" />
        <span className="topbar-user">
          <span className="mono">{me.username}</span>
          <Badge label={me.role} tone={roleTone(me.role)} title={me.sso ? "SSO session" : undefined} />
        </span>
        <button className="btn btn-ghost" onClick={onLogout}>
          Log out
        </button>
      </header>

      <main className="content">
        <nav className="tabs" role="tablist">
          <button
            role="tab"
            aria-selected={tab === "devices"}
            className={tab === "devices" ? "tab tab-active" : "tab"}
            onClick={() => setTab("devices")}
          >
            Devices
          </button>
          <button
            role="tab"
            aria-selected={tab === "audit"}
            className={tab === "audit" ? "tab tab-active" : "tab"}
            onClick={() => setTab("audit")}
          >
            Audit log
          </button>
          {showApprovals && (
            <button
              role="tab"
              aria-selected={tab === "approvals"}
              className={tab === "approvals" ? "tab tab-active" : "tab"}
              onClick={() => setTab("approvals")}
            >
              Approvals
              {pendingCount > 0 && <Badge label={String(pendingCount)} tone="warn" />}
            </button>
          )}
          {isOwner && (
            <button
              role="tab"
              aria-selected={tab === "admins"}
              className={tab === "admins" ? "tab tab-active" : "tab"}
              onClick={() => setTab("admins")}
            >
              Admins
            </button>
          )}
        </nav>

        {error && (
          <div className="error-banner" role="alert">
            <span>Could not reach the escrow server: {error}</span>
            <button className="btn btn-small" onClick={refresh}>
              Retry
            </button>
          </div>
        )}

        {devices === null ? (
          <SkeletonTable cols={colsFor} />
        ) : tab === "devices" ? (
          <>
            <StatTiles devices={devices} />
            {devices.length === 0 ? (
              <EmptyDevices showToast={showToast} />
            ) : (
              <DevicesTable
                devices={devices}
                onReveal={setRevealFor}
                onRotate={rotate}
                rotating={rotating}
                canReveal={canReveal}
                canRotate={canRotate}
              />
            )}
          </>
        ) : tab === "audit" ? (
          <AuditTable entries={audit} />
        ) : tab === "approvals" ? (
          <ApprovalsTable
            requests={requests}
            me={me}
            canApprove={canApprove}
            onDecide={decide}
            onComplete={setCompleteReq}
            busyId={reqBusy}
          />
        ) : (
          <AdminsPanel admins={admins} onAdd={addAdmin} onDelete={deleteAdmin} busyUser={reqBusy} />
        )}
      </main>

      {revealFor && (
        <RevealModal
          token={token}
          device={revealFor}
          onClose={() => {
            setRevealFor(null);
            refresh(); // reveal writes an audit entry / may create a request
          }}
          onAuthError={onLogout}
          showToast={showToast}
        />
      )}

      {completeReq && (
        <RevealModal
          token={token}
          request={completeReq}
          onClose={() => {
            setCompleteReq(null);
            refresh(); // completion flips the request to consumed
          }}
          onAuthError={onLogout}
          showToast={showToast}
        />
      )}

      {toast && (
        <div className="toast" role="status">
          {toast}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- app

export default function App() {
  const [token, setToken] = useState<string | null>(null);
  const [me, setMe] = useState<Me | null>(null);
  const [ready, setReady] = useState(false);

  // On load: try the stored token, or a trusted-proxy/SSO session (token null).
  useEffect(() => {
    (async () => {
      const stored = sessionStorage.getItem(TOKEN_KEY);
      try {
        const m = await api<Me>(stored, "api/v1/me");
        setToken(stored);
        setMe(m);
      } catch {
        sessionStorage.removeItem(TOKEN_KEY);
        sessionStorage.removeItem(ROLE_KEY);
      } finally {
        setReady(true);
      }
    })();
  }, []);

  const authed = useCallback((t: string | null, m: Me) => {
    if (t) {
      sessionStorage.setItem(TOKEN_KEY, t);
      sessionStorage.setItem(ROLE_KEY, m.role);
    } else {
      sessionStorage.removeItem(TOKEN_KEY);
      sessionStorage.removeItem(ROLE_KEY);
    }
    setToken(t);
    setMe(m);
  }, []);

  const logout = useCallback(() => {
    const t = sessionStorage.getItem(TOKEN_KEY);
    if (t) api(t, "api/v1/auth/logout", { method: "POST" }).catch(() => {});
    sessionStorage.removeItem(TOKEN_KEY);
    sessionStorage.removeItem(ROLE_KEY);
    setToken(null);
    setMe(null);
  }, []);

  if (!ready)
    return (
      <div className="login-wrap">
        <p className="dim">Loading…</p>
      </div>
    );
  if (!me) return <Login onAuthed={authed} />;
  return <Portal token={token} me={me} onLogout={logout} />;
}
