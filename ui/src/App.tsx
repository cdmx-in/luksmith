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

const TOKEN_KEY = "luksmith_token";

class AuthError extends Error {}

async function api<T>(token: string, path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: { ...(init?.headers ?? {}), Authorization: `Bearer ${token}` },
  });
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

function Login({ onLogin }: { onLogin: (token: string) => void }) {
  const [value, setValue] = useState("");
  const [show, setShow] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    const token = value.trim();
    if (!token) return;
    setBusy(true);
    setError(null);
    try {
      await api<{ devices: Device[] }>(token, "api/v1/devices");
      onLogin(token);
    } catch (err) {
      setError(err instanceof AuthError ? "Invalid admin token." : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-wrap">
      <form className="login-card" onSubmit={submit}>
        <Wordmark />
        <p className="login-sub">
          LUKS key escrow for managed fleets. Every key retrieval is audited.
        </p>
        <label className="field-label" htmlFor="token">
          Admin token
        </label>
        <div className="token-field">
          <input
            id="token"
            type={show ? "text" : "password"}
            autoFocus
            autoComplete="off"
            spellCheck={false}
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder="Bearer token"
          />
          <button
            type="button"
            className="btn btn-ghost token-toggle"
            aria-label={show ? "Hide token" : "Show token"}
            aria-pressed={show}
            onClick={() => setShow((s) => !s)}
          >
            {show ? "Hide" : "Show"}
          </button>
        </div>
        {error && <p className="form-error" role="alert">{error}</p>}
        <button type="submit" className="btn btn-primary" disabled={busy || !value.trim()}>
          {busy ? "Checking…" : "Sign in"}
        </button>
      </form>
    </div>
  );
}

// ---------------------------------------------------------------- reveal modal

function RevealModal({
  token,
  device,
  onClose,
  onAuthError,
  showToast,
}: {
  token: string;
  device: Device;
  onClose: () => void;
  onAuthError: () => void;
  showToast: (msg: string) => void;
}) {
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<Reveal | null>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    const r = reason.trim();
    if (!r) return;
    setBusy(true);
    setError(null);
    try {
      const data = await api<Reveal>(
        token,
        `api/v1/keys/${encodeURIComponent(device.id)}/reveal?reason=${encodeURIComponent(r)}`,
        { method: "POST" },
      );
      setResult(data);
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
            Reveal recovery key <span className="mono dim">{device.hostname}</span>
          </h2>
          <button className="btn btn-ghost btn-icon" onClick={onClose} aria-label="Close dialog">
            <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" aria-hidden="true">
              <path d="M1 1l12 12M13 1L1 13" />
            </svg>
          </button>
        </div>

        {!result ? (
          <form onSubmit={submit} className="modal-body">
            <div className="callout callout-warn" role="note">
              <strong>This action is recorded.</strong> Revealing the escrowed
              ciphertext for <code className="mono">{device.id}</code> writes a
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
        ) : (
          <div className="modal-body">
            <p className="modal-copy">
              Escrowed ciphertext for <code className="mono">{device.id}</code>{" "}
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
}: {
  devices: Device[];
  onReveal: (d: Device) => void;
  onRotate: (d: Device) => void;
  rotating: string | null;
}) {
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
                  <button
                    className="btn btn-small"
                    onClick={() => onRotate(d)}
                    disabled={rotating === d.id || !!d.rotate_requested}
                  >
                    {rotating === d.id ? "Requesting…" : "Request rotation"}
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
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

function Portal({ token, onLogout }: { token: string; onLogout: () => void }) {
  const [devices, setDevices] = useState<Device[] | null>(null);
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [tab, setTab] = useState<"devices" | "audit">("devices");
  const [error, setError] = useState<string | null>(null);
  const [revealFor, setRevealFor] = useState<Device | null>(null);
  const [rotating, setRotating] = useState<string | null>(null);
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
      setError(null);
    } catch (err) {
      if (err instanceof AuthError) return onLogout();
      setError(String(err instanceof Error ? err.message : err));
    }
  }, [token, onLogout]);

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

  return (
    <div className="portal">
      <header className="topbar">
        <Wordmark />
        <span className="topbar-spacer" />
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
          <SkeletonTable cols={tab === "devices" ? 6 : 5} />
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
              />
            )}
          </>
        ) : (
          <AuditTable entries={audit} />
        )}
      </main>

      {revealFor && (
        <RevealModal
          token={token}
          device={revealFor}
          onClose={() => {
            setRevealFor(null);
            refresh(); // reveal writes an audit entry
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
  const [token, setToken] = useState<string | null>(() => sessionStorage.getItem(TOKEN_KEY));

  const logout = useCallback(() => {
    sessionStorage.removeItem(TOKEN_KEY);
    setToken(null);
  }, []);

  if (!token)
    return (
      <Login
        onLogin={(t) => {
          sessionStorage.setItem(TOKEN_KEY, t);
          setToken(t);
        }}
      />
    );
  return <Portal token={token} onLogout={logout} />;
}
