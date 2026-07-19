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

type Tone = "ok" | "bad" | "muted" | "warn";

function bootBadge(r: Report | null): { label: string; tone: Tone } {
  const bc = r?.boot_class;
  if (bc === "tpm_unlock_ok") return { label: "TPM unlock", tone: "ok" };
  if (bc === "fallback_used" || bc === "tpm_binding_missing")
    return { label: "Fallback used", tone: "bad" };
  return { label: "No TPM", tone: "muted" };
}

function Badge({ label, tone }: { label: string; tone: Tone }) {
  return <span className={`badge badge-${tone}`}>{label}</span>;
}

// ---------------------------------------------------------------- login

function Login({ onLogin }: { onLogin: (token: string) => void }) {
  const [value, setValue] = useState("");
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
        <div className="wordmark">
          <span aria-hidden="true">&#128273;</span> luksmith
        </div>
        <p className="login-sub">
          Key escrow portal. Enter the admin token to continue — every key
          retrieval is audited.
        </p>
        <label className="field-label" htmlFor="token">
          Admin token
        </label>
        <input
          id="token"
          type="password"
          autoFocus
          autoComplete="off"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder="Bearer token"
        />
        {error && <p className="form-error">{error}</p>}
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
}: {
  token: string;
  device: Device;
  onClose: () => void;
  onAuthError: () => void;
}) {
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<Reveal | null>(null);
  const [copied, setCopied] = useState(false);
  const dialogRef = useRef<HTMLDivElement>(null);

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

  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable (non-secure context) */
    }
  }

  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal" role="dialog" aria-modal="true" aria-label="Reveal recovery key" ref={dialogRef}>
        <div className="modal-head">
          <h2>
            Reveal recovery key <span className="mono dim">{device.hostname}</span>
          </h2>
          <button className="btn btn-ghost" onClick={onClose} aria-label="Close">
            &#10005;
          </button>
        </div>

        {!result ? (
          <form onSubmit={submit} className="modal-body">
            <p className="modal-copy">
              You are about to retrieve the escrowed ciphertext for{" "}
              <code className="mono">{device.id}</code>. This action is written
              to the append-only audit log along with your reason — state the
              ticket or incident that justifies it.
            </p>
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
            {error && <p className="form-error">{error}</p>}
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
              {relTime(result.created_at)} ({fmtTime(result.created_at)}). This
              retrieval has been audited.
            </p>
            <div className="cipher-block">
              <pre className="mono cipher-text">{result.ciphertext}</pre>
              <button className="btn btn-small copy-btn" onClick={() => copy(result.ciphertext)}>
                {copied ? "Copied" : "Copy"}
              </button>
            </div>
            <p className="field-label">Decrypt on an admin workstation</p>
            <pre className="mono hint-block">{result.decrypt_hint}</pre>
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

// ---------------------------------------------------------------- tables

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
  if (devices.length === 0)
    return (
      <p className="empty">
        No devices enrolled yet. Run <code className="mono">luksmith enroll</code>{" "}
        on a managed host.
      </p>
    );
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
                    <span className="badge badge-warn" title="PCR7 measurement drift detected">
                      PCR7 drift
                    </span>
                  )}
                </td>
                <td className="mono dim">{d.id}</td>
                <td title={d.last_seen ? fmtTime(d.last_seen) : undefined}>
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
                    <span className="badge badge-warn" title="Rotation requested; awaiting agent check-in">
                      Rotation pending
                    </span>
                  )}
                </td>
                <td className="td-actions">
                  <button
                    className="btn btn-small"
                    onClick={() => onReveal(d)}
                    disabled={d.active_keys === 0}
                    title={d.active_keys === 0 ? "No active key escrowed" : "Reveal recovery key (audited)"}
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
  if (entries.length === 0) return <p className="empty">No audit events yet.</p>;
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
              <td title={fmtTime(a.ts)}>{relTime(a.ts)}</td>
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

// ---------------------------------------------------------------- portal

function Portal({ token, onLogout }: { token: string; onLogout: () => void }) {
  const [devices, setDevices] = useState<Device[] | null>(null);
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [tab, setTab] = useState<"devices" | "audit">("devices");
  const [error, setError] = useState<string | null>(null);
  const [revealFor, setRevealFor] = useState<Device | null>(null);
  const [rotating, setRotating] = useState<string | null>(null);

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
      await refresh();
    } catch (err) {
      if (err instanceof AuthError) return onLogout();
      setError(String(err instanceof Error ? err.message : err));
    } finally {
      setRotating(null);
    }
  }

  const total = devices?.length ?? 0;
  const escrowed = devices?.filter((d) => d.active_keys > 0).length ?? 0;

  return (
    <div className="portal">
      <header className="topbar">
        <div className="wordmark">
          <span aria-hidden="true">&#128273;</span> luksmith
        </div>
        <div className="topbar-stats">
          <span className="stat">
            <strong>{total}</strong> device{total === 1 ? "" : "s"}
          </span>
          <span className={`stat ${total > 0 && escrowed < total ? "stat-bad" : "stat-ok"}`}>
            escrow health: <strong>{escrowed}</strong> of <strong>{total}</strong> escrowed
          </span>
        </div>
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

        {error && <p className="form-error banner">{error}</p>}
        {devices === null ? (
          <p className="empty">Loading…</p>
        ) : tab === "devices" ? (
          <DevicesTable devices={devices} onReveal={setRevealFor} onRotate={rotate} rotating={rotating} />
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
        />
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
