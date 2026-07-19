#!/usr/bin/env python3
"""luksmith — org-grade LUKS management for Ubuntu.

BitLocker parity for LUKS: TPM2 auto-unlock enrollment, recovery-key
generation, escrow to a central portal (E2E-encrypted to the org's RSA
public key via openssl), post-boot verification, and PCR-drift
re-enrollment.

Stdlib only. Root required for everything except `status`.
"""

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

CONFIG_DIR = "/etc/luksmith"
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")
STATE_DIR = "/var/lib/luksmith"
STATE_PATH = os.path.join(STATE_DIR, "state.json")
COMPLIANCE_PATH = os.path.join(STATE_DIR, "compliance.json")

# systemd-cryptenroll recovery keys: 64 modhex chars in 8 dash-joined groups.
RECOVERY_KEY_RE = re.compile(r"\b(?:[cbdefghijklnrtuv]{8}-){7}[cbdefghijklnrtuv]{8}\b")

TPM_FAILURE_MARKERS = (
    "Failed to unseal secret using TPM2",
    "TPM2 operation failed, falling back to traditional unlocking",
    "PCR have changed since checked",
)


def run(cmd, **kwargs):
    """Single choke point for subprocess calls (mocked in tests).

    A missing binary (no TPM stack, no fwupd, ...) reports like a failed
    command instead of crashing the agent."""
    kwargs.setdefault("capture_output", True)
    kwargs.setdefault("text", True)
    try:
        return subprocess.run(cmd, **kwargs)
    except FileNotFoundError:
        err = f"{cmd[0]}: not found"
        if not kwargs.get("text"):
            err = err.encode()
        return subprocess.CompletedProcess(cmd, 127, None, err)


def die(msg, code=1):
    print(f"luksmith: error: {msg}", file=sys.stderr)
    sys.exit(code)


def load_json(path, default=None):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def save_json(path, data, mode=0o600):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


# ---------------------------------------------------------------- discovery

def find_luks_devices():
    """All crypto_LUKS block devices, via lsblk JSON."""
    p = run(["lsblk", "-J", "-p", "-o", "NAME,PATH,FSTYPE,TYPE"])
    if p.returncode != 0:
        return []
    devices = []

    def walk(nodes):
        for n in nodes:
            if n.get("fstype") == "crypto_LUKS":
                devices.append(n.get("path") or n.get("name"))
            walk(n.get("children", []))

    walk(json.loads(p.stdout).get("blockdevices", []))
    return devices


def pick_device(explicit):
    if explicit:
        return explicit
    devs = find_luks_devices()
    if not devs:
        die("no LUKS devices found (is the disk encrypted?)")
    if len(devs) > 1:
        die(f"multiple LUKS devices found ({', '.join(devs)}); pass --device")
    return devs[0]


def has_tpm():
    return os.path.exists("/dev/tpmrm0") or os.path.exists("/dev/tpm0")


def luks_tokens(device):
    """Token types present in the LUKS2 header, e.g. ['clevis', 'systemd-recovery']."""
    p = run(["cryptsetup", "luksDump", device])
    if p.returncode != 0:
        return []
    return re.findall(r"^\s+\d+:\s+(\S+)$", p.stdout, re.MULTILINE)


def clevis_tpm2_slot(device):
    """First clevis tpm2 keyslot number, or None."""
    p = run(["clevis", "luks", "list", "-d", device])
    if p.returncode != 0:
        return None
    m = re.search(r"^(\d+):\s+tpm2", p.stdout, re.MULTILINE)
    return int(m.group(1)) if m else None


def read_pcr7():
    """Current sha256 PCR 7 value as hex, or None without a TPM."""
    p = run(["tpm2_pcrread", "sha256:7"])
    if p.returncode != 0:
        return None
    m = re.search(r"7\s*:\s*0x([0-9A-Fa-f]+)", p.stdout)
    return m.group(1).lower() if m else None


# ------------------------------------------------------------------ escrow

def encrypt_to_org_key(secret, org_pubkey_path):
    """RSA-OAEP encrypt `secret` to the org public key via openssl.

    E2E: the server only ever stores this ciphertext; decryption needs the
    org private key, which never leaves the admin's custody.
    """
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(secret.encode())
        tmp = tf.name
    try:
        p = run(
            ["openssl", "pkeyutl", "-encrypt", "-pubin", "-inkey", org_pubkey_path,
             "-pkeyopt", "rsa_padding_mode:oaep", "-pkeyopt", "rsa_oaep_md:sha256",
             "-in", tmp],
            text=False, capture_output=True,
        )
    finally:
        os.unlink(tmp)
    if p.returncode != 0:
        die(f"openssl encryption failed: {p.stderr.decode(errors='replace').strip()}")
    return base64.b64encode(p.stdout).decode()


def api(config, method, path, payload=None, token=None):
    url = config["server_url"].rstrip("/") + path
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    if config.get("enroll_secret"):
        req.add_header("X-Enroll-Secret", config["enroll_secret"])
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        die(f"server returned {e.code} for {path}: {e.read().decode(errors='replace')[:200]}")
    except urllib.error.URLError as e:
        die(f"cannot reach server at {url}: {e.reason}")


def machine_id():
    try:
        with open("/etc/machine-id") as f:
            return f.read().strip()
    except OSError:
        return hashlib.sha256(socket.gethostname().encode()).hexdigest()[:32]


# ------------------------------------------------------------ compliance

def write_compliance(state, extra=None):
    """Non-secret status file, world-readable, consumed by the Intune
    custom-compliance discovery script (which runs without root)."""
    data = {
        "disk_encrypted": True,
        "tpm_bound": bool(state.get("tpm_mode")),
        "recovery_key_escrowed": bool(state.get("recovery_escrowed")),
        "escrow_key_id": state.get("escrow_key_id"),
        "last_verify": state.get("last_verify"),
        "last_boot_class": state.get("last_boot_class"),
    }
    if extra:
        data.update(extra)
    save_json(COMPLIANCE_PATH, data, mode=0o644)


# ------------------------------------------------------------- commands

def cmd_status(args):
    devs = find_luks_devices()
    state = load_json(STATE_PATH, {})
    out = {
        "luks_devices": devs,
        "tpm_present": has_tpm(),
        "enrolled": bool(state.get("device_id")),
        "tpm_mode": state.get("tpm_mode"),
        "recovery_key_escrowed": bool(state.get("recovery_escrowed")),
        "pcr7_baseline": state.get("pcr7_baseline"),
        "pcr7_current": read_pcr7(),
        "last_boot_class": state.get("last_boot_class"),
    }
    print(json.dumps(out, indent=2))


def enroll_recovery_key(device, unlock_key_file):
    """Generate a recovery key slot; capture the key from stdout."""
    cmd = ["systemd-cryptenroll", "--recovery-key"]
    if unlock_key_file:
        cmd.append(f"--unlock-key-file={unlock_key_file}")
    cmd.append(device)
    # Interactive when no unlock keyfile: systemd-cryptenroll prompts for the
    # existing passphrase itself, so inherit the TTY but capture stdout.
    p = run(cmd, stdin=None)
    if p.returncode != 0:
        die(f"systemd-cryptenroll --recovery-key failed: {(p.stderr or '').strip()}")
    m = RECOVERY_KEY_RE.search(p.stdout or "")
    if not m:
        die("could not parse recovery key from systemd-cryptenroll output")
    return m.group(0)


def tpm_bind(device, mode, pcrs, unlock_key_file):
    if mode == "clevis":
        if not shutil.which("clevis"):
            die("clevis not installed (apt install clevis clevis-luks clevis-tpm2 clevis-initramfs tpm2-tools)")
        cfg = json.dumps({"pcr_bank": "sha256", "pcr_ids": str(pcrs)})
        cmd = ["clevis", "luks", "bind", "-d", device, "tpm2", cfg]
        if unlock_key_file:
            cmd[3:3] = ["-k", unlock_key_file]
        p = run(cmd, stdin=None)
        if p.returncode != 0:
            die(f"clevis luks bind failed: {(p.stderr or '').strip()}")
        install_tss_hook()
        run(["update-initramfs", "-u"], stdin=None)
    else:  # systemd (dracut / non-root volumes)
        cmd = ["systemd-cryptenroll", "--tpm2-device=auto", f"--tpm2-pcrs={pcrs}"]
        if unlock_key_file:
            cmd.append(f"--unlock-key-file={unlock_key_file}")
        cmd.append(device)
        p = run(cmd, stdin=None)
        if p.returncode != 0:
            die(f"systemd-cryptenroll tpm2 enrollment failed: {(p.stderr or '').strip()}")


TSS_HOOK_PATH = "/etc/initramfs-tools/hooks/luksmith-tss-user"
# Ubuntu's clevis-initramfs omits the tss user from the initramfs, which
# breaks tpm2 tools at early boot (see README: LP #1980018 context).
TSS_HOOK = """#!/bin/sh
PREREQ=""
prereqs() { echo "$PREREQ"; }
case "$1" in prereqs) prereqs; exit 0;; esac
. /usr/share/initramfs-tools/hook-functions
getent passwd tss >> "${DESTDIR}/etc/passwd" || true
getent group tss >> "${DESTDIR}/etc/group" || true
exit 0
"""


def install_tss_hook():
    if os.path.isdir(os.path.dirname(TSS_HOOK_PATH)) and not os.path.exists(TSS_HOOK_PATH):
        with open(TSS_HOOK_PATH, "w") as f:
            f.write(TSS_HOOK)
        os.chmod(TSS_HOOK_PATH, 0o755)


def cmd_enroll(args):
    config = load_json(CONFIG_PATH, {})
    if args.server:
        config["server_url"] = args.server
    if args.org_pubkey:
        config["org_pubkey"] = args.org_pubkey
    if args.enroll_secret:
        config["enroll_secret"] = args.enroll_secret
    for key in ("server_url", "org_pubkey"):
        if not config.get(key):
            die(f"missing --{key.replace('_', '-')} (or set it in {CONFIG_PATH})")

    device = pick_device(args.device)
    state = load_json(STATE_PATH, {})

    # 1. Register with the portal.
    if not state.get("device_id"):
        resp = api(config, "POST", "/api/v1/devices/enroll",
                   {"hostname": socket.gethostname(), "machine_id": machine_id()})
        state.update(device_id=resp["device_id"], device_token=resp["device_token"])
        save_json(STATE_PATH, state)

    # 2. Recovery key first.
    recovery_key = enroll_recovery_key(device, args.unlock_key_file)

    # 3. ESCROW-FIRST GATE (BitLocker semantics): the key must be safely on
    #    the server before any TPM auto-unlock exists. If escrow fails we
    #    stop here and the machine still requires its passphrase.
    ciphertext = encrypt_to_org_key(recovery_key, config["org_pubkey"])
    resp = api(config, "POST", "/api/v1/keys",
               {"device_id": state["device_id"], "ciphertext": ciphertext},
               token=state["device_token"])
    state["recovery_escrowed"] = True
    state["escrow_key_id"] = resp.get("key_id")
    del recovery_key, ciphertext

    # 4. Only now: TPM auto-unlock binding.
    if args.no_tpm or not has_tpm():
        state["tpm_mode"] = None
        print("recovery key escrowed; skipping TPM bind"
              + ("" if has_tpm() else " (no TPM present)"))
    else:
        tpm_bind(device, args.mode, args.pcrs, args.unlock_key_file)
        state["tpm_mode"] = args.mode
        state["pcr7_baseline"] = read_pcr7()

    state["luks_device"] = device
    save_json(STATE_PATH, state)
    save_json(CONFIG_PATH, config)
    write_compliance(state)
    print(json.dumps({"enrolled": True, "device": device,
                      "escrow_key_id": state.get("escrow_key_id"),
                      "tpm_mode": state.get("tpm_mode")}, indent=2))


def classify_boot(state):
    """Did this boot auto-unlock via TPM, or did a human type a secret?"""
    device = state.get("luks_device")
    mode = state.get("tpm_mode")
    if not mode:
        return "no_tpm_binding"
    if mode == "clevis":
        slot = clevis_tpm2_slot(device)
        if slot is None:
            return "tpm_binding_missing"
        # If the sealed secret can't be unsealed against *current* PCRs, it
        # cannot have unlocked this boot either -> a human typed a secret.
        p = run(["clevis", "luks", "pass", "-d", device, "-s", str(slot)])
        return "tpm_unlock_ok" if p.returncode == 0 else "fallback_used"
    # systemd mode: the initrd journal records the unseal outcome.
    p = run(["journalctl", "-b", "-o", "cat", "--no-pager"])
    text = p.stdout or ""
    if any(marker in text for marker in TPM_FAILURE_MARKERS):
        return "fallback_used"
    return "tpm_unlock_ok"


def cmd_verify(args):
    import datetime
    state = load_json(STATE_PATH, {})
    if not state.get("device_id"):
        die("not enrolled; run `luksmith enroll` first")
    config = load_json(CONFIG_PATH, {})

    boot_class = classify_boot(state)
    current = read_pcr7()
    drift = bool(state.get("pcr7_baseline") and current
                 and current != state["pcr7_baseline"])

    regenerated = False
    if (drift or boot_class == "fallback_used") and state.get("tpm_mode") == "clevis" \
            and not args.no_regen:
        slot = clevis_tpm2_slot(state["luks_device"])
        if slot is not None:
            p = run(["clevis", "luks", "regen", "-q", "-d", state["luks_device"],
                     "-s", str(slot)])
            regenerated = p.returncode == 0
            if regenerated:
                state["pcr7_baseline"] = read_pcr7()
                drift = False

    state["last_boot_class"] = boot_class
    state["last_verify"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    save_json(STATE_PATH, state)
    write_compliance(state, {"pcr7_drift": drift})

    report = {"boot_class": boot_class, "pcr7_drift": drift,
              "rebound": regenerated}
    if config.get("server_url"):
        resp = api(config, "POST", f"/api/v1/devices/{state['device_id']}/checkin",
                   report, token=state.get("device_token"))
        if resp.get("rotate_requested"):
            report["rotate_requested"] = True
    print(json.dumps(report, indent=2))


def cmd_check_updates(args):
    """Flag pending updates that will change PCR 7 (fwupd `affects-fde`)."""
    p = run(["fwupdmgr", "get-updates", "--json"])
    risky = []
    if p.returncode == 0 and p.stdout:
        try:
            for dev in json.loads(p.stdout).get("Devices", []):
                for rel in dev.get("Releases", []):
                    flags = rel.get("Flags", [])
                    if "affects-fde" in flags:
                        risky.append({"device": dev.get("Name"),
                                      "update": rel.get("Version")})
        except ValueError:
            pass
    print(json.dumps({"fde_breaking_updates": risky}, indent=2))
    if risky:
        # ponytail: report-only for now; BitLocker-style pre-suspend
        # (temporary PCR-less slot before reboot) is the upgrade path.
        sys.exit(2)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="luksmith", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status", help="report LUKS/TPM/enrollment state as JSON")

    en = sub.add_parser("enroll", help="recovery key + escrow + TPM auto-unlock")
    en.add_argument("--server", help="portal URL, e.g. https://keys.example.com")
    en.add_argument("--org-pubkey", help="path to org RSA public key (PEM)")
    en.add_argument("--enroll-secret", help="shared enrollment secret")
    en.add_argument("--device", help="LUKS device (auto-detected if single)")
    en.add_argument("--mode", choices=["clevis", "systemd"], default="clevis",
                    help="TPM bind mode: clevis = stock Ubuntu (initramfs-tools); "
                         "systemd = dracut installs / non-root volumes")
    en.add_argument("--pcrs", default="7", help="PCR list to bind (default: 7)")
    en.add_argument("--unlock-key-file", help="existing passphrase file (non-interactive)")
    en.add_argument("--no-tpm", action="store_true",
                    help="escrow only, skip TPM auto-unlock")

    ve = sub.add_parser("verify", help="post-boot: classify boot, detect PCR drift, re-enroll")
    ve.add_argument("--no-regen", action="store_true", help="report only, never rebind")

    sub.add_parser("check-updates", help="warn about pending PCR-breaking firmware updates")

    args = ap.parse_args(argv)
    {"status": cmd_status, "enroll": cmd_enroll,
     "verify": cmd_verify, "check-updates": cmd_check_updates}[args.cmd](args)


if __name__ == "__main__":
    main()
