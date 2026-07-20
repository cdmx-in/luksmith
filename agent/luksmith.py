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


def distro_family():
    """'rhel' for RHEL/Fedora/Rocky/Alma, else 'debian' (Ubuntu/Debian/default).

    Reads /etc/os-release ID and ID_LIKE. Missing file -> debian, the safe
    default: that's where the clevis + initramfs-tools workaround lives."""
    try:
        with open("/etc/os-release") as f:
            data = f.read()
    except OSError:
        return "debian"
    fields = dict(re.findall(r'^(ID|ID_LIKE)=["\']?([^"\'\n]*)', data, re.MULTILINE))
    ids = f"{fields.get('ID', '')} {fields.get('ID_LIKE', '')}".lower().split()
    return "rhel" if any(t in ids for t in ("rhel", "fedora", "centos")) else "debian"


def default_mode():
    """rhel-family defaults to systemd (dracut native TPM path); Debian to clevis."""
    return "systemd" if distro_family() == "rhel" else "clevis"


def regen_initramfs():
    """Rebuild the initramfs so a new keyslot/token is seen at boot.

    dracut on rhel-family, update-initramfs on Debian. Best-effort: failures
    are non-fatal — the binding lives in the LUKS header regardless (and CI
    runners have no cryptroot)."""
    cmd = ["dracut", "--force"] if distro_family() == "rhel" else ["update-initramfs", "-u"]
    p = run(cmd, stdin=None)
    if p.returncode != 0:
        print(f"luksmith: warning: {cmd[0]} failed: {(p.stderr or '').strip()}",
              file=sys.stderr)


def has_tpm():
    # TPM2TOOLS_TCTI covers software TPMs (swtpm) — tpm2-tools and clevis
    # both honor it, and child processes inherit it automatically.
    return (os.path.exists("/dev/tpmrm0") or os.path.exists("/dev/tpm0")
            or bool(os.environ.get("TPM2TOOLS_TCTI")))


def luks_tokens(device):
    """Token types present in the LUKS2 header, e.g. ['clevis', 'systemd-recovery']."""
    p = run(["cryptsetup", "luksDump", device])
    if p.returncode != 0:
        return []
    return re.findall(r"^\s+\d+:\s+(\S+)$", p.stdout, re.MULTILINE)


def clevis_tpm2_slots(device):
    """All clevis tpm2 keyslot numbers."""
    p = run(["clevis", "luks", "list", "-d", device])
    if p.returncode != 0:
        return []
    return [int(m) for m in re.findall(r"^(\d+):\s+tpm2", p.stdout, re.MULTILINE)]


def clevis_tpm2_slot(device):
    """First clevis tpm2 keyslot number, or None."""
    slots = clevis_tpm2_slots(device)
    return slots[0] if slots else None


def clevis_slot(device, pin):
    """First clevis keyslot bound with `pin` (tpm2/tang/sss), or None."""
    p = run(["clevis", "luks", "list", "-d", device])
    if p.returncode != 0:
        return None
    m = re.search(rf"^(\d+):\s+{pin}\b", p.stdout, re.MULTILINE)
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
        "unlock_mode": state.get("tpm_mode"),  # clevis/systemd (TPM), tang (network), or null
        "recovery_key_escrowed": bool(state.get("recovery_escrowed")),
        "escrow_key_id": state.get("escrow_key_id"),
        "last_verify": state.get("last_verify"),
        "last_boot_class": state.get("last_boot_class"),
        "suspended": bool(state.get("suspended")),
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
        "pin": bool(state.get("pin")),
        "suspended": bool(state.get("suspended")),
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


def tpm_bind(device, mode, pcrs, unlock_key_file, with_pin=False, tang_url=None):
    if mode == "tang":
        # Network-bound auto-unlock (clevis + Tang, NBDE): the BitLocker-without-
        # -TPM analog. clevis mints a fresh random key per machine, split against
        # the Tang server's key — no shared secret, no TPM. Off-network the
        # recovery keyslot still unlocks. No PCRs, so no drift/tss-hook needed.
        if not shutil.which("clevis"):
            die("clevis not installed (apt install clevis clevis-luks clevis-initramfs)")
        cmd = ["clevis", "luks", "bind", "-y", "-d", device, "tang",
               json.dumps({"url": tang_url})]  # -y: auto-trust the org's Tang key
        if unlock_key_file:
            cmd[4:4] = ["-k", unlock_key_file]
        p = run(cmd, stdin=None)
        if p.returncode != 0:
            die(f"clevis luks bind (tang) failed: {(p.stderr or '').strip()}")
        regen_initramfs()  # network unlock lives in initramfs (clevis-initramfs)
        return
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
        # The tss-user hook is a Debian/initramfs-tools workaround; rhel uses
        # dracut's own clevis module. Regen is best-effort either way: the TPM
        # binding lives in the LUKS header regardless (CI has no cryptroot).
        if distro_family() == "debian":
            try:
                install_tss_hook()
            except OSError as e:
                print(f"luksmith: warning: tss hook install failed: {e}", file=sys.stderr)
        regen_initramfs()
    else:  # systemd (dracut / non-root volumes)
        cmd = ["systemd-cryptenroll", "--tpm2-device=auto", f"--tpm2-pcrs={pcrs}"]
        if with_pin:
            cmd.append("--tpm2-with-pin=yes")  # PIN prompt is systemd's own
        if unlock_key_file:
            cmd.append(f"--unlock-key-file={unlock_key_file}")
        cmd.append(device)
        p = run(cmd, stdin=None)
        if p.returncode != 0:
            die(f"systemd-cryptenroll tpm2 enrollment failed: {(p.stderr or '').strip()}")
        # dracut native path: regenerate so the enrolled TPM2 token is picked
        # up at boot. Debian systemd mode (non-root data volumes) needs no regen.
        if distro_family() == "rhel":
            regen_initramfs()


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
    if args.mode is None:
        args.mode = default_mode()
    if args.with_pin and args.mode != "systemd":
        die("--with-pin requires --mode systemd (and a dracut initrd): "
            "TPM+PIN is a systemd-cryptenroll feature; clevis has no PIN support")
    if args.mode == "tang" and not args.tang_url:
        die("--mode tang requires --tang-url http://TANG-SERVER "
            "(network-bound auto-unlock, no TPM needed)")
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

    # 4. Only now: auto-unlock binding.
    if args.mode == "tang":
        # Network-bound: no TPM required, so bind regardless of has_tpm().
        tpm_bind(device, "tang", None, args.unlock_key_file, tang_url=args.tang_url)
        state["tpm_mode"] = "tang"
        state["tang_url"] = args.tang_url
    elif args.no_tpm or not has_tpm():
        state["tpm_mode"] = None
        print("recovery key escrowed; skipping TPM bind"
              + ("" if has_tpm() else " (no TPM present)"))
    else:
        tpm_bind(device, args.mode, args.pcrs, args.unlock_key_file, args.with_pin)
        state["tpm_mode"] = args.mode
        state["pcrs"] = args.pcrs
        state["pin"] = bool(args.with_pin)
        state["pcr7_baseline"] = read_pcr7()
        if state["pcr7_baseline"] is None:
            print("luksmith: warning: TPM bound but PCR baseline unreadable "
                  "(is tpm2-tools installed?) — drift detection is disabled",
                  file=sys.stderr)

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
    if mode in ("clevis", "tang"):
        pin = "tpm2" if mode == "clevis" else "tang"
        slot = clevis_slot(device, pin)
        if slot is None:
            return "tpm_binding_missing"
        # If the secret can't be recovered now (drifted PCRs, or Tang server
        # unreachable), it can't have auto-unlocked this boot either -> a human
        # typed the recovery key.
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
        slots = [s for s in clevis_tpm2_slots(state["luks_device"])
                 if s != state.get("suspend_slot")]
        slot = slots[0] if slots else None
        if slot is not None:
            # regen recovers the passphrase from an existing clevis binding
            # (e.g. a PCR-less suspend slot survives drift) or prompts; with
            # stdin closed a prompt just fails instead of hanging.
            p = run(["clevis", "luks", "regen", "-q", "-d", state["luks_device"],
                     "-s", str(slot)], stdin=subprocess.DEVNULL)
            regenerated = p.returncode == 0
            if not regenerated and args.unlock_key_file:
                # After drift the old secret can't be unsealed, so rebind
                # from scratch against current PCRs using the provided key.
                run(["clevis", "luks", "unbind", "-d", state["luks_device"],
                     "-s", str(slot), "-f"])
                tpm_bind(state["luks_device"], "clevis",
                         state.get("pcrs", "7"), args.unlock_key_file)
                regenerated = True
            if regenerated:
                state["pcr7_baseline"] = read_pcr7()
                drift = False

    # BitLocker semantics: suspension lasts exactly one reboot. Once this
    # boot is verified and any drift is rebound, drop the temporary slot.
    if state.get("suspended") and not drift:
        clear_suspension(state)

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


def cmd_rotate(args):
    """New recovery key, escrowed, old recovery slots wiped.

    Wipe and enrollment happen in one systemd-cryptenroll call (the newly
    enrolled slot is excepted from wiping), so there is no window with zero
    recovery slots. If the subsequent escrow fails, compliance.json flags the
    device un-escrowed and Intune/portal show it red until a retry succeeds.
    """
    state = load_json(STATE_PATH, {})
    config = load_json(CONFIG_PATH, {})
    if not state.get("device_id"):
        die("not enrolled; run `luksmith enroll` first")
    device = state["luks_device"]

    cmd = ["systemd-cryptenroll", "--wipe-slot=recovery", "--recovery-key"]
    if args.unlock_key_file:
        cmd.append(f"--unlock-key-file={args.unlock_key_file}")
    cmd.append(device)
    p = run(cmd, stdin=None)
    if p.returncode != 0:
        die(f"recovery key rotation failed: {(p.stderr or '').strip()}")
    m = RECOVERY_KEY_RE.search(p.stdout or "")
    if not m:
        die("could not parse rotated recovery key from systemd-cryptenroll output")

    state["recovery_escrowed"] = False
    save_json(STATE_PATH, state)
    write_compliance(state)

    ciphertext = encrypt_to_org_key(m.group(0), config["org_pubkey"])
    resp = api(config, "POST", "/api/v1/keys",
               {"device_id": state["device_id"], "ciphertext": ciphertext},
               token=state["device_token"])
    state["recovery_escrowed"] = True
    state["escrow_key_id"] = resp.get("key_id")
    save_json(STATE_PATH, state)
    write_compliance(state)
    print(json.dumps({"rotated": True, "escrow_key_id": state["escrow_key_id"]},
                     indent=2))


def do_suspend(state, unlock_key_file):
    """Add a TEMPORARY non-PCR-bound TPM protector (BitLocker suspend).

    The next reboot auto-unlocks even if firmware updates change PCR 7;
    `verify` removes the slot after that one boot.
    """
    if not has_tpm():
        die("no TPM available; nothing to suspend")
    if state.get("suspended"):
        print(json.dumps({"suspended": True,
                          "suspend_slot": state.get("suspend_slot")}, indent=2))
        return
    device = state.get("luks_device") or pick_device(None)
    state["luks_device"] = device
    mode = state.get("tpm_mode") or "clevis"
    if mode == "clevis":
        before = set(clevis_tpm2_slots(device))
        cmd = ["clevis", "luks", "bind", "-d", device, "tpm2", "{}"]  # no PCR policy
        if unlock_key_file:
            cmd[3:3] = ["-k", unlock_key_file]
        p = run(cmd, stdin=None)
        if p.returncode != 0:
            die(f"clevis suspend bind failed: {(p.stderr or '').strip()}")
        new = set(clevis_tpm2_slots(device)) - before
        state["suspend_slot"] = min(new) if new else None
    else:
        cmd = ["systemd-cryptenroll", "--tpm2-device=auto", "--tpm2-pcrs="]
        if unlock_key_file:
            cmd.append(f"--unlock-key-file={unlock_key_file}")
        cmd.append(device)
        p = run(cmd, stdin=None)
        if p.returncode != 0:
            die(f"systemd-cryptenroll suspend enrollment failed: {(p.stderr or '').strip()}")
        m = re.search(r"key slot (\d+)", p.stdout or "")
        state["suspend_slot"] = int(m.group(1)) if m else None
    state["suspended"] = True
    save_json(STATE_PATH, state)
    write_compliance(state)
    print(json.dumps({"suspended": True,
                      "suspend_slot": state["suspend_slot"]}, indent=2))


def clear_suspension(state):
    """Remove the temporary PCR-less slot and drop the suspended flag."""
    slot = state.get("suspend_slot")
    if slot is None:
        print("luksmith: warning: suspend slot unknown; remove any PCR-less "
              "TPM slot manually", file=sys.stderr)
    else:
        if state.get("tpm_mode") == "systemd":
            p = run(["systemd-cryptenroll", f"--wipe-slot={slot}",
                     state["luks_device"]])
        else:
            p = run(["clevis", "luks", "unbind", "-d", state["luks_device"],
                     "-s", str(slot), "-f"])
        if p.returncode != 0:
            print(f"luksmith: warning: could not remove suspend slot {slot}: "
                  f"{(p.stderr or '').strip()}", file=sys.stderr)
            return False
    state["suspended"] = False
    state.pop("suspend_slot", None)
    return True


def cmd_suspend(args):
    state = load_json(STATE_PATH, {})
    if args.device:
        state["luks_device"] = args.device
    do_suspend(state, args.unlock_key_file)


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
    # fwupd behaves identically across distros; the manual-update trigger hint
    # differs (dnf/rpm vs apt/dpkg), surfaced so schedulers can act per-distro.
    pkg_mgr = "dnf" if distro_family() == "rhel" else "apt"
    print(json.dumps({"fde_breaking_updates": risky, "pkg_manager": pkg_mgr}, indent=2))
    if risky:
        if getattr(args, "suspend", False):
            do_suspend(load_json(STATE_PATH, {}),
                       getattr(args, "unlock_key_file", None))
        sys.exit(2)  # still exit 2 so schedulers notice


def main(argv=None):
    ap = argparse.ArgumentParser(prog="luksmith", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status", help="report LUKS/TPM/enrollment state as JSON")

    en = sub.add_parser("enroll", help="recovery key + escrow + TPM auto-unlock")
    en.add_argument("--server", help="portal URL, e.g. https://keys.example.com")
    en.add_argument("--org-pubkey", help="path to org RSA public key (PEM)")
    en.add_argument("--enroll-secret", help="shared enrollment secret")
    en.add_argument("--device", help="LUKS device (auto-detected if single)")
    en.add_argument("--mode", choices=["clevis", "systemd", "tang"], default=None,
                    help="auto-unlock mode (default: clevis on Debian/Ubuntu, "
                         "systemd on RHEL/Fedora). clevis/systemd = TPM; "
                         "tang = network-bound (clevis+Tang), no TPM needed")
    en.add_argument("--tang-url", help="Tang server URL, required for --mode tang "
                                       "(e.g. http://tang.example.com)")
    en.add_argument("--pcrs", default="7", help="PCR list to bind (default: 7)")
    en.add_argument("--unlock-key-file", help="existing passphrase file (non-interactive)")
    en.add_argument("--no-tpm", action="store_true",
                    help="escrow only, skip TPM auto-unlock")
    en.add_argument("--with-pin", action="store_true",
                    help="require a PIN at boot in addition to the TPM "
                         "(systemd mode only; PIN prompt is interactive)")

    ve = sub.add_parser("verify", help="post-boot: classify boot, detect PCR drift, re-enroll")
    ve.add_argument("--no-regen", action="store_true", help="report only, never rebind")
    ve.add_argument("--unlock-key-file",
                    help="passphrase file used to rebind when the sealed "
                         "secret can no longer be unsealed after PCR drift")

    ro = sub.add_parser("rotate", help="replace + re-escrow the recovery key")
    ro.add_argument("--unlock-key-file", help="existing passphrase file (non-interactive)")

    su = sub.add_parser("suspend",
                        help="add a temporary PCR-less TPM slot before a risky "
                             "reboot (auto-removed by verify after one boot)")
    su.add_argument("--device", help="LUKS device (auto-detected if single)")
    su.add_argument("--unlock-key-file", help="existing passphrase file (non-interactive)")

    cu = sub.add_parser("check-updates", help="warn about pending PCR-breaking firmware updates")
    cu.add_argument("--suspend", action="store_true",
                    help="auto-suspend TPM PCR policy when FDE-breaking updates are found")
    cu.add_argument("--unlock-key-file", help="existing passphrase file (non-interactive)")

    args = ap.parse_args(argv)
    {"status": cmd_status, "enroll": cmd_enroll, "verify": cmd_verify,
     "rotate": cmd_rotate, "suspend": cmd_suspend,
     "check-updates": cmd_check_updates}[args.cmd](args)


if __name__ == "__main__":
    main()
