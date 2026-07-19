#!/usr/bin/env python3
"""luksmith - stamp a recovery-key POINTER into Intune device notes.

Intune/Entra cannot STORE a Linux LUKS recovery key: the BitLocker key store is
read-only via Graph and its write path is welded to the Windows MDM stack. But
the per-device `managedDevice.notes` field IS writable via the beta Graph API.
So this helper stamps a POINTER - the luksmith portal deep-link + escrow key id
for that device - into the Intune device's notes, letting a helpdesk admin pivot
straight from the Intune device page to the luksmith portal to reveal the key.

  NEVER put the key or ciphertext here. Only the pointer.

The pointer lives inside a delimited block so re-runs are idempotent and never
clobber notes a human wrote:

    [luksmith]
    ... pointer ...
    [/luksmith]

Two modes:
  --from-portal https://PORTAL   pull the device list from a luksmith portal and
                                 stamp every matching Intune device
  --device NAME --pointer URL     stamp one device by hand

Stdlib only (urllib). See --help for the required Entra app permission.
"""

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

GRAPH = "https://graph.microsoft.com"
LOGIN = "https://login.microsoftonline.com"

# The delimited, idempotently-replaceable pointer block.
BEGIN, END = "[luksmith]", "[/luksmith]"
BLOCK_RE = re.compile(re.escape(BEGIN) + r".*?" + re.escape(END), re.DOTALL)


class GraphError(Exception):
    pass


# ----------------------------------------------------------- notes block logic

def upsert_block(existing, body):
    """Return `existing` notes with the luksmith pointer block set to `body`.

    Replaces an existing [luksmith]..[/luksmith] block in place (preserving all
    surrounding text); appends one if absent; returns just the block if notes
    were empty. This is the one piece of real logic - it has a self-test."""
    block = BEGIN + "\n" + body.strip() + "\n" + END
    existing = existing or ""
    if BLOCK_RE.search(existing):
        # lambda replacement: body may contain regex-special chars / backslashes.
        return BLOCK_RE.sub(lambda _m: block, existing, count=1)
    if existing.strip():
        return existing.rstrip() + "\n\n" + block
    return block


def pointer_body(portal_url, escrow_key_id=None):
    lines = ["recovery-key POINTER (not the key) - retrieve in the luksmith portal",
             "portal: " + portal_url]
    if escrow_key_id:
        lines.append("escrow_key_id: " + str(escrow_key_id))
    return "\n".join(lines)


def portal_pointer_url(portal_base, device_id):
    return portal_base.rstrip("/") + "/#device=" + urllib.parse.quote(str(device_id))


# --------------------------------------------------------------------- http

def _post_form(url, fields):
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())


def get_token(tenant, client_id, client_secret):
    url = f"{LOGIN}/{urllib.parse.quote(tenant)}/oauth2/v2.0/token"
    try:
        resp = _post_form(url, {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": f"{GRAPH}/.default",
        })
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:300]
        raise GraphError(f"token request failed ({e.code}): {detail}")
    except urllib.error.URLError as e:
        raise GraphError(f"cannot reach {LOGIN}: {e.reason}")
    tok = resp.get("access_token")
    if not tok:
        raise GraphError(f"no access_token in token response: {resp}")
    return tok


def _graph(token, method, path, body=None):
    url = GRAPH + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", "Bearer " + token)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read().decode()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:300]
        raise GraphError(f"Graph {method} {path} -> {e.code}: {detail}")
    except urllib.error.URLError as e:
        raise GraphError(f"cannot reach Graph: {e.reason}")


def find_device_id(token, device_name):
    """managedDevice id for a deviceName, or None. Raises GraphError on failure."""
    flt = urllib.parse.quote(f"deviceName eq '{device_name}'")
    resp = _graph(token, "GET",
                  f"/beta/deviceManagement/managedDevices?$filter={flt}")
    vals = resp.get("value") or []
    if not vals:
        return None
    if len(vals) > 1:
        sys.stderr.write(
            f"  note: {len(vals)} Intune devices named {device_name!r}; using first\n")
    return vals[0].get("id")


def get_notes(token, device_id):
    resp = _graph(token, "GET",
                  f"/beta/deviceManagement/managedDevices/{device_id}?$select=notes")
    return resp.get("notes") or ""


def patch_notes(token, device_id, notes):
    _graph(token, "PATCH",
           f"/beta/deviceManagement/managedDevices/{device_id}", {"notes": notes})


# ------------------------------------------------------------------ portal

def portal_devices(portal_base, admin_token):
    url = portal_base.rstrip("/") + "/api/v1/devices"
    req = urllib.request.Request(url, method="GET")
    req.add_header("Authorization", "Bearer " + admin_token)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode()).get("devices", [])
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:300]
        raise GraphError(f"portal {url} -> {e.code}: {detail}")
    except urllib.error.URLError as e:
        raise GraphError(f"cannot reach portal {url}: {e.reason}")


def device_escrow_key_id(dev):
    """Best-effort escrow key id from a portal device record (may be absent)."""
    if dev.get("escrow_key_id"):
        return dev["escrow_key_id"]
    rep = dev.get("last_report") or {}
    return rep.get("escrow_key_id")


# ------------------------------------------------------------------- driver

def stamp_one(token, device_name, body, dry_run):
    """Upsert the pointer block on one Intune device. Returns True on success.

    Never raises for a per-device problem - reports and returns False so a bulk
    run keeps going."""
    try:
        if dry_run:
            new = upsert_block("<existing notes fetched at run time>", body)
            print(f"[dry-run] {device_name}: would PATCH notes ->")
            print(_indent(new))
            return True
        dev_id = find_device_id(token, device_name)
        if not dev_id:
            sys.stderr.write(f"  MISS {device_name}: no Intune managedDevice\n")
            return False
        new = upsert_block(get_notes(token, dev_id), body)
        patch_notes(token, dev_id, new)
        print(f"  OK   {device_name} ({dev_id})")
        return True
    except GraphError as e:
        sys.stderr.write(f"  FAIL {device_name}: {e}\n")
        return False


def _indent(text):
    return "\n".join("    " + ln for ln in text.splitlines())


def run_from_portal(token, portal_base, admin_token, dry_run):
    devices = portal_devices(portal_base, admin_token)
    if not devices:
        print("portal returned no devices; nothing to stamp")
        return 0
    ok = 0
    for dev in devices:
        hostname = dev.get("hostname")
        if not hostname:
            continue
        body = pointer_body(portal_pointer_url(portal_base, dev.get("id")),
                            device_escrow_key_id(dev))
        if stamp_one(token, hostname, body, dry_run):
            ok += 1
    print(f"stamped {ok}/{len(devices)} device(s)")
    return 0 if ok == len(devices) else 1


def run_manual(token, device_name, pointer, dry_run):
    body = pointer_body(pointer)
    return 0 if stamp_one(token, device_name, body, dry_run) else 1


# -------------------------------------------------------------------- self-test

def self_test():
    # replace preserves surrounding text
    before = "asset tag 42\n\n[luksmith]\nold\n[/luksmith]\n\nowned by IT"
    out = upsert_block(before, "portal: X")
    assert "asset tag 42" in out and "owned by IT" in out, out
    assert "old" not in out and "portal: X" in out, out
    assert out.count(BEGIN) == 1 and out.count(END) == 1, out

    # append when a block is absent, keeping the human note
    out = upsert_block("hand-written note", "portal: Y")
    assert out.startswith("hand-written note"), out
    assert out.endswith(END) and "portal: Y" in out, out

    # empty notes -> just the block
    assert upsert_block("", "portal: Z") == BEGIN + "\nportal: Z\n" + END
    assert upsert_block(None, "portal: Z").startswith(BEGIN)

    # a second run over already-stamped notes is stable (idempotent)
    once = upsert_block("keep me", "portal: A")
    assert upsert_block(once, "portal: A") == once, "not idempotent"

    # body with regex-special chars survives the sub()
    out = upsert_block(before, "portal: http://h/#d=a\\b$1")
    assert "http://h/#d=a\\b$1" in out, out

    # pointer url shape
    assert portal_pointer_url("https://p:8443/", "dev1") == "https://p:8443/#device=dev1"
    print("self-test OK")
    return 0


# -------------------------------------------------------------------------- cli

EPILOG = """\
required Entra app permission:
  DeviceManagementManagedDevices.ReadWrite.All  (APPLICATION permission,
  admin-consented). Grant it on your app registration under API permissions ->
  Microsoft Graph -> Application permissions, then click "Grant admin consent".
  Read-only ReadWrite is required because the helper PATCHes managedDevice.notes.

  Auth is client-credentials OAuth2 against
  {login}/{{tenant}}/oauth2/v2.0/token with scope {graph}/.default.

credentials (flags or env):
  --tenant / LUKSMITH_GRAPH_TENANT
  --client-id / LUKSMITH_GRAPH_CLIENT_ID
  --client-secret / LUKSMITH_GRAPH_CLIENT_SECRET
  --portal-token / LUKSMITH_ADMIN_TOKEN   (for --from-portal)

examples:
  # stamp every portal device into its matching Intune device
  luksmith-graph-notes.py --from-portal https://portal:8443 --portal-token $TOK
  # one device, by hand, preview only
  luksmith-graph-notes.py --device web-01 \\
      --pointer 'https://portal:8443/#device=abc123' --dry-run
""".format(login=LOGIN, graph=GRAPH)


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Stamp a luksmith recovery-key pointer into Intune device notes.",
        epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--tenant", default=os.environ.get("LUKSMITH_GRAPH_TENANT"))
    p.add_argument("--client-id", default=os.environ.get("LUKSMITH_GRAPH_CLIENT_ID"))
    p.add_argument("--client-secret",
                   default=os.environ.get("LUKSMITH_GRAPH_CLIENT_SECRET"))
    p.add_argument("--from-portal", metavar="PORTAL_URL",
                   help="pull device list from this luksmith portal and stamp all")
    p.add_argument("--portal-token", default=os.environ.get("LUKSMITH_ADMIN_TOKEN"),
                   help="portal admin bearer token (env LUKSMITH_ADMIN_TOKEN)")
    p.add_argument("--device", help="single Intune deviceName to stamp")
    p.add_argument("--pointer", help="pointer URL for --device mode")
    p.add_argument("--dry-run", action="store_true",
                   help="print the notes that would be PATCHed; call nothing")
    p.add_argument("--self-test", action="store_true",
                   help="run the notes-block upsert self-check and exit")
    args = p.parse_args(argv)

    if args.self_test:
        return self_test()

    if not args.from_portal and not (args.device and args.pointer):
        p.error("use --from-portal PORTAL_URL, or --device NAME --pointer URL")

    # --dry-run never touches Graph, so it needs no credentials.
    token = None
    if not args.dry_run:
        if not (args.tenant and args.client_id and args.client_secret):
            p.error("Graph auth needs --tenant, --client-id and --client-secret "
                    "(or their LUKSMITH_GRAPH_* env vars); or add --dry-run")
        try:
            token = get_token(args.tenant, args.client_id, args.client_secret)
        except GraphError as e:
            sys.stderr.write(f"auth failed: {e}\n")
            return 2

    try:
        if args.from_portal:
            if not args.portal_token:
                p.error("--from-portal needs --portal-token (or LUKSMITH_ADMIN_TOKEN)")
            return run_from_portal(token, args.from_portal, args.portal_token,
                                   args.dry_run)
        return run_manual(token, args.device, args.pointer, args.dry_run)
    except GraphError as e:
        sys.stderr.write(f"error: {e}\n")
        return 2


if __name__ == "__main__":
    sys.exit(main())
