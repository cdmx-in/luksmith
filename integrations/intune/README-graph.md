# luksmith-graph-notes.py — Intune device-notes pointer helper

Intune/Entra **cannot store a Linux recovery key** (the BitLocker key store is
read-only via Graph). But the per-device `managedDevice.notes` field *is*
writable via the beta Graph API. This helper stamps a **pointer** — the luksmith
portal deep-link plus the escrow key id — into each Intune device's notes, so a
helpdesk admin looking at a device in Intune can pivot straight to the luksmith
portal to reveal the actual key.

**Never put the key or ciphertext in Intune. Only the pointer.**

## Entra app permission

- `DeviceManagementManagedDevices.ReadWrite.All` — **Application** permission,
  **admin-consented** (API permissions → Microsoft Graph → Application
  permissions → *Grant admin consent*). ReadWrite is required because the helper
  PATCHes `managedDevice.notes`.

Auth is client-credentials OAuth2 against
`https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`, scope
`https://graph.microsoft.com/.default`.

## Credentials (flags or env)

| Flag | Env |
|------|-----|
| `--tenant` | `LUKSMITH_GRAPH_TENANT` |
| `--client-id` | `LUKSMITH_GRAPH_CLIENT_ID` |
| `--client-secret` | `LUKSMITH_GRAPH_CLIENT_SECRET` |
| `--portal-token` | `LUKSMITH_ADMIN_TOKEN` |

## Usage

```sh
# Stamp every portal device into its matching Intune managedDevice (by hostname)
python luksmith-graph-notes.py --from-portal https://portal:8443 \
    --portal-token "$LUKSMITH_ADMIN_TOKEN"

# One device, by hand
python luksmith-graph-notes.py --device web-01 \
    --pointer 'https://portal:8443/#device=abc123'

# Preview without calling Graph (no credentials needed)
python luksmith-graph-notes.py --device web-01 --pointer 'https://...' --dry-run
```

Devices are matched to Intune by `deviceName eq '<hostname>'`. The pointer is
written inside a delimited block so re-runs are **idempotent** and never clobber
notes a human wrote:

```
[luksmith]
recovery-key POINTER (not the key) - retrieve in the luksmith portal
portal: https://portal:8443/#device=abc123
escrow_key_id: <id>
[/luksmith]
```

A missing Intune device or a Graph 4xx on one device is reported and skipped —
the bulk run continues. `--self-test` exercises the notes-block upsert logic.
