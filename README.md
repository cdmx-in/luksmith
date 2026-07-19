# 🔑 luksmith

**Org-grade disk encryption management for Ubuntu — BitLocker + Intune parity for LUKS.**

BitLocker gives Windows fleets TPM auto-unlock, recovery keys escrowed to a portal, helpdesk retrieval with audit trails, and compliance reporting. Linux fleets get LUKS — excellent encryption, and none of the management. Every TPM tool stops at *"here's your recovery key, store it somewhere safe"*; every escrow tool ignores the TPM entirely; the only mainstream product that escrows LUKS keys at all paywalls it.

luksmith is the missing piece: a zero-dependency agent + self-hosted portal that does what BitLocker does, for Ubuntu.

| Capability | BitLocker + Intune | Fleet (Premium 💰) | clevis | sectpmctl | Ubuntu snap-FDE | **luksmith** |
|---|---|---|---|---|---|---|
| TPM2 auto-unlock on startup | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ |
| Recovery key auto-escrow to portal | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ |
| Server never sees plaintext key | ❌ | ❌ | — | — | — | ✅ (E2E RSA-OAEP) |
| Escrow-first gating (no unlock until key is safe) | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Boot classification (TPM ok vs fallback typed) | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ |
| PCR-drift detection + auto re-enroll | ✅ | ❌ | manual | ✅ | ✅ | ✅ |
| Audited key retrieval with mandatory reason | ✅ | partial | — | — | — | ✅ |
| Works on stock Ubuntu (GRUB + initramfs-tools) | — | ✅ | ✅ | ✅ | new installs only | ✅ |
| Free & open source | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ |

## Why this exists

Three facts make this project necessary:

1. **Stock Ubuntu can't TPM-unlock its root disk with systemd alone.** `systemd-cryptenroll --tpm2-device=auto` *succeeds*, then the boot prompt ignores it — Ubuntu's initramfs-tools doesn't understand TPM2 tokens ([LP #1980018](https://bugs.launchpad.net/ubuntu/+source/cryptsetup/+bug/1980018), deliberately unfixed). Working auto-unlock on stock installs needs clevis plus an initramfs fix luksmith applies for you.
2. **You cannot store Linux keys in Intune/Entra.** The BitLocker key store is read-only via Graph; its write path is welded to the Windows MDM stack. Intune can only *check* Linux encryption compliance. So the portal has to be yours — luksmith ships it.
3. **Nobody combines enrollment and escrow.** Fleet escrows but won't touch the TPM (and it's Premium-only). clevis/sectpmctl do TPM but have no server. luksmith does both, in the right order.

## Architecture

```mermaid
flowchart LR
    subgraph laptop [Ubuntu machine]
        A[luksmith agent] -->|systemd-cryptenroll| RK[recovery-key keyslot]
        A -->|clevis luks bind, PCR 7| TPM[TPM2 auto-unlock keyslot]
        A --> C[compliance.json]
    end
    subgraph portal [luksmith-server, self-hosted]
        K[(ciphertext store)] --- AU[append-only audit log]
        D[dashboard + REST API]
    end
    A -->|"recovery key encrypted to org RSA public key"| K
    C -->|custom compliance script| I[Microsoft Intune]
    H[helpdesk admin] -->|"reveal (reason required, audited)"| D
    H -->|org private key, offline| DEC[decrypt]
```

**The enrollment order is the product.** `luksmith enroll`:

1. Generates a recovery key into a real LUKS2 keyslot (`systemd-cryptenroll --recovery-key`) — it works at any passphrase prompt, on any Ubuntu.
2. Encrypts it to your org's RSA public key (`openssl pkeyutl`, RSA-OAEP/SHA-256) and escrows the **ciphertext** to the portal. The server, the network, and a database backup thief never see a usable key; decryption requires the org private key, which stays with your admins.
3. **Only after escrow succeeds** does it bind TPM auto-unlock (BitLocker's escrow-first semantics — a machine can never end up conveniently unlocked but unrecoverable).
4. Records a PCR 7 baseline for drift detection.

After every boot, `luksmith verify` (systemd timer) classifies the boot — did the TPM unlock it, or did a human have to type a secret? — by test-unsealing against *current* PCRs, detects PCR drift, re-binds automatically (`clevis luks regen`), and checks in to the portal.

## Quickstart

### 1. One-time org keypair (on an admin workstation, NOT the server)

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out org_private.pem
openssl pkey -in org_private.pem -pubout -out org_public.pem
```

`org_private.pem` decrypts every escrowed key — keep it offline (password manager / HSM). Only `org_public.pem` gets distributed.

### 2. Portal

```bash
git clone https://github.com/cdmx-in/luksmith && cd luksmith
LUKSMITH_ADMIN_TOKEN=$(openssl rand -hex 32) \
LUKSMITH_ENROLL_SECRET=$(openssl rand -hex 16) \
docker compose up -d
```

Two more ways to run it, same API and database either way:
- **Static binary** (Go, no runtime at all): grab `luksmith-server-linux-amd64` + `luksmith-ui.tar.gz` from [releases](https://github.com/cdmx-in/luksmith/releases), `./luksmith-server-linux-amd64 --ui-dir dist --admin-token ... --enroll-secret ...`
- **Zero-dependency Python**: `python3 server/luksmith_server.py --admin-token ... --enroll-secret ...`

Put TLS in front (Caddy/nginx) or pass `--tls-cert/--tls-key`. The web portal at `https://your-server:8443/` is a React admin UI — token login, device fleet with boot/escrow health, audited key reveals, rotation, audit log.

### 3. Agent (each Ubuntu 22.04/24.04 machine, disk already LUKS-encrypted)

```bash
curl -fsSL https://cdmx-in.github.io/luksmith/setup.sh | sudo sh   # adds the apt repo + keyring
sudo apt install luksmith
sudo luksmith enroll --server https://YOUR-PORTAL:8443 \
  --org-pubkey /etc/luksmith/org_public.pem --enroll-secret YOUR-SECRET
```

Updates then arrive via normal `sudo apt upgrade`. Alternatives: grab `luksmith.deb` straight from [releases](https://github.com/cdmx-in/luksmith/releases) (`sudo apt install ./luksmith.deb`), or `sudo ./install.sh` from a checkout.

**Fedora / RHEL / Rocky / AlmaLinux:** install the RPM from [releases](https://github.com/cdmx-in/luksmith/releases) (`sudo dnf install ./luksmith-*.noarch.rpm`) or build it from a checkout with `rpmbuild -bb packaging/luksmith.spec`. luksmith auto-detects the distro and defaults to `--mode systemd` there (RHEL-family ships dracut, so the native TPM path works with no clevis workaround), running `dracut --force` after enrollment so the token is picked up next boot.

Enroll prompts once for the existing LUKS passphrase, then: recovery key created → escrowed → TPM auto-unlock bound → PCR baseline stored. Next reboot: no passphrase prompt.

**Recovering a machine** (lost laptop, departed employee, broken TPM): click *Reveal* in the portal (reason mandatory, audited), decrypt on the admin workstation with `org_private.pem`, type the recovery key at the normal boot prompt.

### Intune integration

Intune can't hold the key, but it can *enforce that escrow happened*:

1. Upload [`integrations/intune/luksmith-discovery.sh`](integrations/intune/luksmith-discovery.sh) as a Linux custom-compliance script (it runs unprivileged and reads only the non-secret `compliance.json`).
2. Attach [`luksmith-compliance-rules.json`](integrations/intune/luksmith-compliance-rules.json) to a compliance policy.
3. Devices without an escrowed key go non-compliant → Conditional Access does the rest. Helpdesk pivots from the Intune device page to your luksmith portal for the actual key.

#### Recovery-key pointer in Intune device notes

Intune can't *store* the Linux key, but it can point to it. [`integrations/intune/luksmith-graph-notes.py`](integrations/intune/luksmith-graph-notes.py) stamps a **pointer** — the portal deep-link (`https://PORTAL/#device=<id>`) plus escrow key id — into each device's writable `managedDevice.notes` field via the beta Graph API, so helpdesk can pivot from the Intune device page straight to the portal. The key and ciphertext never leave the portal.

```sh
python integrations/intune/luksmith-graph-notes.py \
    --from-portal https://YOUR-PORTAL:8443 --portal-token "$LUKSMITH_ADMIN_TOKEN"
```

Requires an Entra app with `DeviceManagementManagedDevices.ReadWrite.All` (application permission, admin-consented); auth is client-credentials OAuth2. The pointer lives in an idempotent `[luksmith]…[/luksmith]` block so re-runs update in place; `--dry-run` previews without calling Graph. See [`integrations/intune/README-graph.md`](integrations/intune/README-graph.md).

## Portal admin accounts, roles & approvals

The master `--admin-token` still works as a superuser, but the portal also supports named admin accounts with roles, SSO, and two-person key release:

- **Roles:** `owner` (manage admins + everything), `admin` (rotate, request + approve reveals), `helpdesk` (request reveals only), `auditor` (read-only devices + audit log). Create accounts in the UI's **Admins** tab or `POST /api/v1/admins`.
- **SSO:** put the portal behind an auth proxy (oauth2-proxy / Authelia). With `--trust-proxy` + `--proxy-shared-secret`, luksmith maps the proxy-asserted email and groups to a role (`--sso-group-map`) — any IdP, no OIDC code in the server. Proxy headers are ignored unless the shared secret matches.
- **Two-person release:** with `--require-approval`, a reveal becomes a *request* — a second admin (never the requester) must approve it in the **Approvals** tab before the key is shown. Every request, approval, denial, and release is audited with both parties named.

## TPM modes

| Mode | When | How |
|---|---|---|
| `--mode clevis` | Default on Debian/Ubuntu (GRUB + initramfs-tools) | `clevis luks bind` on PCR 7 + the `tss`-user initramfs hook luksmith installs (works around the packaging gap that breaks TPM at early boot) |
| `--mode systemd` | Default on Fedora/RHEL (dracut); also Ubuntu ≥25.10 or non-root data volumes | Native `systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7` |
| `--no-tpm` | Servers/VMs without TPM, or escrow-only rollouts | Recovery key + escrow only; passphrase prompt remains |

The default follows the distro (`/etc/os-release`); `--mode` always overrides.

PCR policy is **7 only** (Secure Boot certificates) by default — routine kernel/GRUB updates don't change it, so no recovery prompts after `apt upgrade`. What *does* change it (Secure Boot toggles, dbx/firmware updates): `luksmith check-updates` flags pending fwupd updates marked `affects-fde` before you reboot, and `verify` re-binds automatically after (pass `--unlock-key-file` to let it rebind from scratch when the old binding can't unseal at all).

### Suspend (BitLocker-style, one reboot)

Firmware updates rewrite PCR 7 and break TPM auto-unlock on the next boot. Before a risky reboot:

```bash
sudo luksmith suspend            # or: sudo luksmith check-updates --suspend
```

This adds a *temporary* TPM slot with no PCR policy, so the machine still auto-unlocks after the update. On the next `luksmith verify`, once the boot is verified and any PCR drift is rebound, the temporary slot is removed automatically — suspension lasts exactly one reboot, like BitLocker's `Suspend-BitLocker`. `check-updates --suspend` chains detection and suspension (and still exits 2 so schedulers notice).

### TPM + PIN

```bash
sudo luksmith enroll --mode systemd --with-pin ...
```

Boot then requires the TPM state *and* a PIN (prompted by systemd) — BitLocker's TPM+PIN equivalent. systemd mode only; clevis has no PIN support and the agent refuses the combination.

### Software TPM (swtpm)

A set `TPM2TOOLS_TCTI` counts as a present TPM — tpm2-tools and clevis honor it, so the whole clevis lifecycle runs against `swtpm socket --tpm2` (use `sudo -E` to keep the variable). CI's `tpm-integration` job uses exactly this to prove enroll → verify → PCR drift → auto-rebind on every push.

## Hardware acceptance test

CI proves the escrow crypto and the software-TPM lifecycle, but the one thing it
can't cover is a real TPM unlocking a real disk. Before trusting luksmith on a
fleet, run the ~30-minute checklist in [HARDWARE-TEST.md](HARDWARE-TEST.md) on a
spare TPM machine: enroll → **reboot with no passphrase prompt** → reveal + decrypt
the escrowed key → confirm it opens the volume.

## Security model

- **E2E encryption:** keys are encrypted on the device to the org public key; the server stores ciphertext only. Compromising the server or its backups yields nothing usable without the org private key.
- **Escrow-first:** TPM convenience is never enabled before the recovery path is durably stored.
- **Audited retrieval:** every reveal requires a reason and lands in an append-only audit log; so do enrollments and escrows.
- **Honest ceiling:** TPM auto-unlock with an *unsigned* initramfs (any GRUB-based Ubuntu, luksmith or not) is weaker than BitLocker's signed-boot-chain binding — an attacker with disk access can tamper with the initramfs. This is Ubuntu's argument in LP #1980018 and it's fair. Mitigations: TPM+PIN (`systemd` mode on 24.04+ supports `--tpm2-with-pin`), or accept that the threat model is "lost/stolen laptop, powered off," which PCR-7-bound TPM unlock handles. The recovery key + escrow layers are unaffected either way.

## What CI proves

Every push exercises the full chain on a real LUKS2 volume — against **both** portal implementations: format → enroll → escrow → admin reveal → RSA decrypt → **the recovered key actually opens the volume** (`cryptsetup open --test-passphrase`) → admin-triggered rotation → **the old key no longer opens it, the new one does**. A separate job runs the **complete TPM lifecycle against a software TPM (swtpm)**: clevis enroll → verified TPM unlock → PCR 7 extended to simulate a firmware update → drift detected → automatic re-bind → verified TPM unlock again. Plus unit tests on Python 3.10/3.12, the agent suite on a Fedora container, Go tests (RBAC + escrow, matching the Python server), the Intune discovery script against fixture data, shellcheck, the UI build, and a Docker image build with live health check.

## Roadmap

- [ ] `systemd-pcrlock` support once usable on shipped Ubuntu (≥25.10/26.04)

## License

MIT © [Codemax IT Solutions Pvt Ltd](https://cdmx.in)
