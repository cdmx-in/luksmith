# Hardware acceptance test

CI proves the escrow crypto and the software-TPM lifecycle, but it can't prove a
*real* TPM auto-unlocks a *real* disk at boot. This is the one manual test to run
before trusting luksmith on a fleet. Budget ~30 minutes.

## Prerequisites

- A **spare / wipeable** machine with a TPM 2.0 and UEFI Secure Boot enabled
  (check: `ls /dev/tpmrm0` exists, `mokutil --sb-state` says enabled).
- A fresh Ubuntu 22.04/24.04 (or Fedora/RHEL) install with **LUKS full-disk
  encryption** selected during setup, so you know the passphrase.
- A reachable luksmith portal and the org public key on the machine. Bring up a
  throwaway portal if needed:
  ```bash
  LUKSMITH_ADMIN_TOKEN=$(openssl rand -hex 32) \
  LUKSMITH_ENROLL_SECRET=$(openssl rand -hex 16) \
  docker compose up -d
  ```
  Note both secrets. Generate the org keypair on your workstation and copy only
  `org_public.pem` to the test machine (`/etc/luksmith/org_public.pem`).

> ⚠️ Do this on a machine you can afford to reinstall. A wrong PCR binding or a
> firmware quirk can leave you at the recovery prompt — which is exactly what
> you're testing, but plan for a reinstall just in case.

## Steps

1. **Install & enroll**
   ```bash
   curl -fsSL https://cdmx-in.github.io/luksmith/setup.sh | sudo sh
   sudo apt install luksmith          # dnf on Fedora/RHEL
   sudo luksmith enroll --server https://YOUR-PORTAL:8443 \
     --org-pubkey /etc/luksmith/org_public.pem --enroll-secret YOUR-SECRET
   ```
   Expect: prompts once for the existing LUKS passphrase, then JSON with
   `"enrolled": true`, an `escrow_key_id`, and a `tpm_mode`.

2. **Confirm state before rebooting**
   ```bash
   sudo luksmith status
   ```
   Expect `tpm_present: true`, `recovery_key_escrowed: true`, a non-null
   `tpm_mode`, and a `pcr7_baseline`.

3. **★ The actual test — reboot**
   ```bash
   sudo reboot
   ```
   **PASS = the machine boots to the login screen with no passphrase prompt.**
   FAIL = you get the LUKS passphrase prompt (TPM binding didn't take — capture
   `journalctl -b -1 | grep -i tpm` after logging in).

4. **Verify the portal & boot classification**
   ```bash
   sudo luksmith verify
   ```
   Expect `"boot_class": "tpm_unlock_ok"`. Then open the portal — the device
   should show a green **TPM unlock** badge and **Escrowed**.

5. **Recovery drill** (prove the escrow actually works)
   - In the portal, **Reveal** the device's key (enter a reason — it's audited).
   - On your workstation, decrypt it:
     ```bash
     echo "<ciphertext>" | base64 -d | openssl pkeyutl -decrypt \
       -inkey org_private.pem -pkeyopt rsa_padding_mode:oaep \
       -pkeyopt rsa_oaep_md:sha256
     ```
   - Confirm the printed recovery key is accepted at the LUKS prompt (reboot and
     type it, or `sudo cryptsetup open --test-passphrase <dev>`).

6. **Drift & re-bind** (optional but recommended)
   - `sudo luksmith suspend`, then change a BIOS setting or run a firmware update
     and reboot. The machine should still auto-unlock (suspend slot).
   - `sudo luksmith verify` should detect PCR drift, re-bind, and clear the
     suspension. A final `verify` reports `tpm_unlock_ok` again.

## Pass criteria

| # | Check | Pass |
|---|-------|------|
| 1 | Enroll returns `enrolled: true` + escrow id | ☐ |
| 2 | `status` shows TPM bound + key escrowed | ☐ |
| 3 | **Reboots with no passphrase prompt** | ☐ |
| 4 | `verify` = `tpm_unlock_ok`, portal badge green | ☐ |
| 5 | Revealed+decrypted key opens the volume | ☐ |
| 6 | Suspend survives a firmware change; verify re-binds | ☐ |

All six green on at least one Ubuntu and (if targeting it) one Fedora/RHEL
machine → luksmith is validated for that hardware class. Record the make/model
and firmware version tested — TPM behaviour varies by vendor.
