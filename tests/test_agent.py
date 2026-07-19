"""Unit tests for the luksmith agent (pure parsing + classification logic).

Subprocess calls go through luksmith.run(), mocked here — these tests run on
any OS. The real cryptsetup/TPM path is exercised by CI's integration job.
"""

import json
import os
import subprocess
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))
import luksmith  # noqa: E402


def proc(stdout="", returncode=0, stderr=""):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


LSBLK = json.dumps({"blockdevices": [
    {"name": "/dev/sda", "path": "/dev/sda", "fstype": None, "type": "disk",
     "children": [
         {"name": "/dev/sda1", "path": "/dev/sda1", "fstype": "vfat", "type": "part"},
         {"name": "/dev/sda3", "path": "/dev/sda3", "fstype": "crypto_LUKS", "type": "part",
          "children": [{"name": "/dev/mapper/root", "path": "/dev/mapper/root",
                        "fstype": "ext4", "type": "crypt"}]}]}]})


class TestDiscovery(unittest.TestCase):
    def test_finds_single_luks_device(self):
        with mock.patch.object(luksmith, "run", return_value=proc(LSBLK)):
            self.assertEqual(luksmith.find_luks_devices(), ["/dev/sda3"])

    def test_lsblk_failure_is_empty(self):
        with mock.patch.object(luksmith, "run", return_value=proc("", 1)):
            self.assertEqual(luksmith.find_luks_devices(), [])

    def test_luks_tokens_parse(self):
        dump = "Tokens:\n  0: clevis\n\tKeyslot:    1\n  1: systemd-recovery\n\tKeyslot:  2\n"
        with mock.patch.object(luksmith, "run", return_value=proc(dump)):
            self.assertEqual(luksmith.luks_tokens("/dev/sda3"),
                             ["clevis", "systemd-recovery"])

    def test_clevis_slot_parse(self):
        with mock.patch.object(luksmith, "run", return_value=proc("1: tpm2 '{...}'\n")):
            self.assertEqual(luksmith.clevis_tpm2_slot("/dev/sda3"), 1)
        with mock.patch.object(luksmith, "run", return_value=proc("")):
            self.assertIsNone(luksmith.clevis_tpm2_slot("/dev/sda3"))

    def test_pcr7_parse(self):
        out = "  sha256:\n    7 : 0xA3B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1\n"
        with mock.patch.object(luksmith, "run", return_value=proc(out)):
            self.assertEqual(luksmith.read_pcr7(),
                             "a3b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1")


class TestRecoveryKey(unittest.TestCase):
    KEY = "cbdefghi-jklnrtuv-cbdefghi-jklnrtuv-cbdefghi-jklnrtuv-cbdefghi-jklnrtuv"

    def test_regex_matches_modhex_key(self):
        blob = f"A secret recovery key has been generated:\n\n    {self.KEY}\n"
        self.assertEqual(luksmith.RECOVERY_KEY_RE.search(blob).group(0), self.KEY)

    def test_regex_rejects_non_modhex(self):
        bad = "aaaaaaaa-" * 7 + "aaaaaaaa"  # 'a' is not in the modhex alphabet
        self.assertIsNone(luksmith.RECOVERY_KEY_RE.search(bad))

    def test_enroll_parses_key_from_stdout(self):
        with mock.patch.object(luksmith, "run",
                               return_value=proc(f"key:\n{self.KEY}\n")):
            self.assertEqual(luksmith.enroll_recovery_key("/dev/x", None), self.KEY)


class TestClassifyBoot(unittest.TestCase):
    STATE = {"luks_device": "/dev/sda3", "tpm_mode": "clevis"}

    def test_unbound_state(self):
        self.assertEqual(luksmith.classify_boot({"tpm_mode": None}), "no_tpm_binding")

    def test_clevis_unseal_ok(self):
        def fake(cmd, **kw):
            if cmd[:3] == ["clevis", "luks", "list"]:
                return proc("1: tpm2 '{...}'\n")
            if cmd[:3] == ["clevis", "luks", "pass"]:
                return proc("sekrit")
            raise AssertionError(cmd)
        with mock.patch.object(luksmith, "run", side_effect=fake):
            self.assertEqual(luksmith.classify_boot(self.STATE), "tpm_unlock_ok")

    def test_clevis_unseal_fails_means_fallback(self):
        def fake(cmd, **kw):
            if cmd[:3] == ["clevis", "luks", "list"]:
                return proc("1: tpm2 '{...}'\n")
            return proc("", 1, "unseal failed")
        with mock.patch.object(luksmith, "run", side_effect=fake):
            self.assertEqual(luksmith.classify_boot(self.STATE), "fallback_used")

    def test_systemd_mode_reads_journal(self):
        state = {"luks_device": "/dev/sda3", "tpm_mode": "systemd"}
        with mock.patch.object(luksmith, "run",
                               return_value=proc("Failed to unseal secret using TPM2\n")):
            self.assertEqual(luksmith.classify_boot(state), "fallback_used")
        with mock.patch.object(luksmith, "run", return_value=proc("all fine\n")):
            self.assertEqual(luksmith.classify_boot(state), "tpm_unlock_ok")


class TestFwupdParse(unittest.TestCase):
    def test_affects_fde_flag_detected(self):
        payload = json.dumps({"Devices": [
            {"Name": "System Firmware",
             "Releases": [{"Version": "1.2", "Flags": ["affects-fde"]}]},
            {"Name": "NVMe", "Releases": [{"Version": "9", "Flags": []}]}]})
        with mock.patch.object(luksmith, "run", return_value=proc(payload)), \
                mock.patch.object(luksmith.sys, "exit") as ex, \
                mock.patch("builtins.print") as pr:
            luksmith.cmd_check_updates(None)
        ex.assert_called_once_with(2)
        out = json.loads(pr.call_args[0][0])
        self.assertEqual(out["fde_breaking_updates"],
                         [{"device": "System Firmware", "update": "1.2"}])


if __name__ == "__main__":
    unittest.main()
