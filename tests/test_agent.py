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


class TestRun(unittest.TestCase):
    def test_missing_binary_reports_as_failure_not_crash(self):
        p = luksmith.run(["definitely-not-a-real-binary-xyz"])
        self.assertEqual(p.returncode, 127)
        self.assertIn("not found", p.stderr)
        # e.g. read_pcr7 on a TPM-less machine must degrade to None
        with mock.patch.object(luksmith.subprocess, "run",
                               side_effect=FileNotFoundError):
            self.assertIsNone(luksmith.read_pcr7())


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

    def test_tang_unseal_ok(self):
        # tang mode reuses the clevis unseal path but keys off the tang pin.
        def fake(cmd, **kw):
            if cmd[:3] == ["clevis", "luks", "list"]:
                return proc("1: tang '{\"url\":\"http://tang\"}'\n")
            if cmd[:3] == ["clevis", "luks", "pass"]:
                return proc("sekrit")
            raise AssertionError(cmd)
        state = {"luks_device": "/dev/sda3", "tpm_mode": "tang"}
        with mock.patch.object(luksmith, "run", side_effect=fake):
            self.assertEqual(luksmith.classify_boot(state), "tpm_unlock_ok")

    def test_tang_server_unreachable_means_fallback(self):
        def fake(cmd, **kw):
            if cmd[:3] == ["clevis", "luks", "list"]:
                return proc("1: tang '{\"url\":\"http://tang\"}'\n")
            return proc("", 1, "Error communicating with server")
        state = {"luks_device": "/dev/sda3", "tpm_mode": "tang"}
        with mock.patch.object(luksmith, "run", side_effect=fake):
            self.assertEqual(luksmith.classify_boot(state), "fallback_used")


class TestTangBind(unittest.TestCase):
    def test_tang_bind_uses_tang_pin_and_url(self):
        calls = []

        def fake(cmd, **kw):
            calls.append(cmd)
            return proc("")
        with mock.patch.object(luksmith, "run", side_effect=fake), \
                mock.patch.object(luksmith.shutil, "which", return_value="/usr/bin/clevis"), \
                mock.patch.object(luksmith, "regen_initramfs"):
            luksmith.tpm_bind("/dev/sda3", "tang", None, "/tmp/pass.key",
                              tang_url="http://tang.example.com")
        bind = next(c for c in calls if c[:3] == ["clevis", "luks", "bind"])
        self.assertIn("tang", bind)
        self.assertIn('{"url": "http://tang.example.com"}', bind)
        self.assertIn("-y", bind)  # non-interactive: auto-trust the org Tang key
        self.assertIn("-k", bind)  # unlock keyfile threaded through


class TestHasTpm(unittest.TestCase):
    def test_tcti_env_counts_as_tpm(self):
        with mock.patch.object(luksmith.os.path, "exists", return_value=False):
            with mock.patch.dict(luksmith.os.environ,
                                 {"TPM2TOOLS_TCTI": "swtpm:port=2321"}):
                self.assertTrue(luksmith.has_tpm())
            with mock.patch.dict(luksmith.os.environ, {}, clear=True):
                self.assertFalse(luksmith.has_tpm())

    def test_dev_tpm_still_detected(self):
        with mock.patch.object(luksmith.os.path, "exists",
                               side_effect=lambda p: p == "/dev/tpmrm0"), \
                mock.patch.dict(luksmith.os.environ, {}, clear=True):
            self.assertTrue(luksmith.has_tpm())


class TestSuspend(unittest.TestCase):
    def test_clevis_suspend_binds_pcrless_and_records_slot(self):
        state = {"luks_device": "/dev/sda3", "tpm_mode": "clevis"}
        lists = iter(["1: tpm2 '{...}'\n", "1: tpm2 '{...}'\n2: tpm2 '{}'\n"])
        calls = []

        def fake(cmd, **kw):
            calls.append(cmd)
            if cmd[:3] == ["clevis", "luks", "list"]:
                return proc(next(lists))
            if cmd[:3] == ["clevis", "luks", "bind"]:
                return proc("")
            raise AssertionError(cmd)

        with mock.patch.object(luksmith, "run", side_effect=fake), \
                mock.patch.object(luksmith, "has_tpm", return_value=True), \
                mock.patch.object(luksmith, "save_json"), \
                mock.patch.object(luksmith, "write_compliance"), \
                mock.patch("builtins.print"):
            luksmith.do_suspend(state, None)
        bind = next(c for c in calls if c[:3] == ["clevis", "luks", "bind"])
        self.assertEqual(bind[-2:], ["tpm2", "{}"])  # empty config = no PCR policy
        self.assertEqual(state["suspend_slot"], 2)
        self.assertTrue(state["suspended"])

    def test_systemd_suspend_uses_empty_pcr_list(self):
        state = {"luks_device": "/dev/sda3", "tpm_mode": "systemd"}
        calls = []

        def fake(cmd, **kw):
            calls.append(cmd)
            return proc("New TPM2 token enrolled as key slot 3.")

        with mock.patch.object(luksmith, "run", side_effect=fake), \
                mock.patch.object(luksmith, "has_tpm", return_value=True), \
                mock.patch.object(luksmith, "save_json"), \
                mock.patch.object(luksmith, "write_compliance"), \
                mock.patch("builtins.print"):
            luksmith.do_suspend(state, "/tmp/pass")
        self.assertEqual(calls[0][:2], ["systemd-cryptenroll", "--tpm2-device=auto"])
        self.assertIn("--tpm2-pcrs=", calls[0])
        self.assertIn("--unlock-key-file=/tmp/pass", calls[0])
        self.assertEqual(state["suspend_slot"], 3)
        self.assertTrue(state["suspended"])

    def test_clear_suspension_unbinds_and_clears(self):
        state = {"luks_device": "/dev/sda3", "tpm_mode": "clevis",
                 "suspended": True, "suspend_slot": 2}
        calls = []
        with mock.patch.object(
                luksmith, "run",
                side_effect=lambda cmd, **kw: (calls.append(cmd), proc(""))[1]):
            self.assertTrue(luksmith.clear_suspension(state))
        self.assertEqual(calls, [["clevis", "luks", "unbind", "-d", "/dev/sda3",
                                  "-s", "2", "-f"]])
        self.assertFalse(state["suspended"])
        self.assertNotIn("suspend_slot", state)

    def test_verify_clears_suspension_after_clean_boot(self):
        state = {"device_id": "d", "luks_device": "/dev/sda3", "tpm_mode": "clevis",
                 "suspended": True, "suspend_slot": 2}
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)
            if cmd[:3] == ["clevis", "luks", "list"]:
                return proc("1: tpm2 '{...}'\n2: tpm2 '{}'\n")
            if cmd[:3] == ["clevis", "luks", "pass"]:
                return proc("sekrit")
            if cmd[:3] == ["clevis", "luks", "unbind"]:
                return proc("")
            if cmd[0] == "tpm2_pcrread":
                return proc("  7 : 0xAB\n")
            raise AssertionError(cmd)

        args = mock.Mock(no_regen=False, unlock_key_file=None)
        with mock.patch.object(luksmith, "load_json",
                               side_effect=lambda p, d=None:
                               state if p == luksmith.STATE_PATH else {}), \
                mock.patch.object(luksmith, "run", side_effect=fake_run), \
                mock.patch.object(luksmith, "save_json"), \
                mock.patch.object(luksmith, "write_compliance"), \
                mock.patch("builtins.print"):
            luksmith.cmd_verify(args)
        self.assertIn(["clevis", "luks", "unbind", "-d", "/dev/sda3", "-s", "2", "-f"],
                      calls)
        self.assertFalse(state["suspended"])
        self.assertNotIn("suspend_slot", state)

    def test_check_updates_suspend_flag_triggers_suspend(self):
        payload = json.dumps({"Devices": [
            {"Name": "FW", "Releases": [{"Version": "1", "Flags": ["affects-fde"]}]}]})
        args = mock.Mock(suspend=True, unlock_key_file="/tmp/pass")
        with mock.patch.object(luksmith, "run", return_value=proc(payload)), \
                mock.patch.object(luksmith, "do_suspend") as ds, \
                mock.patch.object(luksmith, "load_json",
                                  return_value={"luks_device": "/dev/x"}), \
                mock.patch.object(luksmith.sys, "exit") as ex, \
                mock.patch("builtins.print"):
            luksmith.cmd_check_updates(args)
        ds.assert_called_once_with({"luks_device": "/dev/x"}, "/tmp/pass")
        ex.assert_called_once_with(2)

    def test_check_updates_no_flag_does_not_suspend(self):
        payload = json.dumps({"Devices": [
            {"Name": "FW", "Releases": [{"Version": "1", "Flags": ["affects-fde"]}]}]})
        args = mock.Mock(suspend=False)
        with mock.patch.object(luksmith, "run", return_value=proc(payload)), \
                mock.patch.object(luksmith, "do_suspend") as ds, \
                mock.patch.object(luksmith.sys, "exit"), \
                mock.patch("builtins.print"):
            luksmith.cmd_check_updates(args)
        ds.assert_not_called()


class TestWithPin(unittest.TestCase):
    def test_systemd_bind_appends_pin_flag(self):
        calls = []
        with mock.patch.object(
                luksmith, "run",
                side_effect=lambda cmd, **kw: (calls.append(cmd), proc(""))[1]):
            luksmith.tpm_bind("/dev/x", "systemd", "7", None, with_pin=True)
        self.assertIn("--tpm2-with-pin=yes", calls[0])

    def test_systemd_bind_without_pin_omits_flag(self):
        calls = []
        with mock.patch.object(
                luksmith, "run",
                side_effect=lambda cmd, **kw: (calls.append(cmd), proc(""))[1]):
            luksmith.tpm_bind("/dev/x", "systemd", "7", None)
        self.assertNotIn("--tpm2-with-pin=yes", calls[0])

    def test_clevis_mode_rejects_pin(self):
        args = mock.Mock(mode="clevis", with_pin=True)
        with mock.patch("builtins.print"), self.assertRaises(SystemExit):
            luksmith.cmd_enroll(args)


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


class TestDistro(unittest.TestCase):
    OS_RELEASE = {
        'NAME="Ubuntu"\nID=ubuntu\nID_LIKE=debian\n': "debian",
        'ID=fedora\nVERSION_ID=41\n': "rhel",
        'ID="rhel"\nID_LIKE="fedora"\n': "rhel",
        'ID="rocky"\nID_LIKE="rhel centos fedora"\n': "rhel",
        'ID="almalinux"\nID_LIKE="rhel centos fedora"\n': "rhel",
    }

    def test_distro_family_parsing(self):
        for data, expected in self.OS_RELEASE.items():
            with mock.patch("builtins.open", mock.mock_open(read_data=data)):
                self.assertEqual(luksmith.distro_family(), expected, data)

    def test_os_release_missing_defaults_debian(self):
        with mock.patch("builtins.open", side_effect=OSError):
            self.assertEqual(luksmith.distro_family(), "debian")

    def test_default_mode_by_family(self):
        with mock.patch.object(luksmith, "distro_family", return_value="rhel"):
            self.assertEqual(luksmith.default_mode(), "systemd")
        with mock.patch.object(luksmith, "distro_family", return_value="debian"):
            self.assertEqual(luksmith.default_mode(), "clevis")

    def test_systemd_bind_on_rhel_regenerates_via_dracut_not_initramfs(self):
        calls = []
        with mock.patch.object(
                luksmith, "run",
                side_effect=lambda cmd, **kw: (calls.append(cmd), proc(""))[1]), \
                mock.patch.object(luksmith, "distro_family", return_value="rhel"):
            luksmith.tpm_bind("/dev/x", "systemd", "7", None)
        cmds = [c[0] for c in calls]
        self.assertIn("dracut", cmds)
        self.assertNotIn("update-initramfs", cmds)

    def test_clevis_bind_on_rhel_skips_tss_hook_and_initramfs(self):
        calls = []
        with mock.patch.object(
                luksmith, "run",
                side_effect=lambda cmd, **kw: (calls.append(cmd), proc(""))[1]), \
                mock.patch.object(luksmith, "distro_family", return_value="rhel"), \
                mock.patch.object(luksmith, "install_tss_hook") as hook, \
                mock.patch.object(luksmith.shutil, "which", return_value="/usr/bin/clevis"):
            luksmith.tpm_bind("/dev/x", "clevis", "7", None)
        hook.assert_not_called()
        cmds = [c[0] for c in calls]
        self.assertNotIn("update-initramfs", cmds)
        self.assertIn("dracut", cmds)

    def test_debian_systemd_bind_regenerates_nothing(self):
        # backward compat: systemd mode on Debian never touched the initramfs.
        calls = []
        with mock.patch.object(
                luksmith, "run",
                side_effect=lambda cmd, **kw: (calls.append(cmd), proc(""))[1]), \
                mock.patch.object(luksmith, "distro_family", return_value="debian"):
            luksmith.tpm_bind("/dev/x", "systemd", "7", None)
        cmds = [c[0] for c in calls]
        self.assertNotIn("dracut", cmds)
        self.assertNotIn("update-initramfs", cmds)


if __name__ == "__main__":
    unittest.main()
