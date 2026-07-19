"""Unit tests for the Intune graph-notes pointer helper.

Pure stdlib, no network: urllib is mocked. The helper filename has hyphens, so
it is loaded by path rather than imported by name.
"""

import io
import json
import os
import unittest
from unittest import mock
import importlib.util

_PATH = os.path.join(os.path.dirname(__file__), "..",
                     "integrations", "intune", "luksmith-graph-notes.py")
_spec = importlib.util.spec_from_file_location("gn", _PATH)
gn = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gn)


class UpsertBlock(unittest.TestCase):
    def test_replace_preserves_surrounding_text(self):
        before = "tag 42\n\n[luksmith]\nold\n[/luksmith]\n\nowned by IT"
        out = gn.upsert_block(before, "portal: X")
        self.assertIn("tag 42", out)
        self.assertIn("owned by IT", out)
        self.assertNotIn("old", out)
        self.assertIn("portal: X", out)
        self.assertEqual(out.count(gn.BEGIN), 1)
        self.assertEqual(out.count(gn.END), 1)

    def test_append_when_absent(self):
        out = gn.upsert_block("hand note", "portal: Y")
        self.assertTrue(out.startswith("hand note"))
        self.assertTrue(out.rstrip().endswith(gn.END))
        self.assertIn("portal: Y", out)

    def test_empty_and_none(self):
        self.assertEqual(gn.upsert_block("", "portal: Z"),
                         gn.BEGIN + "\nportal: Z\n" + gn.END)
        self.assertTrue(gn.upsert_block(None, "portal: Z").startswith(gn.BEGIN))

    def test_idempotent(self):
        once = gn.upsert_block("keep me", "portal: A")
        self.assertEqual(gn.upsert_block(once, "portal: A"), once)

    def test_regex_special_body_survives(self):
        before = "x\n[luksmith]\nold\n[/luksmith]\ny"
        out = gn.upsert_block(before, "portal: http://h/#d=a\\b$1")
        self.assertIn("http://h/#d=a\\b$1", out)

    def test_pointer_url(self):
        self.assertEqual(gn.portal_pointer_url("https://p:8443/", "d1"),
                         "https://p:8443/#device=d1")


class GraphFlow(unittest.TestCase):
    """find_device_id / patch route through the mocked _graph."""

    def test_find_device_id_first_of_many(self):
        with mock.patch.object(gn, "_graph",
                               return_value={"value": [{"id": "A"}, {"id": "B"}]}):
            self.assertEqual(gn.find_device_id("t", "web-01"), "A")

    def test_find_device_id_missing(self):
        with mock.patch.object(gn, "_graph", return_value={"value": []}):
            self.assertIsNone(gn.find_device_id("t", "nope"))

    def test_stamp_one_missing_device_continues(self):
        # Missing device -> returns False, does not raise (bulk run keeps going).
        with mock.patch.object(gn, "find_device_id", return_value=None):
            self.assertFalse(gn.stamp_one("t", "ghost", "body", dry_run=False))

    def test_stamp_one_upserts_existing_notes(self):
        captured = {}
        with mock.patch.object(gn, "find_device_id", return_value="ID1"), \
             mock.patch.object(gn, "get_notes", return_value="human note"), \
             mock.patch.object(gn, "patch_notes",
                               side_effect=lambda t, i, n: captured.update(notes=n)):
            ok = gn.stamp_one("t", "web-01", "portal: P", dry_run=False)
        self.assertTrue(ok)
        self.assertIn("human note", captured["notes"])
        self.assertIn("portal: P", captured["notes"])

    def test_stamp_one_graph_error_is_caught(self):
        with mock.patch.object(gn, "find_device_id",
                               side_effect=gn.GraphError("boom")):
            self.assertFalse(gn.stamp_one("t", "web-01", "b", dry_run=False))


class TokenParse(unittest.TestCase):
    def test_get_token_reads_access_token(self):
        with mock.patch.object(gn, "_post_form",
                               return_value={"access_token": "tok123"}):
            self.assertEqual(gn.get_token("ten", "cid", "sec"), "tok123")

    def test_get_token_missing_raises(self):
        with mock.patch.object(gn, "_post_form", return_value={"error": "bad"}):
            with self.assertRaises(gn.GraphError):
                gn.get_token("ten", "cid", "sec")


class SelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        self.assertEqual(gn.self_test(), 0)


if __name__ == "__main__":
    unittest.main()
