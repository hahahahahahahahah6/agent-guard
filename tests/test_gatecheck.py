"""Tests for the gate-liveness verifier (v0.6)."""

import json
import os
import sys
import tempfile
import unittest

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "src")
sys.path.insert(0, SRC)

from agent_guard import gatecheck, state, xtool  # noqa: E402


class TestCheck(unittest.TestCase):
    def _env(self, tmp):
        old = dict(os.environ)
        os.environ["AGENT_GUARD_DIR"] = os.path.join(tmp, "state")
        os.environ.pop("CODEX_HOME", None)
        return old

    def test_not_installed(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = self._env(tmp)
            try:
                home = os.path.join(tmp, ".codex")
                rep = gatecheck.check("codex", days=7, home=home)
                self.assertFalse(rep["config_exists"])
                for g in rep["guards"].values():
                    self.assertEqual(g["status"], "NOT INSTALLED")
                self.assertTrue(rep["issues"])
            finally:
                os.environ.clear()
                os.environ.update(old)

    def test_silent_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = self._env(tmp)
            try:
                home = os.path.join(tmp, ".codex")
                xtool.install_codex(home=home)
                rep = gatecheck.check("codex", days=7, home=home)
                for g in rep["guards"].values():
                    self.assertEqual(g["status"], "SILENT")
                text = gatecheck.format_report(rep)
                self.assertIn("SILENT FAILURE", text)
            finally:
                os.environ.clear()
                os.environ.update(old)

    def test_live_after_pings(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = self._env(tmp)
            try:
                home = os.path.join(tmp, ".codex")
                xtool.install_codex(home=home)
                state.record_ping("test")
                state.record_ping("snapshot")
                rep = gatecheck.check("codex", days=7, home=home)
                self.assertEqual(rep["guards"]["test"]["status"], "LIVE")
                self.assertGreaterEqual(rep["guards"]["test"]["runs"], 2)
                self.assertEqual(rep["guards"]["outbound"]["status"],
                                 "SILENT")
            finally:
                os.environ.clear()
                os.environ.update(old)

    def test_audit_decisions_count_as_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = self._env(tmp)
            try:
                home = os.path.join(tmp, ".codex")
                xtool.install_codex(home=home)
                state.append_audit({"guard": "outbound", "tool": "Bash",
                                    "decision": "blocked", "rule": "x"})
                rep = gatecheck.check("codex", days=7, home=home)
                self.assertEqual(rep["guards"]["outbound"]["status"],
                                 "LIVE")
                self.assertEqual(rep["guards"]["outbound"]["decisions"], 1)
            finally:
                os.environ.clear()
                os.environ.update(old)

    def test_missing_features_flag_noted(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = self._env(tmp)
            try:
                home = os.path.join(tmp, ".codex")
                os.makedirs(home)
                with open(os.path.join(home, "hooks.json"), "w") as fh:
                    json.dump({"hooks": {}}, fh)
                rep = gatecheck.check("codex", days=7, home=home)
                self.assertTrue(any("hooks" in i for i in rep["issues"]))
            finally:
                os.environ.clear()
                os.environ.update(old)


class TestRun(unittest.TestCase):
    def test_unknown_tool(self):
        code, text = gatecheck.run(tool="cursor")
        self.assertEqual(code, 2)
        self.assertIn("unknown tool", text)

    def test_all_tools_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = dict(os.environ)
            os.environ["AGENT_GUARD_DIR"] = os.path.join(tmp, "state")
            try:
                code, text = gatecheck.run(tool=None, days=7)
                self.assertEqual(code, 1)  # nothing installed -> issues
                self.assertIn("gate check: claude", text)
                self.assertIn("gate check: codex", text)
                self.assertIn("gate check: gemini", text)
            finally:
                os.environ.clear()
                os.environ.update(old)

    def test_days_clamped(self):
        rep = gatecheck.check("gemini", days=0)
        self.assertEqual(rep["days"], 1)


class TestFormatReport(unittest.TestCase):
    def test_all_live_message(self):
        rep = {"tool": "claude", "days": 7, "config_path": "/x",
               "config_exists": True, "note": "",
               "guards": {"test": {"mounted": True, "runs": 3,
                                   "decisions": 0, "status": "LIVE"}},
               "issues": []}
        text = gatecheck.format_report(rep)
        self.assertIn("LIVE", text)
        self.assertIn("all mounted guards are LIVE", text)

    def test_never_raises(self):
        self.assertIsInstance(gatecheck.format_report({}), str)


if __name__ == "__main__":
    unittest.main()
