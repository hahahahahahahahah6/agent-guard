"""Tests for the tamper-shape scanner (v0.6). stdlib unittest only."""

import json
import os
import subprocess
import sys
import tempfile
import unittest

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "src")
sys.path.insert(0, SRC)

from agent_guard import tamper  # noqa: E402


def kinds_of(text, path="tests/test_x.py"):
    return [k for _, _, k, _ in tamper.score_text(text, path)[1]]


class TestScanText(unittest.TestCase):
    def test_weakened_tobetruthy_fires(self):
        ks = kinds_of("expect(total).toBeTruthy()")
        self.assertIn("weakened-assertion", ks)

    def test_weakened_tobedefined_fires(self):
        ks = kinds_of("expect(user).toBeDefined()")
        self.assertIn("weakened-assertion", ks)

    def test_weakened_asserttrue_fires(self):
        ks = kinds_of("self.assertTrue(result == expected)")
        self.assertIn("weakened-assertion", ks)

    def test_weakened_assertisnotnone_fires(self):
        ks = kinds_of("self.assertIsNotNone(user)")
        self.assertIn("weakened-assertion", ks)

    def test_strong_assertion_clean(self):
        ks = kinds_of("expect(total).toBe(10)\n"
                      "self.assertEqual(total, 10)")
        self.assertEqual(ks, [])

    def test_skip_fires(self):
        ks = kinds_of("it.skip('flaky', () => {")
        self.assertIn("skipped-test", ks)

    def test_only_fires(self):
        ks = kinds_of("describe.only('auth', () => {")
        self.assertIn("skipped-test", ks)

    def test_xit_fires(self):
        ks = kinds_of("xit('does not run', () => {")
        self.assertIn("skipped-test", ks)

    def test_pytest_mark_skip_fires(self):
        ks = kinds_of("@pytest.mark.skip(reason='todo')\ndef test_x(): ...")
        self.assertIn("skipped-test", ks)

    def test_snapshot_call_fires(self):
        ks = kinds_of("expect(tree).toMatchSnapshot()")
        self.assertIn("snapshot-update", ks)

    def test_snapshot_path_fires(self):
        score, hits = tamper.score_text("whatever",
                                        "tests/__snapshots__/a.test.js.snap")
        self.assertIn("snapshot-file",
                      [k for _, _, k, _ in hits])
        self.assertGreater(score, 0)

    def test_clean_test_file(self):
        ks = kinds_of("def test_add():\n    assert add(1, 2) == 3\n")
        self.assertEqual(ks, [])

    def test_fail_open_on_garbage(self):
        score, hits = tamper.score_text(None, None)
        self.assertEqual((score, hits), (0.0, []))
        score, hits = tamper.score_text("", "x.py")
        self.assertEqual((score, hits), (0.0, []))

    def test_score_scales_with_weights(self):
        score, _ = tamper.score_text(
            "expect(a).toBeTruthy()\nit.skip('x', () => {})",
            "tests/test_x.js")
        # 3.0 + 2.5 = 5.5 -> 55.0
        self.assertEqual(score, 55.0)


class TestModeThreshold(unittest.TestCase):
    def test_threshold_default(self):
        env = {k: v for k, v in os.environ.items()
               if k != "AGENT_GUARD_TAMPER_THRESHOLD"}
        old = os.environ.get("AGENT_GUARD_TAMPER_THRESHOLD")
        os.environ.pop("AGENT_GUARD_TAMPER_THRESHOLD", None)
        try:
            self.assertEqual(tamper.threshold({}), 30.0)
        finally:
            if old is not None:
                os.environ["AGENT_GUARD_TAMPER_THRESHOLD"] = old

    def test_threshold_env_override(self):
        os.environ["AGENT_GUARD_TAMPER_THRESHOLD"] = "80"
        try:
            self.assertEqual(tamper.threshold({}), 80.0)
        finally:
            del os.environ["AGENT_GUARD_TAMPER_THRESHOLD"]

    def test_mode_env_override(self):
        os.environ["AGENT_GUARD_TAMPER_MODE"] = "warn"
        try:
            self.assertEqual(tamper.mode({}), "warn")
        finally:
            del os.environ["AGENT_GUARD_TAMPER_MODE"]


def run_cli(args, cwd, env_extra=None):
    env = dict(os.environ)
    env["PYTHONPATH"] = SRC + os.pathsep + env.get("PYTHONPATH", "")
    env.update(env_extra or {})
    p = subprocess.run(
        [sys.executable, "-m", "agent_guard"] + args,
        input="", capture_output=True, text=True, cwd=cwd, env=env,
        timeout=60)
    return p.returncode, p.stdout, p.stderr


class TestTamperCheckCLI(unittest.TestCase):
    def test_check_flags_tampered_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = os.path.join(tmp, "state")
            f = os.path.join(tmp, "test_x.py")
            with open(f, "w") as fh:
                fh.write("def test_a():\n"
                         "    expect(total).toBeTruthy()\n"
                         "    it.skip('x', lambda: None)\n")
            code, out, _ = run_cli(["tamper-check", f], tmp,
                                   {"AGENT_GUARD_DIR": d})
            self.assertEqual(code, 1)
            self.assertIn("TAMPER?", out)

    def test_check_passes_clean_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = os.path.join(tmp, "state")
            f = os.path.join(tmp, "test_x.py")
            with open(f, "w") as fh:
                fh.write("def test_add():\n    assert add(1, 2) == 3\n")
            code, out, _ = run_cli(["tamper-check", f], tmp,
                                   {"AGENT_GUARD_DIR": d})
            self.assertEqual(code, 0)
            self.assertIn("[ok]", out)


def run_hook(args, stdin_obj, cwd, env_extra=None):
    env = dict(os.environ)
    env["PYTHONPATH"] = SRC + os.pathsep + env.get("PYTHONPATH", "")
    env.update(env_extra or {})
    p = subprocess.run(
        [sys.executable, "-m", "agent_guard"] + args,
        input=json.dumps(stdin_obj), capture_output=True, text=True,
        cwd=cwd, env=env, timeout=60)
    return p.returncode, p.stdout, p.stderr


class TestHookTamper(unittest.TestCase):
    def _stdin(self, tool, path, content):
        ti = {"file_path": path}
        if tool == "Write":
            ti["content"] = content
        else:
            ti["new_string"] = content
        return {"tool_name": tool, "tool_input": ti,
                "session_id": "t", "cwd": "/tmp"}

    def test_hook_blocks_weakened_assertion(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = os.path.join(tmp, "state")
            code, _, err = run_hook(
                ["hook-tamper"],
                self._stdin("Write", "tests/test_a.py",
                            "expect(total).toBeTruthy()\n"
                            "expect(other).toBeTruthy()\n"),
                tmp, {"AGENT_GUARD_DIR": d})
            self.assertEqual(code, 2, err)
            self.assertIn("weakened-assertion", err)

    def test_hook_ignores_non_test_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = os.path.join(tmp, "state")
            code, _, _ = run_hook(
                ["hook-tamper"],
                self._stdin("Write", "src/app.py",
                            "expect(total).toBeTruthy()\n"),
                tmp, {"AGENT_GUARD_DIR": d})
            self.assertEqual(code, 0)

    def test_hook_warn_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = os.path.join(tmp, "state")
            code, _, err = run_hook(
                ["hook-tamper"],
                self._stdin("Edit", "tests/test_a.py",
                            "expect(total).toBeTruthy()\n"
                            "expect(other).toBeTruthy()\n"),
                tmp, {"AGENT_GUARD_DIR": d,
                      "AGENT_GUARD_TAMPER_MODE": "warn"})
            self.assertEqual(code, 0)
            self.assertIn("WARNING", err)


if __name__ == "__main__":
    unittest.main()
