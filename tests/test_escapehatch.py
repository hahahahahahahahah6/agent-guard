"""Smoke tests for the v0.7 legit-test-change escape hatch.

Fixtures:
- legit test change (new test function) passes without the hatch
- malicious change (weakened assertion) is blocked
- escape hatch (CLI flag or env) allows with an audited reason
- deleted test files, skips, try/except swallows are blocked
- ambiguous changes (same-strictness expected-value edits) are blocked

Run: pytest tests/test_escapehatch.py  (or python3 tests/test_escapehatch.py)
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "src"))
from agent_guard import escapehatch  # noqa: E402

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "src")
ENV_BASE = dict(os.environ, PYTHONPATH=SRC + os.pathsep +
                os.environ.get("PYTHONPATH", ""))

BASE_TEST = "def test_add():\n    assert add(1, 2) == 3\n"


def run_hook(args, stdin_obj, cwd, env_extra=None):
    env = dict(ENV_BASE)
    env.update(env_extra or {})
    p = subprocess.run(
        [sys.executable, "-m", "agent_guard"] + args,
        input=json.dumps(stdin_obj) if stdin_obj is not None else "",
        capture_output=True, text=True, cwd=cwd, env=env, timeout=30)
    return p.returncode, p.stdout, p.stderr


def run_cli(args, cwd, env_extra=None):
    env = dict(ENV_BASE)
    env.update(env_extra or {})
    p = subprocess.run(
        [sys.executable, "-m", "agent_guard"] + args,
        input="", capture_output=True, text=True, cwd=cwd, env=env,
        timeout=30)
    return p.returncode, p.stdout, p.stderr


def read_audit(state_dir):
    p = os.path.join(state_dir, "audit.jsonl")
    if not os.path.exists(p):
        return []
    out = []
    with open(p, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


class EscapeHatchTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state_dir = os.path.join(self.tmp.name, "state")
        proj = os.path.join(self.tmp.name, "proj")
        os.makedirs(os.path.join(proj, "src"))
        os.makedirs(os.path.join(proj, "tests"))
        with open(os.path.join(proj, "src", "app.py"), "w") as fh:
            fh.write("def add(a, b):\n    return a + b\n")
        with open(os.path.join(proj, "tests", "test_app.py"), "w") as fh:
            fh.write(BASE_TEST)
        self.proj = proj
        self.test_path = os.path.join(proj, "tests", "test_app.py")
        self.snapshot()

    def tearDown(self):
        self.tmp.cleanup()

    def snapshot(self, session="s1"):
        code, _, err = run_hook(
            ["hook-snapshot"], {"session_id": session},
            self.proj, {"AGENT_GUARD_DIR": self.state_dir})
        self.assertEqual(code, 0, err)

    def stop(self, extra_args=None, env_extra=None, session="s1"):
        env = {"AGENT_GUARD_DIR": self.state_dir}
        env.update(env_extra or {})
        return run_hook(["hook-test"] + (extra_args or []),
                        {"session_id": session}, self.proj, env)

    def last_audit(self, decision):
        hits = [e for e in read_audit(self.state_dir)
                if e.get("decision") == decision]
        return hits[-1] if hits else None

    def write_test(self, text):
        with open(self.test_path, "w") as fh:
            fh.write(text)

    # --- classifier unit tests ---
    def test_classifier_new_test_is_legit(self):
        v = escapehatch.classify_change(
            BASE_TEST,
            BASE_TEST + "\ndef test_sub():\n    assert add(5, -2) == 3\n",
            "tests/test_app.py")
        self.assertEqual(v["verdict"], "legit", v)

    def test_classifier_weakened_assert_is_malicious(self):
        v = escapehatch.classify_change(
            BASE_TEST, "def test_add():\n    assert add(1, 2)\n",
            "tests/test_app.py")
        self.assertEqual(v["verdict"], "malicious", v)

    def test_classifier_same_strictness_change_is_ambiguous(self):
        v = escapehatch.classify_change(
            BASE_TEST, "def test_add():\n    assert add(1, 2) == 4\n",
            "tests/test_app.py")
        self.assertEqual(v["verdict"], "ambiguous", v)

    def test_classifier_deleted_file_is_malicious(self):
        v = escapehatch.classify_change(BASE_TEST, None, "tests/test_app.py")
        self.assertEqual(v["verdict"], "malicious", v)

    def test_classifier_added_skip_is_malicious(self):
        v = escapehatch.classify_change(
            BASE_TEST,
            BASE_TEST + "\n@pytest.mark.skip\ndef test_skip():\n"
            "    assert True\n",
            "tests/test_app.py")
        self.assertEqual(v["verdict"], "malicious", v)

    def test_classifier_comment_only_is_legit(self):
        v = escapehatch.classify_change(
            BASE_TEST, "# checks addition\n" + BASE_TEST, "tests/test_app.py")
        self.assertEqual(v["verdict"], "legit", v)

    # --- Stop-hook integration tests ---
    def test_legit_change_allowed_and_audited(self):
        with open(self.test_path, "a") as fh:
            fh.write("\ndef test_sub():\n    assert add(5, -2) == 3\n")
        code, _, err = self.stop()
        self.assertEqual(code, 0, "rc=%d err=%s" % (code, err))
        e = self.last_audit("allowed-legit-test-change")
        self.assertIsNotNone(e, "legit change must be audited")
        self.assertIn("test_app.py", str(e.get("files", "")))

    def test_weakened_assertion_blocked(self):
        self.write_test("def test_add():\n    assert add(1, 2)\n")
        code, _, err = self.stop()
        self.assertEqual(code, 2, "rc=%d" % code)
        self.assertIn("malicious", err)

    def test_env_hatch_allows_and_audits_reason(self):
        self.write_test("def test_add():\n    assert add(1, 2)\n")
        code, _, err = self.stop(env_extra={
            "AGENT_GUARD_ALLOW_TEST_CHANGE": "1",
            "AGENT_GUARD_ALLOW_TEST_CHANGE_REASON":
            "human reviewed the weakening"})
        self.assertEqual(code, 0, "rc=%d" % code)
        e = self.last_audit("allowed-escape-hatch")
        self.assertIsNotNone(e)
        self.assertEqual(e.get("hatch_reason"), "human reviewed the weakening")

    def test_cli_flag_hatch_records_reason(self):
        self.write_test("def test_add():\n    assert add(1, 2) == 4\n")
        code, _, err = self.stop(
            extra_args=["--allow-test-change", "snapshot refresh"])
        self.assertEqual(code, 0, "rc=%d" % code)
        e = self.last_audit("allowed-escape-hatch")
        self.assertIsNotNone(e)
        self.assertEqual(e.get("hatch_reason"), "snapshot refresh")

    def test_deleted_test_file_blocked(self):
        os.remove(self.test_path)
        code, _, err = self.stop()
        self.assertEqual(code, 2, "rc=%d" % code)
        self.assertIn("malicious", err)

    def test_try_except_swallow_blocked(self):
        self.write_test("def test_add():\n"
                        "    try:\n"
                        "        assert add(1, 2) == 3\n"
                        "    except AssertionError:\n"
                        "        pass\n")
        code, _, err = self.stop()
        self.assertEqual(code, 2, "rc=%d" % code)
        self.assertIn("malicious", err)

    def test_fixture_addition_allowed(self):
        with open(self.test_path, "a") as fh:
            fh.write("\n@pytest.fixture\ndef sample():\n"
                     "    return [1, 2, 3]\n")
        code, _, err = self.stop()
        self.assertEqual(code, 0, "rc=%d err=%s" % (code, err))

    def test_ambiguous_value_change_blocked(self):
        self.write_test("def test_add():\n    assert add(1, 2) == 4\n")
        code, _, err = self.stop()
        self.assertEqual(code, 2, "rc=%d" % code)
        self.assertIn("ambiguous", err)

    def test_review_prints_verdicts_never_blocks(self):
        self.write_test("def test_add():\n    assert add(1, 2)\n")
        code, out, err = run_cli(
            ["test-review", "--session", "s1"], self.proj,
            {"AGENT_GUARD_DIR": self.state_dir})
        self.assertEqual(code, 0, err)
        self.assertIn("malicious", out)

    def test_env_value_used_as_reason(self):
        self.write_test("def test_add():\n    assert add(1, 2)\n")
        code, _, err = self.stop(env_extra={
            "AGENT_GUARD_ALLOW_TEST_CHANGE": "fixing flaky test"})
        self.assertEqual(code, 0, "rc=%d" % code)
        e = self.last_audit("allowed-escape-hatch")
        self.assertIsNotNone(e)
        self.assertEqual(e.get("hatch_reason"), "fixing flaky test")

    def test_block_message_documents_hatch(self):
        self.write_test("def test_add():\n    assert add(1, 2)\n")
        code, _, err = self.stop()
        self.assertEqual(code, 2)
        self.assertIn("--allow-test-change", err)

    def test_newly_skipped_test_blocked(self):
        with open(self.test_path, "a") as fh:
            fh.write("\n@pytest.mark.skip(reason='flaky')\n"
                     "def test_flaky():\n    assert add(1, 1) == 2\n")
        code, _, err = self.stop()
        self.assertEqual(code, 2, "rc=%d" % code)
        self.assertIn("malicious", err)


if __name__ == "__main__":
    unittest.main()
