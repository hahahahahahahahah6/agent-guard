"""Tests for cross-tool install + shim normalization (v0.6)."""

import json
import os
import sys
import tempfile
import unittest

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "src")
sys.path.insert(0, SRC)

from agent_guard import xtool  # noqa: E402


class TestInstallCodex(unittest.TestCase):
    def test_install_writes_hooks_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = os.path.join(tmp, ".codex")
            hp, added, feat = xtool.install_codex(home=home)
            self.assertEqual(hp, os.path.join(home, "hooks.json"))
            self.assertGreater(added, 0)
            self.assertTrue(feat)
            with open(hp) as fh:
                settings = json.load(fh)
            self.assertIn("Stop", settings["hooks"])
            self.assertTrue(xtool.codex_hooks_feature_enabled(home=home))

    def test_install_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = os.path.join(tmp, ".codex")
            _, added1, _ = xtool.install_codex(home=home)
            _, added2, _ = xtool.install_codex(home=home)
            self.assertGreater(added1, 0)
            self.assertEqual(added2, 0)

    def test_install_preserves_existing_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = os.path.join(tmp, ".codex")
            os.makedirs(home)
            with open(os.path.join(home, "hooks.json"), "w") as fh:
                json.dump({"hooks": {"Stop": []},
                           "custom": {"keep": True}}, fh)
            hp, _, _ = xtool.install_codex(home=home)
            with open(hp) as fh:
                settings = json.load(fh)
            self.assertTrue(settings["custom"]["keep"])
            self.assertGreater(len(settings["hooks"]["Stop"]), 0)

    def test_features_flag_appended_textually(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = os.path.join(tmp, ".codex")
            os.makedirs(home)
            with open(os.path.join(home, "config.toml"), "w") as fh:
                fh.write('model = "gpt-5"\n')
            xtool.install_codex(home=home)
            with open(os.path.join(home, "config.toml")) as fh:
                text = fh.read()
            self.assertIn('[features]', text)
            self.assertIn('hooks = true', text)
            self.assertIn('model = "gpt-5"', text)

    def test_installed_commands_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = os.path.join(tmp, ".codex")
            xtool.install_codex(home=home)
            cmds = xtool.installed_commands("codex", home=home)
            self.assertTrue(any("hook-test" in c for c in cmds))
            self.assertTrue(any("shim --tool codex" in c for c in cmds))


class TestInstallGemini(unittest.TestCase):
    def test_install_writes_settings_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = os.path.join(tmp, ".gemini")
            sp, added = xtool.install_gemini(home=home)
            self.assertEqual(sp, os.path.join(home, "settings.json"))
            self.assertGreater(added, 0)
            with open(sp) as fh:
                settings = json.load(fh)
            self.assertIn("BeforeTool", settings["hooks"])
            self.assertIn("SessionEnd", settings["hooks"])

    def test_install_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = os.path.join(tmp, ".gemini")
            _, added1 = xtool.install_gemini(home=home)
            _, added2 = xtool.install_gemini(home=home)
            self.assertGreater(added1, 0)
            self.assertEqual(added2, 0)

    def test_before_tool_matchers_cover_shell_and_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = os.path.join(tmp, ".gemini")
            xtool.install_gemini(home=home)
            with open(os.path.join(home, "settings.json")) as fh:
                settings = json.load(fh)
            matchers = [e.get("matcher")
                        for e in settings["hooks"]["BeforeTool"]]
            self.assertIn("run_shell_command", matchers)
            self.assertIn("write_file|replace", matchers)


class TestNormalize(unittest.TestCase):
    def test_gemini_write_file(self):
        data = {"tool_name": "write_file",
                "tool_input": {"file_path": "a.py", "content": "x=1"}}
        norm = xtool.normalize("gemini", data)
        self.assertEqual(norm["tool_name"], "Write")
        self.assertEqual(norm["tool_input"]["content"], "x=1")

    def test_gemini_replace(self):
        data = {"tool_name": "replace",
                "tool_input": {"file_path": "a.py", "old_string": "x",
                               "new_string": "y"}}
        norm = xtool.normalize("gemini", data)
        self.assertEqual(norm["tool_name"], "Edit")
        self.assertEqual(norm["tool_input"]["new_string"], "y")

    def test_gemini_shell(self):
        data = {"tool_name": "run_shell_command",
                "tool_input": {"command": "pytest -q"}}
        norm = xtool.normalize("gemini", data)
        self.assertEqual(norm["tool_name"], "Bash")
        self.assertEqual(norm["tool_input"]["command"], "pytest -q")

    def test_gemini_unknown_tool_fails_open(self):
        data = {"tool_name": "mcp__x__y", "tool_input": {}}
        self.assertIsNone(xtool.normalize("gemini", data))

    def test_codex_bash_passthrough(self):
        data = {"tool_name": "Bash",
                "tool_input": {"command": "git push"}}
        norm = xtool.normalize("codex", data)
        self.assertEqual(norm["tool_name"], "Bash")

    def test_codex_apply_patch_extracts_added_lines(self):
        patch = ("*** Begin Patch\n"
                 "*** Update File: tests/test_a.py\n"
                 "@@\n"
                 "-expect(total).toBe(10)\n"
                 "+expect(total).toBeTruthy()\n"
                 "*** End Patch\n")
        data = {"tool_name": "apply_patch",
                "tool_input": {"command": patch}}
        norm = xtool.normalize("codex", data)
        self.assertEqual(norm["tool_name"], "Edit")
        self.assertEqual(norm["tool_input"]["file_path"],
                         "tests/test_a.py")
        self.assertIn("expect(total).toBeTruthy()",
                      norm["tool_input"]["new_string"])
        self.assertNotIn("toBe(10)", norm["tool_input"]["new_string"])

    def test_codex_apply_patch_no_file_fails_open(self):
        data = {"tool_name": "apply_patch",
                "tool_input": {"command": "not a patch"}}
        self.assertIsNone(xtool.normalize("codex", data))

    def test_garbage_fails_open(self):
        self.assertIsNone(xtool.normalize("gemini", None))
        self.assertIsNone(xtool.normalize("codex",
                                          {"tool_name": "weird_tool"}))


class TestMountSteps(unittest.TestCase):
    def test_steps_mention_trust_for_codex(self):
        steps = xtool.mount_steps("codex")
        self.assertTrue(any("trust" in s.lower() for s in steps))

    def test_steps_warn_about_gemini_stop(self):
        steps = xtool.mount_steps("gemini")
        self.assertTrue(any("Stop" in s for s in steps))


if __name__ == "__main__":
    unittest.main()
