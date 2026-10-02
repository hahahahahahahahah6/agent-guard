"""Tests for the cheat-sniffer (v0.4). Fast, no network."""

import json
import os
import subprocess
import sys
import tempfile

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "src")
sys.path.insert(0, SRC)

from agent_guard import cheatsniff  # noqa: E402

PASS = []


def check(name, cond, detail=""):
    PASS.append(bool(cond))
    print(("PASS " if cond else "FAIL ") + name +
          (" -- " + str(detail) if detail and not cond else ""))


def kinds_of(text, path):
    return [k for _, _, k, _ in cheatsniff.score_text(text, path)[1]]


def test_mock_subject_fires():
    ks = kinds_of('mock.patch("billing.calculate_total", return_value=9)',
                  "tests/test_billing.py")
    check("mock-subject fires on subject patch", "mock-subject" in ks, ks)


def test_mock_collaborator_clean():
    ks = kinds_of('mock.patch("stripe.Charge.create", return_value={})',
                  "tests/test_billing.py")
    check("mocking a collaborator is clean", not ks, ks)


def test_monkeypatch_subject_fires():
    ks = kinds_of('monkeypatch.setattr("billing.total", lambda: 0)',
                  "tests/test_billing.py")
    check("monkeypatch on subject fires", "mock-subject" in ks, ks)


def test_conftest_patch_fires():
    ks = kinds_of('monkeypatch.setattr("billing.total", lambda: 0)',
                  "tests/conftest.py")
    check("conftest plant on subject fires", "conftest-patch" in ks, ks)


def test_conftest_pure_fixture_clean():
    text = ("import pytest\n\n@pytest.fixture\ndef client():\n"
            "    return make_client()\n")
    ks = kinds_of(text, "tests/conftest.py")
    check("conftest with pure fixtures is clean", not ks, ks)


def test_rng_seed_fires():
    ks = kinds_of("random.seed(12345)", "tests/test_sort.py")
    check("fixed RNG seed fires", "rng-seed" in ks, ks)


def test_rng_seed_repro_marker_clean():
    text = "# reproducible: fixed seed for stable tests\nrandom.seed(42)"
    ks = kinds_of(text, "tests/test_sort.py")
    check("seed with reproducibility marker is clean", "rng-seed" not in ks,
          ks)


def test_rng_patch_fires():
    ks = kinds_of('mock.patch("random.shuffle", lambda x: None)',
                  "tests/test_sort.py")
    check("RNG primitive patch fires", "rng-patch" in ks, ks)


def test_seed_none_clean():
    ks = kinds_of("random.seed()", "tests/test_x.py")
    check("random.seed() unseeded is clean", not ks, ks)


def test_time_freeze_fires():
    ks = kinds_of('freeze_time("2024-01-01")', "tests/test_retry.py")
    check("freeze_time fires", "time-freeze" in ks, ks)


def test_sleep_noop_fires():
    ks = kinds_of('mock.patch("time.sleep", lambda s: None)',
                  "tests/test_retry.py")
    check("time.sleep no-op patch fires", "time-freeze" in ks, ks)


def test_weak_comparator_fires():
    text = "def __eq__(self, other):\n    return True\n"
    ks = kinds_of(text, "tests/test_x.py")
    check("always-True __eq__ fires", "weak-comparator" in ks, ks)


def test_honest_eq_clean():
    text = ("def __eq__(self, other):\n"
            "    return self.id == other.id\n")
    ks = kinds_of(text, "tests/test_x.py")
    check("honest __eq__ is clean", "weak-comparator" not in ks, ks)


def test_severe_hit_reaches_threshold():
    score, _ = cheatsniff.score_text(
        'mock.patch("billing.total", return_value=0)', "tests/test_billing.py")
    check("one severe hit reaches default threshold",
          score >= cheatsniff.DEFAULT_THRESHOLD, score)


def test_allowlist():
    cfg = {"cheat_sniff": {"allow": ["test_sort.py:rng-seed"]}}
    hits = cheatsniff._find_hits("random.seed(7)", "tests/test_sort.py")
    kept = cheatsniff.filter_allowed(hits, cfg, "tests/test_sort.py")
    check("allowlist drops the hit", not kept, kept)
    kept2 = cheatsniff.filter_allowed(hits, cfg, "tests/test_other.py")
    check("allowlist is file-scoped", bool(kept2), kept2)


def test_fail_open_on_garbage():
    score, hits = cheatsniff.score_text(None, None)
    check("fail open on garbage input", score == 0.0 and hits == [],
          (score, hits))


def test_scan_path_skips_venv():
    with tempfile.TemporaryDirectory() as tmp:
        venv = os.path.join(tmp, ".venv")
        os.makedirs(venv)
        bad = os.path.join(venv, "evil.py")
        with open(bad, "w") as fh:
            fh.write('mock.patch("random.shuffle", lambda x: None)\n')
        good = os.path.join(tmp, "test_ok.py")
        with open(good, "w") as fh:
            fh.write("def test_a():\n    assert True\n")
        seen = [p for p, _, _ in cheatsniff.scan_path(tmp)]
        check("scan skips .venv", bad not in seen and good in seen, seen)


# --- CLI / hook integration ---

ENV_BASE = dict(os.environ, PYTHONPATH=SRC + os.pathsep +
                os.environ.get("PYTHONPATH", ""))


def run_cli(args, cwd, env_extra=None):
    env = dict(ENV_BASE)
    env.update(env_extra or {})
    p = subprocess.run(
        [sys.executable, "-m", "agent_guard"] + args,
        input="", capture_output=True, text=True, cwd=cwd, env=env,
        timeout=30)
    return p.returncode, p.stdout, p.stderr


def run_hook(args, stdin_obj, cwd, env_extra=None):
    env = dict(ENV_BASE)
    env.update(env_extra or {})
    p = subprocess.run(
        [sys.executable, "-m", "agent_guard"] + args,
        input=json.dumps(stdin_obj) if stdin_obj is not None else "",
        capture_output=True, text=True, cwd=cwd, env=env, timeout=30)
    return p.returncode, p.stdout, p.stderr


def test_cli_check_exit_codes():
    with tempfile.TemporaryDirectory() as tmp:
        sd = os.path.join(tmp, "state")
        os.makedirs(sd)
        cheat = os.path.join(tmp, "test_billing.py")
        with open(cheat, "w") as fh:
            fh.write('import mock\nmock.patch("billing.total", '
                     'return_value=0)\n')
        clean = os.path.join(tmp, "test_ok.py")
        with open(clean, "w") as fh:
            fh.write("def test_a():\n    assert True\n")
        env = {"AGENT_GUARD_DIR": sd}
        code, out, _ = run_cli(["cheatsniff", "--check", cheat], tmp, env)
        check("cheatsniff --check exits 1 on cheat file",
              code == 1 and "CHEAT?" in out, (code, out[:100]))
        code, out, _ = run_cli(["cheatsniff", "--check", clean], tmp, env)
        check("cheatsniff --check exits 0 on clean file",
              code == 0 and "[ok]" in out, (code, out[:100]))


def test_hook_blocks_cheat_in_added_text():
    with tempfile.TemporaryDirectory() as tmp:
        sd = os.path.join(tmp, "state")
        os.makedirs(sd)
        stdin = {
            "session_id": "s1", "tool_name": "Write", "cwd": tmp,
            "tool_input": {
                "file_path": os.path.join(tmp, "tests", "test_sort.py"),
                "content": ('import mock\n'
                            'mock.patch("random.shuffle", lambda x: None)\n'),
            },
        }
        code, _, err = run_hook(["hook-cheatsniff"], stdin, tmp,
                                {"AGENT_GUARD_DIR": sd})
        check("hook blocks RNG-rigging added text", code == 2, code)


def test_hook_ignores_non_test_files():
    with tempfile.TemporaryDirectory() as tmp:
        sd = os.path.join(tmp, "state")
        os.makedirs(sd)
        stdin = {
            "session_id": "s1", "tool_name": "Write", "cwd": tmp,
            "tool_input": {
                "file_path": os.path.join(tmp, "src", "app.py"),
                "content": 'mock.patch("random.shuffle", lambda x: None)\n',
            },
        }
        code, _, _ = run_hook(["hook-cheatsniff"], stdin, tmp,
                              {"AGENT_GUARD_DIR": sd})
        check("hook ignores non-test files", code == 0, code)


def test_hook_warn_mode():
    with tempfile.TemporaryDirectory() as tmp:
        sd = os.path.join(tmp, "state")
        os.makedirs(sd)
        stdin = {
            "session_id": "s1", "tool_name": "Write", "cwd": tmp,
            "tool_input": {
                "file_path": os.path.join(tmp, "test_x.py"),
                "content": 'mock.patch("random.shuffle", lambda x: None)\n',
            },
        }
        code, _, err = run_hook(["hook-cheatsniff"], stdin, tmp,
                                {"AGENT_GUARD_DIR": sd,
                                 "AGENT_GUARD_CHEAT_MODE": "warn"})
        check("warn mode exits 0 with warning",
              code == 0 and "WARNING" in err, (code, err[:60]))


def test_hook_fail_open_on_garbage():
    with tempfile.TemporaryDirectory() as tmp:
        env = dict(ENV_BASE)
        p = subprocess.run(
            [sys.executable, "-m", "agent_guard", "hook-cheatsniff"],
            input="not json{{{", capture_output=True, text=True, cwd=tmp,
            env=env, timeout=30)
        check("hook fails open on garbage stdin", p.returncode == 0,
              p.returncode)


def test_install_registers_cheatsniff():
    with tempfile.TemporaryDirectory() as tmp:
        fake_home = os.path.join(tmp, "home")
        os.makedirs(os.path.join(fake_home, ".claude"))
        env = dict(ENV_BASE, HOME=fake_home)
        p = subprocess.run(
            [sys.executable, "-m", "agent_guard", "install"],
            input="", capture_output=True, text=True, cwd=tmp, env=env,
            timeout=30)
        sp = os.path.join(fake_home, ".claude", "settings.json")
        with open(sp) as fh:
            settings = json.load(fh)
        found = False
        for e in settings.get("hooks", {}).get("PreToolUse", []):
            for h in e.get("hooks", []):
                if h.get("command") == "agent-guard hook-cheatsniff":
                    found = True
        check("install registers hook-cheatsniff", p.returncode == 0
              and found, p.returncode)
        # idempotent
        p2 = subprocess.run(
            [sys.executable, "-m", "agent_guard", "install"],
            input="", capture_output=True, text=True, cwd=tmp, env=env,
            timeout=30)
        with open(sp) as fh:
            settings2 = json.load(fh)
        n = sum(1 for e in settings2.get("hooks", {}).get("PreToolUse", [])
                for h in e.get("hooks", [])
                if h.get("command") == "agent-guard hook-cheatsniff")
        check("install is idempotent", n == 1, n)



def test_direct_assignment_on_imported_module_fires():
    text = "import mymod\nmymod.shuffle = lambda xs: sorted(xs)\n"
    kinds = kinds_of(text, "conftest.py")
    check("direct-assignment/conftest-patch fires", "conftest-patch" in kinds, kinds)


def test_direct_assignment_on_plain_object_clean():
    text = "result = {}\nresult.value = 42\n"
    kinds = kinds_of(text, "conftest.py")
    check("direct-assignment/plain-object clean", "conftest-patch" not in kinds, kinds)


def test_direct_assignment_on_innocent_mod_clean():
    text = "import os\nos.environ = {}\n"
    kinds = kinds_of(text, "conftest.py")
    check("direct-assignment/innocent-mod clean", "conftest-patch" not in kinds, kinds)


def main():
    test_mock_subject_fires()
    test_mock_collaborator_clean()
    test_monkeypatch_subject_fires()
    test_conftest_patch_fires()
    test_conftest_pure_fixture_clean()
    test_rng_seed_fires()
    test_rng_seed_repro_marker_clean()
    test_rng_patch_fires()
    test_seed_none_clean()
    test_time_freeze_fires()
    test_sleep_noop_fires()
    test_weak_comparator_fires()
    test_honest_eq_clean()
    test_severe_hit_reaches_threshold()
    test_allowlist()
    test_fail_open_on_garbage()
    test_scan_path_skips_venv()
    test_cli_check_exit_codes()
    test_hook_blocks_cheat_in_added_text()
    test_hook_ignores_non_test_files()
    test_hook_warn_mode()
    test_hook_fail_open_on_garbage()
    test_install_registers_cheatsniff()
    test_direct_assignment_on_imported_module_fires()
    test_direct_assignment_on_plain_object_clean()
    test_direct_assignment_on_innocent_mod_clean()
    print("\n%d/%d passed" % (sum(PASS), len(PASS)))
    return 0 if all(PASS) else 1




if __name__ == "__main__":
    sys.exit(main())
