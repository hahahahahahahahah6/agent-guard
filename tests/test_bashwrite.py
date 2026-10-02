"""Tests for the cross-tool write guard (v0.5). Fast, no network."""

import json
import os
import subprocess
import sys
import tempfile

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "src")
sys.path.insert(0, SRC)

from agent_guard import bashwrite  # noqa: E402
from agent_guard import state  # noqa: E402

PASS = []


def check(name, cond, detail=""):
    PASS.append(bool(cond))
    print(("PASS " if cond else "FAIL ") + name +
          (" -- " + str(detail) if detail and not cond else ""))


def got_of(command):
    targets, ok = bashwrite.extract_writes(command)
    return [(t, v) for t, v, _ in targets], ok


def contents_of(command):
    targets, _ = bashwrite.extract_writes(command)
    return {t: c for t, _, c in targets}


# ---------------------------------------------------------------------------
# extraction: redirections
# ---------------------------------------------------------------------------

def test_redirect():
    got, ok = got_of("echo hi > out.txt")
    check("redirect extracts target",
          got == [("out.txt", "redirect")] and ok, (got, ok))


def test_append():
    got, ok = got_of("echo hi >> log.txt")
    check("append redirect extracts target",
          got == [("log.txt", "redirect")] and ok, (got, ok))


def test_stderr_redirect():
    got, _ = got_of("echo hi 2> err.log")
    check("stderr redirect extracts target",
          got == [("err.log", "redirect")], got)


def test_attached_redirect():
    got, _ = got_of("echo hi >out.txt")
    check("attached >file extracts target",
          got == [("out.txt", "redirect")], got)


def test_dev_null_skipped():
    for cmd in ("echo hi > /dev/null", "echo hi 2>/dev/null",
                "echo hi >/dev/null"):
        got, _ = got_of(cmd)
        check("dev-null redirect skipped: %s" % cmd, got == [], got)


def test_semicolon_glued():
    got, _ = got_of("printf 'x' > f.txt; echo done")
    check("semicolon-glued target parsed",
          got == [("f.txt", "redirect")], got)


def test_quoted_semicolon_untouched():
    got, _ = got_of('echo "a;b" > q.txt')
    check("quoted semicolon not split", got == [("q.txt", "redirect")], got)


# ---------------------------------------------------------------------------
# extraction: heredocs
# ---------------------------------------------------------------------------

def test_heredoc():
    got, ok = got_of("cat <<EOF > f.txt\nbody line\nEOF")
    check("heredoc extracts target",
          got == [("f.txt", "heredoc")] and ok, (got, ok))
    bodies = contents_of("cat <<EOF > f.txt\nbody line\nEOF")
    check("heredoc body captured",
          bodies.get("f.txt", "").strip() == "body line", bodies)


def test_heredoc_dash():
    got, _ = got_of("cat <<-EOF > f.txt\n\tbody\nEOF")
    check("heredoc-dash extracts target",
          got == [("f.txt", "heredoc")], got)


def test_heredoc_quoted_delim():
    got, _ = got_of("cat <<'EOF' > f.txt\nbody\nEOF")
    check("quoted heredoc delimiter handled",
          got == [("f.txt", "heredoc")], got)


def test_heredoc_scoped_to_segment():
    got, _ = got_of("echo a > one.txt; cat <<EOF > two.txt\nBODY\nEOF")
    check("heredoc body attaches to its own segment",
          got == [("one.txt", "redirect"), ("two.txt", "heredoc")], got)
    bodies = contents_of("echo a > one.txt; cat <<EOF > two.txt\nBODY\nEOF")
    check("body not attached to earlier segment",
          bodies.get("two.txt", "").strip() == "BODY"
          and bodies.get("one.txt") is None, bodies)


# ---------------------------------------------------------------------------
# extraction: commands
# ---------------------------------------------------------------------------

def test_sed_inplace():
    got, _ = got_of("sed -i 's/a/b/' f.py")
    check("sed -i extracts file", got == [("f.py", "sed -i")], got)


def test_sed_inplace_suffix():
    got, _ = got_of("sed -i.bak 's/a/b/' f.py")
    check("sed -i.bak extracts file", got == [("f.py", "sed -i")], got)


def test_sed_inplace_long():
    got, _ = got_of("sed --in-place -e 's/a/b/' f.py")
    check("sed --in-place -e extracts file",
          got == [("f.py", "sed -i")], got)


def test_sed_no_file():
    got, _ = got_of("sed -i 's/a/b/'")
    check("sed -i without file has no target", got == [], got)


def test_tee():
    got, _ = got_of("echo x | tee a.txt b.txt")
    check("tee extracts all files",
          got == [("a.txt", "tee"), ("b.txt", "tee")], got)


def test_tee_append():
    got, _ = got_of("echo x | tee -a a.txt")
    check("tee -a extracts file", got == [("a.txt", "tee")], got)


def test_tee_ignores_input_redirect():
    got, _ = got_of("sudo tee /etc/hosts < data")
    check("tee ignores input-redirect file",
          got == [("/etc/hosts", "tee")], got)


def test_cp_mv_dest():
    got, _ = got_of("cp a.txt b.txt")
    check("cp extracts dest", got == [("b.txt", "cp")], got)
    got, _ = got_of("mv -f a.txt b.txt")
    check("mv extracts dest", got == [("b.txt", "mv")], got)


def test_cp_to_dir_skipped():
    got, _ = got_of("mv a.txt subdir/")
    check("mv to directory/ has no file target", got == [], got)


def test_chained():
    got, _ = got_of("echo hi > one.txt && echo yo > two.txt")
    check("chained commands all scanned",
          got == [("one.txt", "redirect"), ("two.txt", "redirect")], got)


def test_nested_sh_c():
    got, _ = got_of("bash -c 'echo nested > deep.txt'")
    check("bash -c payload scanned",
          got == [("deep.txt", "redirect")], got)


# ---------------------------------------------------------------------------
# extraction: clean cases
# ---------------------------------------------------------------------------

def test_clean_cases():
    for cmd in ("echo hi",
                "grep pattern file.txt",
                "cat < input.txt",
                "echo hi > $OUT",
                "echo 'price: $5' > /dev/null",
                "echo hi > *.log",
                "ls -la"):
        got, ok = got_of(cmd)
        check("clean: %s" % cmd, got == [] and ok, (got, ok))


def test_parse_failure_fail_open():
    got, ok = bashwrite.extract_writes("echo 'unbalanced")
    check("unbalanced quotes fail open", got == [] and ok is False,
          (got, ok))


# ---------------------------------------------------------------------------
# policy: decide()
# ---------------------------------------------------------------------------

def test_decide_opaque_test_write_blocked():
    cfg = state.default_config()
    ok, reason, targets, _ = bashwrite.decide(
        "sed -i 's/a/b/' tests/test_x.py", cfg, "/tmp/proj")
    check("opaque sed -i on test file blocked",
          ok is False and "tests/test_x.py" in reason, (ok, reason[:80]))


def test_decide_clean_bash_allowed():
    cfg = state.default_config()
    ok, _, _, _ = bashwrite.decide("grep pattern tests/test_x.py", cfg, "/tmp")
    check("read-only bash allowed", ok is True, ok)


def test_decide_heredoc_cheat_scored():
    cfg = state.default_config()
    cmd = ("cat > tests/test_x.py <<'EOF'\n"
           "import mock\n"
           "mock.patch(\"random.shuffle\", lambda x: None)\n"
           "EOF\n")
    ok, reason, _, _ = bashwrite.decide(cmd, cfg, "/tmp/proj")
    check("heredoc cheat content blocked",
          ok is False and "cheat score" in reason, (ok, reason[:100]))


def test_decide_heredoc_clean_allowed():
    cfg = state.default_config()
    cmd = ("cat > tests/test_x.py <<'EOF'\n"
           "def test_a():\n    assert True\n"
           "EOF\n")
    ok, _, _, _ = bashwrite.decide(cmd, cfg, "/tmp/proj")
    check("heredoc clean content allowed", ok is True, ok)


def test_decide_protected_paths():
    cfg = state.default_config()
    cfg["bash_write"]["protected_paths"] = ["src/"]
    ok, reason, _, _ = bashwrite.decide("echo x > src/app.py", cfg, "/tmp/proj")
    check("protected_paths prefix enforced",
          ok is False and "src/app.py" in reason, (ok, reason[:80]))
    ok2, _, _, _ = bashwrite.decide("echo x > docs/note.md", cfg, "/tmp/proj")
    check("unprotected path allowed", ok2 is True, ok2)


def test_decide_allowlist():
    cfg = state.default_config()
    cfg["bash_write"]["allow"] = ["test_x.py:bash-write"]
    ok, _, _, _ = bashwrite.decide(
        "sed -i 's/a/b/' tests/test_x.py", cfg, "/tmp/proj")
    check("bash_write.allow suppresses", ok is True, ok)


def test_decide_mode_warn():
    cfg = state.default_config()
    check("bashwrite mode defaults to block",
          bashwrite.mode(cfg) == "block", bashwrite.mode(cfg))
    os.environ["AGENT_GUARD_BASHWRITE_MODE"] = "warn"
    try:
        check("env override wins", bashwrite.mode(cfg) == "warn",
              bashwrite.mode(cfg))
    finally:
        del os.environ["AGENT_GUARD_BASHWRITE_MODE"]


def test_config_merge_includes_sections():
    with tempfile.TemporaryDirectory() as tmp:
        sd = os.path.join(tmp, "state")
        os.makedirs(sd)
        with open(os.path.join(sd, "config.json"), "w") as fh:
            json.dump({"bash_write": {"mode": "warn"},
                       "cheat_sniff": {"threshold": 99}}, fh)
        old = os.environ.get("AGENT_GUARD_DIR")
        os.environ["AGENT_GUARD_DIR"] = sd
        try:
            cfg = state.load_config()
            check("bash_write user config merged",
                  cfg["bash_write"]["mode"] == "warn",
                  cfg["bash_write"])
            check("cheat_sniff user config merged",
                  cfg["cheat_sniff"]["threshold"] == 99,
                  cfg["cheat_sniff"])
        finally:
            if old is None:
                del os.environ["AGENT_GUARD_DIR"]
            else:
                os.environ["AGENT_GUARD_DIR"] = old


# ---------------------------------------------------------------------------
# regression (v0.5.1): false positives — the hook blocked things that are
# not test files. Only real code suffixes count as test files; fixture /
# data dirs and __init__.py never do.
# ---------------------------------------------------------------------------

def test_fp_log_file_not_testy():
    cfg = state.default_config()
    ok, _, _, _ = bashwrite.decide(
        "pytest -q 2>&1 | tee test_output.log", cfg, "/tmp/proj")
    check("FP: test_*.log is not a test file", ok is True, ok)


def test_fp_fixture_data_not_testy():
    cfg = state.default_config()
    ok, _, _, _ = bashwrite.decide(
        "echo '{}' > tests/fixtures/data.json", cfg, "/tmp/proj")
    check("FP: tests/fixtures/ data is not a test file", ok is True, ok)


def test_fp_testdata_dir_not_testy():
    cfg = state.default_config()
    ok, _, _, _ = bashwrite.decide(
        "echo x > tests/testdata/case1.json", cfg, "/tmp/proj")
    check("FP: tests/testdata/ is not a test file", ok is True, ok)


def test_fp_init_py_not_testy():
    cfg = state.default_config()
    ok, _, _, _ = bashwrite.decide(
        "echo '' > tests/__init__.py", cfg, "/tmp/proj")
    check("FP: tests/__init__.py is not a test file", ok is True, ok)


def test_fp_real_test_file_still_blocked():
    cfg = state.default_config()
    ok, _, _, _ = bashwrite.decide(
        "echo x > tests/test_x.py", cfg, "/tmp/proj")
    check("real test file still blocked", ok is False, ok)


# ---------------------------------------------------------------------------
# regression (v0.5.1): perl -i is sed -i's exact equivalent and must be
# treated the same way
# ---------------------------------------------------------------------------

def test_perl_inplace_extracts():
    got, _ = got_of("perl -pi -e 's/a/b/' tests/test_x.py")
    check("perl -pi -e extracts file",
          got == [("tests/test_x.py", "perl -i")], got)


def test_perl_inplace_bak_extracts():
    got, _ = got_of("perl -pi.bak -e 's/a/b/' tests/test_x.py")
    check("perl -pi.bak extracts file",
          got == [("tests/test_x.py", "perl -i")], got)


def test_perl_no_inplace_no_target():
    got, _ = got_of("perl -pe 's/a/b/' tests/test_x.py")
    check("perl without -i has no write target", got == [], got)


def test_perl_inplace_on_test_file_blocked():
    cfg = state.default_config()
    ok, reason, _, _ = bashwrite.decide(
        "perl -pi -e 's/a/b/' tests/test_x.py", cfg, "/tmp/proj")
    check("perl -pi -e on test file blocked",
          ok is False and "tests/test_x.py" in reason, (ok, reason[:80]))


# ---------------------------------------------------------------------------
# hook: subprocess end-to-end
# ---------------------------------------------------------------------------

ENV_BASE = dict(os.environ, PYTHONPATH=SRC + os.pathsep +
                os.environ.get("PYTHONPATH", ""))


def run_hook(args, stdin_obj, cwd, env_extra=None):
    env = dict(ENV_BASE)
    env.update(env_extra or {})
    p = subprocess.run(
        [sys.executable, "-m", "agent_guard"] + args,
        input=json.dumps(stdin_obj) if stdin_obj is not None else "",
        capture_output=True, text=True, cwd=cwd, env=env, timeout=30)
    return p.returncode, p.stdout, p.stderr


def _bash_stdin(command, cwd):
    return {"session_id": "s1", "tool_name": "Bash", "cwd": cwd,
            "tool_input": {"command": command}}


def test_hook_blocks_sed_on_test_file():
    with tempfile.TemporaryDirectory() as tmp:
        sd = os.path.join(tmp, "state")
        os.makedirs(sd)
        stdin = _bash_stdin("sed -i 's/a/b/' tests/test_x.py", tmp)
        code, _, err = run_hook(["hook-bashwrite"], stdin, tmp,
                                {"AGENT_GUARD_DIR": sd})
        check("hook blocks sed -i on test file",
              code == 2 and "Bash-write guard" in err, (code, err[:60]))


def test_hook_blocks_heredoc_cheat():
    with tempfile.TemporaryDirectory() as tmp:
        sd = os.path.join(tmp, "state")
        os.makedirs(sd)
        cmd = ("cat > tests/test_x.py <<'EOF'\n"
               "import mock\n"
               "mock.patch(\"random.shuffle\", lambda x: None)\n"
               "EOF\n")
        code, _, err = run_hook(["hook-bashwrite"], _bash_stdin(cmd, tmp),
                                tmp, {"AGENT_GUARD_DIR": sd})
        check("hook blocks heredoc cheat content",
              code == 2 and "cheat score" in err, (code, err[:80]))


def test_hook_ignores_readonly():
    with tempfile.TemporaryDirectory() as tmp:
        sd = os.path.join(tmp, "state")
        os.makedirs(sd)
        code, _, _ = run_hook(
            ["hook-bashwrite"],
            _bash_stdin("grep -rn pattern tests/ | head", tmp),
            tmp, {"AGENT_GUARD_DIR": sd})
        check("hook ignores read-only bash", code == 0, code)


def test_hook_ignores_non_bash_tool():
    with tempfile.TemporaryDirectory() as tmp:
        sd = os.path.join(tmp, "state")
        os.makedirs(sd)
        stdin = {"session_id": "s1", "tool_name": "Write", "cwd": tmp,
                 "tool_input": {"file_path": "tests/test_x.py",
                                "content": "x"}}
        code, _, _ = run_hook(["hook-bashwrite"], stdin, tmp,
                              {"AGENT_GUARD_DIR": sd})
        check("hook ignores non-Bash tool", code == 0, code)


def test_hook_warn_mode():
    with tempfile.TemporaryDirectory() as tmp:
        sd = os.path.join(tmp, "state")
        os.makedirs(sd)
        stdin = _bash_stdin("sed -i 's/a/b/' tests/test_x.py", tmp)
        code, _, err = run_hook(
            ["hook-bashwrite"], stdin, tmp,
            {"AGENT_GUARD_DIR": sd, "AGENT_GUARD_BASHWRITE_MODE": "warn"})
        check("warn mode exits 0 with warning",
              code == 0 and "WARNING" in err, (code, err[:60]))


def test_hook_fail_open_on_garbage():
    with tempfile.TemporaryDirectory() as tmp:
        env = dict(ENV_BASE)
        p = subprocess.run(
            [sys.executable, "-m", "agent_guard", "hook-bashwrite"],
            input="not json{{{", capture_output=True, text=True, cwd=tmp,
            env=env, timeout=30)
        check("hook fails open on garbage stdin", p.returncode == 0,
              p.returncode)


def test_hook_writes_audit():
    with tempfile.TemporaryDirectory() as tmp:
        sd = os.path.join(tmp, "state")
        os.makedirs(sd)
        stdin = _bash_stdin("sed -i 's/a/b/' tests/test_x.py", tmp)
        run_hook(["hook-bashwrite"], stdin, tmp, {"AGENT_GUARD_DIR": sd})
        audit = os.path.join(sd, "audit.jsonl")
        found = False
        if os.path.exists(audit):
            with open(audit) as fh:
                for line in fh:
                    try:
                        e = json.loads(line)
                    except Exception:
                        continue
                    if e.get("guard") == "bashwrite" \
                            and e.get("decision") == "blocked":
                        found = True
        check("blocked bash write audit-logged", found, found)


def test_install_registers_bashwrite():
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
            if e.get("matcher") != "Bash":
                continue
            for h in e.get("hooks", []):
                if h.get("command") == "agent-guard hook-bashwrite":
                    found = True
        check("install registers hook-bashwrite",
              p.returncode == 0 and found, p.returncode)
        p2 = subprocess.run(
            [sys.executable, "-m", "agent_guard", "install"],
            input="", capture_output=True, text=True, cwd=tmp, env=env,
            timeout=30)
        with open(sp) as fh:
            settings2 = json.load(fh)
        n = sum(1 for e in settings2.get("hooks", {}).get("PreToolUse", [])
                for h in e.get("hooks", [])
                if h.get("command") == "agent-guard hook-bashwrite")
        check("install is idempotent", p2.returncode == 0 and n == 1, n)


def main():
    test_redirect()
    test_append()
    test_stderr_redirect()
    test_attached_redirect()
    test_dev_null_skipped()
    test_semicolon_glued()
    test_quoted_semicolon_untouched()
    test_heredoc()
    test_heredoc_dash()
    test_heredoc_quoted_delim()
    test_heredoc_scoped_to_segment()
    test_sed_inplace()
    test_sed_inplace_suffix()
    test_sed_inplace_long()
    test_sed_no_file()
    test_tee()
    test_tee_append()
    test_tee_ignores_input_redirect()
    test_cp_mv_dest()
    test_cp_to_dir_skipped()
    test_chained()
    test_nested_sh_c()
    test_clean_cases()
    test_parse_failure_fail_open()
    test_decide_opaque_test_write_blocked()
    test_decide_clean_bash_allowed()
    test_decide_heredoc_cheat_scored()
    test_decide_heredoc_clean_allowed()
    test_decide_protected_paths()
    test_decide_allowlist()
    test_decide_mode_warn()
    test_config_merge_includes_sections()
    test_fp_log_file_not_testy()
    test_fp_fixture_data_not_testy()
    test_fp_testdata_dir_not_testy()
    test_fp_init_py_not_testy()
    test_fp_real_test_file_still_blocked()
    test_perl_inplace_extracts()
    test_perl_inplace_bak_extracts()
    test_perl_no_inplace_no_target()
    test_perl_inplace_on_test_file_blocked()
    test_hook_blocks_sed_on_test_file()
    test_hook_blocks_heredoc_cheat()
    test_hook_ignores_readonly()
    test_hook_ignores_non_bash_tool()
    test_hook_warn_mode()
    test_hook_fail_open_on_garbage()
    test_hook_writes_audit()
    test_install_registers_bashwrite()
    print("\n%d/%d passed" % (sum(PASS), len(PASS)))
    return 0 if all(PASS) else 1


if __name__ == "__main__":
    sys.exit(main())
