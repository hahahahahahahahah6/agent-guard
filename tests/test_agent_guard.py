"""Smoke tests for agent-guard. Run: python3 tests/test_agent_guard.py"""

import json
import os
import subprocess
import sys
import tempfile

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "src")
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


def run_cli(args, cwd, env_extra=None):
    """Run a non-hook CLI subcommand (no stdin)."""
    env = dict(ENV_BASE)
    env.update(env_extra or {})
    p = subprocess.run(
        [sys.executable, "-m", "agent_guard"] + args,
        input="", capture_output=True, text=True, cwd=cwd, env=env,
        timeout=30)
    return p.returncode, p.stdout, p.stderr


def make_proj(tmp):
    proj = os.path.join(tmp, "proj")
    os.makedirs(os.path.join(proj, "src"))
    os.makedirs(os.path.join(proj, "tests"))
    with open(os.path.join(proj, "src", "app.py"), "w") as fh:
        fh.write("def add(a, b):\n    return a + b\n")
    with open(os.path.join(proj, "tests", "test_app.py"), "w") as fh:
        fh.write("def test_add():\n    assert add(1, 2) == 3\n")
    return proj


def snapshot(proj, state_dir):
    code, _, err = run_hook(["hook-snapshot"], {"session_id": "s1"},
                            proj, {"AGENT_GUARD_DIR": state_dir})
    assert code == 0, err


def stop_check(proj, state_dir, env_extra=None, session_id="s1",
               stop_hook_active=False):
    env = {"AGENT_GUARD_DIR": state_dir}
    env.update(env_extra or {})
    stdin = {"session_id": session_id}
    if stop_hook_active:
        stdin["stop_hook_active"] = True
    return run_hook(["hook-test"], stdin, proj, env)


def bash_check(cmd, state_dir, config=None, env_extra=None, hook_cwd=None):
    if config is not None:
        os.makedirs(state_dir, exist_ok=True)
        with open(os.path.join(state_dir, "config.json"), "w") as fh:
            json.dump(config, fh)
    env = {"AGENT_GUARD_DIR": state_dir}
    env.update(env_extra or {})
    stdin = {"session_id": "s1", "tool_name": "Bash",
             "tool_input": {"command": cmd}}
    if hook_cwd is not None:
        stdin["cwd"] = hook_cwd  # what the PreToolUse hook reports
    return run_hook(["hook-outbound"], stdin, "/tmp", env)


def make_git_repo(tmp, branch):
    """A real git repo on `branch`, for destination-aware push tests."""
    repo = os.path.join(tmp, "repo-" + branch.replace("/", "-"))
    os.makedirs(repo, exist_ok=True)

    def g(*a):
        subprocess.run(["git"] + list(a), cwd=repo, capture_output=True,
                       check=True, timeout=30)

    g("init", "-q")
    g("config", "user.email", "test@example.com")
    g("config", "user.name", "test")
    g("config", "commit.gpgsign", "false")
    with open(os.path.join(repo, "f.txt"), "w") as fh:
        fh.write("x\n")
    g("add", ".")
    g("commit", "-qm", "init")
    g("branch", "-M", branch)
    return repo


PASS = []


def check(name, cond, detail=""):
    PASS.append(cond)
    print(("PASS " if cond else "FAIL ") + name + (" — " + detail if detail and not cond else ""))


def main():
    # --- test-tampering guard ---
    with tempfile.TemporaryDirectory() as tmp:
        sd = os.path.join(tmp, "state")
        proj = make_proj(tmp)
        snapshot(proj, sd)
        with open(os.path.join(proj, "tests", "test_app.py"), "a") as fh:
            fh.write("    assert add(0, 0) == 1  # weakened\n")
        code, _, err = stop_check(proj, sd)
        check("tests-only change blocked",
              code == 2 and "fails without the fix" in err, "rc=%d" % code)

    with tempfile.TemporaryDirectory() as tmp:
        sd = os.path.join(tmp, "state")
        proj = make_proj(tmp)
        snapshot(proj, sd)
        with open(os.path.join(proj, "src", "app.py"), "a") as fh:
            fh.write("def sub(a, b):\n    return a - b\n")
        with open(os.path.join(proj, "tests", "test_app.py"), "a") as fh:
            fh.write("def test_sub():\n    assert sub(1, 2) == -1\n")
        code, _, _ = stop_check(proj, sd)
        check("source+tests changed -> allowed", code == 0, "rc=%d" % code)

    with tempfile.TemporaryDirectory() as tmp:
        sd = os.path.join(tmp, "state")
        proj = make_proj(tmp)
        snapshot(proj, sd)
        code, _, _ = stop_check(proj, sd)
        check("no change -> allowed", code == 0, "rc=%d" % code)

    with tempfile.TemporaryDirectory() as tmp:
        sd = os.path.join(tmp, "state")
        proj = make_proj(tmp)
        snapshot(proj, sd)
        with open(os.path.join(sd, "test-snapshot.s1.json"), "w") as fh:
            fh.write("{corrupt!!")
        with open(os.path.join(proj, "tests", "test_app.py"), "a") as fh:
            fh.write("# x\n")
        code, _, _ = stop_check(proj, sd)
        check("corrupt snapshot -> fail open", code == 0, "rc=%d" % code)

    with tempfile.TemporaryDirectory() as tmp:
        sd = os.path.join(tmp, "state")
        proj = make_proj(tmp)
        snapshot(proj, sd)
        with open(os.path.join(proj, "tests", "test_app.py"), "a") as fh:
            fh.write("    assert add(0, 0) == 1  # weakened\n")
        # First Stop blocks; when Claude Code reports the hook already fired
        # (stop_hook_active), we MUST NOT block again, or the session loops.
        code, _, err = stop_check(proj, sd, stop_hook_active=True)
        check("stop_hook_active -> never blocks (no infinite loop)",
              code == 0, "rc=%d err=%s" % (code, err.strip()[:80]))

    with tempfile.TemporaryDirectory() as tmp:
        sd = os.path.join(tmp, "state")
        proj = make_proj(tmp)
        snapshot(proj, sd)  # session s1
        code, _, _ = run_hook(["hook-snapshot"], {"session_id": "s2"},
                              proj, {"AGENT_GUARD_DIR": sd})
        assert code == 0
        s1f = os.path.join(sd, "test-snapshot.s1.json")
        s2f = os.path.join(sd, "test-snapshot.s2.json")
        check("snapshots stored per session",
              os.path.exists(s1f) and os.path.exists(s2f)
              and not os.path.exists(os.path.join(sd, "test-snapshot.json")))
        with open(os.path.join(proj, "tests", "test_app.py"), "a") as fh:
            fh.write("    assert add(0, 0) == 1  # weakened\n")
        # A session with no snapshot of its own fails open instead of
        # reading another session's snapshot.
        code, _, _ = stop_check(proj, sd, session_id="sN")
        check("unknown session -> fail open (no cross-session block)",
              code == 0, "rc=%d" % code)
        code, _, _ = stop_check(proj, sd, session_id="s1")
        check("own session still blocks on its snapshot",
              code == 2, "rc=%d" % code)

    with tempfile.TemporaryDirectory() as tmp:
        sd = os.path.join(tmp, "state")
        proj = make_proj(tmp)
        snapshot(proj, sd)
        with open(os.path.join(proj, "tests", "test_app.py"), "a") as fh:
            fh.write("# y\n")
        code, _, err = stop_check(proj, sd, {"AGENT_GUARD_TEST_MODE": "warn"})
        check("warn mode never blocks", code == 0 and "WARNING" in err,
              "rc=%d" % code)

    # --- outbound-action guard ---
    with tempfile.TemporaryDirectory() as tmp:
        sd = os.path.join(tmp, "state")
        code, _, err = bash_check("git push origin main", sd)
        check("git push origin main blocked",
              code == 2 and "git-push-protected" in err, "rc=%d" % code)

    with tempfile.TemporaryDirectory() as tmp:
        sd = os.path.join(tmp, "state")
        # Explicit refspecs need no branch resolution (cwd /tmp is not a repo).
        push_cases = [
            ("git push origin main", 2),
            ("git -C . push origin main", 2),      # flags between git and push
            ("git push origin :main", 2),          # deletes remote main
            ("git push origin feature-x:main", 2), # dst main, src feature
            ("git push origin HEAD:main", 2),      # dst main
            ("git push --force origin main", 2),
            ("git push --force-with-lease origin main", 2),
            ("git push --all", 2),                 # pushes every ref
            ("git push --mirror", 2),
            ("git push origin feature/cool", 0),   # explicit safe branch
            ("git push origin main:feature-x", 0), # src protected, dst safe
            ("git push origin v1.2.3", 0),         # tag push
            ("git push --tags", 0),                # tags only, no branch push
            ("git push --force origin feature-x", 0),  # force, dst unprotected
            # No refspec and branch unknowable (not a repo) -> fail open.
            ("git push", 0),
            ("git push origin", 0),
        ]
        all_ok = True
        for cmd, want in push_cases:
            code, _, _ = bash_check(cmd, sd)
            if code != want:
                all_ok = False
                print("   push case rc=%d want=%d: %s" % (code, want, cmd))
        check("git push parser cases", all_ok)

    # --- destination-aware push blocking (real git repos) ---
    with tempfile.TemporaryDirectory() as tmp:
        sd = os.path.join(tmp, "state")
        feat = make_git_repo(tmp, "feature/cool")
        main = make_git_repo(tmp, "main")
        detach = make_git_repo(tmp, "feature/detach")
        subprocess.run(["git", "checkout", "-q", "--detach", "HEAD"],
                       cwd=detach, capture_output=True, timeout=30)
        cases = [
            # (name, command, hook cwd, want rc)
            ("plain push on feature branch allowed",
             "git push", feat, 0),
            ("push origin HEAD on feature allowed",
             "git push origin HEAD", feat, 0),
            ("push remote-only on feature allowed",
             "git push origin", feat, 0),
            ("plain push on main blocked",
             "git push", main, 2),
            ("push origin HEAD on main blocked",
             "git push origin HEAD", main, 2),
            ("push origin main from feature branch blocked",
             "git push origin main", feat, 2),
            ("push feature-x:main from feature branch blocked",
             "git push origin feature-x:main", feat, 2),
            ("-C feature repo: plain push allowed",
             "git -C %s push" % feat, "/tmp", 0),
            ("-C main repo: plain push blocked",
             "git -C %s push" % main, "/tmp", 2),
            ("force push feature branch allowed",
             "git push --force origin feature/cool", feat, 0),
            ("force push main blocked",
             "git push --force origin main", feat, 2),
            ("delete non-protected remote branch allowed",
             "git push origin :feature/gone", feat, 0),
            ("detached HEAD: branch unknowable -> fail open",
             "git push", detach, 0),
        ]
        all_ok = True
        for name, cmd, hook_cwd, want in cases:
            code, _, _ = bash_check(cmd, sd, hook_cwd=hook_cwd)
            if code != want:
                all_ok = False
                print("   rc=%d want=%d: %s [%s]" % (code, want, cmd, name))
        check("destination-aware push blocking", all_ok)

    with tempfile.TemporaryDirectory() as tmp:
        sd = os.path.join(tmp, "state")
        code, _, err = bash_check("npm publish --access public", sd)
        check("npm publish blocked", code == 2, "rc=%d" % code)

    with tempfile.TemporaryDirectory() as tmp:
        sd = os.path.join(tmp, "state")
        code, _, err = bash_check("twine upload dist/*", sd)
        check("twine upload blocked", code == 2 and "package-publish" in err,
              "rc=%d" % code)

    with tempfile.TemporaryDirectory() as tmp:
        sd = os.path.join(tmp, "state")
        code1, _, _ = bash_check("git push origin feature/cool-thing", sd)
        code2, _, _ = bash_check("ls -la && pytest -q", sd)
        code3, _, _ = bash_check("npm publish --dry-run", sd)
        check("benign commands allowed",
              code1 == 0 and code2 == 0 and code3 == 0,
              "rc=%d,%d,%d" % (code1, code2, code3))

    with tempfile.TemporaryDirectory() as tmp:
        sd = os.path.join(tmp, "state")
        cfg = {"outbound": {"allow": [r"my-registry\.internal"]}}
        code, _, _ = bash_check(
            "npm publish --registry https://my-registry.internal", sd, cfg)
        entries = []
        ap = os.path.join(sd, "audit.jsonl")
        if os.path.exists(ap):
            for line in open(ap):
                try:
                    entries.append(json.loads(line))
                except Exception:
                    pass
        check("allowlist override allowed+audited",
              code == 0 and any(e.get("decision") == "allowed-override"
                                for e in entries),
              "rc=%d entries=%d" % (code, len(entries)))

    with tempfile.TemporaryDirectory() as tmp:
        sd = os.path.join(tmp, "state")
        p = subprocess.run(
            [sys.executable, "-m", "agent_guard", "hook-outbound"],
            input="not json{{{{", capture_output=True, text=True,
            cwd="/tmp", env=dict(ENV_BASE, AGENT_GUARD_DIR=sd), timeout=30)
        check("garbage stdin -> fail open", p.returncode == 0,
              "rc=%d" % p.returncode)

    with tempfile.TemporaryDirectory() as tmp:
        sd = os.path.join(tmp, "state")
        code, _, _ = bash_check(
            "curl -X POST https://hooks.slack.com/services/T/B/X -d hi", sd)
        ap = os.path.join(sd, "audit.jsonl")
        entries = [json.loads(l) for l in open(ap)] if os.path.exists(ap) else []
        check("block writes audit entry",
              code == 2 and any(e.get("decision") == "blocked"
                                and e.get("rule") == "mass-send"
                                for e in entries),
              "rc=%d entries=%d" % (code, len(entries)))

    # --- script-content inspection (v0.2) ---
    with tempfile.TemporaryDirectory() as tmp:
        sd = os.path.join(tmp, "state")
        with open(os.path.join(tmp, "evil.sh"), "w") as fh:
            fh.write("curl -X POST https://hooks.slack.com/services/T/B/X -d hi\n")
        with open(os.path.join(tmp, "deploy.sh"), "w") as fh:
            fh.write("git push origin main\n")
        with open(os.path.join(tmp, "good.sh"), "w") as fh:
            fh.write("echo hello\n")
        with open(os.path.join(tmp, "notes.txt"), "w") as fh:
            fh.write("curl -X POST https://hooks.slack.com/services/T/B/X -d hi\n")
        code1, _, err1 = bash_check("bash evil.sh", sd, hook_cwd=tmp)
        code2, _, err2 = bash_check("bash deploy.sh", sd, hook_cwd=tmp)
        code3, _, _ = bash_check("bash good.sh", sd, hook_cwd=tmp)
        code4, _, _ = bash_check("bash missing.sh", sd, hook_cwd=tmp)
        code5, _, _ = bash_check("bash notes.txt", sd, hook_cwd=tmp)
        code6, _, err6 = bash_check("./deploy.sh", sd, hook_cwd=tmp)
        code7, _, err7 = bash_check("bash -c 'git push origin main'", sd,
                                   hook_cwd=tmp)
        ap = os.path.join(sd, "audit.jsonl")
        entries = [json.loads(l) for l in open(ap)] if os.path.exists(ap) else []
        check("script with mass-send blocked as script-content",
              code1 == 2 and "script-content:mass-send" in err1,
              "rc=%d" % code1)
        check("script with git push to main blocked as script-content",
              code2 == 2 and "script-content:git-push-protected" in err2,
              "rc=%d" % code2)
        check("benign/missing/non-script files allowed",
              code3 == 0 and code4 == 0 and code5 == 0,
              "rc=%d,%d,%d" % (code3, code4, code5))
        check("direct ./ execution scanned too",
              code6 == 2 and "script-content:git-push-protected" in err6,
              "rc=%d" % code6)
        check("bash -c inline code scanned too",
              code7 == 2 and "script-content:git-push-protected" in err7,
              "rc=%d" % code7)
        check("script-content blocks audited with prefixed rule id",
              any(e.get("decision") == "blocked"
                  and str(e.get("rule", "")).startswith("script-content:")
                  for e in entries),
              "entries=%d" % len(entries))

    with tempfile.TemporaryDirectory() as tmp:
        sd = os.path.join(tmp, "state")
        with open(os.path.join(tmp, "evil.sh"), "w") as fh:
            fh.write("curl -X POST https://hooks.slack.com/services/T/B/X -d hi\n")
        cfg = {"outbound": {"disabled_rules": ["mass-send"]}}
        code, _, _ = bash_check("bash evil.sh", sd, cfg, hook_cwd=tmp)
        check("disabled_rules covers script-content variant", code == 0,
              "rc=%d" % code)

    # --- mutation test-honesty (v0.2) ---
    def make_mut_proj(tmp):
        proj = os.path.join(tmp, "mutproj")
        os.makedirs(proj)
        with open(os.path.join(proj, "run_tests.py"), "w") as fh:
            fh.write(
                "import sys\n"
                "mod = __import__(sys.argv[1])\n"
                "fails = 0\n"
                "for name in sorted(dir(mod)):\n"
                "    if name.startswith('test_'):\n"
                "        try:\n"
                "            getattr(mod, name)()\n"
                "        except Exception:\n"
                "            fails += 1\n"
                "sys.exit(1 if fails else 0)\n")
        # Weak: the assertion sits behind `if False:` so it can never fail.
        with open(os.path.join(proj, "test_weak.py"), "w") as fh:
            fh.write("def test_weak():\n"
                     "    x = 5\n"
                     "    if False:\n"
                     "        assert x == 5\n")
        # Strong: mutating the assertion must turn the test red.
        with open(os.path.join(proj, "test_strong.py"), "w") as fh:
            fh.write("def test_strong():\n"
                     "    x = 5\n"
                     "    assert x == 5\n")
        return proj

    def mutate_check(test_file, proj, state_dir):
        env = {"AGENT_GUARD_DIR": state_dir}
        return run_hook(
            ["mutate-check", test_file, "--project-root", proj, "--",
             "python3", "run_tests.py",
             os.path.splitext(os.path.basename(test_file))[0]],
            {}, proj, env)

    with tempfile.TemporaryDirectory() as tmp:
        sd = os.path.join(tmp, "state")
        proj = make_mut_proj(tmp)
        code, out, err = mutate_check(os.path.join(proj, "test_weak.py"),
                                      proj, sd)
        check("mutate-check flags weak test (exit 1, survivor reported)",
              code == 1 and "SURVIVED (1)" in out and "WEAK" in out,
              "rc=%d" % code)

    with tempfile.TemporaryDirectory() as tmp:
        sd = os.path.join(tmp, "state")
        proj = make_mut_proj(tmp)
        code, out, err = mutate_check(os.path.join(proj, "test_strong.py"),
                                      proj, sd)
        check("mutate-check passes strong test (exit 0, all killed)",
              code == 0 and "all 1 mutation(s) killed" in out,
              "rc=%d" % code)

    with tempfile.TemporaryDirectory() as tmp:
        sd = os.path.join(tmp, "state")
        proj = make_mut_proj(tmp)
        code, out, err = mutate_check(os.path.join(proj, "nope.py"),
                                      proj, sd)
        check("mutate-check missing file -> fail open (exit 0)",
              code == 0 and "failing open" in out, "rc=%d" % code)

    # --- post-exec read-back verifier (v0.2) ---
    def verify_check(cmd, state_dir, hook_cwd):
        env = {"AGENT_GUARD_DIR": state_dir}
        stdin = {"session_id": "s1", "tool_name": "Bash",
                 "tool_input": {"command": cmd}, "cwd": hook_cwd}
        return run_hook(["hook-verify"], stdin, "/tmp", env)

    with tempfile.TemporaryDirectory() as tmp:
        sd = os.path.join(tmp, "state")
        repo = make_git_repo(tmp, "main")
        empty = os.path.join(tmp, "empty.git")
        full = os.path.join(tmp, "full.git")
        subprocess.run(["git", "init", "-q", "--bare", empty],
                       capture_output=True, timeout=30)
        subprocess.run(["git", "init", "-q", "--bare", full],
                       capture_output=True, timeout=30)
        subprocess.run(["git", "remote", "add", "emptyorigin", empty],
                       cwd=repo, capture_output=True, timeout=30)
        subprocess.run(["git", "remote", "add", "fullorigin", full],
                       cwd=repo, capture_output=True, timeout=30)
        subprocess.run(["git", "push", "-q", "fullorigin", "main"],
                       cwd=repo, capture_output=True, timeout=30)
        code1, _, err1 = verify_check("git push emptyorigin main", sd, repo)
        code2, _, err2 = verify_check("git push fullorigin main", sd, repo)
        code3, _, err3 = verify_check("ls -la", sd, repo)
        code4, _, err4 = verify_check("npm publish", sd, repo)
        check("hook-verify warns (exit 0) when push not visible remotely",
              code1 == 0 and "not visible" in err1, "rc=%d" % code1)
        check("hook-verify silent when push is visible",
              code2 == 0 and err2 == "", "rc=%d err=%r" % (code2, err2[:60]))
        check("hook-verify silent for unrelated commands",
              code3 == 0 and err3 == "", "rc=%d" % code3)
        check("hook-verify silent for npm publish without package.json",
              code4 == 0 and err4 == "", "rc=%d" % code4)

    # --- install ---
    with tempfile.TemporaryDirectory() as tmp:
        home = os.path.join(tmp, "home")
        os.makedirs(os.path.join(home, ".claude"))
        sp = os.path.join(home, ".claude", "settings.json")
        with open(sp, "w") as fh:
            json.dump({"hooks": {"PreToolUse": []}}, fh)
        env = dict(ENV_BASE, HOME=home)
        for _ in range(2):
            p = subprocess.run([sys.executable, "-m", "agent_guard", "install"],
                               capture_output=True, text=True, env=env,
                               timeout=30)
            assert p.returncode == 0, p.stderr
        settings = json.load(open(sp))
        n_start = len(settings["hooks"].get("SessionStart", []))
        n_stop = len(settings["hooks"].get("Stop", []))
        n_pre = len(settings["hooks"].get("PreToolUse", []))
        n_post = len(settings["hooks"].get("PostToolUse", []))
        post_cmds = [h.get("command", "")
                     for e in settings["hooks"].get("PostToolUse", [])
                     for h in e.get("hooks", [])]
        pre_cmds = [h.get("command", "")
                    for e in settings["hooks"].get("PreToolUse", [])
                    for h in e.get("hooks", [])]
        pre_matchers = [e.get("matcher", "")
                        for e in settings["hooks"].get("PreToolUse", [])]
        bak_ok = os.path.exists(sp + ".bak")
        check("install idempotent",
              n_start == 1 and n_stop == 1 and n_pre == 2 and n_post == 1
              and bak_ok
              and any("hook-verify" in c for c in post_cmds)
              and any("hook-commentslop" in c for c in pre_cmds)
              and "Bash" in pre_matchers and "Write|Edit" in pre_matchers,
              "start=%d stop=%d pre=%d post=%d bak=%s"
              % (n_start, n_stop, n_pre, n_post, bak_ok))

    # --- comment-slop guard ---
    sys.path.insert(0, SRC)
    from agent_guard import commentslop

    sloppy_py = (
        "# x = compute(1);\n"
        "# y = compute(2);\n"
        "# This function adds two numbers\n"
        "# Fixed the off-by-one error in the loop\n"
        "# all done \U0001F600\n"
        "def f():\n    pass\n")
    score, hits = commentslop.score_text(sloppy_py, "py")
    kinds = {k for _, _, k, _ in hits}
    check("slop kinds detected",
          kinds == {"commented-code", "restatement", "changelog", "emoji"}
          and score >= 30,
          "kinds=%s score=%s" % (sorted(kinds), score))

    clean_py = ("#!/usr/bin/env python3\n"
                "# initialize the client\n"
                "client = make_client()  # noqa\n"
                'url = "http://example.com/a//b"\n')
    score, hits = commentslop.score_text(clean_py, "py")
    check("clean code scores 0", score == 0 and hits == [],
          "score=%s hits=%s" % (score, hits))

    score, hits = commentslop.score_text(
        '"""Add a and b."""\ndef add(a, b):\n    return a + b\n', "py")
    check("obvious docstring flagged",
          any(k == "obvious-doc" for _, _, k, _ in hits),
          "hits=%s" % ([k for _, _, k, _ in hits],))
    score, hits = commentslop.score_text(
        '"""Add a and b.\n\nUses Kahan summation for numerical stability."""\n'
        'def add(a, b):\n    return a + b\n', "py")
    check("informative docstring not flagged",
          not any(k == "obvious-doc" for _, _, k, _ in hits),
          "hits=%s" % ([k for _, _, k, _ in hits],))

    with tempfile.TemporaryDirectory() as tmp:
        sd = os.path.join(tmp, "state")
        sloppy = os.path.join(tmp, "sloppy.py")
        with open(sloppy, "w") as fh:
            fh.write(sloppy_py)
        clean = os.path.join(tmp, "clean.py")
        with open(clean, "w") as fh:
            fh.write(clean_py)
        env = {"AGENT_GUARD_DIR": sd}
        code, out, _ = run_cli(["decomment", "--check", sloppy, clean],
                               tmp, env)
        check("decomment --check exits 1 on slop",
              code == 1 and "SLOP" in out and "[ok]" in out, "rc=%d" % code)
        code, _, _ = run_cli(["decomment", "--check", clean], tmp, env)
        check("decomment --check exits 0 on clean", code == 0,
              "rc=%d" % code)
        code, out, _ = run_cli(["decomment", "--fix", sloppy], tmp, env)
        body = open(sloppy).read()
        bak = sloppy + ".bak"
        check("decomment --fix removes only commented code",
              code == 0 and os.path.exists(bak)
              and "compute(1)" not in body and "compute(2)" not in body
              and "This function adds two numbers" in body
              and "compute(1)" in open(bak).read(),
              "rc=%d" % code)

    def slop_stdin(tool, content, path="/tmp/x.py"):
        ti = {"file_path": path}
        if tool == "Write":
            ti["content"] = content
        else:
            ti["old_string"] = "a"
            ti["new_string"] = content
        return {"session_id": "s1", "tool_name": tool, "tool_input": ti}

    slop_content = ("# This function adds two numbers\n"
                    "# x = compute(1);\n# y = compute(2);\n"
                    "def add(a, b):\n    return a + b\n")

    with tempfile.TemporaryDirectory() as tmp:
        sd = os.path.join(tmp, "state")
        code, _, err = run_hook(["hook-commentslop"],
                                slop_stdin("Write", slop_content), tmp,
                                {"AGENT_GUARD_DIR": sd})
        check("hook blocks Write with heavy slop",
              code == 2 and "L1" in err and "restatement" in err,
              "rc=%d" % code)
        code, _, _ = run_hook(
            ["hook-commentslop"],
            slop_stdin("Write", "# initialize the client\nx = 1\n"), tmp,
            {"AGENT_GUARD_DIR": sd})
        check("hook allows clean Write", code == 0, "rc=%d" % code)
        code, _, _ = run_hook(
            ["hook-commentslop"],
            slop_stdin("Edit", "# sorry, temporary hack\n# t = x(\n# u = y("),
            tmp, {"AGENT_GUARD_DIR": sd})
        check("hook blocks Edit with slop", code == 2, "rc=%d" % code)
        code, _, _ = run_hook(["hook-commentslop"],
                              slop_stdin("Write", slop_content), tmp,
                              {"AGENT_GUARD_DIR": sd,
                               "AGENT_GUARD_COMMENT_MODE": "warn"})
        check("warn mode exits 0", code == 0, "rc=%d" % code)
        code, _, _ = run_hook(["hook-commentslop"], None, tmp,
                              {"AGENT_GUARD_DIR": sd})
        check("garbage stdin fails open", code == 0, "rc=%d" % code)
        code, _, _ = run_hook(
            ["hook-commentslop"],
            {"session_id": "s1", "tool_name": "Bash",
             "tool_input": {"command": "ls"}}, tmp,
            {"AGENT_GUARD_DIR": sd})
        check("non-Write/Edit tool ignored", code == 0, "rc=%d" % code)
        entries = []
        audit = os.path.join(sd, "audit.jsonl")
        if os.path.exists(audit):
            for line in open(audit):
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
        check("slop blocks are audit-logged",
              any(e.get("guard") == "commentslop"
                  and e.get("decision") == "blocked" for e in entries),
              "entries=%d" % len(entries))

    print("\n%d/%d passed" % (sum(PASS), len(PASS)))
    return 0 if all(PASS) else 1


if __name__ == "__main__":
    sys.exit(main())
