"""agent-guard: behavior-guardrail hooks for Claude Code."""

import argparse
import json
import os
import shutil
import sys

from . import mutate, outbound, state, testguard, verify


def _hook_input():
    """Read the hook's stdin JSON defensively."""
    try:
        raw = sys.stdin.read()
        obj = json.loads(raw)
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def _project_root(data):
    root = data.get("cwd") or os.getcwd()
    try:
        return os.path.abspath(root)
    except Exception:
        return os.getcwd()


def cmd_snapshot(args):
    """SessionStart: record test+source digests. Never blocks."""
    try:
        data = _hook_input()
        session = str(data.get("session_id", "") or "")
        testguard.snapshot(_project_root(data), session_id=session or None)
    except Exception:
        pass
    return 0


def cmd_test(args):
    """Stop: diff test files vs snapshot; block tests-only changes.

    Honors `stop_hook_active`: when Claude Code tells us a Stop hook already
    fired, we must not block again or the session can never end (infinite
    loop). The first block already delivered the warning to the agent.
    """
    try:
        data = _hook_input()
        if data.get("stop_hook_active"):
            return 0
        session = str(data.get("session_id", "") or "unknown")
        root = _project_root(data)
        sid = None if session == "unknown" else session
        allowed, reason = testguard.check(root, session_id=sid)
        if not allowed:
            state.append_audit({
                "guard": "test", "tool": "Stop", "session": session,
                "decision": "blocked", "rule": "tests-only-change",
                "reason": reason.split("\n")[0],
            })
            if testguard.mode() == "warn":
                sys.stderr.write("WARNING (not blocking): " + reason + "\n")
                return 0
            sys.stderr.write(reason + "\n")
            return 2
        return 0
    except Exception:
        return 0  # fail open, always


def cmd_outbound(args):
    """PreToolUse on Bash: denylist risky outbound actions."""
    try:
        data = _hook_input()
        tool = data.get("tool_name", "")
        if tool != "Bash":
            return 0
        session = str(data.get("session_id", "") or "unknown")
        tool_input = data.get("tool_input")
        command = tool_input.get("command", "") if isinstance(tool_input, dict) else ""
        cfg = state.load_config()
        hook_cwd = data.get("cwd") or os.getcwd()
        allowed, reason, rule = outbound.check(command, cfg, cwd=hook_cwd)
        verbose = os.environ.get("AGENT_GUARD_VERBOSE", "") == "1"
        if rule is not None or verbose:
            state.append_audit({
                "guard": "outbound", "tool": "Bash", "session": session,
                "command": (command or "")[:500],
                "decision": "blocked" if not allowed
                            else ("allowed-override" if rule else "allowed"),
                "rule": rule,
            })
        if not allowed:
            sys.stderr.write(reason + "\n")
            return 2
        return 0
    except Exception:
        return 0  # fail open, always


def cmd_verify(args):
    """PostToolUse on Bash: warn when a claimed effect isn't visible.

    Advisory only: always exits 0, never blocks.
    """
    try:
        return verify.run_hook()
    except Exception:
        return 0  # fail open, always


def cmd_mutate(args):
    """Mutation test-honesty check (see agent_guard.mutate)."""
    try:
        cmd = [a for a in (args.test_cmd or []) if a != "--"]
        code, report = mutate.check(
            args.test_file, cmd,
            project_root=args.project_root,
            max_mutations=args.max_mutations,
            timeout=args.timeout)
        sys.stdout.write(report)
        return code
    except Exception as e:
        sys.stderr.write("mutate-check: internal error (%s); failing open.\n"
                         % e)
        return 0


def _settings_path():
    return os.path.join(os.path.expanduser("~"), ".claude", "settings.json")


SNIPPETS = {
    "SessionStart": [{"hooks": [{"type": "command",
                                 "command": "agent-guard hook-snapshot"}]}],
    "Stop": [{"hooks": [{"type": "command",
                         "command": "agent-guard hook-test"}]}],
    "PreToolUse": [{"matcher": "Bash",
                    "hooks": [{"type": "command",
                               "command": "agent-guard hook-outbound"}]}],
    "PostToolUse": [{"matcher": "Bash",
                     "hooks": [{"type": "command",
                                "command": "agent-guard hook-verify"}]}],
}


def _present(entries, key):
    want = SNIPPETS[key]
    for e in entries:
        if not isinstance(e, dict):
            continue
        if key in ("PreToolUse", "PostToolUse") \
                and e.get("matcher") != "Bash":
            continue
        for h in e.get("hooks", []):
            if "agent-guard" in (h.get("command", "") or ""):
                return True
    return False


def cmd_install(args):
    """Merge hooks into ~/.claude/settings.json (with backup)."""
    sp = _settings_path()
    settings = {}
    if os.path.exists(sp):
        try:
            with open(sp, "r", encoding="utf-8") as fh:
                settings = json.load(fh)
            if not isinstance(settings, dict):
                settings = {}
        except Exception as e:
            print("Could not parse %s: %s" % (sp, e), file=sys.stderr)
            return 1
        try:
            bak = sp + ".bak"
            shutil.copy2(sp, bak)
            print("Backed up %s -> %s" % (sp, bak))
        except OSError as e:
            print("Backup failed: %s" % e, file=sys.stderr)
            return 1

    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        hooks = {}
        settings["hooks"] = hooks

    added = 0
    for key, snippet in SNIPPETS.items():
        entries = hooks.get(key)
        if not isinstance(entries, list):
            entries = []
            hooks[key] = entries
        if _present(entries, key):
            continue
        entries.extend(snippet)
        added += 1

    os.makedirs(os.path.dirname(sp), exist_ok=True)
    with open(sp, "w", encoding="utf-8") as fh:
        json.dump(settings, fh, indent=2)
        fh.write("\n")
    print("Installed agent-guard hooks into %s (%d added)." % (sp, added))
    print("Restart Claude Code for the hooks to take effect.")
    return 0


def cmd_log(args):
    entries = state.read_audit()
    entries.sort(key=lambda e: e.get("ts", 0))
    for e in entries[-args.limit:]:
        import datetime
        ts = datetime.datetime.fromtimestamp(
            e.get("ts", 0)).strftime("%m-%d %H:%M:%S")
        print("%s  %-8s %-16s %-30s %s" % (
            ts, e.get("guard", ""), e.get("decision", ""),
            str(e.get("rule", ""))[:30],
            (e.get("command", "") or e.get("reason", ""))[:80]))
    return 0


def cmd_status(args):
    cfg = state.load_config()
    print("state dir:  %s" % state.state_dir())
    print("config:     %s" % state.config_path())
    print("audit log:  %s (%d entries)"
          % (state.audit_path(), len(state.read_audit())))
    print("test mode:  %s" % testguard.mode())
    print("rules:      %s" % ", ".join(outbound.rule_ids()))
    print("settings:   %s" % _settings_path())
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        prog="agent-guard",
        description="Behavior-guardrail hooks for Claude Code: "
                    "test-tampering + outbound-action guards, mutation "
                    "test-honesty, and post-exec verification.")
    sub = p.add_subparsers(dest="cmd", required=True)

    for name, help_text, func in [
        ("hook-snapshot", "SessionStart hook: snapshot test digests.", cmd_snapshot),
        ("hook-test", "Stop hook: block tests-only changes.", cmd_test),
        ("hook-outbound", "PreToolUse hook: block risky Bash actions.", cmd_outbound),
        ("hook-verify", "PostToolUse hook: warn when a claimed effect "
                        "isn't visible (never blocks).", cmd_verify),
        ("mutate-check", "Mutation test-honesty check: mutate assertions, "
                         "re-run tests, report survivors.", cmd_mutate),
        ("install", "Install hooks into ~/.claude/settings.json.", cmd_install),
        ("log", "Show recent guard decisions.", cmd_log),
        ("status", "Show state paths and config.", cmd_status),
    ]:
        sp = sub.add_parser(name, help=help_text)
        sp.set_defaults(func=func)
    sub.choices["log"].add_argument("--limit", type=int, default=20)
    mc = sub.choices["mutate-check"]
    mc.add_argument("test_file", help="test file to mutate")
    mc.add_argument("test_cmd", nargs="*",
                    help="test command (pass after -- : e.g. -- pytest -q)")
    mc.add_argument("--project-root", default=None,
                    help="project root (default: nearest dir with project markers)")
    mc.add_argument("--max-mutations", type=int, default=mutate.DEFAULT_MAX_MUTATIONS)
    mc.add_argument("--timeout", type=int, default=mutate.DEFAULT_TIMEOUT,
                    help="per-mutation test command timeout in seconds")
    return p


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    # argparse's REMAINDER greedily swallows optionals (e.g. --project-root
    # ends up in test_cmd), so split the test command off at `--` manually.
    tail = []
    if "mutate-check" in argv and "--" in argv:
        i = argv.index("--")
        tail = argv[i + 1:]
        argv = argv[:i]
    args = build_parser().parse_args(argv)
    if getattr(args, "cmd", None) == "mutate-check":
        args.test_cmd = tail
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
