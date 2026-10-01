"""agent-guard: behavior-guardrail hooks for Claude Code."""

import argparse
import copy
import json
import os
import shutil
import sys

from . import commentslop, mutate, outbound, state, testguard, verify


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


def _decomment_check(files, threshold):
    """Print per-file slop scores; exit 1 if any file hits the threshold."""
    try:
        bad = 0
        for path in files:
            score, hits = commentslop.score_file(path)
            flag = "SLOP" if score >= threshold else "ok"
            print("%s: score %.1f (%d hits) [%s]" % (path, score, len(hits),
                                                    flag))
            for ln, end_ln, kind, excerpt in hits[:10]:
                loc = "L%d" % ln if ln == end_ln else "L%d-%d" % (ln, end_ln)
                print("  %s [%s] %s" % (loc, kind, excerpt))
            if score >= threshold:
                bad += 1
        if bad:
            print("%d file(s) at or above the slop threshold (%.1f)."
                  % (bad, threshold))
            return 1
        return 0
    except Exception as e:
        sys.stderr.write("decomment --check: internal error (%s); "
                         "failing open.\n" % e)
        return 0


def _decomment_fix(files):
    """Remove commented-code blocks only, with .bak backups."""
    try:
        for path in files:
            removed, bak = commentslop.fix_file(path)
            if removed:
                print("%s: removed %d commented-out line(s), backup at %s"
                      % (path, removed, bak))
            else:
                print("%s: nothing to fix" % path)
        return 0
    except Exception as e:
        sys.stderr.write("decomment --fix: internal error (%s); aborting.\n"
                         % e)
        return 1


def cmd_decomment(args):
    """Check or fix comment slop in files."""
    try:
        files = args.files or []
        if args.fix:
            return _decomment_fix(files)
        cfg = state.load_config()
        threshold = args.threshold
        if threshold is None:
            threshold = commentslop.threshold(cfg)
        return _decomment_check(files, threshold)
    except Exception as e:
        sys.stderr.write("decomment: internal error (%s); failing open.\n"
                         % e)
        return 0


def _added_text(tool, tool_input):
    """Comment-bearing text the agent is adding. Never raises."""
    try:
        if tool == "Write":
            content = tool_input.get("content")
            return content if isinstance(content, str) else ""
        # Edit: new_string, or a list of edits
        new_string = tool_input.get("new_string")
        if isinstance(new_string, str):
            return new_string
        parts = []
        edits = tool_input.get("edits")
        if isinstance(edits, list):
            for e in edits:
                if isinstance(e, dict):
                    s = e.get("new_string")
                    if isinstance(s, str):
                        parts.append(s)
        return "\n".join(parts)
    except Exception:
        return ""


def cmd_commentslop(args):
    """PreToolUse on Write/Edit: block comment slop in added text.

    Only the ADDED/NEW comment lines are scored, never the whole file —
    pre-existing code is not punished. Blocks (exit 2) in block mode,
    warns (exit 0) in warn mode. Fails open on everything unexpected.
    """
    try:
        data = _hook_input()
        tool = data.get("tool_name", "")
        if tool not in ("Write", "Edit"):
            return 0
        tool_input = data.get("tool_input")
        if not isinstance(tool_input, dict):
            return 0
        session = str(data.get("session_id", "") or "unknown")
        path = tool_input.get("file_path") or ""
        added = _added_text(tool, tool_input)
        if not added.strip():
            return 0
        cfg = state.load_config()
        score, hits = commentslop.score_text(
            added, commentslop.lang_of(path))
        threshold = commentslop.threshold(cfg)
        if score < threshold:
            return 0
        lines = []
        for ln, end_ln, kind, excerpt in hits[:8]:
            loc = "L%d" % ln if ln == end_ln else "L%d-%d" % (ln, end_ln)
            lines.append("  %s [%s] %s" % (loc, kind, excerpt))
        reason = (
            "Comment-slop guard: the %s is adding comments that look like "
            "narrative slop (score %.1f >= %.1f).\n%s\n"
            "Trim the narrative — keep only what the code doesn't already "
            "say. `agent-guard decomment --fix <file>` removes "
            "commented-out code automatically.\n"
            "Bypass (not recommended): AGENT_GUARD_COMMENT_MODE=warn, or "
            "comment_slop.mode=warn in %s."
            % (tool, score, threshold, "\n".join(lines),
               state.config_path()))
        state.append_audit({
            "guard": "commentslop", "tool": tool, "session": session,
            "file": str(path)[:200],
            "decision": "blocked" if commentslop.mode(cfg) == "block"
                        else "warn",
            "score": score,
            "reason": reason.split("\n")[0],
        })
        if commentslop.mode(cfg) == "warn":
            sys.stderr.write("WARNING (not blocking): " + reason + "\n")
            return 0
        sys.stderr.write(reason + "\n")
        return 2
    except Exception:
        return 0  # fail open, always


def _settings_path():
    return os.path.join(os.path.expanduser("~"), ".claude", "settings.json")


SNIPPETS = {
    "SessionStart": [{"hooks": [{"type": "command",
                                 "command": "agent-guard hook-snapshot"}]}],
    "Stop": [{"hooks": [{"type": "command",
                         "command": "agent-guard hook-test"}]}],
    "PreToolUse": [{"matcher": "Bash",
                    "hooks": [{"type": "command",
                               "command": "agent-guard hook-outbound"}]},
                   {"matcher": "Write|Edit",
                    "hooks": [{"type": "command",
                               "command": "agent-guard hook-commentslop"}]}],
    "PostToolUse": [{"matcher": "Bash",
                     "hooks": [{"type": "command",
                                "command": "agent-guard hook-verify"}]}],
}


def _entry_present(entries, key, want):
    """Is one SNIPPETS entry already installed? Never raises."""
    try:
        for e in entries:
            if not isinstance(e, dict):
                continue
            if key in ("PreToolUse", "PostToolUse") \
                    and e.get("matcher") != want.get("matcher"):
                continue
            for h in e.get("hooks", []):
                if (h.get("command", "") or "") == \
                        want["hooks"][0]["command"]:
                    return True
        return False
    except Exception:
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
    for key, snippet_list in SNIPPETS.items():
        entries = hooks.get(key)
        if not isinstance(entries, list):
            entries = []
            hooks[key] = entries
        for want in snippet_list:
            if _entry_present(entries, key, want):
                continue
            entries.append(copy.deepcopy(want))
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
    print("comment mode: %s (threshold %.1f)"
          % (commentslop.mode(), commentslop.threshold()))
    print("rules:      %s" % ", ".join(outbound.rule_ids()))
    print("settings:   %s" % _settings_path())
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        prog="agent-guard",
        description="Behavior-guardrail hooks for Claude Code: "
                    "test-tampering + outbound-action + comment-slop guards, "
                    "mutation test-honesty, and post-exec verification.")
    sub = p.add_subparsers(dest="cmd", required=True)

    for name, help_text, func in [
        ("hook-snapshot", "SessionStart hook: snapshot test digests.", cmd_snapshot),
        ("hook-test", "Stop hook: block tests-only changes.", cmd_test),
        ("hook-outbound", "PreToolUse hook: block risky Bash actions.", cmd_outbound),
        ("hook-verify", "PostToolUse hook: warn when a claimed effect "
                        "isn't visible (never blocks).", cmd_verify),
        ("hook-commentslop", "PreToolUse hook: block comment slop in "
                             "Write/Edit.", cmd_commentslop),
        ("mutate-check", "Mutation test-honesty check: mutate assertions, "
                         "re-run tests, report survivors.", cmd_mutate),
        ("decomment", "Check or fix comment slop in files.", cmd_decomment),
        ("install", "Install hooks into ~/.claude/settings.json.", cmd_install),
        ("log", "Show recent guard decisions.", cmd_log),
        ("status", "Show state paths and config.", cmd_status),
    ]:
        sp = sub.add_parser(name, help=help_text)
        sp.set_defaults(func=func)
    sub.choices["log"].add_argument("--limit", type=int, default=20)
    dc = sub.choices["decomment"]
    dc.add_argument("files", nargs="+", help="files to check or fix")
    dc.add_argument("--check", action="store_true",
                    help="report slop scores (default mode)")
    dc.add_argument("--fix", action="store_true",
                    help="remove commented-out code blocks (with .bak backup)")
    dc.add_argument("--threshold", type=float, default=None,
                    help="slop score (0-100) that fails --check (default: "
                         "config comment_slop.threshold, 30)")
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
