"""agent-guard: behavior-guardrail hooks for Claude Code."""

import argparse
import copy
import io
import json
import os
import shutil
import sys

from . import bashwrite, cheatsniff, commentslop, escapehatch, gatecheck, \
    mutate, outbound, semreview, state, tamper, testguard, verify, xtool


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
        state.record_ping("snapshot")
        data = _hook_input()
        session = str(data.get("session_id", "") or "")
        testguard.snapshot(_project_root(data), session_id=session or None)
    except Exception:
        pass
    return 0


def _tamper_enrichment(root, session_id):
    """Scan blocked-session test files for tamper shapes. Never raises."""
    try:
        lines = []
        for rel in testguard.changed_test_files(root, session_id)[:10]:
            full = os.path.join(root, rel)
            score, hits = tamper.scan_file(full)
            for ln, end_ln, kind, excerpt in hits[:5]:
                loc = "L%d" % ln if ln == end_ln else "L%d-%d" % (ln, end_ln)
                lines.append("  - %s %s [%s] %s" % (rel, loc, kind, excerpt))
        if not lines:
            return ""
        return ("Tamper shapes spotted in the changed tests:\n" +
                "\n".join(lines) + "\n")
    except Exception:
        return ""


def cmd_test(args):
    """Stop: diff test files vs snapshot; block tests-only changes.

    Honors `stop_hook_active`: when Claude Code tells us a Stop hook already
    fired, we must not block again or the session can never end (infinite
    loop). The first block already delivered the warning to the agent.
    AGENT_GUARD_FORCE_WARN=1 (set by the cross-tool shim for events that
    cannot block, e.g. Gemini CLI SessionEnd) downgrades to a warning.
    """
    try:
        state.record_ping("test")
        data = _hook_input()
        if data.get("stop_hook_active"):
            return 0
        session = str(data.get("session_id", "") or "unknown")
        root = _project_root(data)
        sid = None if session == "unknown" else session
        detail = testguard.check_detail(root, session_id=sid)
        forced_warn = os.environ.get("AGENT_GUARD_FORCE_WARN", "") == "1"
        warn_mode = testguard.mode() == "warn" or forced_warn
        if detail["allowed"]:
            if detail.get("verdicts"):
                state.append_audit({
                    "guard": "test", "tool": "Stop", "session": session,
                    "decision": "allowed-legit-test-change",
                    "files": detail["changed_tests"][:10],
                    "verdicts": {k: v["verdict"]
                                 for k, v in
                                 detail["verdicts"].items()},
                    "reason": "all changed test files classified legit",
                })
                if warn_mode:
                    sys.stderr.write(
                        "WARNING (not blocking): test files changed "
                        "without source changes, but every change was "
                        "classified legit:\n" +
                        "".join("  - %s [%s]\n"
                                % (p, detail["verdicts"][p]["verdict"])
                                for p in detail["changed_tests"]))
            return 0
        # Escape hatch: explicit, audited, always visible in `agent-guard log`.
        hatch, hatch_reason = escapehatch.hatch_request(args)
        if hatch:
            state.append_audit({
                "guard": "test", "tool": "Stop", "session": session,
                "decision": "allowed-escape-hatch",
                "hatch_reason": hatch_reason,
                "files": detail["changed_tests"][:10],
                "verdicts": {k: v["verdict"]
                             for k, v in detail["verdicts"].items()},
                "reason": "escape hatch: %s"
                          % (hatch_reason or "(no reason given)"),
            })
            sys.stderr.write(
                "agent-guard: test-guard escape hatch used%s -- "
                "recorded in the audit log (`agent-guard log`).\n"
                % (" (reason: %s)" % hatch_reason if hatch_reason else ""))
            return 0
        # Nemotron second opinion -- only now that the block/warn decision
        # is final and the user has not taken the escape hatch (P-C1/P-H1).
        # Advisory: enriches the message, never changes the decision; a
        # model PASS is audit-only, never shown to the agent (P-H2).
        opinions = testguard.attach_semantic_opinions(detail, root=root)
        reason = detail["reason"]
        extra = _tamper_enrichment(root, sid)
        if extra:
            reason = reason.rstrip("\n") + "\n" + extra
        warn_mode = testguard.mode() == "warn" or forced_warn
        audit_rec = {
            "guard": "test", "tool": "Stop", "session": session,
            "decision": "warn" if warn_mode else "blocked",
            "rule": "tests-only-change",
            "verdicts": {k: v["verdict"]
                         for k, v in detail["verdicts"].items()},
            "reason": reason.split("\n")[0],
        }
        if opinions:
            audit_rec["semantic"] = {
                rel: semreview.effective_verdict(op)
                for rel, op in opinions.items()}
        state.append_audit(audit_rec)
        if warn_mode:
            sys.stderr.write("WARNING (not blocking): " + reason + "\n")
            return 0
        sys.stderr.write(reason + "\n")
        return 2
    except Exception:
        return 0  # fail open, always


def cmd_testreview(args):
    """Advisory: classify the test-only changes vs the current snapshot.

    Prints each changed test file's verdict (legit / ambiguous /
    malicious) and the markers behind it. Never blocks (exit 0).
    """
    try:
        root = os.path.abspath(args.root) if args.root else os.getcwd()
        sid = args.session or None
        detail = testguard.check_detail(root, session_id=sid)
        if not detail["snapshot_ok"]:
            print("no usable snapshot for %s; the SessionStart hook "
                  "(`agent-guard hook-snapshot`) records one." % root)
            return 0
        if not detail["changed_tests"]:
            print("no test files changed since the snapshot.")
            return 0
        print("source files changed: %s"
              % ("yes" if detail["changed_sources"] else "no"))
        for rel in detail["changed_tests"]:
            v = detail["verdicts"][rel]
            print("%s: %s" % (rel, v["verdict"]))
            for kind, excerpt in v["markers"][:10]:
                print("  [%s] %s" % (kind, excerpt[:100]))
        if detail["allowed"]:
            print("verdict: STOP allowed (all changes classified legit)")
        else:
            print("verdict: would BLOCK -- use "
                  "`agent-guard hook-test --allow-test-change \"<reason>\"` "
                  "to escape (audited)")
        return 0
    except Exception as e:
        sys.stderr.write("test-review: internal error (%s); failing open.\n"
                         % e)
        return 0


def cmd_outbound(args):
    """PreToolUse on Bash: denylist risky outbound actions."""
    try:
        state.record_ping("outbound")
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
        state.record_ping("verify")
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
        state.record_ping("commentslop")
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


def _testy_path(path):
    """Does this file look like a test/support file? Never raises."""
    try:
        p = str(path or "")
        base = os.path.basename(p)
        return (base == "conftest.py"
                or base.startswith("test_")
                or base.endswith("_test.py")
                or "/tests/" in p.replace("\\", "/"))
    except Exception:
        return False


def _cheatsniff_check(paths, threshold):
    """Print per-file cheat scores; exit 1 if any file hits the threshold."""
    try:
        cfg = state.load_config()
        bad = 0
        for root in paths:
            for path, score, hits in cheatsniff.scan_path(root):
                hits = cheatsniff.filter_allowed(hits, cfg, path)
                score = min(100.0, 10.0 * sum(
                    cheatsniff.WEIGHTS.get(k, 1.0) for _, _, k, _ in hits))
                score = round(score, 1)
                flag = "CHEAT?" if score >= threshold else "ok"
                print("%s: score %.1f (%d hits) [%s]" % (path, score,
                                                        len(hits), flag))
                for ln, end_ln, kind, excerpt in hits[:10]:
                    loc = "L%d" % ln if ln == end_ln else "L%d-%d" % (ln, end_ln)
                    print("  %s [%s] %s" % (loc, kind, excerpt))
                if score >= threshold:
                    bad += 1
        if bad:
            print("%d file(s) at or above the cheat threshold (%.1f)."
                  % (bad, threshold))
            return 1
        return 0
    except Exception as e:
        sys.stderr.write("cheatsniff: internal error (%s); failing open.\n"
                         % e)
        return 0


def cmd_cheatsniff(args):
    """Scan test files for non-test-file cheating (RNG/mocks/conftest)."""
    try:
        cfg = state.load_config()
        threshold = args.threshold
        if threshold is None:
            threshold = cheatsniff.threshold(cfg)
        return _cheatsniff_check(args.paths, threshold)
    except Exception as e:
        sys.stderr.write("cheatsniff: internal error (%s); failing open.\n"
                         % e)
        return 0


def cmd_hook_cheatsniff(args):
    """PreToolUse on Write/Edit: block cheat patterns in added test text.

    Only fires for test-ish files (test_*.py, conftest.py, ...). Scores the
    ADDED text only — pre-existing code is not punished. Blocks (exit 2) in
    block mode, warns (exit 0) in warn mode. Fails open on everything.
    """
    try:
        state.record_ping("cheatsniff")
        data = _hook_input()
        tool = data.get("tool_name", "")
        if tool not in ("Write", "Edit"):
            return 0
        tool_input = data.get("tool_input")
        if not isinstance(tool_input, dict):
            return 0
        session = str(data.get("session_id", "") or "unknown")
        path = tool_input.get("file_path") or ""
        if not _testy_path(path):
            return 0
        added = _added_text(tool, tool_input)
        if not added.strip():
            return 0
        cfg = state.load_config()
        score, hits = cheatsniff.score_text(added, path)
        hits = cheatsniff.filter_allowed(hits, cfg, path)
        score = min(100.0, 10.0 * sum(
            cheatsniff.WEIGHTS.get(k, 1.0) for _, _, k, _ in hits))
        score = round(score, 1)
        threshold = cheatsniff.threshold(cfg)
        if score < threshold:
            return 0
        lines = []
        for ln, end_ln, kind, excerpt in hits[:8]:
            loc = "L%d" % ln if ln == end_ln else "L%d-%d" % (ln, end_ln)
            lines.append("  %s [%s] %s" % (loc, kind, excerpt))
        reason = (
            "Cheat-sniff guard: the %s is adding test code that looks like "
            "cheating WITHOUT touching test assertions (score %.1f >= %.1f).\n"
            "%s\n"
            "Half of agent cheating never edits test files -- it rigs the "
            "RNG, mocks the function under test, or plants helpers in "
            "conftest.py. Fix the source instead.\n"
            "Bypass (not recommended): AGENT_GUARD_CHEAT_MODE=warn, or "
            "cheat_sniff.mode=warn in %s."
            % (tool, score, threshold, "\n".join(lines),
               state.config_path()))
        state.append_audit({
            "guard": "cheatsniff", "tool": tool, "session": session,
            "file": str(path)[:200],
            "decision": "blocked" if cheatsniff.mode(cfg) == "block"
                        else "warn",
            "score": score,
            "reason": reason.split("\n")[0],
        })
        if cheatsniff.mode(cfg) == "warn":
            sys.stderr.write("WARNING (not blocking): " + reason + "\n")
            return 0
        sys.stderr.write(reason + "\n")
        return 2
    except Exception:
        return 0  # fail open, always


def cmd_hook_bashwrite(args):
    """PreToolUse on Bash: block file writes that bypass Edit/Write hooks.

    Extracts write targets (redirections, heredocs, sed -i, tee, cp/mv)
    from the Bash command and applies the same policy the Write-tool
    guards would apply: test-ish targets get cheat-sniffed when the
    content is visible (heredoc), opaque writes to protected files are
    treated as violations. Blocks (exit 2) in block mode, warns (exit 0)
    in warn mode. Fails open on everything.
    """
    try:
        state.record_ping("bashwrite")
        data = _hook_input()
        if data.get("tool_name", "") != "Bash":
            return 0
        tool_input = data.get("tool_input")
        command = tool_input.get("command", "") \
            if isinstance(tool_input, dict) else ""
        if not command or not str(command).strip():
            return 0
        session = str(data.get("session_id", "") or "unknown")
        cwd = data.get("cwd") or os.getcwd()
        cfg = state.load_config()
        ok, reason, targets, parse_ok = bashwrite.decide(command, cfg, cwd)
        if not parse_ok:
            sys.stderr.write("bashwrite: could not parse command; "
                             "allowing (fail-open).\n")
        if ok:
            return 0
        state.append_audit({
            "guard": "bashwrite", "tool": "Bash", "session": session,
            "command": str(command)[:500],
            "targets": [str(t)[:200] for t in targets][:10],
            "decision": "blocked" if bashwrite.mode(cfg) == "block"
                        else "warn",
            "reason": reason.split("\n")[0],
        })
        if bashwrite.mode(cfg) == "warn":
            sys.stderr.write("WARNING (not blocking): " + reason + "\n")
            return 0
        sys.stderr.write(reason + "\n")
        return 2
    except Exception:
        return 0  # fail open, always


def cmd_semreview(args):
    """Semantic review of a test diff or shell command via Nemotron.

    Advisory layer on top of the pattern guards: catches rephrased-but-
    weakened assertions and obfuscated outbound actions the regexes miss.
    Fails open -- any problem (no API key, network error, timeout,
    malformed model output) degrades to "warn", never blocks. Exits 1
    only when the effective verdict is "block" (requires
    semreview.mode=block or AGENT_GUARD_SEMREVIEW_MODE=block).
    """
    try:
        state.record_ping("semreview")
        if bool(args.diff) == bool(args.command):
            sys.stderr.write(
                "semreview: pass exactly one of --diff <file> or "
                "--command \"<cmd>\".\n")
            return 2
        cfg = state.load_config()
        if args.diff:
            result = semreview.review_diff_file(args.diff, cfg=cfg)
            label = args.diff
        else:
            result = semreview.review_command(args.command, cfg=cfg)
            label = args.command[:120]
        verdict = semreview.effective_verdict(result, cfg)
        state.append_audit({
            "guard": "semreview", "tool": "semreview",
            "target": label[:200],
            "decision": verdict,
            "model": result.get("model", ""),
            "confidence": result.get("confidence", 0.0),
            "degraded": bool(result.get("degraded")),
            "reason": str(result.get("rationale", ""))[:200],
        })
        if args.json:
            out = dict(result)
            out["verdict"] = verdict
            sys.stdout.write(json.dumps(out, indent=2) + "\n")
        else:
            sys.stdout.write(
                semreview.format_human(result, verdict, label) + "\n")
        return 1 if verdict == "block" else 0
    except Exception as e:
        sys.stderr.write("semreview: internal error (%s); failing open.\n"
                         % e)
        return 0


def cmd_hook_tamper(args):
    """PreToolUse on Write/Edit: block tamper shapes in added test text.

    Only fires for test-ish files. Scores the ADDED text only for
    weakened assertions (toBe -> toBeTruthy), newly skipped/focused
    tests (.skip/.only), and snapshot updates. Blocks (exit 2) in block
    mode, warns (exit 0) in warn mode. Fails open on everything.
    """
    try:
        state.record_ping("tamper")
        data = _hook_input()
        tool = data.get("tool_name", "")
        if tool not in ("Write", "Edit"):
            return 0
        tool_input = data.get("tool_input")
        if not isinstance(tool_input, dict):
            return 0
        session = str(data.get("session_id", "") or "unknown")
        path = tool_input.get("file_path") or ""
        if not _testy_path(path) and not tamper.is_snapshot_path(path):
            return 0
        added = _added_text(tool, tool_input)
        if not added.strip() and not tamper.is_snapshot_path(path):
            return 0
        cfg = state.load_config()
        score, hits = tamper.score_text(added, path)
        threshold = tamper.threshold(cfg)
        if score < threshold:
            return 0
        lines = []
        for ln, end_ln, kind, excerpt in hits[:8]:
            loc = "L%d" % ln if ln == end_ln else "L%d-%d" % (ln, end_ln)
            lines.append("  %s [%s] %s" % (loc, kind, excerpt))
        reason = (
            "Tamper guard: the %s is adding test changes that match known "
            "test-tampering shapes (score %.1f >= %.1f).\n%s\n"
            "Weakened assertions, skipped/focused tests, and unreviewed "
            "snapshot updates make the suite green without proving the "
            "fix. Keep the strong assertion, unskip the test, or review "
            "the snapshot diff before updating.\n"
            "Bypass (not recommended): AGENT_GUARD_TAMPER_MODE=warn, or "
            "tamper.mode=warn in %s."
            % (tool, score, threshold, "\n".join(lines),
               state.config_path()))
        forced_warn = os.environ.get("AGENT_GUARD_FORCE_WARN", "") == "1"
        warn_mode = tamper.mode(cfg) == "warn" or forced_warn
        state.append_audit({
            "guard": "tamper", "tool": tool, "session": session,
            "file": str(path)[:200],
            "decision": "warn" if warn_mode else "blocked",
            "score": score,
            "reason": reason.split("\n")[0],
        })
        if warn_mode:
            sys.stderr.write("WARNING (not blocking): " + reason + "\n")
            return 0
        sys.stderr.write(reason + "\n")
        return 2
    except Exception:
        return 0  # fail open, always


def _tamper_check(paths, threshold):
    """Print per-file tamper scores; exit 1 if any hits the threshold."""
    try:
        bad = 0
        for root in paths:
            for path, score, hits in tamper.scan_path(root):
                flag = "TAMPER?" if score >= threshold else "ok"
                print("%s: score %.1f (%d hits) [%s]" % (path, score,
                                                        len(hits), flag))
                for ln, end_ln, kind, excerpt in hits[:10]:
                    loc = "L%d" % ln if ln == end_ln else "L%d-%d" % (ln, end_ln)
                    print("  %s [%s] %s" % (loc, kind, excerpt))
                if score >= threshold:
                    bad += 1
        if bad:
            print("%d file(s) at or above the tamper threshold (%.1f)."
                  % (bad, threshold))
            return 1
        return 0
    except Exception as e:
        sys.stderr.write("tamper-check: internal error (%s); failing open.\n"
                         % e)
        return 0


def cmd_tampercheck(args):
    """Scan test files for tamper shapes: weakened assertions, skips,
    snapshot updates."""
    try:
        cfg = state.load_config()
        threshold = args.threshold
        if threshold is None:
            threshold = tamper.threshold(cfg)
        return _tamper_check(args.paths, threshold)
    except Exception as e:
        sys.stderr.write("tamper-check: internal error (%s); failing open.\n"
                         % e)
        return 0


SHIM_COMMANDS = {
    "hook-snapshot": "cmd_snapshot",
    "hook-test": "cmd_test",
    "hook-outbound": "cmd_outbound",
    "hook-verify": "cmd_verify",
    "hook-commentslop": "cmd_commentslop",
    "hook-cheatsniff": "cmd_hook_cheatsniff",
    "hook-bashwrite": "cmd_hook_bashwrite",
    "hook-tamper": "cmd_hook_tamper",
}


def cmd_shim(args):
    """Cross-tool shim: normalize a Codex/Gemini hook payload, then run a
    hook command unchanged.

    Usage: agent-guard shim --tool codex|gemini [--warn] <hook-command>
    --warn downgrades blocks to warnings (for events the tool cannot
    block, e.g. Gemini CLI SessionEnd).
    """
    try:
        data = _hook_input()
        norm = xtool.normalize(args.tool, data)
        if norm is None:
            return 0  # unmapped payload: nothing to guard, fail open
        if args.warn:
            os.environ["AGENT_GUARD_FORCE_WARN"] = "1"
        func = globals().get(SHIM_COMMANDS.get(args.hook_cmd, ""))
        if not callable(func):
            return 0
        sys.stdin = io.StringIO(json.dumps(norm))
        return func(args)
    except Exception:
        return 0  # fail open, always


def cmd_gatecheck(args):
    """Gate-liveness check: are the hooks mounted, and did they run?

    `agent-guard verify [--tool claude|codex|gemini] [--days N]`
    Reports LIVE / SILENT / NOT INSTALLED per guard. A mounted guard
    with zero runs in the window is a SILENT FAILURE -- the dangerous
    state where the gate looks wired but nothing is checking.

    (Not to be confused with `hook-verify`: the PostToolUse read-back
    verifier that checks a claimed outbound effect is visible.)
    """
    try:
        code, text = gatecheck.run(tool=args.tool, days=args.days)
        sys.stdout.write(text)
        return code
    except Exception as e:
        sys.stderr.write("verify: internal error (%s); failing open.\n" % e)
        return 0


SNIPPETS = {
    "SessionStart": [{"hooks": [{"type": "command",
                                 "command": "agent-guard hook-snapshot"}]}],
    "Stop": [{"hooks": [{"type": "command",
                         "command": "agent-guard hook-test",
                         "timeout": 30}]}],
    "PreToolUse": [{"matcher": "Bash",
                    "hooks": [{"type": "command",
                               "command": "agent-guard hook-outbound"}]},
                   {"matcher": "Bash",
                    "hooks": [{"type": "command",
                               "command": "agent-guard hook-bashwrite"}]},
                   {"matcher": "Write|Edit",
                    "hooks": [{"type": "command",
                               "command": "agent-guard hook-commentslop"}]},
                   {"matcher": "Write|Edit",
                    "hooks": [{"type": "command",
                               "command": "agent-guard hook-cheatsniff"}]}],    "PostToolUse": [{"matcher": "Bash",
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
    """Install hooks for a tool (default: claude).

    --tool claude  -> ~/.claude/settings.json (with backup)
    --tool codex   -> ~/.codex/hooks.json + [features] hooks=true
    --tool gemini  -> ~/.gemini/settings.json
    All merges are idempotent.
    """
    tool = getattr(args, "tool", "claude") or "claude"
    if tool not in xtool.TOOLS:
        print("unknown tool %r (choose from %s)" % (tool, ", ".join(
            xtool.TOOLS)), file=sys.stderr)
        return 2
    if tool == "codex":
        hp, added, feat = xtool.install_codex()
        print("Installed agent-guard hooks into %s (%d added)."
              % (hp, added))
        print("Codex hooks feature flag: %s"
              % ("enabled" if feat else "COULD NOT ENABLE -- set "
                 "[features] hooks=true in ~/.codex/config.toml manually"))
        for step in xtool.mount_steps("codex"):
            print("  " + step)
        return 0
    if tool == "gemini":
        sp, added = xtool.install_gemini()
        print("Installed agent-guard hooks into %s (%d added)."
              % (sp, added))
        for step in xtool.mount_steps("gemini"):
            print("  " + step)
        return 0
    return _install_claude()


def _install_claude():
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
    print("cheat mode:   %s (threshold %.1f)"
          % (cheatsniff.mode(), cheatsniff.threshold()))
    print("bash-write mode: %s" % bashwrite.mode())
    print("rules:      %s" % ", ".join(outbound.rule_ids()))
    print("settings:   %s" % _settings_path())
    for t in ("codex", "gemini"):
        cmds = xtool.installed_commands(t)
        print("%-11s %d agent-guard hook entr%s" % (
            t + ":", len(cmds), "y" if len(cmds) == 1 else "ies"))
    print("tamper mode:  %s (threshold %.1f)"
          % (tamper.mode(), tamper.threshold()))
    print("escape hatch: %s"
          % ("ON (env AGENT_GUARD_ALLOW_TEST_CHANGE set)"
             if os.environ.get("AGENT_GUARD_ALLOW_TEST_CHANGE", "")
             not in ("", "0") else "off"))
    print("hint: agent-guard verify [--tool claude|codex|gemini] checks "
          "whether the gates are mounted AND actually ran.")
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        prog="agent-guard",
        description="Behavior-guardrail hooks for Claude Code: "
                    "test-tampering + outbound-action + comment-slop + "
                    "cheat-sniffing + cross-tool-write guards, mutation "
                    "test-honesty, and post-exec verification.")
    sub = p.add_subparsers(dest="cmd", required=True)

    for name, help_text, func in [
        ("hook-snapshot", "SessionStart hook: snapshot test digests.", cmd_snapshot),
        ("hook-test", "Stop hook: block tests-only changes (with legit-test-change escape hatch).", cmd_test),
        ("test-review", "Classify test-only changes vs the snapshot (legit/ambiguous/malicious); never blocks.", cmd_testreview),
        ("hook-outbound", "PreToolUse hook: block risky Bash actions.", cmd_outbound),
        ("hook-verify", "PostToolUse hook: warn when a claimed effect "
                        "isn't visible (never blocks).", cmd_verify),
        ("hook-commentslop", "PreToolUse hook: block comment slop in "
                             "Write/Edit.", cmd_commentslop),
        ("hook-cheatsniff", "PreToolUse hook: block cheat patterns (RNG rig, "
                             "subject-mocking, conftest plants) in added "
                             "test text.", cmd_hook_cheatsniff),
        ("hook-bashwrite", "PreToolUse hook: block Bash file writes "
                           "(sed -i, heredocs, redirections) that bypass "
                           "the Edit/Write hooks.", cmd_hook_bashwrite),
        ("cheatsniff", "Scan test files for cheating that never touches "
                       "test assertions.", cmd_cheatsniff),
        ("mutate-check", "Mutation test-honesty check: mutate assertions, "
                         "re-run tests, report survivors.", cmd_mutate),
        ("decomment", "Check or fix comment slop in files.", cmd_decomment),
        ("semreview", "Semantic review of a test diff or shell command via "
                      "Nemotron on Nebius Token Factory (advisory, "
                      "fail-open).", cmd_semreview),
        ("hook-tamper", "PreToolUse hook: block weakened assertions, "
                          "newly skipped/focused tests, and snapshot "
                          "updates in added test text.", cmd_hook_tamper),
        ("tamper-check", "Scan test files for tamper shapes: weakened "
                       "assertions, .skip/.only, snapshot updates.",
         cmd_tampercheck),
        ("shim", "Cross-tool shim: normalize a Codex/Gemini hook payload "
               "and run a hook command unchanged.", cmd_shim),
        ("verify", "Gate-liveness check: are the hooks mounted, and did "
                 "they actually run in the last N days?", cmd_gatecheck),
        ("install", "Install hooks (--tool claude|codex|gemini, default "
                  "claude).", cmd_install),
        ("log", "Show recent guard decisions.", cmd_log),
        ("status", "Show state paths and config.", cmd_status),
    ]:
        sp = sub.add_parser(name, help=help_text)
        sp.set_defaults(func=func)
    sub.choices["install"].add_argument(
        "--tool", choices=xtool.TOOLS, default="claude",
        help="which tool's hook config to install into (default: claude)")
    vc = sub.choices["verify"]
    vc.add_argument("--tool", choices=xtool.TOOLS, default=None,
                    help="check one tool (default: all three)")
    vc.add_argument("--days", type=int, default=7,
                    help="look-back window for hook runs (default: 7)")
    sc2 = sub.choices["shim"]
    sc2.add_argument("--tool", choices=("codex", "gemini"), required=True,
                     help="which tool's payload format to normalize")
    sc2.add_argument("--warn", action="store_true",
                     help="downgrade blocks to warnings (events the tool "
                          "cannot block, e.g. Gemini SessionEnd)")
    sc2.add_argument("hook_cmd", choices=sorted(SHIM_COMMANDS),
                     help="hook command to run after normalization")
    sub.choices["log"].add_argument("--limit", type=int, default=20)
    ht = sub.choices["hook-test"]
    ht.add_argument("--allow-test-change", nargs="?", const="", default=None,
                    metavar="REASON",
                    help="escape hatch: allow test-only changes this once; "
                         "the reason is written to the audit log "
                         "(env AGENT_GUARD_ALLOW_TEST_CHANGE works too)")
    tr = sub.choices["test-review"]
    tr.add_argument("--root", default=None,
                    help="project root (default: cwd)")
    tr.add_argument("--session", default=None,
                    help="session id of the snapshot to diff against")
    dc = sub.choices["decomment"]
    dc.add_argument("files", nargs="+", help="files to check or fix")
    dc.add_argument("--check", action="store_true",
                    help="report slop scores (default mode)")
    dc.add_argument("--fix", action="store_true",
                    help="remove commented-out code blocks (with .bak backup)")
    dc.add_argument("--threshold", type=float, default=None,
                    help="slop score (0-100) that fails --check (default: "
                         "config comment_slop.threshold, 30)")
    cc = sub.choices["cheatsniff"]
    cc.add_argument("paths", nargs="+", help="files or directories to scan")
    cc.add_argument("--check", action="store_true",
                    help="report cheat scores (default mode)")
    cc.add_argument("--threshold", type=float, default=None,
                    help="cheat score (0-100) that fails --check (default: "
                         "config cheat_sniff.threshold, 30)")
    tc = sub.choices["tamper-check"]
    tc.add_argument("paths", nargs="+", help="files or directories to scan")
    tc.add_argument("--threshold", type=float, default=None,
                    help="tamper score (0-100) that fails the check "
                         "(default: config tamper.threshold, 30)")
    mc = sub.choices["mutate-check"]
    mc.add_argument("test_file", help="test file to mutate")
    mc.add_argument("test_cmd", nargs="*",
                    help="test command (pass after -- : e.g. -- pytest -q)")
    mc.add_argument("--project-root", default=None,
                    help="project root (default: nearest dir with project markers)")
    mc.add_argument("--max-mutations", type=int, default=mutate.DEFAULT_MAX_MUTATIONS)
    mc.add_argument("--timeout", type=int, default=mutate.DEFAULT_TIMEOUT,
                    help="per-mutation test command timeout in seconds")
    sc = sub.choices["semreview"]
    sc.add_argument("--diff", default=None,
                    help="file containing a unified diff of test changes")
    sc.add_argument("--command", default=None,
                    help="shell command string to review")
    sc.add_argument("--json", action="store_true",
                    help="print the verdict as JSON")
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
