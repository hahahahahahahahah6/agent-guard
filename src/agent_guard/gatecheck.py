"""Gate-liveness verifier: "is the gate actually running?"

A gate that is configured but never fires is worse than no gate at
all: it teaches everyone to trust a check that stopped checking. (The
community has seen exactly this failure mode -- gates that looked wired
while none of them ran.) This module answers the question directly:

  agent-guard verify [--tool claude|codex|gemini] [--days N]

For each tool it checks:
  1. Is the hook config present, and does it contain agent-guard
     entries for each guard? (mounted?)
  2. Have the hooks actually executed in the last N days? Two
     instruments: per-day run counters (recorded by every hook
     invocation) and the audit log (recorded guard decisions).
     (fired?)

Verdicts per guard: LIVE (mounted + fired), SILENT (mounted + 0 runs
in the window -- the dangerous one), NOT INSTALLED (no config entry).

Exit 0 when everything mounted is live; exit 1 when anything is
missing or silent. Never blocks anything -- this is a human-run
diagnostic, so exiting nonzero on a bad state is correct here.
"""

import os
import time

from . import state, xtool

# guard -> which agent-guard commands prove it is mounted
GUARD_COMMANDS = {
    "test": ("hook-snapshot", "hook-test"),
    "outbound": ("hook-outbound",),
    "bashwrite": ("hook-bashwrite",),
    "commentslop": ("hook-commentslop",),
    "cheatsniff": ("hook-cheatsniff",),
    "tamper": ("hook-tamper",),
    "verify": ("hook-verify",),
}

# guard names as recorded by state.record_ping / audit log
PING_GUARDS = ("snapshot", "test", "outbound", "verify", "commentslop",
               "cheatsniff", "bashwrite", "semreview", "tamper")
PING_TO_GUARD = {"snapshot": "test", "semreview": "verify"}
PING_TO_GUARD.update({g: g for g in PING_GUARDS
                      if g not in PING_TO_GUARD})


def _claude_settings_path():
    return os.path.join(os.path.expanduser("~"), ".claude",
                        "settings.json")


def _claude_commands():
    import json
    found = set()
    try:
        with open(_claude_settings_path(), "r", encoding="utf-8") as fh:
            settings = json.load(fh)
        hooks = settings.get("hooks") if isinstance(settings, dict) else None
        if not isinstance(hooks, dict):
            return found
        for entries in hooks.values():
            if not isinstance(entries, list):
                continue
            for e in entries:
                if not isinstance(e, dict):
                    continue
                for h in e.get("hooks", []):
                    if isinstance(h, dict):
                        cmd = str(h.get("command", "") or "")
                        if "agent-guard" in cmd:
                            found.add(cmd)
        return found
    except Exception:
        return found


def _tool_state(tool, home):
    """(config_path, config_exists, commands:set, extra_note). Never raises."""
    try:
        if tool == "claude":
            p = _claude_settings_path()
            return p, os.path.exists(p), _claude_commands(), ""
        if tool == "codex":
            p = os.path.join(xtool.codex_dir(home), "hooks.json")
            note = ""
            if not xtool.codex_hooks_feature_enabled(home):
                note = ("[features] hooks is not enabled in "
                        "~/.codex/config.toml: Codex will ignore hooks.json")
            return p, os.path.exists(p), xtool.installed_commands(
                "codex", home), note
        if tool == "gemini":
            p = os.path.join(xtool.gemini_dir(home), "settings.json")
            return p, os.path.exists(p), xtool.installed_commands(
                "gemini", home), ""
        return "", False, set(), ""
    except Exception:
        return "", False, set(), ""


def _evidence(days):
    """(ping_counts, audit_counts) per canonical guard for the window."""
    pings = {g: 0 for g in GUARD_COMMANDS}
    audits = {g: 0 for g in GUARD_COMMANDS}
    try:
        for guard, n in state.read_pings(days).items():
            canon = PING_TO_GUARD.get(guard, guard)
            if canon in pings:
                pings[canon] += n
    except Exception:
        pass
    try:
        cutoff = time.time() - days * 86400
        for e in state.read_audit():
            try:
                if e.get("ts", 0) < cutoff:
                    continue
                g = str(e.get("guard", "") or "")
                canon = PING_TO_GUARD.get(g, g)
                if canon in audits:
                    audits[canon] += 1
            except Exception:
                continue
    except Exception:
        pass
    return pings, audits


def _mounted(commands, guard):
    needles = GUARD_COMMANDS[guard]
    return any(any(n in c for n in needles) for c in commands)


def check(tool="claude", days=7, home=None):
    """Return a report dict. Never raises."""
    try:
        days = max(1, int(days))
    except Exception:
        days = 7
    report = {"tool": tool, "days": days, "guards": {}, "issues": [],
              "config_path": "", "config_exists": False, "note": ""}
    try:
        path, exists, commands, note = _tool_state(tool, home)
        report["config_path"] = path
        report["config_exists"] = exists
        report["note"] = note
        pings, audits = _evidence(days)
        for guard in GUARD_COMMANDS:
            mounted = exists and _mounted(commands, guard)
            runs = pings.get(guard, 0)
            decisions = audits.get(guard, 0)
            if not mounted:
                status = "NOT INSTALLED"
                report["issues"].append(
                    "%s: no agent-guard entry in %s" % (guard, path))
            elif runs == 0 and decisions == 0:
                status = "SILENT"
                report["issues"].append(
                    "SILENT FAILURE: '%s' is configured but has 0 runs in "
                    "the last %d day(s) -- the gate looks wired but is not "
                    "running." % (guard, days))
            else:
                status = "LIVE"
            report["guards"][guard] = {"mounted": mounted, "runs": runs,
                                       "decisions": decisions,
                                       "status": status}
        if note:
            report["issues"].append(note)
        return report
    except Exception:
        return report


def format_report(report):
    """Human-readable text. Never raises."""
    try:
        L = []
        L.append("gate check: %s  (last %d day(s))" %
                 (report["tool"], report["days"]))
        L.append("config: %s %s" % (
            report["config_path"],
            "(found)" if report["config_exists"] else "(MISSING)"))
        L.append("")
        L.append("%-12s %-9s %6s %10s  %s" %
                 ("guard", "mounted", "runs", "decisions", "status"))
        for guard, g in report["guards"].items():
            L.append("%-12s %-9s %6d %10d  %s" % (
                guard, "yes" if g["mounted"] else "no",
                g["runs"], g["decisions"], g["status"]))
        L.append("")
        if report["issues"]:
            L.append("issues:")
            for i in report["issues"]:
                L.append("  ! " + i)
        else:
            L.append("all mounted guards are LIVE: every gate ran in the "
                     "window.")
        L.append("")
        L.append("How it works: each hook invocation records a run counter "
                 "(~/.config/agent-guard/hook-pings.json) and guard "
                 "decisions go to the audit log. Tool transcripts do not "
                 "carry hook-execution traces, so these two are the "
                 "instruments.")
        return "\n".join(L)
    except Exception:
        return "gatecheck: could not format report (failing open)"


def run(tool=None, days=7, home=None):
    """Check one tool (default claude) or all. Returns (code, text)."""
    try:
        tools = [tool] if tool in xtool.TOOLS else list(xtool.TOOLS)
        if tool is not None and tool not in xtool.TOOLS:
            return 2, "unknown tool %r (choose from %s)\n" % (
                tool, ", ".join(xtool.TOOLS))
        parts, code = [], 0
        for t in tools:
            rep = check(t, days, home)
            parts.append(format_report(rep))
            if rep["issues"]:
                code = 1
        return code, ("\n".join(parts) + "\n")
    except Exception:
        return 0, "gatecheck: internal error; failing open.\n"
