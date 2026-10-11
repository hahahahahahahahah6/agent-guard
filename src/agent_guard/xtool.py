"""Cross-tool hook installation: the same interception rules on
Claude Code, Codex CLI, and Gemini CLI.

Each tool's hook system speaks a slightly different dialect, but the
underlying events are the same: session start, before a tool runs, after
a tool runs, session stop. This module maps agent-guard's existing rules
(especially the test-tampering rules) onto each tool's native hook
config format and merges them into the tool's config file, idempotently.

- Claude Code: ~/.claude/settings.json (handled in cli.py, unchanged)
- Codex CLI: ~/.codex/hooks.json (Claude-Code-shaped) + [features]
  hooks=true in ~/.codex/config.toml (required, or Codex ignores
  hooks.json). apply_patch payloads are normalized by the shim.
- Gemini CLI: ~/.gemini/settings.json with BeforeTool/AfterTool/
  SessionStart/SessionEnd. Gemini has no blocking Stop event, so the
  test-tampering check maps to SessionEnd as an advisory warning.

Honest limitations, stated plainly:
- Codex only runs hooks the user has trusted (/hooks in the CLI pins a
  hash per hook). install writes the config; trust is a human step.
- Gemini CLI cannot block at session end: the Stop-time test-tampering
  guard becomes a SessionEnd warning there.

Everything fails open: any unexpected error means "do nothing".
"""

import copy
import json
import os
import re

TOOLS = ("claude", "codex", "gemini")

BIN = "agent-guard"

CODEX_SNIPPETS = {
    "SessionStart": [
        {"hooks": [{"type": "command",
                    "command": BIN + " hook-snapshot"}]},
    ],
    "Stop": [
        {"hooks": [{"type": "command",
                    "command": BIN + " hook-test"}]},
    ],
    "PreToolUse": [
        {"matcher": "Bash",
         "hooks": [{"type": "command",
                    "command": BIN + " hook-outbound"},
                   {"type": "command",
                    "command": BIN + " hook-bashwrite"}]},
        {"matcher": "apply_patch",
         "hooks": [{"type": "command",
                    "command": BIN + " shim --tool codex hook-commentslop"},
                   {"type": "command",
                    "command": BIN + " shim --tool codex hook-cheatsniff"},
                   {"type": "command",
                    "command": BIN + " shim --tool codex hook-tamper"}]},
    ],
    "PostToolUse": [
        {"matcher": "Bash",
         "hooks": [{"type": "command",
                    "command": BIN + " hook-verify"}]},
    ],
}

GEMINI_SNIPPETS = {
    "SessionStart": [
        {"hooks": [{"name": "agent-guard-snapshot", "type": "command",
                    "command": BIN + " hook-snapshot"}]},
    ],
    # Gemini CLI has no blocking Stop event: advisory warning instead.
    "SessionEnd": [
        {"hooks": [{"name": "agent-guard-test", "type": "command",
                    "command": (BIN + " shim --tool gemini --warn "
                                "hook-test"),
                    "description": ("test-tampering check (advisory: "
                                    "Gemini CLI has no blocking Stop "
                                    "event)")}]}],
    "BeforeTool": [
        {"matcher": "run_shell_command",
         "hooks": [{"name": "agent-guard-outbound", "type": "command",
                    "command": BIN + " hook-outbound"},
                   {"name": "agent-guard-bashwrite", "type": "command",
                    "command": BIN + " hook-bashwrite"}]},
        {"matcher": "write_file|replace",
         "hooks": [{"name": "agent-guard-commentslop", "type": "command",
                    "command": (BIN + " shim --tool gemini "
                                "hook-commentslop")},
                   {"name": "agent-guard-cheatsniff", "type": "command",
                    "command": (BIN + " shim --tool gemini "
                                "hook-cheatsniff")},
                   {"name": "agent-guard-tamper", "type": "command",
                    "command": (BIN + " shim --tool gemini "
                                "hook-tamper")}]},
    ],
    "AfterTool": [
        {"matcher": "run_shell_command",
         "hooks": [{"name": "agent-guard-verify", "type": "command",
                    "command": BIN + " hook-verify"}]},
    ],
}

# Gemini tool names -> agent-guard's Claude-shaped tool names.
GEMINI_TOOL_MAP = {
    "run_shell_command": "Bash",
    "write_file": "Write",
    "replace": "Edit",
}

# Codex tool names -> agent-guard's Claude-shaped tool names.
# apply_patch needs patch parsing (handled in normalize); Bash passes
# through untouched.
CODEX_TOOL_MAP = {
    "apply_patch": "Edit",
}


def codex_dir(home=None):
    try:
        return os.path.abspath(os.path.expanduser(
            home or os.environ.get("CODEX_HOME", "~/.codex")))
    except Exception:
        return os.path.expanduser("~/.codex")


def gemini_dir(home=None):
    try:
        return os.path.abspath(os.path.expanduser(
            home or os.environ.get("GEMINI_DIR", "~/.gemini")))
    except Exception:
        return os.path.expanduser("~/.gemini")


def _load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            obj = json.load(fh)
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def _command_of(hook):
    try:
        return str(hook.get("command", "") or "")
    except Exception:
        return ""


def _entry_present(entries, key, want):
    """Is one snippet entry already installed? Never raises."""
    try:
        for e in entries:
            if not isinstance(e, dict):
                continue
            if key in ("PreToolUse", "PostToolUse", "BeforeTool",
                       "AfterTool") and \
                    e.get("matcher") != want.get("matcher"):
                continue
            have = {_command_of(h) for h in e.get("hooks", [])
                    if isinstance(h, dict)}
            for h in want.get("hooks", []):
                if _command_of(h) in have:
                    return True
        return False
    except Exception:
        return False


def _merge_snippets(settings, snippets):
    """Merge snippet entries into settings['hooks']. Returns added count."""
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        hooks = {}
        settings["hooks"] = hooks
    added = 0
    for key, snippet_list in snippets.items():
        entries = hooks.get(key)
        if not isinstance(entries, list):
            entries = []
            hooks[key] = entries
        for want in snippet_list:
            if _entry_present(entries, key, want):
                continue
            entries.append(copy.deepcopy(want))
            added += 1
    return added


def _write_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2)
        fh.write("\n")


def install_codex(home=None):
    """Merge hooks into ~/.codex/hooks.json; enable [features] hooks.

    Returns (hooks_path, hooks_added, features_enabled). Never raises.
    """
    d = codex_dir(home)
    hp = os.path.join(d, "hooks.json")
    settings = _load_json(hp)
    added = _merge_snippets(settings, CODEX_SNIPPETS)
    try:
        _write_json(hp, settings)
    except OSError:
        return hp, 0, False
    return hp, added, _enable_codex_hooks_feature(d)


def _enable_codex_hooks_feature(d):
    """Ensure '[features] hooks = true' in config.toml (textual, stdlib).

    Returns True when the flag is present after this call. Never raises.
    """
    try:
        cp = os.path.join(d, "config.toml")
        text = ""
        if os.path.exists(cp):
            with open(cp, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        lines = text.splitlines()
        in_features = False
        for i, line in enumerate(lines):
            s = line.strip()
            if s.startswith("["):
                in_features = s == "[features]"
                continue
            if in_features and re.match(r"hooks\s*=", s):
                lines[i] = "hooks = true"
                _write_toml(cp, lines)
                return True
        if in_features:
            lines.append("hooks = true")
        else:
            if lines and lines[-1].strip():
                lines.append("")
            lines.append("[features]")
            lines.append("hooks = true")
        _write_toml(cp, lines)
        return True
    except Exception:
        return False


def _write_toml(path, lines):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines).rstrip("\n") + "\n")


def install_gemini(home=None):
    """Merge hooks into ~/.gemini/settings.json.

    Returns (settings_path, added). Never raises.
    """
    d = gemini_dir(home)
    sp = os.path.join(d, "settings.json")
    settings = _load_json(sp)
    added = _merge_snippets(settings, GEMINI_SNIPPETS)
    try:
        _write_json(sp, settings)
    except OSError:
        return sp, 0
    return sp, added


def installed_commands(tool, home=None):
    """Set of agent-guard hook commands found in the tool's config."""
    found = set()
    try:
        if tool == "codex":
            settings = _load_json(os.path.join(codex_dir(home),
                                               "hooks.json"))
        elif tool == "gemini":
            settings = _load_json(os.path.join(gemini_dir(home),
                                               "settings.json"))
        else:
            return found
        hooks = settings.get("hooks")
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
                        cmd = _command_of(h)
                        if BIN in cmd:
                            found.add(cmd)
        return found
    except Exception:
        return found


def codex_hooks_feature_enabled(home=None):
    """Is [features] hooks=true in codex config.toml? Never raises."""
    try:
        cp = os.path.join(codex_dir(home), "config.toml")
        with open(cp, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        in_features = False
        for line in text.splitlines():
            s = line.strip()
            if s.startswith("["):
                in_features = s == "[features]"
                continue
            if in_features and re.match(r"hooks\s*=\s*true\b", s):
                return True
        return False
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Shim: normalize a foreign tool's hook payload into the Claude-shaped
# payload the hook commands expect, so every guard runs unchanged.
# ---------------------------------------------------------------------------

_APPLY_PATCH_FILE = re.compile(
    r"^\*\*\*\s+(?:Update File|Add File):\s*(.+?)\s*$")


def _codex_apply_patch_to_edit(tool_input):
    """Extract (file_path, new_string) from an apply_patch command.

    Takes the first file's added lines; good enough for the added-text
    guards (commentslop/cheatsniff/tamper). Never raises.
    """
    try:
        command = tool_input.get("command", "") if isinstance(
            tool_input, dict) else ""
        if not isinstance(command, str):
            return None
        path, added = None, []
        for line in command.splitlines():
            m = _APPLY_PATCH_FILE.match(line.strip())
            if m:
                if path is None:
                    path = m.group(1)
                continue
            if path is not None and line.startswith("+") and \
                    not line.startswith("+++"):
                added.append(line[1:])
        if path is None:
            return None
        return {"file_path": path, "new_string": "\n".join(added)}
    except Exception:
        return None


def normalize(tool, data):
    """Normalize a hook payload to Claude-shaped fields.

    Returns a new dict with tool_name/tool_input rewritten, or None when
    the payload cannot be mapped (caller should allow). Never raises.
    """
    try:
        if not isinstance(data, dict):
            return None
        data = dict(data)
        name = str(data.get("tool_name", "") or "")
        tool_input = data.get("tool_input")
        if not isinstance(tool_input, dict):
            tool_input = {}
        if tool == "gemini":
            mapped = GEMINI_TOOL_MAP.get(name)
            if mapped is None:
                return None
            new_input = dict(tool_input)
            if mapped == "Write" and "content" in new_input:
                pass  # write_file already has file_path + content
            data["tool_name"] = mapped
            data["tool_input"] = new_input
            return data
        if tool == "codex":
            if name == "Bash":
                return data  # Codex Bash payloads are Claude-shaped
            mapped = CODEX_TOOL_MAP.get(name)
            if mapped is None:
                return None
            edit = _codex_apply_patch_to_edit(tool_input)
            if edit is None:
                return None
            data["tool_name"] = mapped
            data["tool_input"] = edit
            return data
        return None
    except Exception:
        return None


def mount_steps(tool):
    """Human-readable mount steps for a tool. Never raises."""
    try:
        if tool == "codex":
            return [
                "agent-guard install --tool codex   # writes ~/.codex/hooks.json",
                "Codex requires the hooks feature flag: [features] hooks=true",
                "  in ~/.codex/config.toml (install sets it automatically).",
                "Trust the hooks once: open Codex, type /hooks, trust the",
                "  agent-guard entries (Codex pins a hash per hook).",
                "Restart Codex.",
            ]
        if tool == "gemini":
            return [
                "agent-guard install --tool gemini  # writes ~/.gemini/settings.json",
                "Note: Gemini CLI has no blocking Stop event, so the",
                "  test-tampering check runs at SessionEnd as an advisory",
                "  warning instead of a block.",
                "Restart Gemini CLI.",
            ]
        return [
            "agent-guard install   # writes ~/.claude/settings.json",
            "Restart Claude Code.",
        ]
    except Exception:
        return []
