"""Post-exec read-back verifier.

A PostToolUse hook on Bash: after a command that claimed an outbound
effect, read back world state and WARN (stderr, exit 0 -- NEVER blocks)
when the claimed effect isn't visible. This is defense-in-depth on top of
the PreToolUse prevention: prevent first, verify after.

Cases:
  * `git push <remote> <ref>`: run `git ls-remote <remote> <ref>` and warn
    when the ref is absent remotely (<remote> defaults to `origin`).
  * `npm publish`: read package.json in the cwd for name+version, run
    `npm view <name>@<version> version`, and warn when it isn't visible.
    Silent when there is no package.json or npm is missing.

Timeouts on all subprocess calls (10s). Fails open on everything:
inconclusive checks stay silent.
"""

import json
import os
import re
import shlex
import subprocess
import sys

from . import state

_TIMEOUT = 10

# Push options that take a value (the next token is not a positional).
_PUSH_OPTS_WITH_VAL = {"--repo", "--receive-pack", "--exec", "-C"}


def _warn(msg, audit_extra=None):
    """Emit a warning to stderr, audit-log it, never raise, never block."""
    try:
        sys.stderr.write("agent-guard verify: %s\n" % msg)
        entry = {"guard": "verify", "decision": "warn", "reason": msg}
        if isinstance(audit_extra, dict):
            entry.update(audit_extra)
        state.append_audit(entry)
    except Exception:
        pass


def _current_branch(cwd):
    """Current branch name, or None when it cannot be determined."""
    try:
        p = subprocess.run(
            ["git", "symbolic-ref", "--short", "HEAD"],
            cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, timeout=_TIMEOUT)
    except Exception:
        return None
    if p.returncode != 0:
        return None
    return (p.stdout or "").strip() or None


def _looks_like_refspec(arg):
    return ":" in arg or arg.startswith("+")


def _dst_of_refspec(rs):
    """Destination branch of a push refspec, or None if unknowable."""
    try:
        s = (rs or "").strip()
        if s.startswith("+"):
            s = s[1:]
        if ":" in s:
            src, dst = s.split(":", 1)
        else:
            src, dst = s, s
        dst = dst.strip()
        if not dst:
            dst = src.strip()
        # `:dst` with empty src is a remote-branch deletion: there is
        # nothing to verify as "visible", so skip it.
        if not src.strip():
            return None
        return dst or None
    except Exception:
        return None


def parse_push_targets(command, cwd=None):
    """Extract (remote, ref, repo_dir) triples from `git push` commands.

    Simpler re-parse than outbound.py's full parser: enough to know what
    to look for remotely. Returns a list; empty when no push found.
    Never raises.
    """
    out = []
    try:
        chunks = re.split(r"[|;&]", command or "")
    except Exception:
        return out
    for chunk in chunks:
        try:
            toks = shlex.split(chunk, posix=True)
        except ValueError:
            toks = chunk.split()
        except Exception:
            continue
        gi = next((i for i, t in enumerate(toks)
                   if t == "git" or t.endswith("/git")), None)
        if gi is None:
            continue
        # Skip git global options; honor -C <dir>.
        git_dir = None
        j = gi + 1
        while j < len(toks):
            t = toks[j]
            if t == "-C" and j + 1 < len(toks):
                git_dir = toks[j + 1]
                j += 2
                continue
            if t.startswith("-") and t != "-":
                j += 1
                continue
            break
        if j >= len(toks) or toks[j] != "push":
            continue
        repo_dir = cwd or os.getcwd()
        if git_dir:
            try:
                repo_dir = (git_dir if os.path.isabs(git_dir)
                            else os.path.normpath(
                                os.path.join(repo_dir, git_dir)))
            except Exception:
                pass
        # Collect positionals, skipping push options.
        args = []
        k = j + 1
        while k < len(toks):
            t = toks[k]
            if t == "--":
                args.extend(toks[k + 1:])
                break
            if t.startswith("-") and t != "-":
                base = t.split("=", 1)[0]
                k += 2 if (base in _PUSH_OPTS_WITH_VAL
                           and "=" not in t) else 1
                continue
            args.append(t)
            k += 1
        if not args:
            refspecs, remote = [], "origin"
        elif len(args) == 1 and _looks_like_refspec(args[0]):
            refspecs, remote = args, "origin"
        else:
            refspecs, remote = args[1:], args[0]
        refs = []
        for rs in refspecs:
            dst = _dst_of_refspec(rs)
            if dst:
                refs.append(dst)
        if not refs:
            # Bare push: destination is the current branch.
            branch = _current_branch(repo_dir)
            if branch:
                refs.append(branch)
        # Resolve HEAD and de-dup.
        seen = set()
        for ref in refs:
            r = ref
            if r.upper() == "HEAD":
                r = _current_branch(repo_dir)
            if r and r not in seen:
                seen.add(r)
                out.append((remote, r, repo_dir))
    return out


def _ref_visible_remotely(repo_dir, remote, ref):
    """True/False, or None when the check is inconclusive. Never raises."""
    try:
        p = subprocess.run(
            ["git", "ls-remote", remote, ref],
            cwd=repo_dir, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, timeout=_TIMEOUT)
    except Exception:
        return None  # git missing, timeout, bad cwd: fail open
    if p.returncode != 0:
        return None  # cannot reach remote: inconclusive, stay silent
    for line in (p.stdout or "").splitlines():
        parts = line.split()
        if len(parts) == 2:
            name = parts[1]
            if name == ref or name == "refs/heads/" + ref:
                return True
    return False


def check_git_push(command, cwd=None):
    """Warn for pushed refs that are not visible on the remote.

    Returns a list of warning strings (empty when all visible or when
    nothing could be verified). Never raises, never blocks.
    """
    warnings = []
    try:
        for remote, ref, repo_dir in parse_push_targets(command, cwd):
            visible = _ref_visible_remotely(repo_dir, remote, ref)
            if visible is False:
                warnings.append(
                    "`git push %s %s` ran but ref '%s' is not visible on "
                    "remote '%s' (git ls-remote found nothing). The push "
                    "may have failed silently; check `git status` and push "
                    "again if needed." % (remote, ref, ref, remote))
    except Exception:
        pass
    return warnings


def _npm_package(cwd):
    """(name, version) from package.json in cwd, or (None, None)."""
    try:
        with open(os.path.join(cwd, "package.json"), "r",
                   encoding="utf-8") as fh:
            pkg = json.load(fh)
        if not isinstance(pkg, dict):
            return None, None
        name, version = pkg.get("name"), pkg.get("version")
        if isinstance(name, str) and name and isinstance(version, str) \
                and version:
            return name, version
        return None, None
    except Exception:
        return None, None


def check_npm_publish(command, cwd=None):
    """Warn when a published package version isn't visible on npm.

    Returns a list of warning strings. Silent when there is no
    package.json, npm is missing, or the check is inconclusive.
    Never raises, never blocks.
    """
    warnings = []
    try:
        if not re.search(r"\bnpm\s+publish\b(?![^|;&]*--dry-run)",
                         command or "", re.IGNORECASE):
            return warnings
        cwd = cwd or os.getcwd()
        name, version = _npm_package(cwd)
        if not name:
            return warnings  # no package.json: nothing to verify
        try:
            p = subprocess.run(
                ["npm", "view", "%s@%s" % (name, version), "version"],
                cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, timeout=_TIMEOUT)
        except FileNotFoundError:
            return warnings  # npm not installed: silent
        except Exception:
            return warnings
        shown = (p.stdout or "").strip()
        if p.returncode == 0 and version in shown:
            return warnings
        err = (p.stderr or "")
        if p.returncode != 0 and not re.search(r"404|E404", err):
            return warnings  # network/auth failure: inconclusive
        warnings.append(
            "`npm publish` ran but `%s@%s` is not visible on the npm "
            "registry (npm view found nothing). The publish may have "
            "failed; check the publish output." % (name, version))
    except Exception:
        pass
    return warnings


def verify(command, cwd=None):
    """Collect post-exec warnings for a Bash command. Never raises."""
    try:
        return check_git_push(command, cwd) + check_npm_publish(command, cwd)
    except Exception:
        return []


def run_hook():
    """PostToolUse entry point: warn on stderr, always exit 0."""
    try:
        raw = sys.stdin.read()
        data = json.loads(raw) if raw.strip() else {}
        if not isinstance(data, dict):
            data = {}
        if data.get("tool_name") != "Bash":
            return 0
        tool_input = data.get("tool_input")
        command = (tool_input.get("command", "")
                   if isinstance(tool_input, dict) else "")
        cwd = data.get("cwd") or os.getcwd()
        for w in verify(command, cwd):
            _warn(w, {"tool": "Bash",
                      "command": (command or "")[:500]})
    except Exception:
        pass
    return 0  # NEVER block: PostToolUse is advisory only


if __name__ == "__main__":
    sys.exit(run_hook())
