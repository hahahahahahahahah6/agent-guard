"""Outbound-action guard.

A PreToolUse hook on Bash that matches the command string against a denylist
of risky action patterns: pushes to protected branches, package publishes,
prod deploys, cloud provisioning (spend), and mass-send channels. Matches
block (exit 2); a user allowlist in config.json overrides the denylist.

Everything fails open: any unexpected error means "allow".
"""

import re
import shlex

# (rule_id, human description, [regexes])
# NOTE: git push is NOT regexed here; it is parsed by _check_git_push below,
# which understands `git -C <dir> push`, bare pushes, and HEAD refspecs.
RULES = [
    ("package-publish",
     "Publish a package (npm/twine/cargo/gh release)",
     [r"\bnpm\s+publish\b(?![^|;&]*--dry-run)",
      r"\btwine\s+upload\b",
      r"\bcargo\s+publish\b",
      r"\bgh\s+release\s+create\b"]),
    ("prod-deploy",
     "Production deploy",
     [r"\bkubectl\s+(apply|delete|replace)\b",
      r"\bkubectl\s+rollout\s+restart\b",
      r"\bterraform\s+apply\b",
      r"\bfly\s+deploy\b",
      r"\bvercel\b[^|;&]*--prod\b",
      r"\bserverless\s+deploy\b",
      r"\bsls\s+deploy\b"]),
    ("cloud-provision",
     "Cloud resource provisioning (spend)",
     [r"\baws\s+ec2\s+run-instances\b",
      r"\bgcloud\s+compute\s+instances\s+create\b",
      r"\baz\s+vm\s+create\b",
      r"\bdoctl\s+compute\s+droplet\s+create\b",
      r"\bfly\s+launch\b",
      r"\bfly\s+machine\s+run\b"]),
    ("mass-send",
     "Mass-send channel (Slack webhook / mailer / email API)",
     [r"https?://hooks\.slack\.com/services/",
      r"\bsendmail\b",
      r"\bmsmtp\b",
      r"api\.sendgrid\.com",
      r"api\.mailgun\.net"]),
]

_COMPILED = [(rid, desc, [re.compile(p, re.IGNORECASE) for p in pats])
             for rid, desc, pats in RULES]


# ---------------------------------------------------------------------------
# git push: parsed, not regexed
# ---------------------------------------------------------------------------

def _looks_protected_ref(name):
    n = name.lower()
    if n in ("main", "master", "prod", "production"):
        return True
    return n.startswith("release/")


_GIT_GLOBAL_OPTS_WITH_VAL = {
    "-C", "-c", "--git-dir", "--work-tree", "--namespace",
    "--super-prefix", "--config-env",
}
_PUSH_OPTS_WITH_VAL = {"--repo", "--receive-pack", "--exec"}


def _check_git_push(command):
    """Block risky `git push` invocations.

    Blocked when a push:
      * names a protected ref (main/master/prod*/release/*) or HEAD as a
        refspec source or destination (`git push origin main`,
        `git push origin HEAD`, `git push origin :main` which *deletes*
        the remote branch), or
      * carries no usable refspec, so the target branch cannot be
        determined (`git push`, `git push origin`).
    Tolerates git global flags between `git` and `push` (`git -C <dir> push`).
    Returns (rule_id, detail) or (None, None) when no push is risky.
    Never raises.
    """
    try:
        return _check_git_push_inner(command)
    except Exception:
        return None, None  # fail open


def _check_git_push_inner(command):
    for chunk in re.split(r"[|;&]", command):
        try:
            toks = shlex.split(chunk, posix=True)
        except ValueError:
            toks = chunk.split()

        gi = next((i for i, t in enumerate(toks)
                   if t == "git" or t.endswith("/git")), None)
        if gi is None:
            continue

        # Skip git global options between `git` and the subcommand.
        j = gi + 1
        while j < len(toks):
            t = toks[j]
            base = t.split("=", 1)[0]
            if t in _GIT_GLOBAL_OPTS_WITH_VAL:
                j += 2
            elif base in _GIT_GLOBAL_OPTS_WITH_VAL:
                j += 1  # attached --opt=value form
            elif t.startswith("-") and t != "-":
                j += 1  # boolean global flag
            else:
                break
        if j >= len(toks) or toks[j] != "push":
            continue

        # Parse push args: skip options, collect positional args.
        args, force = [], False
        k = j + 1
        while k < len(toks):
            t = toks[k]
            if t == "--":
                args.extend(toks[k + 1:])
                break
            if t.startswith("-") and t != "-":
                base = t.split("=", 1)[0]
                if base in ("--force", "-f"):
                    force = True
                if base in _PUSH_OPTS_WITH_VAL and "=" not in t:
                    k += 2
                else:
                    k += 1
                continue
            args.append(t)
            k += 1

        if force:
            return ("git-push-force",
                    "force push rewrites remote history")
        if not args:
            return ("git-push-protected",
                    "bare `git push` (target branch cannot be determined)")
        if len(args) == 1:
            # `git push <x>`: ambiguous between remote and refspec; if <x>
            # is a remote, the current branch gets pushed. Block it.
            return ("git-push-protected",
                    "`git push %s` (target branch cannot be determined)"
                    % args[0])
        # args[0] is the remote; the rest are refspecs.
        for rs in args[1:]:
            core = rs.lstrip("+^")
            parts = [p for p in core.split(":") if p != ""]
            names = parts or [core]
            for name in names:
                short = name.split("/")[-1]
                if short.upper() == "HEAD" or name.upper() == "HEAD":
                    return ("git-push-protected",
                            "`git push` targeting HEAD (resolves to the "
                            "current branch)")
                if _looks_protected_ref(short) or _looks_protected_ref(name):
                    return ("git-push-protected",
                            "push to protected ref '%s'" % name)
    return None, None


def check(command, config=None):
    """Decide whether a Bash command may run.

    Returns (allowed: bool, reason: str, rule_id or None).
    allowed-by-allowlist returns (True, "", "allowlist:<pattern>").
    Never raises.
    """
    try:
        return _check_inner(command or "", config or {})
    except Exception:
        return True, "", None  # fail open


def _check_inner(command, config):
    out = config.get("outbound", {}) if isinstance(config, dict) else {}

    for pat in out.get("allow", []) or []:
        try:
            if re.search(pat, command, re.IGNORECASE):
                return True, "", "allowlist:" + pat
        except re.error:
            continue

    disabled = set(out.get("disabled_rules", []) or [])

    rid, detail = _check_git_push(command)
    if rid is not None and rid not in disabled:
        desc = {"git-push-protected":
                "Push to a protected branch (main/master/prod*/release/*), "
                "a bare push, or a HEAD push",
                "git-push-force":
                "Force push (rewrites remote history)"}[rid]
        reason = (
            "Outbound-action guard blocked this command (rule '%s': %s: %s).\n"
            "If this action is intended, add an allowlist regex to "
            "outbound.allow in %s, or run it yourself outside the agent."
            % (rid, desc, detail, _config_hint()))
        return False, reason, rid

    for rid, desc, rxs in _COMPILED:
        if rid in disabled:
            continue
        if any(rx.search(command) for rx in rxs):
            reason = (
                "Outbound-action guard blocked this command (rule '%s': %s).\n"
                "If this action is intended, add an allowlist regex to "
                "outbound.allow in %s, or run it yourself outside the agent."
                % (rid, desc, _config_hint()))
            return False, reason, rid

    for pat in out.get("deny_extra", []) or []:
        try:
            if re.search(pat, command, re.IGNORECASE):
                return (False,
                        "Outbound-action guard blocked this command "
                        "(user rule '%s')." % pat,
                        "deny_extra:" + pat)
        except re.error:
            continue

    return True, "", None


def _config_hint():
    from . import state
    return state.config_path()


def rule_ids():
    return (["git-push-protected", "git-push-force"]
            + [rid for rid, _, _ in RULES])
