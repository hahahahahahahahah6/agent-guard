"""Outbound-action guard.

A PreToolUse hook on Bash that matches the command string against a denylist
of risky action patterns: pushes to protected branches, package publishes,
prod deploys, cloud provisioning (spend), and mass-send channels. Matches
block (exit 2); a user allowlist in config.json overrides the denylist.

Everything fails open: any unexpected error means "allow".
"""

import os
import re
import shlex
import subprocess

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


def _is_protected_ref(name):
    """True if a ref name (branch or refs/heads/<branch>) is protected."""
    n = (name or "").strip()
    if n.lower().startswith("refs/heads/"):
        n = n[len("refs/heads/"):]
    return _looks_protected_ref(n) or _looks_protected_ref(n.split("/")[-1])


_GIT_GLOBAL_OPTS_WITH_VAL = {
    "-C", "-c", "--git-dir", "--work-tree", "--namespace",
    "--super-prefix", "--config-env",
}
_PUSH_OPTS_WITH_VAL = {"--repo", "--receive-pack", "--exec"}
_FORCE_FLAGS = ("--force", "-f", "--force-with-lease")

# Sentinel: push destination is the current branch (resolve via git).
_CURRENT_BRANCH = object()


def _current_branch(cwd):
    """Current branch name via `git symbolic-ref --short HEAD`.

    Returns None when it cannot be determined (detached HEAD, not a git
    repo, git missing or erroring). Callers treat None as "fail open".
    Never raises.
    """
    try:
        p = subprocess.run(
            ["git", "symbolic-ref", "--short", "HEAD"],
            cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, timeout=10)
    except Exception:
        return None
    if p.returncode != 0:
        return None
    name = (p.stdout or "").strip()
    return name or None


def _resolve_cwd(git_dir, hook_cwd):
    """Effective repo dir: the hook's cwd, overridden by `git -C <dir>`."""
    try:
        base = hook_cwd or os.getcwd()
        if not git_dir:
            return base
        if os.path.isabs(git_dir):
            return os.path.normpath(git_dir)
        return os.path.normpath(os.path.join(base, git_dir))
    except Exception:
        return hook_cwd or os.getcwd()


def _looks_like_refspec(arg):
    """A lone positional that is clearly a refspec, not a repository."""
    return ":" in arg or arg.startswith("+")


def _dst_of_refspec(rs):
    """Split a push refspec into (destination, is_force).

    Destination is a branch name, the literal "HEAD" (resolved by the
    caller against the current branch), or None when it cannot be
    determined. Never raises.
    """
    try:
        s = (rs or "").strip()
        force = False
        if s.startswith("+"):
            force = True
            s = s[1:]
        # Ref names cannot contain ':', so split on the first one.
        # `src` -> dst defaults to src; `src:dst` -> dst; `:dst` -> dst
        # (remote-branch deletion).
        if ":" in s:
            src, dst = s.split(":", 1)
        else:
            src, dst = s, s
        dst = dst.strip()
        if not dst:
            dst = src.strip()
        if not dst:
            return None, force
        return dst, force
    except Exception:
        return None, False


def _check_git_push(command, cwd=None):
    """Block `git push` only when its DESTINATION is a protected branch.

    The destination is resolved from the push arguments:
      * `git push` / `git push <repo>` (no refspec): the current branch,
        via `git symbolic-ref --short HEAD` in the hook's cwd
        (`git -C <dir>` overrides the cwd).
      * `git push <repo> <refspec>...`: the destination side of each
        refspec (`feature-x:main` -> main); HEAD resolves to the current
        branch; `:main` (remote-branch deletion) counts as main.
      * `--force` / `--force-with-lease` (or a `+` refspec) targeting a
        protected branch stays blocked; force to other branches is allowed.
      * `--all` / `--mirror` push every ref, so they are blocked;
        `--tags` alone pushes no branches and is allowed.
    When the destination cannot be determined (detached HEAD, not a git
    repo, git errors), the push is allowed — fail open, never break the
    user on ambiguity.
    Returns (rule_id, detail) or (None, None) when no push is risky.
    Never raises.
    """
    try:
        return _check_git_push_inner(command, cwd)
    except Exception:
        return None, None  # fail open


def _check_git_push_inner(command, cwd):
    for chunk in re.split(r"[|;&]", command):
        try:
            toks = shlex.split(chunk, posix=True)
        except ValueError:
            toks = chunk.split()

        gi = next((i for i, t in enumerate(toks)
                   if t == "git" or t.endswith("/git")), None)
        if gi is None:
            continue

        # Skip git global options between `git` and the subcommand,
        # remembering -C <dir> (it changes which repo the push targets).
        git_dir = None
        j = gi + 1
        while j < len(toks):
            t = toks[j]
            if t == "-C":
                if j + 1 < len(toks):
                    git_dir = toks[j + 1]
                j += 2
                continue
            if t.startswith("-C") and len(t) > 2:
                git_dir = t[2:]  # attached -C<dir> form
                j += 1
                continue
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

        # Parse push args: skip options, collect positionals.
        args, force = [], False
        push_all = push_tags = False
        k = j + 1
        while k < len(toks):
            t = toks[k]
            if t == "--":
                args.extend(toks[k + 1:])
                break
            if t.startswith("-") and t != "-":
                base = t.split("=", 1)[0]
                if base in _FORCE_FLAGS:
                    force = True
                elif base in ("--all", "--mirror"):
                    push_all = True
                elif base == "--tags":
                    push_tags = True
                if base in _PUSH_OPTS_WITH_VAL and "=" not in t:
                    k += 2
                else:
                    k += 1
                continue
            args.append(t)
            k += 1

        if push_all:
            return ("git-push-protected",
                    "`git push --all`/`--mirror` pushes every ref, "
                    "including protected branches")

        # Split positionals into refspecs. `git push [<repo> [<refspec>..]]`:
        # a lone positional is the repository (destination = current
        # branch), unless it is clearly a refspec (`:main`, `+main`).
        if not args:
            refspecs = []
        elif len(args) == 1 and _looks_like_refspec(args[0]):
            refspecs = args
        else:
            refspecs = args[1:]

        if push_tags and not refspecs:
            continue  # tags only: no branch destination

        eff_cwd = _resolve_cwd(git_dir, cwd)
        _cache = {}

        def current_branch():
            if "branch" not in _cache:
                _cache["branch"] = _current_branch(eff_cwd)
            return _cache["branch"]

        # (destination-spec, is_force); _CURRENT_BRANCH resolves via git.
        pairs = []
        if not refspecs:
            pairs.append((_CURRENT_BRANCH, force))
        else:
            for rs in refspecs:
                dst, rs_force = _dst_of_refspec(rs)
                pairs.append((dst, force or rs_force))

        for spec, f in pairs:
            if spec is _CURRENT_BRANCH:
                dst = current_branch()
            elif isinstance(spec, str) and spec.upper() == "HEAD":
                dst = current_branch()
            else:
                dst = spec
            if not dst:
                continue  # destination unknown -> fail open
            if _is_protected_ref(dst):
                if f:
                    return ("git-push-force",
                            "force push to protected ref '%s'" % dst)
                return ("git-push-protected",
                        "push to protected ref '%s'" % dst)
    return None, None


def check(command, config=None, cwd=None):
    """Decide whether a Bash command may run.

    Returns (allowed: bool, reason: str, rule_id or None).
    allowed-by-allowlist returns (True, "", "allowlist:<pattern>").
    `cwd` is the hook's working directory, used to resolve the current
    branch for destination-aware `git push` checks.
    Never raises.
    """
    try:
        return _check_inner(command or "", config or {}, cwd)
    except Exception:
        return True, "", None  # fail open


def _check_inner(command, config, cwd):
    out = config.get("outbound", {}) if isinstance(config, dict) else {}

    for pat in out.get("allow", []) or []:
        try:
            if re.search(pat, command, re.IGNORECASE):
                return True, "", "allowlist:" + pat
        except re.error:
            continue

    disabled = set(out.get("disabled_rules", []) or [])

    rid, detail = _check_git_push(command, cwd)
    if rid is not None and rid not in disabled:
        desc = {"git-push-protected":
                "Push to a protected branch (main/master/prod*/release/*)",
                "git-push-force":
                "Force push to a protected branch "
                "(rewrites remote history)"}[rid]
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
