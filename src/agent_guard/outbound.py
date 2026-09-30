"""Outbound-action guard.

A PreToolUse hook on Bash that matches the command string against a denylist
of risky action patterns: pushes to protected branches, package publishes,
prod deploys, cloud provisioning (spend), and mass-send channels. Matches
block (exit 2); a user allowlist in config.json overrides the denylist.

Everything fails open: any unexpected error means "allow".
"""

import re

# (rule_id, human description, [regexes])
RULES = [
    ("git-push-protected",
     "Push to a protected branch (main/master/prod*/release/*)",
     [r"\bgit\s+push\b[^|;&]*\b(main|master|prod(uction)?|release/[\w.\-]+)\b"]),
    ("git-push-force",
     "Force push (rewrites remote history)",
     [r"\bgit\s+push\b[^|;&]*--force\b",
      r"\bgit\s+push\b[^|;&]*\s-f(\s|$)"]),
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
    return [rid for rid, _, _ in RULES]
