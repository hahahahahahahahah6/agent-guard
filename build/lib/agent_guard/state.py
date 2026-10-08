"""Shared state helpers: dirs, config, digests, audit log.

Everything fails open: helpers never raise to callers that matter; the
cli layer wraps hook entry points in a final try/except anyway.
"""

import hashlib
import json
import os
import time

MAX_HASH_BYTES = 50 * 1024 * 1024
MAX_AUDIT_LINES = 20000
PRUNE_KEEP = 10000


def state_dir():
    return os.environ.get(
        "AGENT_GUARD_DIR",
        os.path.join(os.path.expanduser("~"), ".config", "agent-guard"))


def config_path():
    return os.path.join(state_dir(), "config.json")


def audit_path():
    return os.path.join(state_dir(), "audit.jsonl")


def snapshot_path(session_id=None):
    if session_id:
        safe = "".join(
            c for c in str(session_id) if c.isalnum() or c in ("-", "_"))[:64]
        if safe:
            return os.path.join(state_dir(), "test-snapshot.%s.json" % safe)
    return os.path.join(state_dir(), "test-snapshot.json")


def prune_old_snapshots(max_age_days=7):
    """Delete per-session snapshots older than max_age_days. Never raises."""
    try:
        cutoff = time.time() - max_age_days * 86400
        d = state_dir()
        for fn in os.listdir(d):
            if fn.startswith("test-snapshot.") and fn.endswith(".json"):
                p = os.path.join(d, fn)
                try:
                    if os.path.getmtime(p) < cutoff:
                        os.remove(p)
                except OSError:
                    pass
    except OSError:
        pass


def default_config():
    return {
        "test_guard": {
            "mode": "block",       # "block" or "warn"
            "ignore_paths": [],    # substring matches, skipped entirely
        },
        "outbound": {
            "allow": [],           # regexes; win over the denylist
            "deny_extra": [],      # extra user regexes added to the denylist
            "disabled_rules": [],  # rule ids to turn off
        },
        "comment_slop": {
            "mode": "block",       # "block" or "warn"
            "threshold": 30,       # slop score (0-100) that trips the hook
        },
        "cheat_sniff": {
            "mode": "block",       # "block" or "warn"
            "threshold": 30,       # cheat score (0-100) that trips the hook
            "allow": [],           # "path-or-basename:kind" suppressions
        },
        "bash_write": {
            "mode": "block",       # "block" or "warn"
            "protected_paths": [],  # path prefixes; empty = test files
                                    # (same definition as the test-tampering
                                    # guard) plus conftest.py
            "allow": [],           # "path-or-basename:bash-write" suppressions
        },
        "semreview": {
            "mode": "warn",        # "warn" downgrades a model "block" to
                                   # "warn"; "block" honors it. Env override:
                                   # AGENT_GUARD_SEMREVIEW_MODE
            "model": "nvidia/nemotron-3-nano-30b-a3b",  # Nemotron on Nebius
                                   # Token Factory. Env override:
                                   # AGENT_GUARD_SEMREVIEW_MODEL
            "timeout": 20,         # seconds per API call. Env override:
                                   # AGENT_GUARD_SEMREVIEW_TIMEOUT
            "max_tokens": 4000,    # per-request input budget (estimated)
            "max_output_tokens": 600,
            "cache_ttl_days": 7,   # semantic verdicts cached by content hash
        },
    }


def load_config():
    """Return merged config dict. Never raises."""
    cfg = default_config()
    try:
        with open(config_path(), "r", encoding="utf-8") as fh:
            user = json.load(fh)
    except Exception:
        return cfg
    if not isinstance(user, dict):
        return cfg
    for section in ("test_guard", "outbound", "comment_slop",
                    "cheat_sniff", "bash_write", "semreview"):
        u = user.get(section)
        if isinstance(u, dict):
            for k, v in u.items():
                if k in cfg[section]:
                    cfg[section][k] = v
    return cfg


def digest_of(path):
    """sha256 of file contents; falls back to mtime+size for huge files."""
    try:
        size = os.path.getsize(path)
    except OSError:
        return None
    try:
        if size > MAX_HASH_BYTES:
            st = os.stat(path)
            return "stat:%d:%d" % (st.st_mtime_ns, st.st_size)
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return "sha256:" + h.hexdigest()
    except OSError:
        return None


def _prune(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError:
        return
    if len(lines) <= MAX_AUDIT_LINES:
        return
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.writelines(lines[-PRUNE_KEEP:])
    except OSError:
        pass


def append_audit(entry):
    """Append one audit entry. Never raises."""
    try:
        os.makedirs(state_dir(), exist_ok=True)
        entry = dict(entry)
        entry.setdefault("ts", time.time())
        with open(audit_path(), "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
        _prune(audit_path())
    except OSError:
        pass


def read_audit():
    """Return list of entry dicts; tolerates missing/corrupt file."""
    entries = []
    try:
        fh = open(audit_path(), "r", encoding="utf-8", errors="replace")
    except OSError:
        return entries
    with fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if isinstance(obj, dict):
                entries.append(obj)
    return entries
