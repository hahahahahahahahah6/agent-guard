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


def snapshot_path():
    return os.path.join(state_dir(), "test-snapshot.json")


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
    for section in ("test_guard", "outbound"):
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
