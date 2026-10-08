"""Test-tampering guard.

Model: on SessionStart, record sha256 digests of every test file AND every
source file under the project root. On Stop, re-hash and diff. If test files
were modified or deleted while no source file changed, the session is blocked:
that is the exact shape of the "agent edits assertions to get green instead
of fixing the code" failure mode.

Newly added test files do NOT count as tampering (writing new tests for new
code is legitimate). Modified or deleted test files with an untouched source
tree do.

Everything fails open: any unexpected error means "allow".
"""

import os
import re
import time
import json

from . import state

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv",
             ".tox", "dist", "build", ".idea", ".vscode", "target"}

SOURCE_EXTS = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
               ".go", ".java", ".rb", ".rs", ".c", ".h", ".cpp", ".hpp",
               ".cs", ".php", ".swift", ".kt", ".kts", ".scala"}

TEST_FILE_RES = [
    r"(^|/)test_[^/]*\.py$",
    r"(^|/)[^/]*_test\.py$",
    r"(^|/)[^/]*_test\.go$",
    r"(^|/)[^/]*\.test\.[jt]sx?$",
    r"(^|/)[^/]*\.spec\.[jt]sx?$",
    r"(^|/)[^/]*Test\.java$",
    r"(^|/)[^/]*_test\.rb$",
    r"(^|/)test_[^/]*\.rb$",
    r"(^|/)[^/]*\.t$",          # perl
]
TEST_FILE_RES = [re.compile(p) for p in TEST_FILE_RES]
TEST_DIR_SEGS = {"test", "tests", "__tests__", "spec"}


def _ignored(rel, ignore_paths):
    return any(sub in rel for sub in ignore_paths)


def is_test_file(rel):
    if any(seg in rel.split(os.sep) for seg in TEST_DIR_SEGS):
        return True
    return any(rx.search(rel) for rx in TEST_FILE_RES)


def is_source_file(rel):
    if is_test_file(rel):
        return False
    _, ext = os.path.splitext(rel)
    return ext.lower() in SOURCE_EXTS


def _walk(root, ignore_paths):
    """Yield (relpath, abspath) for test and source files under root."""
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root)
            if _ignored(rel, ignore_paths):
                continue
            if is_test_file(rel) or is_source_file(rel):
                out.append((rel, full))
    return out


def snapshot(root, session_id=None):
    """Record digests of test + source files. Never raises.

    Snapshots are stored per session_id so two concurrent sessions or
    projects never overwrite each other.
    """
    try:
        cfg = state.load_config()
        ignore = cfg["test_guard"].get("ignore_paths", []) or []
        tests, sources = {}, {}
        for rel, full in _walk(root, ignore):
            d = state.digest_of(full)
            if d is None:
                continue
            (tests if is_test_file(rel) else sources)[rel] = d
        os.makedirs(state.state_dir(), exist_ok=True)
        with open(state.snapshot_path(session_id), "w", encoding="utf-8") as fh:
            json.dump({"root": os.path.abspath(root), "ts": time.time(),
                       "tests": tests, "sources": sources}, fh)
        state.prune_old_snapshots()
    except Exception:
        pass


def check(root, session_id=None):
    """Decide whether the session may stop.

    Returns (allowed: bool, reason: str). Never raises.
    """
    try:
        return _check_inner(root, session_id)
    except Exception:
        return True, ""  # fail open


def _check_inner(root, session_id):
    cfg = state.load_config()
    ignore = cfg["test_guard"].get("ignore_paths", []) or []
    try:
        with open(state.snapshot_path(session_id), "r", encoding="utf-8") as fh:
            snap = json.load(fh)
    except Exception:
        return True, ""  # no usable snapshot: fail open
    if not isinstance(snap, dict) or snap.get("root") != os.path.abspath(root):
        return True, ""  # snapshot is for a different project

    old_tests = snap.get("tests", {}) or {}
    old_sources = snap.get("sources", {}) or {}

    current = {}
    for rel, full in _walk(root, ignore):
        d = state.digest_of(full)
        if d is not None:
            current[rel] = d

    changed_tests = sorted(
        rel for rel, d in old_tests.items()
        if rel not in current or current[rel] != d)  # modified or deleted
    changed_sources = sorted(
        rel for rel, d in old_sources.items()
        if rel not in current or current[rel] != d)
    # New source files also count as "source changed" (new feature + tests).
    for rel in current:
        if rel not in old_tests and rel not in old_sources \
                and is_source_file(rel):
            changed_sources.append(rel)

    if not changed_tests:
        return True, ""
    if changed_sources:
        return True, ""  # normal development: code and tests moved together

    reason = (
        "Test-tampering guard: test files changed but no source files "
        "changed since this session started.\n"
        "Changed test files:\n" +
        "".join("  - %s\n" % p for p in changed_tests) +
        "This matches a known failure mode where an agent edits test "
        "assertions to make them pass instead of fixing the source code. "
        "Before proceeding, verify each changed test actually fails without "
        "the fix: revert the source change, re-run the test, and confirm it "
        "goes red. A test that stays green without the fix is not covering "
        "the bug.\n"
        "Bypass (not recommended): set AGENT_GUARD_TEST_MODE=warn, or add "
        "paths to test_guard.ignore_paths in %s."
        % state.config_path())
    return False, reason


def mode():
    """'block' or 'warn', env override wins."""
    env = os.environ.get("AGENT_GUARD_TEST_MODE", "").strip().lower()
    if env in ("warn", "block"):
        return env
    cfg = state.load_config()
    m = (cfg["test_guard"].get("mode") or "block").strip().lower()
    return m if m in ("warn", "block") else "block"
