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

import base64
import os
import re
import time
import json
import zlib

from . import escapehatch, state

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv",
             ".tox", "dist", "build", ".idea", ".vscode", "target"}

# Test files are small; keep a compressed copy in the snapshot so the Stop
# hook can diff *what* changed (for legit-vs-tamper classification).
MAX_STORED_BYTES = 256 * 1024

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


def _stored_content(full):
    """zlib+base64 of a test file, or None. Never raises."""
    try:
        if os.path.getsize(full) > MAX_STORED_BYTES:
            return None
        with open(full, "rb") as fh:
            data = fh.read()
        return base64.b64encode(zlib.compress(data, 6)).decode("ascii")
    except Exception:
        return None


def _decode_content(blob):
    """Inverse of _stored_content. None on any problem. Never raises."""
    try:
        if not blob:
            return None
        return zlib.decompress(base64.b64decode(blob)).decode(
            "utf-8", errors="replace")
    except Exception:
        return None


def _read_current(root, rel):
    """Current text of a project file, None if deleted. Never raises."""
    try:
        full = os.path.join(root, rel)
        if not os.path.isfile(full):
            return None
        if os.path.getsize(full) > MAX_STORED_BYTES:
            return ""
        with open(full, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except Exception:
        return ""


def snapshot(root, session_id=None):
    """Record digests of test + source files. Never raises.

    Snapshots are stored per session_id so two concurrent sessions or
    projects never overwrite each other. Compressed copies of test files
    are kept so the Stop hook can classify *what* changed (v0.7).
    """
    try:
        cfg = state.load_config()
        ignore = cfg["test_guard"].get("ignore_paths", []) or []
        tests, sources, contents = {}, {}, {}
        for rel, full in _walk(root, ignore):
            d = state.digest_of(full)
            if d is None:
                continue
            if is_test_file(rel):
                tests[rel] = d
                blob = _stored_content(full)
                if blob is not None:
                    contents[rel] = blob
            else:
                sources[rel] = d
        os.makedirs(state.state_dir(), exist_ok=True)
        with open(state.snapshot_path(session_id), "w", encoding="utf-8") as fh:
            json.dump({"root": os.path.abspath(root), "ts": time.time(),
                       "tests": tests, "sources": sources,
                       "test_contents": contents}, fh)
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


def _diff(root, session_id):
    """(changed_tests, changed_sources, snapshot_ok). Never raises."""
    try:
        cfg = state.load_config()
        ignore = cfg["test_guard"].get("ignore_paths", []) or []
        try:
            with open(state.snapshot_path(session_id), "r",
                      encoding="utf-8") as fh:
                snap = json.load(fh)
        except Exception:
            return [], [], False
        if not isinstance(snap, dict) or \
                snap.get("root") != os.path.abspath(root):
            return [], [], False

        old_tests = snap.get("tests", {}) or {}
        old_sources = snap.get("sources", {}) or {}

        current = {}
        for rel, full in _walk(root, ignore):
            d = state.digest_of(full)
            if d is not None:
                current[rel] = d

        changed_tests = sorted(
            rel for rel, d in old_tests.items()
            if rel not in current or current[rel] != d)
        changed_sources = sorted(
            rel for rel, d in old_sources.items()
            if rel not in current or current[rel] != d)
        # New source files also count as "source changed" (new feature +
        # tests).
        for rel in current:
            if rel not in old_tests and rel not in old_sources \
                    and is_source_file(rel):
                changed_sources.append(rel)
        return changed_tests, changed_sources, True
    except Exception:
        return [], [], False


def changed_test_files(root, session_id=None):
    """Test files changed since the snapshot. Never raises."""
    try:
        changed, _, ok = _diff(root, session_id)
        return changed if ok else []
    except Exception:
        return []


def _load_snapshot(root, session_id):
    """Parsed snapshot dict, or None. Never raises."""
    try:
        with open(state.snapshot_path(session_id), "r",
                  encoding="utf-8") as fh:
            snap = json.load(fh)
        if not isinstance(snap, dict) or \
                snap.get("root") != os.path.abspath(root):
            return None
        return snap
    except Exception:
        return None


def check_detail(root, session_id=None):
    """Full Stop-hook decision with per-file classification. Never raises.

    Returns {"allowed": bool, "reason": str, "verdicts": {rel: {...}},
             "changed_tests": [...], "changed_sources": [...],
             "snapshot_ok": bool, "legit": bool}.
    """
    try:
        return _check_detail_inner(root, session_id)
    except Exception:
        return {"allowed": True, "reason": "", "verdicts": {},
                "changed_tests": [], "changed_sources": [],
                "snapshot_ok": False, "legit": False}


def _check_detail_inner(root, session_id):
    changed_tests, changed_sources, ok = _diff(root, session_id)
    base = {"changed_tests": changed_tests,
            "changed_sources": changed_sources,
            "snapshot_ok": ok, "verdicts": {}, "legit": False}
    if not ok:
        return dict(base, allowed=True, reason="")  # fail open
    if not changed_tests:
        return dict(base, allowed=True, reason="")
    if changed_sources:
        return dict(base, allowed=True, reason="")  # normal development

    # Tests changed, sources untouched: classify each file's diff.
    snap = _load_snapshot(root, session_id) or {}
    contents = snap.get("test_contents", {}) or {}
    verdicts = {}
    for rel in changed_tests:
        old = _decode_content(contents.get(rel))
        new = _read_current(root, rel)
        if old is None and new is not None:
            # Snapshot predates content storage (or the file was too big):
            # can't classify -> ambiguous (block as before).
            verdicts[rel] = {"verdict": "ambiguous",
                             "markers": [("no-baseline",
                                          "no snapshot copy to diff")] }
        else:
            verdicts[rel] = escapehatch.classify_change(old, new, rel)
    base["verdicts"] = verdicts

    if verdicts and all(v["verdict"] == "legit"
                        for v in verdicts.values()):
        # All changes are clearly benign (new tests, fixtures, helpers,
        # renames): let the session stop, but audit it.
        base["legit"] = True
        return dict(base, allowed=True, reason="")

    lines = []
    for rel in changed_tests:
        v = verdicts[rel]
        lines.append("  - %s [%s]" % (rel, v["verdict"]))
        for kind, excerpt in v["markers"][:6]:
            lines.append("      [%s] %s" % (kind, excerpt[:100]))
    reason = (
        "Test-tampering guard: test files changed but no source files "
        "changed since this session started.\n"
        "Changed test files (with change classification):\n" +
        "\n".join(lines) + "\n"
        "This matches a known failure mode where an agent edits test "
        "assertions to make them pass instead of fixing the source code. "
        "Before proceeding, verify each changed test actually fails without "
        "the fix: revert the source change, re-run the test, and confirm it "
        "goes red. A test that stays green without the fix is not covering "
        "the bug.\n"
        "If a change above is legitimate (snapshot update, flaky-test fix, "
        "new fixture), use the explicit, audited escape hatch:\n"
        "  agent-guard hook-test --allow-test-change \"<reason>\"\n"
        "  or: AGENT_GUARD_ALLOW_TEST_CHANGE=1 "
        "(reason via AGENT_GUARD_ALLOW_TEST_CHANGE_REASON)\n"
        "Every hatch use is written to the audit log (`agent-guard log`).\n"
        "Bypass (not recommended): set AGENT_GUARD_TEST_MODE=warn, or add "
        "paths to test_guard.ignore_paths in %s."
        % state.config_path())
    return dict(base, allowed=False, reason=reason)


def _check_inner(root, session_id):
    detail = check_detail(root, session_id)
    return detail["allowed"], detail["reason"]


def mode():
    """'block' or 'warn', env override wins."""
    env = os.environ.get("AGENT_GUARD_TEST_MODE", "").strip().lower()
    if env in ("warn", "block"):
        return env
    cfg = state.load_config()
    m = (cfg["test_guard"].get("mode") or "block").strip().lower()
    return m if m in ("warn", "block") else "block"
