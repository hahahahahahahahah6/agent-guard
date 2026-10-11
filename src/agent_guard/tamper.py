"""Tamper-pattern scanner: how a test file was changed matters as much as
whether it changed.

The SessionStart/Stop test-tampering guard (testguard.py) catches
"test files changed, no source changed". This module goes one level
deeper and scores the *shape* of test edits:

- weakened-assertion: a strong assertion swapped for a weaker one
  (``toBe(x)`` -> ``toBeTruthy()``, ``assertEqual(a, b)`` ->
  ``assertTrue(a)``). The test still "passes" while proving less.
- skipped-test: newly skipped or focused tests (``.skip(``, ``.only(``,
  ``xit(``, ``pytest.mark.skip``, ``#[ignore]``). A skipped failing test
  is a green suite that proves nothing.
- snapshot-update: snapshot files or ``toMatchSnapshot()`` calls touched
  without review. ``jest -u`` makes red go green by redefining "correct".

Used two ways: a PreToolUse hook on Write/Edit (``hook-tamper``) that
scores only the added text of test files, and enrichment of the Stop
hook's block reason so the agent sees *which* tamper shapes were found.

Everything fails open: any unexpected error means "clean".
"""

import os
import re

WEIGHTS = {
    "weakened-assertion": 3.0,
    "skipped-test": 2.5,
    "snapshot-update": 2.0,
    "snapshot-file": 2.0,
}

PATTERNS = [
    # (kind, compiled regex)
    ("weakened-assertion", re.compile(
        r"\.\s*toBeTruthy\s*\(\s*\)|\.\s*toBeDefined\s*\(\s*\)"
        r"|\.\s*toBeFalsy\s*\(\s*\)")),
    ("weakened-assertion", re.compile(
        r"(?<!\w)assertTrue\s*\(|(?<!\w)assertIsNotNone\s*\(")),
    ("weakened-assertion", re.compile(
        r"(?<!\w)assert\s*\(\s*bool\s*\(")),
    ("skipped-test", re.compile(
        r"\.(skip|only)\s*\(|(?<![\w.])\b(fdescribe|fit|xit|"
        r"xdescribe)\b")),
    ("skipped-test", re.compile(
        r"pytest\.mark\.skip\b|@pytest\.mark\.skip\b|#\[ignore\]"
        r"|@Disabled\b|(?<![\w.])t\.skip\s*\(|\.Skip\s*\(")),
    ("snapshot-update", re.compile(
        r"toMatchSnapshot\s*\(|toMatchInlineSnapshot\s*\(|"
        r"assertSnapshot\s*\(|assert_snapshot\s*\(|--update-snapshot"
        r"|\binsta::assert")),
]

SNAPSHOT_PATH_RES = [
    re.compile(r"(^|/|\\)__snapshots__([/\\]|$)"),
    re.compile(r"\.snap$"),
    re.compile(r"(^|/|\\)snapshots?([/\\]|$).*\.snap$"),
]

MAX_SCAN_BYTES = 2 * 1024 * 1024


def is_snapshot_path(path):
    """Does this path look like a snapshot artifact? Never raises."""
    try:
        p = str(path or "").replace("\\", "/")
        return any(rx.search(p) for rx in SNAPSHOT_PATH_RES)
    except Exception:
        return False


def _hit_lines(kind, excerpt):
    return kind, excerpt


def score_text(text, path):
    """Score added/changed test text for tamper patterns.

    Returns (score: float, hits: [(lineno, end_lineno, kind, excerpt)]).
    Never raises.
    """
    hits = []
    try:
        if not isinstance(text, str) or not text.strip():
            return 0.0, hits
        if is_snapshot_path(path):
            hits.append((1, 1, "snapshot-file",
                         "snapshot artifact: %s" % str(path)[:80]))
        for i, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "//")):
                continue
            for kind, rx in PATTERNS:
                m = rx.search(line)
                if m:
                    excerpt = stripped[:100]
                    hits.append((i, i, kind, excerpt))
                    break  # one hit per line is enough
        score = min(100.0, 10.0 * sum(WEIGHTS.get(k, 1.0)
                                      for _, _, k, _ in hits))
        return round(score, 1), hits
    except Exception:
        return 0.0, []


def scan_file(path):
    """Scan a file on disk. Returns (score, hits). Never raises."""
    try:
        size = os.path.getsize(path)
        if size > MAX_SCAN_BYTES:
            return 0.0, []
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        return score_text(text, path)
    except Exception:
        return 0.0, []


def scan_path(root):
    """Yield (path, score, hits) for test-ish files under root. Never raises."""
    try:
        from . import testguard
    except Exception:
        return
    try:
        paths = []
        if os.path.isfile(root):
            paths = [root]
        else:
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = [d for d in dirnames
                               if d not in testguard.SKIP_DIRS]
                for fn in filenames:
                    full = os.path.join(dirpath, fn)
                    rel = os.path.relpath(full, root)
                    if testguard.is_test_file(rel) or is_snapshot_path(rel):
                        paths.append(full)
        for path in sorted(paths):
            score, hits = scan_file(path)
            yield path, score, hits
    except Exception:
        return


def threshold(cfg=None):
    """Cheat score (0-100) that trips the hook. Never raises."""
    try:
        env = os.environ.get("AGENT_GUARD_TAMPER_THRESHOLD", "").strip()
        if env:
            return max(0.0, min(100.0, float(env)))
        if cfg is None:
            from . import state
            cfg = state.load_config()
        t = cfg.get("tamper", {}).get("threshold", 30)
        return max(0.0, min(100.0, float(t)))
    except Exception:
        return 30.0


def mode(cfg=None):
    """'block' or 'warn', env override wins. Never raises."""
    try:
        env = os.environ.get("AGENT_GUARD_TAMPER_MODE", "").strip().lower()
        if env in ("warn", "block"):
            return env
        if cfg is None:
            from . import state
            cfg = state.load_config()
        m = (cfg.get("tamper", {}).get("mode") or "block").strip().lower()
        return m if m in ("warn", "block") else "block"
    except Exception:
        return "block"
