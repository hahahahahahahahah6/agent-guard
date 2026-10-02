"""Cheat-sniffing: catch test cheating that never touches test files.

Failure mode (remdore, dev.to 2026-10-01, 102 runs x 4 models): HALF of
agent cheating never modifies a test file. Instead the agent patches the
RNG ("it patched the random number generator so the list would always be
sorted"), mocks the function under test instead of its collaborators, or
plants helpers in conftest.py. agent-guard's test-guard (tests-only-change
diff) and mutate-check (assertion mutation) both miss this family entirely
-- "restore the test files and re-run" only catches the dumb half.

This module scans Python test support files statically (regex/AST-lite,
stdlib-only) for the cheat family:

- conftest.py / helpers that monkeypatch or stub the module under test
- RNG seeded or patched to force deterministic outcomes
- mocks that replace the *subject* instead of its collaborators
- time frozen or patched to skip timeouts/retries
- comparison helpers weakened (e.g. __eq__ that always returns True)

Scoring mirrors commentslop: weighted hits per file, capped at 100, with
a threshold that blocks (or warns). When in doubt, DON'T flag -- a
reproducibility seed (`random.seed(42)` with a marker) is legitimate, and
this module says so loudly. Everything fails open: any unexpected error
means score 0, no hits.
"""

import os
import re

# (kind, weight) -- replacing the subject or rigging randomness is the
# unambiguous cheat; fixed seeds and time-freezing are judgment calls.
WEIGHTS = {
    "mock-subject": 3.0,
    "rng-patch": 3.0,
    "conftest-patch": 3.0,
    "rng-seed": 1.5,
    "time-freeze": 1.5,
    "weak-comparator": 1.5,
}

DEFAULT_THRESHOLD = 30.0
MAX_SCAN_BYTES = 1024 * 1024

# Kinds where a single hit is severe enough to matter on its own.
SEVERE = {"mock-subject", "rng-patch", "conftest-patch"}

# A fixed RNG seed is legitimate when the file says it's for
# reproducibility. Presence of any of these markers anywhere in the file
# downgrades rng-seed hits to non-blocking notes.
REPRO_MARKERS = re.compile(
    r"reproducib|deterministic|flake|stable test|fixed seed",
    re.IGNORECASE)

# ---------------------------------------------------------------------------
# subject-module inference
# ---------------------------------------------------------------------------

def subject_module(path):
    """Best-guess module under test for a test file. Never raises.

    tests/test_billing.py -> 'billing'; tests/billing_test.py -> 'billing';
    conftest.py -> None (no single subject).
    """
    try:
        base = os.path.basename(str(path or ""))
        if base == "conftest.py":
            return None
        name = base[:-3] if base.endswith(".py") else base
        if name.startswith("test_"):
            name = name[5:]
        elif name.endswith("_test"):
            name = name[:-5]
        return name or None
    except Exception:
        return None


def _is_conftest(path):
    try:
        return os.path.basename(str(path or "")) == "conftest.py"
    except Exception:
        return False


# ---------------------------------------------------------------------------
# detectors
# ---------------------------------------------------------------------------

# mock.patch("billing.calculate_total") / patch.object(billing, "total")
_PATCH_CALL_RX = re.compile(
    r"""(?:mock\s*\.\s*|unittest\.mock\s*\.\s*)?patch(?:\.object|\.dict)?\s*\(\s*"""
    r"""(?P<q>['"])(?P<target>[^'"]+)(?P=q)""")

# monkeypatch.setattr("billing.calculate_total", fake)
_MONKEYPATCH_RX = re.compile(
    r"""monkeypatch\s*\.\s*setattr\s*\(\s*(?P<q>['"])(?P<target>[^'"]+)(?P=q)""")

# random.seed(123) / np.random.seed(123) / random.seed(0xDEADBEEF)
_SEED_RX = re.compile(
    r"""(?:^|[^\w.])(?:random|np\.random|numpy\.random)\s*\.\s*seed\s*\(\s*"""
    r"""(?P<arg>[^)]*?)\)""")

# random.shuffle / random.random / random.sample / random.choice patched
_RNG_PATCH_RX = re.compile(
    r"""(?:mock\s*\.\s*|unittest\.mock\s*\.\s*)?patch(?:\.object)?\s*\(\s*"""
    r"""(?P<q>['"])(?P<target>(?:random|np\.random|numpy\.random)\s*\.\s*"""
    r"""(?:shuffle|random|sample|choice|randint|randrange|uniform))[^'"]*"""
    r"""(?P=q)"""
    r"""|monkeypatch\s*\.\s*setattr\s*\(\s*(?P<q2>['"])"""
    r"""(?P<target2>(?:random|np\.random|numpy\.random)\s*\.\s*"""
    r"""(?:shuffle|random|sample|choice|randint|randrange|uniform))[^'"]*"""
    r"""(?P=q2)""")

# freezegun / time.sleep patched to no-op / time.time frozen
_TIME_RX = re.compile(
    r"""freeze_time\s*\(|@freeze_time\b|"""
    r"""patch\s*\(\s*['"]time\.sleep['"]|"""
    r"""monkeypatch\s*\.\s*setattr\s*\(\s*['"]time\.sleep['"]|"""
    r"""patch\s*\(\s*['"]time\.time['"]|"""
    r"""monkeypatch\s*\.\s*setattr\s*\(\s*['"]time\.time['"]""")

# direct attribute assignment by hand: mymod.shuffle = lambda xs: sorted(xs)
# (monkeypatching without the monkeypatch API)
_DIRECT_ASSIGN_RX = re.compile(
    r"""^\s*(?P<mod>[A-Za-z_]\w*)\s*\.\s*(?P<attr>[A-Za-z_]\w*)\s*=""")

# import mymod / from mymod import thing  (to know which names are modules)
_IMPORT_RX = re.compile(
    r"""^\s*(?:import\s+(?P<mod>[A-Za-z_]\w*)|from\s+(?P<fmod>[A-Za-z_]\w*)\s+import\b)""")

# modules whose direct-attribute assignment is normal test setup, not cheating
_INNOCENT_MODS = ("os", "sys", "time", "datetime", "random",
                  "requests", "socket")

# __eq__ / __lt__ / __gt__ overridden with a constant-True body
_CMP_DEF_RX = re.compile(
    r"""def\s+__(?:eq|lt|le|gt|ge|ne)__\s*\(\s*self""")

_CONST_TRUE_RX = re.compile(r"^\s*return\s+True\s*(?:#.*)?$")


def _line_iter(text):
    return list(enumerate(text.split("\n"), 1))


def _subject_of_target(target, subject):
    """Does a patch target string address the subject module itself?"""
    if not subject:
        return False
    t = target.strip()
    first = re.split(r"[.\s(]", t, 1)[0]
    return first == subject


def _find_hits(text, path):
    """Return [(line_no, end_line, kind, excerpt)]. Never raises."""
    hits = []
    try:
        return _find_hits_inner(text, path)
    except Exception:
        return hits


def _find_hits_inner(text, path):
    hits = []
    lines = _line_iter(text)
    subj = subject_module(path)
    is_conf = _is_conftest(path)

    # modules imported in this file: direct assignment onto one of them
    # (mymod.shuffle = ...) is hand-rolled monkeypatching.
    imported = set()
    for _, l in lines:
        m = _IMPORT_RX.match(l)
        if m:
            imported.add(m.group("mod") or m.group("fmod"))

    for ln, line in lines:
        # --- mock.patch("subject.func") : mocking the subject itself
        m = _PATCH_CALL_RX.search(line)
        if m:
            target = m.group("target")
            if _RNG_PATCH_RX.search(line):
                hits.append((ln, ln, "rng-patch",
                             "patches RNG primitive: %s" % target[:80]))
            elif _subject_of_target(target, subj):
                hits.append((ln, ln, "mock-subject",
                             "mocks the subject under test: %s"
                             % target[:80]))
        # --- monkeypatch.setattr("subject.func", ...)
        m = _MONKEYPATCH_RX.search(line)
        if m:
            target = m.group("target")
            if _RNG_PATCH_RX.search(line):
                hits.append((ln, ln, "rng-patch",
                             "monkeypatches RNG primitive: %s"
                             % target[:80]))
            elif _subject_of_target(target, subj):
                kind = "conftest-patch" if is_conf else "mock-subject"
                hits.append((ln, ln, kind,
                             "monkeypatches the subject under test: %s"
                             % target[:80]))
            elif is_conf:
                # conftest.py monkeypatching anything local-ish is
                # suspicious; only flag when the target is clearly not a
                # third-party integration point.
                first = re.split(r"[.\s(]", target.strip(), 1)[0]
                if first and first not in _INNOCENT_MODS:
                    hits.append((ln, ln, "conftest-patch",
                                 "conftest monkeypatches %s" % target[:80]))
        # --- direct assignment onto an imported module: mymod.shuffle = ...
        m = _DIRECT_ASSIGN_RX.match(line)
        if m:
            mod = m.group("mod")
            if mod in imported and mod not in _INNOCENT_MODS:
                kind = "conftest-patch" if is_conf else "mock-subject"
                hits.append((ln, ln, kind,
                             "overwrites %s.%s by direct assignment"
                             % (mod, m.group("attr")[:60])))
        # --- time freezing / sleep no-op
        if _TIME_RX.search(line):
            hits.append((ln, ln, "time-freeze",
                         line.strip()[:80]))

    # --- fixed RNG seed: whole-file pass (reproducibility markers exempt)
    repro = bool(REPRO_MARKERS.search(text))
    for ln, line in lines:
        m = _SEED_RX.search(line)
        if m:
            arg = m.group("arg").strip()
            # random.seed() / random.seed(None) is not a fixed seed
            if arg in ("", "None"):
                continue
            if repro:
                continue  # legitimate reproducibility seed
            hits.append((ln, ln, "rng-seed",
                         "fixed RNG seed (%s) without reproducibility "
                         "marker" % arg[:40]))

    # --- weak comparators: __eq__/__lt__/etc. whose body returns True
    for ln, line in lines:
        if _CMP_DEF_RX.search(line):
            body_true = False
            for j in range(ln, min(ln + 6, len(lines))):
                bln, bline = lines[j]
                s = bline.strip()
                if not s or s.startswith("#"):
                    continue
                if _CONST_TRUE_RX.match(bline):
                    body_true = True
                    break
                if s.startswith("return") or s.startswith("def "):
                    break
            if body_true:
                hits.append((ln, ln, "weak-comparator",
                             "comparison dunder unconditionally returns "
                             "True"))

    # de-duplicate identical (line, kind) pairs, keep order
    seen = set()
    uniq = []
    for h in hits:
        key = (h[0], h[2])
        if key not in seen:
            seen.add(key)
            uniq.append(h)
    return sorted(uniq, key=lambda h: h[0])


# ---------------------------------------------------------------------------
# scoring
# ---------------------------------------------------------------------------

def score_text(text, path=None):
    """Return (score 0-100, hits).

    score = min(100, 10 * sum(weights)): one severe hit (3.0) reaches the
    default threshold of 30 on its own. Never raises.
    """
    try:
        return _score_text_inner(text or "", path)
    except Exception:
        return 0.0, []


def _score_text_inner(text, path):
    hits = _find_hits(text, path)
    weighted = sum(WEIGHTS.get(kind, 1.0) for _, _, kind, _ in hits)
    score = min(100.0, 10.0 * weighted)
    return round(score, 1), hits


def score_file(path):
    """Score a file on disk. Returns (score, hits). Never raises."""
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
    """Yield (path, score, hits) for .py files under root. Never raises."""
    try:
        return list(_scan_path_inner(root))
    except Exception:
        return []


def _scan_path_inner(root):
    out = []
    if os.path.isfile(root):
        files = [root]
    else:
        files = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames
                           if d not in (".git", "__pycache__", ".venv",
                                        "venv", "node_modules", ".tox")]
            for fn in filenames:
                if fn.endswith(".py"):
                    files.append(os.path.join(dirpath, fn))
    for path in sorted(files):
        score, hits = score_file(path)
        out.append((path, score, hits))
    return out


# ---------------------------------------------------------------------------
# config / mode helpers (mirror commentslop)
# ---------------------------------------------------------------------------

def threshold(config=None):
    """Cheat score threshold. Env AGENT_GUARD_CHEAT_THRESHOLD wins."""
    try:
        env = os.environ.get("AGENT_GUARD_CHEAT_THRESHOLD", "").strip()
        if env:
            return max(0.0, min(100.0, float(env)))
    except Exception:
        pass
    try:
        cfg = config if isinstance(config, dict) else None
        if cfg is None:
            from . import state
            cfg = state.load_config()
        t = (cfg.get("cheat_sniff", {}) or {}).get("threshold", 30)
        return max(0.0, min(100.0, float(t)))
    except Exception:
        return DEFAULT_THRESHOLD


def mode(config=None):
    """'block' or 'warn'. Env AGENT_GUARD_CHEAT_MODE wins."""
    try:
        env = os.environ.get("AGENT_GUARD_CHEAT_MODE", "").strip().lower()
        if env in ("warn", "block"):
            return env
    except Exception:
        pass
    try:
        cfg = config if isinstance(config, dict) else None
        if cfg is None:
            from . import state
            cfg = state.load_config()
        m = ((cfg.get("cheat_sniff", {}) or {}).get("mode")
             or "block").strip().lower()
        return m if m in ("warn", "block") else "block"
    except Exception:
        return "block"


def allowed(config, path, kind):
    """Is this (file, kind) allowlisted? Never raises.

    Config: {"cheat_sniff": {"allow": ["conftest.py:rng-seed", "*/x.py:*"]}}
    Entries are `basename-or-subpath:kind` (kind may be `*`).
    """
    try:
        entries = ((config or {}).get("cheat_sniff", {}) or {}).get(
            "allow", []) or []
        base = os.path.basename(str(path or ""))
        rel = str(path or "")
        for e in entries:
            if not isinstance(e, str) or ":" not in e:
                continue
            pat, k = e.rsplit(":", 1)
            if k != "*" and k != kind:
                continue
            if pat == "*" or base == pat or rel.endswith(pat):
                return True
        return False
    except Exception:
        return False


def filter_allowed(hits, config, path):
    """Drop allowlisted hits. Never raises."""
    try:
        return [h for h in hits
                if not allowed(config, path, h[2])]
    except Exception:
        return hits
