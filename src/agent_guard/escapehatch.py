"""Legit-test-change escape hatch.

The test-tampering guard's most common false positive is a test file that
changed without a source change where the change is perfectly legitimate:
a snapshot update, a flaky-test timing fix, a new fixture, a renamed
helper. Guardrails that can't tell the difference get ripped out; this
module answers the "how does the guard know a test change is legitimate?"
question (Coldboot, dev.to) with two pieces:

1. classify_change(old_text, new_text, rel) -> verdict dict. Every changed
   test file is diffed line-by-line against the snapshot copy and sorted
   into:
     - "legit": only clearly-benign shapes -- new test functions,
       fixtures/helpers, new imports, renames, comment-only edits.
     - "malicious": weakened/removed/inverted assertions, newly skipped
       tests, try/except swallowing a removed assertion, whole-file
       deletion. Anything that makes the suite prove less than before.
     - "ambiguous": everything else -- e.g. an expected value changed at
       the same strictness (could be a snapshot update, could be cheating).
   The classifier is heuristic and fail-safe: when it can't tell, it says
   "ambiguous", and the guard blocks as before.
2. An explicit, audited escape hatch: `agent-guard hook-test
   --allow-test-change "<reason>"` (or AGENT_GUARD_ALLOW_TEST_CHANGE=1).
   When the Stop hook would otherwise block, the hatch lets the session
   stop -- but every use is written to the audit log with the reason, the
   session, the files, and their verdicts. Escape is cheap; escape is
   visible.

Everything fails open: any unexpected error means "ambiguous" (block as
before) for classification, and "no hatch" for the escape request.
"""

import difflib
import os
import re

VERDICTS = ("legit", "ambiguous", "malicious")

ENV_FLAG = "AGENT_GUARD_ALLOW_TEST_CHANGE"
ENV_REASON = "AGENT_GUARD_ALLOW_TEST_CHANGE_REASON"

# ---------------------------------------------------------------------------
# line-level patterns
# ---------------------------------------------------------------------------

_ASSERT_RX = re.compile(r"^\s*assert(?:\s+|\s*\()")
_NEW_TEST_RX = re.compile(r"^\s*(?:async\s+)?def\s+test\w*\s*\(")
_FIXTURE_RX = re.compile(r"^\s*@pytest\.fixture\b")
_HELPER_DEF_RX = re.compile(r"^\s*(?:async\s+)?def\s+[A-Za-z_]\w*\s*\(")
_IMPORT_RX = re.compile(r"^\s*(?:import\s+|from\s+\S+\s+import\b)")
_COMMENT_RX = re.compile(r"^\s*(#|//)")
_TRY_RX = re.compile(r"^\s*try\s*:")
_EXCEPT_RX = re.compile(r"^\s*except\b")
_SKIP_RX = re.compile(
    r"pytest\.mark\.skip|@pytest\.mark\.skip|\.skip\s*\(|xit\s*\(|"
    r"xdescribe\s*\(|#\[ignore\]|@Disabled\b|t\.skip\s*\(")


def _is_assert(line):
    try:
        return bool(_ASSERT_RX.match(line or ""))
    except Exception:
        return False


def _assert_body(line):
    """Text after `assert ` / `assert(...)`. Never raises."""
    try:
        s = (line or "").strip()
        m = re.match(r"^assert\s*\((.*)\)\s*$", s)
        if m:
            return m.group(1).strip()
        m = re.match(r"^assert\s+(.*)$", s)
        if m:
            return m.group(1).strip()
        return ""
    except Exception:
        return ""


def _strictness(body):
    """Proof strength of an assert body: higher = proves more.

    3: exact equality (assert x == 3, assertEqual)
    2: ordered/membership comparison (>=, <=, >, <, in)
    1: bare truthiness (assert x, bool(x), is not None)
    0: tautology (assert True)
    Never raises.
    """
    try:
        b = (body or "").strip()
        if not b:
            return 1
        if re.fullmatch(r"True|1\s*==\s*1|0\s*==\s*0", b):
            return 0
        low = b.lower()
        if re.search(r"\b(bool|assertTrue|assertIsNotNone)\s*\(", b) \
                or re.search(r"\bis\s+not\s+None\b", low) \
                or re.search(r"!=\s*None\b", b) \
                or re.search(r"toBeTruthy|toBeDefined|toBeFalsy", b):
            return 1
        if re.search(r">=|<=|(?<![=!<>])>(?!=)|(?<![=!<>])<(?!=)"
                     r"|\bin\b|toContain|toBeGreaterThan|toBeLessThan", b):
            return 2
        if "==" in b or re.search(r"\bassertEqual\b", b) \
                or "toBe(" in b or "toStrictEqual" in b or "toEqual(" in b:
            return 3
        return 1  # bare `assert x`: truthiness
    except Exception:
        return 1


def _norm(s):
    try:
        return re.sub(r"\s+", " ", s or "").strip()
    except Exception:
        return ""


def _inverted(old_body, new_body):
    """`assert x` -> `assert not x`: semantics flipped. Never raises."""
    try:
        a, b = _norm(old_body), _norm(new_body)
        return a == "not " + b or b == "not " + a
    except Exception:
        return False


def _compare_asserts(old_line, new_line):
    """Classify an old->new assert pair.

    Returns (marker_kind_or_None, excerpt). "ignore" means no meaningful
    change. Never raises.
    """
    try:
        ob, nb = _assert_body(old_line), _assert_body(new_line)
        if _norm(ob) == _norm(nb):
            return None, ""
        if _inverted(ob, nb):
            return ("assertion-inverted",
                    "flipped: %s -> %s" % (ob[:60], nb[:60]))
        so, sn = _strictness(ob), _strictness(nb)
        if sn < so:
            return ("assertion-weakened",
                    "%s -> %s" % (ob[:60], nb[:60]))
        return ("assertion-changed",
                "%s -> %s" % (ob[:60], nb[:60]))
    except Exception:
        return ("assertion-changed", "unparseable assert edit")


_MALICIOUS = {
    "test-file-deleted",
    "assertion-removed",
    "assertion-weakened",
    "assertion-inverted",
    "assertion-swallowed",
    "skipped-test",
    "weakened-assertion",  # from tamper.py's second opinion
}

_LEGIT = {
    "test-added",
    "helper-added",
    "comment-added",
    "comment-removed",
    "renamed",
}


def _handle_removed(line, markers):
    s = line.strip()
    if not s:
        return
    if _is_assert(s):
        markers.append(("assertion-removed", "removed: %s" % s[:100]))
    elif _COMMENT_RX.match(s):
        markers.append(("comment-removed", s[:100]))
    else:
        markers.append(("code-removed", s[:100]))


def _added_block_kind(lines):
    """Classify a whole inserted block (handles new test functions)."""
    first = ""
    for l in lines:
        if l.strip():
            first = l
            break
    if _NEW_TEST_RX.match(first) or _FIXTURE_RX.match(first):
        return "legit"
    return None


def _handle_added(line, markers):
    s = line.strip()
    if not s:
        return
    if _SKIP_RX.search(s):
        markers.append(("skipped-test", "added: %s" % s[:100]))
    elif _COMMENT_RX.match(s):
        markers.append(("comment-added", s[:100]))
    elif _IMPORT_RX.match(s) or _HELPER_DEF_RX.match(s):
        markers.append(("helper-added", "added: %s" % s[:100]))
    elif _TRY_RX.match(s):
        markers.append(("try-added", "added: %s" % s[:100]))
    elif _EXCEPT_RX.match(s):
        markers.append(("except-added", "added: %s" % s[:100]))
    elif _is_assert(s):
        # A bare added assert outside a new test function changes what the
        # suite proves; can't tell legit from cheat -> ambiguous.
        markers.append(("assertion-added", "added: %s" % s[:100]))
    else:
        markers.append(("code-added", "added: %s" % s[:100]))


def _handle_replace(olds, news, markers):
    # Single-line swaps are the classic weakening shape.
    if len(olds) == 1 and len(news) == 1:
        o, n = olds[0].strip(), news[0].strip()
        if _is_assert(o) and _is_assert(n):
            kind, excerpt = _compare_asserts(o, n)
            if kind:
                markers.append((kind, excerpt))
            return
        if _is_assert(o) and not _is_assert(n):
            markers.append(("assertion-removed",
                            "removed: %s" % o[:100]))
            _handle_added(n, markers)
            return
        if _is_assert(n) and not _is_assert(o):
            _handle_removed(o, markers)
            markers.append(("assertion-added", "added: %s" % n[:100]))
            return
        ratio = difflib.SequenceMatcher(None, o, n).ratio()
        if ratio > 0.9:
            markers.append(("renamed",
                            "%s -> %s" % (o[:50], n[:50])))
        else:
            markers.append(("lines-changed",
                            "%s -> %s" % (o[:60], n[:60])))
        return
    for l in olds:
        _handle_removed(l, markers)
    block = _added_block_kind(news)
    if block == "legit":
        markers.append(("test-added",
                        "added: %s" % (news[0].strip()[:100])))
    else:
        for l in news:
            _handle_added(l, markers)


def _classify_inner(old_text, new_text, rel):
    markers = []
    if new_text is None:
        return {"verdict": "malicious",
                "markers": [("test-file-deleted",
                             "deleted: %s" % (rel or "?")[:120])]}
    old_lines = (old_text or "").splitlines()
    new_lines = (new_text or "").splitlines()
    sm = difflib.SequenceMatcher(None, old_lines, new_lines,
                                 autojunk=False)
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        olds, news = old_lines[i1:i2], new_lines[j1:j2]
        if tag == "delete":
            for l in olds:
                _handle_removed(l, markers)
        elif tag == "insert":
            block = _added_block_kind(news)
            if block == "legit":
                markers.append(("test-added",
                                "added: %s"
                                % (news[0].strip()[:100])))
            else:
                for l in news:
                    _handle_added(l, markers)
        else:
            _handle_replace(olds, news, markers)

    # try/except added while an assert disappeared: the classic swallow.
    kinds = {k for k, _ in markers}
    if "assertion-removed" in kinds and \
            ("try-added" in kinds or "except-added" in kinds):
        markers.append(("assertion-swallowed",
                        "assert removed inside new try/except"))

    # Reuse the tamper-shape scanner on the added lines: a second opinion
    # on weakened assertions / skips the line rules missed.
    try:
        from . import tamper as _t
        added = []
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag in ("insert", "replace"):
                added.extend(new_lines[j1:j2])
        _, thits = _t.score_text("\n".join(added), rel)
        for _, _, kind, excerpt in thits:
            if kind in ("weakened-assertion", "skipped-test"):
                markers.append((kind, excerpt[:100]))
    except Exception:
        pass

    kinds = {k for k, _ in markers}
    if kinds & _MALICIOUS:
        verdict = "malicious"
    elif not markers:
        verdict = "legit"  # whitespace-only
    elif all(k in _LEGIT for k, _ in markers):
        verdict = "legit"
    else:
        verdict = "ambiguous"
    return {"verdict": verdict, "markers": markers}


def classify_change(old_text, new_text, rel=""):
    """Classify one test file's change. Never raises.

    Returns {"verdict": "legit"|"ambiguous"|"malicious",
             "markers": [(kind, excerpt)]}.
    """
    try:
        return _classify_inner(old_text, new_text, rel)
    except Exception:
        return {"verdict": "ambiguous",
                "markers": [("unclassifiable", "classifier error")]}


def classify_batch(changes):
    """changes: {rel: (old_text, new_text)}. Never raises."""
    out = {}
    try:
        for rel, pair in (changes or {}).items():
            old, new = pair
            out[rel] = classify_change(old, new, rel)
    except Exception:
        pass
    return out


# ---------------------------------------------------------------------------
# escape hatch request
# ---------------------------------------------------------------------------

def hatch_request(args):
    """Was the escape hatch explicitly requested? Never raises.

    Returns (requested: bool, reason: str). CLI flag --allow-test-change
    wins; env AGENT_GUARD_ALLOW_TEST_CHANGE covers agents that can't pass
    flags (a non-boolean env value is treated as the reason itself).
    """
    try:
        flag = getattr(args, "allow_test_change", None)
        if flag is not None:
            return True, str(flag or "").strip()
        env = os.environ.get(ENV_FLAG, "").strip()
        if not env or env == "0" or env.lower() in ("no", "false", "off"):
            return False, ""
        if env.lower() in ("1", "yes", "true", "on"):
            return True, os.environ.get(ENV_REASON, "").strip()
        return True, env
    except Exception:
        return False, ""
