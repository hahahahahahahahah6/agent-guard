"""Comment-slop guard.

Failure mode: the agent dumps conversation state into code comments —
narrative restatements of obvious code ("This function adds two numbers"),
changelogs narrating the diff, commented-out code, meta/apologetic notes,
emoji. sfjailbird's complaint: "9 out of 10 of my revisions to Claude's work
is deleting or rewriting comments".

This module scores comment slop in source text. Pattern matching is
regex-based and deliberately conservative: when in doubt, DON'T flag. The
CLI (`decomment --check/--fix`) and the PreToolUse hook (`hook-commentslop`)
build on top of `score_text` / `score_file`.

Everything fails open: any unexpected error means score 0, no hits.
"""

import os
import re

# (kind, weight) — commented-code is weighted highest: dead code in
# comments is unambiguous slop, prose patterns are judgment calls.
WEIGHTS = {
    "commented-code": 3.0,
    "restatement": 1.5,
    "changelog": 1.0,
    "meta-apology": 1.0,
    "emoji": 0.5,
    "obvious-doc": 1.5,
}

DEFAULT_THRESHOLD = 30.0
MAX_SCORE_BYTES = 1024 * 1024

# Tool directives are not slop — never flag these.
_DIRECTIVE_RES = [
    r"noqa",
    r"type:\s*ignore",
    r"pylint:\s*disable",
    r"eslint-disable",
    r"@ts-ignore",
    r"@ts-nocheck",
    r"\bnosec\b",
    r"#\s*pragma",
    r"istanbul\s+ignore",
    r"spell-checker:\s*disable",
    r"cspell:",
]
_DIRECTIVE_RX = [re.compile(p, re.IGNORECASE) for p in _DIRECTIVE_RES]


def _is_directive(text):
    return any(rx.search(text) for rx in _DIRECTIVE_RX)


# ---------------------------------------------------------------------------
# comment extraction (language-aware)
# ---------------------------------------------------------------------------

def lang_of(path):
    """'py' | 'js' | 'c' | 'hash'. Never raises."""
    try:
        ext = os.path.splitext(str(path or ""))[1].lower()
    except Exception:
        return "c"
    if ext == ".py":
        return "py"
    if ext in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
        return "js"
    if ext in (".sh", ".bash", ".zsh", ".rb", ".pl", ".r", ".yaml", ".yml",
               ".toml", ".ini", ".cfg"):
        return "hash"
    return "c"  # // + /* */ family (go, rust, java, c/c++, c#, ...)


def _line_comment_start(line, marker):
    """Index where a line comment starts, or None. Quote-aware."""
    q = None
    m = len(marker)
    i = 0
    n = len(line)
    while i < n:
        c = line[i]
        if q:
            if c == "\\":
                i += 2
                continue
            if c == q:
                q = None
        else:
            if c in "\"'`":
                q = c
            elif line.startswith(marker, i):
                return i
        i += 1
    return None


def _c_comments(text):
    """Yield (start_line, end_line, kind, content) for // and /* */."""
    out = []
    i, n = 0, len(text)
    line = 1
    q = None
    while i < n:
        c = text[i]
        if c == "\n":
            line += 1
            i += 1
            continue
        if q:
            if c == "\\":
                i += 2
                continue
            if c == q:
                q = None
            i += 1
            continue
        if c in "\"'`":
            q = c
            i += 1
            continue
        if c == "/" and i + 1 < n:
            d = text[i + 1]
            if d == "/":
                j = text.find("\n", i)
                if j == -1:
                    j = n
                out.append((line, line, "line", text[i + 2:j]))
                i = j
                continue
            if d == "*":
                k = text.find("*/", i + 2)
                if k == -1:
                    seg, j = text[i:], n
                else:
                    seg, j = text[i:k + 2], k + 2
                inner = seg[2:-2] if seg.endswith("*/") else seg[2:]
                end_line = line + seg.count("\n")
                out.append((line, end_line, "block", inner))
                line = end_line
                i = j
                continue
        i += 1
    return out


def _hash_comments(text):
    """Yield (line, line, 'line', content) for # comments."""
    out = []
    for ln, raw in enumerate(text.split("\n"), 1):
        if ln == 1 and raw.startswith("#!"):
            continue  # shebang is not a comment worth scoring
        idx = _line_comment_start(raw, "#")
        if idx is not None:
            out.append((ln, ln, "line", raw[idx + 1:]))
    return out


def _py_docstrings(text):
    """Yield (start, end, 'docstring', content) for line-leading docstrings."""
    out = []
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        s = lines[i].lstrip()
        if s.startswith('"""') or s.startswith("'''"):
            qm = s[:3]
            rest = s[3:]
            start = i + 1
            if qm in rest:
                out.append((start, start, "docstring",
                            rest[:rest.index(qm)]))
            else:
                buf = [rest]
                j = i + 1
                while j < len(lines) and qm not in lines[j]:
                    buf.append(lines[j])
                    j += 1
                if j < len(lines):
                    seg = lines[j]
                    buf.append(seg[:seg.index(qm)])
                    end = j + 1
                else:
                    end = len(lines)  # unterminated: take to EOF
                out.append((start, end, "docstring", "\n".join(buf)))
                i = j
        i += 1
    return out


def extract_comments(text, lang=None):
    """Return [(start_line, end_line, kind, content)].

    kind is 'line', 'block', or 'docstring'. Never raises.
    """
    try:
        lang = lang or "c"
        if lang == "py":
            return sorted(_hash_comments(text) + _py_docstrings(text))
        if lang == "hash":
            return sorted(_hash_comments(text))
        return sorted(_c_comments(text))
    except Exception:
        return []


# ---------------------------------------------------------------------------
# slop patterns
# ---------------------------------------------------------------------------

_RESTATEMENT_RES = [
    r"\bthis (function|method|class|module|script|file|code)\b",
    r"^\s*here we\b",
    r"\bthe following (lines?|code|function|steps?|changes?)\b",
    r"\bthis code (does|is|will|should)\b",
]
_CHANGELOG_RX = re.compile(
    r"^\s*(changed|updated|fixed|added|removed|modified|deleted)\b.{8,}$",
    re.IGNORECASE)
_META_RES = [
    r"\bHACK\b",
    r"\bsorry\b",
    r"!{2,}",
    r"(?i)\bworkaround\b",
    r"(?i)\bfix this later\b",
]
_EMOJI_RX = re.compile(
    "[\U0001F000-\U0001FAFF\u2600-\u27BF\u2B00-\u2BFF]")

_CODE_KEYWORDS_RX = re.compile(
    r"^\s*(import|from|return|def |class |function |const |let |var |"
    r"if |elif |else|for |while |switch|case |break|continue|try:|"
    r"except|raise |new |await |async |export |require\()", re.IGNORECASE)
_ASSIGN_CODE_RX = re.compile(r"^[\w.']+\s*=\s*.+")
_CODE_CHARS_RX = re.compile(r"[(){}\[\];]|=>|->|\breturn\b")


def _looks_like_code(text):
    """Does a comment's content look like commented-out code?"""
    t = text.strip()
    if len(t) < 2:
        return False
    if _is_directive(t):
        return False
    if t.endswith(";"):
        return True
    if _CODE_KEYWORDS_RX.match(t):
        return True
    if _ASSIGN_CODE_RX.match(t) and _CODE_CHARS_RX.search(t):
        return True
    if re.match(r"^[\w.]+\s*\([^;]*\)\s*;?\s*$", t) and "(" in t:
        return True
    return False


def _comment_lines(comments):
    """Flatten comments to [(line_no, content)] per content line."""
    out = []
    for start, end, kind, content in comments:
        parts = content.split("\n")
        for off, part in enumerate(parts):
            ln = start + off
            # strip leading '*' from block-comment continuation lines
            p = re.sub(r"^\s*\*\s?", "", part) if kind == "block" else part
            out.append((ln, p))
    return out


def _find_hits(text, lang):
    """Return [(line_no, end_line, kind, excerpt)]. Never raises."""
    hits = []
    try:
        return _find_hits_inner(text, lang)
    except Exception:
        return hits


def _find_hits_inner(text, lang):
    hits = []
    comments = extract_comments(text, lang)
    lines = _comment_lines(comments)

    # --- commented-code: runs of 2+ consecutive code-looking comment lines
    # (empty comment lines are transparent: they don't break a run)
    empty = {ln for ln, c in lines if not c.strip()}
    run = []
    prev_ln = None
    for ln, content in lines + [(None, "")]:
        if ln is not None and not content.strip():
            continue  # transparent: neither breaks runs nor counts
        code_like = ln is not None and _looks_like_code(content)
        continues = (ln is not None
                     and (prev_ln is None or ln == prev_ln + 1
                          or all(l in empty
                                 for l in range(prev_ln + 1, ln))))
        if code_like and continues:
            run.append((ln, content.strip()))
        else:
            if len(run) >= 2:
                excerpt = " / ".join(c for _, c in run[:3])
                hits.append((run[0][0], run[-1][0], "commented-code",
                             excerpt[:120]))
            run = []
            if code_like:
                run.append((ln, content.strip()))
        if ln is not None and content.strip():
            prev_ln = ln

    # --- per-line prose patterns
    restatement_rxs = [re.compile(p, re.IGNORECASE)
                       for p in _RESTATEMENT_RES]
    meta_rxs = [re.compile(p) for p in _META_RES]
    for ln, content in lines:
        t = content.strip()
        if not t or _is_directive(t) or _looks_like_code(t):
            continue
        if any(rx.search(t) for rx in restatement_rxs):
            hits.append((ln, ln, "restatement", t[:120]))
        elif _CHANGELOG_RX.match(t):
            hits.append((ln, ln, "changelog", t[:120]))
        elif any(rx.search(t) for rx in meta_rxs):
            hits.append((ln, ln, "meta-apology", t[:120]))
        if _EMOJI_RX.search(t):
            hits.append((ln, ln, "emoji", t[:120]))

    # --- obvious-doc: docstring/block restating the next signature line
    hits.extend(_obvious_doc_hits(text, comments))
    # de-duplicate identical (line, kind) pairs, keep order
    seen = set()
    uniq = []
    for h in hits:
        key = (h[0], h[2])
        if key not in seen:
            seen.add(key)
            uniq.append(h)
    return sorted(uniq, key=lambda h: h[0])


_SIG_RX = re.compile(
    r"^\s*(def|function|class)\s+([A-Za-z_][\w]*)|"
    r"^\s*(?:const|let|var)\s+([A-Za-z_][\w]*)\s*=")
_STOPWORDS = {
    "a", "an", "the", "and", "or", "to", "of", "in", "for", "with", "on",
    "is", "are", "be", "by", "as", "it", "its", "this", "that", "from",
    "returns", "return", "function", "method", "class", "def", "takes",
    "given", "does", "do", "will", "into", "s",
}


def _stem(w):
    """Light verb stemming: adds->add, computes->compute. Never raises."""
    try:
        if len(w) > 3 and re.match(r".*[dtpknmr]s$", w) \
                and not w.endswith(("ss", "us", "is")):
            return w[:-1]
        return w
    except Exception:
        return w


def _obvious_doc_hits(text, comments):
    """Flag docstrings whose words are mostly covered by the next signature.

    Conservative: needs >= 2 meaningful doc words and >70% of them present
    as identifier words in the next code line (lightly stemmed).
    """
    hits = []
    src_lines = text.split("\n")
    for start, end, kind, content in comments:
        if kind not in ("docstring", "block"):
            continue
        # next non-empty source line after the comment
        j = end
        sig = ""
        while j < len(src_lines):
            s = src_lines[j].strip()
            j += 1
            if s:
                sig = s
                break
        if not _SIG_RX.match(sig):
            continue
        sig_words = {_stem(w.lower()) for w in
                     re.findall(r"[A-Za-z_][A-Za-z0-9_]*", sig)}
        doc_words = [_stem(w.lower()) for w in re.findall(r"[a-zA-Z]+", content)
                     if w.lower() not in _STOPWORDS]
        if len(doc_words) < 2:
            continue
        covered = sum(1 for w in doc_words if w in sig_words)
        if covered / len(doc_words) > 0.7:
            excerpt = " ".join(content.split())[:120]
            hits.append((start, end, "obvious-doc", excerpt))
    return hits


# ---------------------------------------------------------------------------
# scoring
# ---------------------------------------------------------------------------

def score_text(text, lang=None):
    """Return (score 0-100, hits).

    score = weighted hits per 100 comment lines, capped at 100.
    Never raises.
    """
    try:
        return _score_text_inner(text or "", lang)
    except Exception:
        return 0.0, []


def _score_text_inner(text, lang):
    comments = extract_comments(text, lang)
    n_comment_lines = sum(1 for _ in _comment_lines(comments))
    hits = _find_hits(text, lang)
    weighted = sum(WEIGHTS.get(kind, 1.0) for _, _, kind, _ in hits)
    score = min(100.0, 100.0 * weighted / max(1, n_comment_lines))
    return round(score, 1), hits


def score_file(path):
    """Score a file on disk. Returns (score, hits). Never raises."""
    try:
        size = os.path.getsize(path)
        if size > MAX_SCORE_BYTES:
            return 0.0, []
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        return score_text(text, lang_of(path))
    except Exception:
        return 0.0, []


# ---------------------------------------------------------------------------
# config / mode helpers
# ---------------------------------------------------------------------------

def threshold(config=None):
    """Slop score threshold. Env AGENT_GUARD_COMMENT_THRESHOLD wins."""
    try:
        env = os.environ.get("AGENT_GUARD_COMMENT_THRESHOLD", "").strip()
        if env:
            return max(0.0, min(100.0, float(env)))
    except Exception:
        pass
    try:
        cfg = config if isinstance(config, dict) else None
        if cfg is None:
            from . import state
            cfg = state.load_config()
        t = (cfg.get("comment_slop", {}) or {}).get("threshold", 30)
        return max(0.0, min(100.0, float(t)))
    except Exception:
        return DEFAULT_THRESHOLD


def mode(config=None):
    """'block' or 'warn'. Env AGENT_GUARD_COMMENT_MODE wins."""
    try:
        env = os.environ.get("AGENT_GUARD_COMMENT_MODE", "").strip().lower()
        if env in ("warn", "block"):
            return env
    except Exception:
        pass
    try:
        cfg = config if isinstance(config, dict) else None
        if cfg is None:
            from . import state
            cfg = state.load_config()
        m = ((cfg.get("comment_slop", {}) or {}).get("mode")
             or "block").strip().lower()
        return m if m in ("warn", "block") else "block"
    except Exception:
        return "block"


# ---------------------------------------------------------------------------
# decomment --fix
# ---------------------------------------------------------------------------

def fix_file(path):
    """Remove commented-code blocks from a file.

    Only kind='commented-code' hits are removed (conservative). Writes a
    `.bak` backup before modifying. Returns (removed_line_count, backup_path).
    Never raises.
    """
    try:
        return _fix_file_inner(path)
    except Exception:
        return 0, None


def _fix_file_inner(path):
    import shutil
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    score, hits = score_text(text, lang_of(path))
    ranges = [(s, e) for s, e, kind, _ in hits if kind == "commented-code"]
    if not ranges:
        return 0, None
    drop = set()
    for s, e in ranges:
        for ln in range(s, e + 1):
            drop.add(ln)
    bak = path + ".bak"
    shutil.copy2(path, bak)
    lines = text.split("\n")
    kept = [ln_text for i, ln_text in enumerate(lines, 1) if i not in drop]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(kept))
    return len(drop), bak
