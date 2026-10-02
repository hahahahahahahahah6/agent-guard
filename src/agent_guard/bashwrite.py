"""Cross-tool write guard: stop Bash from bypassing Edit/Write hooks.

A guardrail on one tool protects nothing if another tool can do the same
thing. Hooks that block writes through Edit/Write are bypassed the moment
the agent reaches for Bash instead: ``sed -i``, a heredoc, a redirection.
This module statically extracts file-write targets from a Bash command
string (shlex-based, standard library only) and applies the same policy
the Write-tool guards would apply:

- target is a test-ish file -> cheat-sniff the written content when it is
  visible (heredoc body); an opaque write (``sed -i``, bare ``>``) to a
  test file is treated as a violation, because that is exactly the bypass.
- target is under ``bash_write.protected_paths`` -> the Write-tool policy
  for that file kind (comment-slop for source-ish content when visible,
  opaque otherwise).

Everything fails open: unparsable input yields no targets, never a block.
"""

import os
import re
import shlex

from . import cheatsniff, commentslop, testguard

# ---------------------------------------------------------------------------
# extraction
# ---------------------------------------------------------------------------

# <<EOF / <<-EOF / <<"EOF" / <<'EOF'
_HEREDOC_RX = re.compile(r"<<-?\s*(?P<q>['\"]?)(?P<delim>[A-Za-z_]\w*)(?P=q)")

# operator-only redirection tokens: ">", ">>", ">|", "2>", "&>", "2>>"
_OP_ONLY_RX = re.compile(r"^(?:\d+|&)?(?:>>?|>\|)$")
# attached at token start: ">file", "2>file", "&>file", ">>file"
_ATTACHED_RX = re.compile(r"^(?:\d+|&)?(?:>>?|>\|)(?P<rest>.*)$")

_HEREDOC_OPS = ("<<", "<<-")
_CHAIN_OPS = (";", "&&", "||", "|", "&")
_WRAPPERS = ("sudo", "doas", "command")
_SHELLS = ("sh", "bash", "dash", "zsh", "ksh")

# targets that are never real file writes
_SKIP_TARGETS = frozenset({
    "/dev/null", "/dev/stdout", "/dev/stderr", "/dev/stdin", "/dev/tty",
    "-", "&1", "&2", "&0",
})

# `sed -i` / `tee` / `cp` / `mv` / `install` write targets
_SED_CMDS = ("sed", "gsed")


def _strip_heredocs(command):
    """Replace heredoc bodies; return (command_without_bodies, [bodies]).

    Bodies are collected in order of appearance so they can be matched to
    the ``<<`` operators found later during token scanning. The ``<<``
    operator itself is kept (delimiter word removed) so the segment that
    owned the heredoc is still identifiable. Never raises.
    """
    try:
        return _strip_heredocs_inner(command)
    except Exception:
        return command, []


def _strip_heredocs_inner(command):
    lines = command.split("\n")
    out = []
    bodies = []
    i = 0
    while i < len(lines):
        line = lines[i]
        m = _HEREDOC_RX.search(line)
        if not m:
            out.append(line)
            i += 1
            continue
        delim = m.group("delim")
        out.append(_HEREDOC_RX.sub("<<", line, count=1))
        i += 1
        body = []
        while i < len(lines) and lines[i].strip() != delim:
            body.append(lines[i])
            i += 1
        bodies.append("\n".join(body))
        i += 1  # skip the delimiter line (harmless past EOF)
    return "\n".join(out), bodies


def _isolate_semis(s):
    """Put whitespace around `;` when it is not inside quotes, so `cmd>f;cmd2`
    tokenizes into separate segments. Quote-aware; never raises."""
    try:
        out = []
        q = None
        i = 0
        n = len(s)
        while i < n:
            c = s[i]
            if q:
                out.append(c)
                if c == "\\" and i + 1 < n:
                    out.append(s[i + 1])
                    i += 1
                elif c == q:
                    q = None
            elif c in ("'", '"'):
                q = c
                out.append(c)
            elif c == ";":
                out.append(" ; ")
            else:
                out.append(c)
            i += 1
        return "".join(out)
    except Exception:
        return s


def _segments(tokens):
    """Split a token list on shell chain/pipe operators."""
    segs, cur = [], []
    for t in tokens:
        if t in _CHAIN_OPS:
            if cur:
                segs.append(cur)
                cur = []
        else:
            cur.append(t)
    if cur:
        segs.append(cur)
    return segs


def _unwrap(seg):
    """Drop sudo/doas/command/env VAR=.. wrappers to find the real command."""
    seg = list(seg)
    while seg and seg[0] in _WRAPPERS:
        seg = seg[1:]
    if seg and seg[0] == "env":
        seg = seg[1:]
        while seg and re.fullmatch(r"[A-Za-z_]\w*=.*", seg[0]):
            seg = seg[1:]
    return seg


def _confident_target(t):
    """Is this plausibly a real file path (not fd/glob/var)? Never raises."""
    try:
        if not t or not isinstance(t, str):
            return False
        if t in _SKIP_TARGETS:
            return False
        if t.startswith("&"):      # fd duplication: 2>&1
            return False
        if "$" in t or "`" in t:   # unresolvable expansion
            return False
        if any(c in t for c in "*?["):  # bare glob
            return False
        if t in (">", ">>", ">|", "<<", "<<-", "|", ";", "&&"):
            return False
        return True
    except Exception:
        return False


def _redir_targets(seg):
    """Yield (target, via) for redirection operators in a segment."""
    out = []
    i = 0
    while i < len(seg):
        tok = seg[i]
        target = None
        if _OP_ONLY_RX.fullmatch(tok):
            if i + 1 < len(seg):
                target = seg[i + 1]
                i += 1  # consume the target token
        else:
            m = _ATTACHED_RX.match(tok)
            if m:
                rest = m.group("rest")
                if rest:
                    target = rest
                elif i + 1 < len(seg):
                    target = seg[i + 1]
                    i += 1
        if target is not None and _confident_target(target):
            out.append((target, "redirect"))
        i += 1
    return out


def _sed_target(seg):
    """Target of `sed -i ...` (in-place edit). None when stdin/no file."""
    try:
        toks = seg[1:]
        cleaned = []
        skip_next = False
        had_e = False
        for t in toks:
            if skip_next:
                skip_next = False
                continue
            if t in ("-e", "--expression"):
                skip_next = True
                had_e = True
                continue
            cleaned.append(t)
        cands = [t for t in cleaned if not t.startswith("-")]
        files = cands if had_e else cands[1:]  # first is the script w/o -e
        if not files:
            return None
        target = files[-1]
        return target if _confident_target(target) else None
    except Exception:
        return None


def _flagless_targets(seg, min_args=1):
    """Non-flag args of cp/mv/install/tee. For cp/mv the dest is last.

    Input redirections (`<`, `<<`) and their files are not write targets.
    """
    try:
        args = []
        skip_next = False
        for t in seg[1:]:
            if skip_next:
                skip_next = False
                continue
            if t in ("<", "<<", "<<-"):
                skip_next = True  # input file, not a write target
                continue
            if t.startswith("-") and t != "-":
                continue
            if _confident_target(t):
                args.append(t)
        if len(args) < min_args:
            return []
        return args
    except Exception:
        return []


def extract_writes(command):
    """Parse a Bash command into file-write targets.

    Returns (targets, parse_ok) where targets is a list of
    (target, via, content): via is one of "redirect", "heredoc",
    "sed -i", "tee", "cp", "mv", "install"; content is the heredoc body
    when the write visibly carries one, else None. Never raises; on any
    parse failure returns ([], False) — fail open.
    """
    try:
        return _extract_inner(command or ""), True
    except Exception:
        return [], False


def _extract_inner(command):
    stripped, bodies = _strip_heredocs(command)
    tokens = shlex.split(_isolate_semis(stripped), posix=True)
    body_iter = iter(bodies)
    out = []
    seen = set()

    def add(target, via, content=None):
        key = (target, via)
        if key not in seen:
            seen.add(key)
            out.append((target, via, content))

    def next_body():
        try:
            return next(body_iter)
        except StopIteration:
            return None

    for seg in _segments(tokens):
        seg_start = len(out)
        # nested `sh -c "..."` / `bash -c "..."`: recurse into the payload
        plain = _unwrap(seg)
        if plain and plain[0] in _SHELLS and "-c" in plain:
            try:
                payload = plain[plain.index("-c") + 1]
                sub, _ = extract_writes(payload)
                for t, v, c in sub:
                    add(t, v, c)
            except Exception:
                pass
        for target, via in _redir_targets(seg):
            add(target, via)
        # attach heredoc bodies to this segment's redirect target, if any
        if any(t in _HEREDOC_OPS for t in seg):
            body = next_body()
            if body is not None:
                for j in range(seg_start, len(out)):
                    target, via, content = out[j]
                    if via == "redirect" and content is None:
                        out[j] = (target, "heredoc", body)
                        break
        if not plain:
            continue
        cmd = plain[0]
        if cmd in _SED_CMDS and any(
                t == "--in-place" or t == "-i" or t.startswith("-i")
                for t in plain[1:]):
            target = _sed_target(plain)
            if target:
                add(target, "sed -i")
        elif cmd == "tee":
            for t in _flagless_targets(plain):
                add(t, "tee")
        elif cmd in ("cp", "mv"):
            args = _flagless_targets(plain, min_args=2)
            if args and not args[-1].endswith("/"):
                add(args[-1], cmd)
        elif cmd == "install":
            args = _flagless_targets(plain, min_args=2)
            if args:
                add(args[-1], "install")
    return out


# ---------------------------------------------------------------------------
# policy
# ---------------------------------------------------------------------------

def _is_testy(rel):
    """Mirror of the Write-hook's test-file definition. Never raises."""
    try:
        p = str(rel or "").replace("\\", "/")
        base = p.rsplit("/", 1)[-1]
        if base == "conftest.py" or base.startswith("test_") \
                or base.endswith("_test.py") or "/tests/" in p:
            return True
        return testguard.is_test_file(rel)
    except Exception:
        return False


def _rel(cwd, target):
    try:
        return os.path.relpath(
            os.path.join(os.path.abspath(cwd), os.path.expanduser(target)),
            os.path.abspath(cwd))
    except Exception:
        return str(target)


def _under_protected(target, rel, prefixes):
    """Does this write land under a user-protected path prefix?"""
    try:
        cands = {str(target), rel}
        for pre in prefixes or []:
            pre = str(pre or "").strip().strip("/").strip("./")
            if not pre:
                continue
            for c in cands:
                c = c.strip().strip("/").strip("./")
                if c == pre or c.startswith(pre + "/"):
                    return True
        return False
    except Exception:
        return False


def mode(config=None):
    """'block' or 'warn'. Env AGENT_GUARD_BASHWRITE_MODE wins."""
    try:
        env = os.environ.get("AGENT_GUARD_BASHWRITE_MODE", "").strip().lower()
        if env in ("warn", "block"):
            return env
    except Exception:
        pass
    try:
        cfg = config if isinstance(config, dict) else None
        if cfg is None:
            from . import state
            cfg = state.load_config()
        m = ((cfg.get("bash_write", {}) or {}).get("mode")
             or "block").strip().lower()
        return m if m in ("warn", "block") else "block"
    except Exception:
        return "block"


def allowed(config, target, rel):
    """Is this Bash write allowlisted? Checks bash_write.allow, then falls
    back to cheat_sniff.allow (shared test-file suppressions).

    Entries are `path-or-basename:kind` where kind is `bash-write` or `*`.
    Never raises.
    """
    try:
        base = os.path.basename(str(target or ""))
        for section in ("bash_write", "cheat_sniff"):
            entries = ((config or {}).get(section, {}) or {}).get(
                "allow", []) or []
            for e in entries:
                if not isinstance(e, str) or ":" not in e:
                    continue
                pat, kind = e.rsplit(":", 1)
                if kind not in ("*", "bash-write"):
                    continue
                if pat == "*" or base == pat \
                        or str(target).endswith(pat) \
                        or str(rel).endswith(pat):
                    return True
        return False
    except Exception:
        return False


def _lang_of(target):
    ext = os.path.splitext(str(target or ""))[1].lower()
    return {"py": "py", ".py": "py", ".js": "js", ".ts": "ts",
            ".jsx": "jsx", ".tsx": "tsx"}.get(ext, ext.lstrip(".") or "txt")


def decide(command, cfg, cwd):
    """Apply Write-tool policy to Bash write targets.

    Returns (allowed: bool, reason: str, targets: list, parse_ok: bool).
    Never raises — fail open.
    """
    try:
        return _decide_inner(command, cfg, cwd)
    except Exception:
        return True, "", [], False


def _decide_inner(command, cfg, cwd):
    targets, parse_ok = extract_writes(command)
    if not targets:
        return True, "", [], parse_ok
    cfg = cfg if isinstance(cfg, dict) else {}
    prefixes = (cfg.get("bash_write", {}) or {}).get("protected_paths", [])
    violations = []  # (target, via, detail)

    for target, via, content in targets:
        rel = _rel(cwd, target)
        testy = _is_testy(rel)
        protected = testy or _under_protected(target, rel, prefixes)
        if not protected:
            continue
        if allowed(cfg, target, rel):
            continue
        if testy and content:
            score, hits = cheatsniff.score_text(content, target)
            hits = cheatsniff.filter_allowed(hits, cfg, target)
            score = min(100.0, 10.0 * sum(
                cheatsniff.WEIGHTS.get(k, 1.0) for _, _, k, _ in hits))
            score = round(score, 1)
            thr = cheatsniff.threshold(cfg)
            if score >= thr:
                kinds = ", ".join(k for _, _, k, _ in hits[:4])
                violations.append(
                    (target, via,
                     "cheat score %.1f >= %.1f (%s)" % (score, thr, kinds)))
            continue  # content scored clean: allow (Stop-time guard watches)
        if content and not testy:
            lang = _lang_of(target)
            score, hits = commentslop.score_text(content, lang)
            thr = commentslop.threshold(cfg)
            if score >= thr:
                violations.append(
                    (target, via,
                     "comment-slop score %.1f >= %.1f" % (score, thr)))
            continue
        violations.append((target, via, "opaque write"))

    if not violations:
        return True, "", [t for t, _, _ in targets], parse_ok

    lines = []
    for target, via, detail in violations:
        lines.append("  - %s (via %s): %s" % (target, via, detail))
    reason = (
        "Bash-write guard: this Bash command writes to %d protected "
        "file(s) outside the Edit/Write tools, where the Write-hook "
        "guards cannot see or score it.\n"
        "%s\n"
        "A guardrail on one tool protects nothing if another tool can do "
        "the same thing: blocked Write/Edit calls are bypassed with "
        "`sed -i`, heredocs, and redirections. Make the change with the "
        "Edit tool instead, where the content is scored.\n"
        "Bypass (not recommended): AGENT_GUARD_BASHWRITE_MODE=warn, or "
        "bash_write.mode=warn in CONFIG_PATH."
        % (len(violations), "\n".join(lines)))
    try:
        from . import state
        cfg_path = state.config_path()
    except Exception:
        cfg_path = "~/.config/agent-guard/config.json"
    reason = reason.replace("CONFIG_PATH", cfg_path)
    return False, reason, [t for t, _, _ in targets], parse_ok
