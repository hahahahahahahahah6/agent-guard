"""Mutation test-honesty checker.

For a given test file, generate simple syntactic mutations and run the
test command against each mutated copy in a temp dir. A mutation that
SURVIVES (the test stays green) means the assertion doesn't actually
cover the bug it claims to cover; a mutation that is KILLED (test goes
red) means the test is honest about that assertion.

Usage: agent-guard mutate-check <test-file> -- <test-cmd...>
       [--project-root DIR] [--max-mutations N] [--timeout SECS]

Everything fails open: weird input, unreadable files, or a test command
that cannot run produce a warning and exit 0, never a crash.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv",
             ".tox", "dist", "build", ".idea", ".vscode", "target",
             ".hg", ".svn"}

DEFAULT_MAX_MUTATIONS = 20
DEFAULT_TIMEOUT = 120


# ---------------------------------------------------------------------------
# mutation operators: (name, regex, replacement-fn)
# Each operator is applied to ONE match at a time (first-order mutants).
# ---------------------------------------------------------------------------

def _inc_num(m):
    s = m.group(0)
    num = m.group(1)
    try:
        if "." in num:
            return s.replace(num, str(float(num) + 1), 1)
        return s.replace(num, str(int(num) + 1), 1)
    except ValueError:
        return s


def _str_mut(m):
    q, s = m.group(1), m.group(2)
    return "toEqual(%s%s_mut%s)" % (q, s, q)


def _neq_line_mut(m):
    line = m.group(0)
    return line.replace("===", "!==") if "===" in line else line


_OPERATORS = [
    # JS/TS
    ("js:toBe(num)+1",
     re.compile(r"toBe\(\s*(-?\d+(?:\.\d+)?)\s*\)"),
     _inc_num),
    ("js:toEqual(str)_mut",
     re.compile(r"toEqual\(\s*('|\")((?:(?!\1).)*)\1\s*\)"),
     _str_mut),
    ("js:toBe(true)->false",
     re.compile(r"toBe\(\s*true\s*\)"),
     lambda m: "toBe(false)"),
    ("js:toBe(false)->true",
     re.compile(r"toBe\(\s*false\s*\)"),
     lambda m: "toBe(true)"),
    ("js:expect-line === -> !==",
     re.compile(r"(?m)^[^\n]*expect\([^\n]*$"),
     _neq_line_mut),
    # Python (anchored at line start so `# assert ...` comments are untouched)
    ("py:assert == num -> num+1",
     re.compile(r"(?m)^([ \t]*assert\b[^\n]*?)==\s*(-?\d+(?:\.\d+)?)"),
     lambda m: m.group(1) + "== " + _inc_num_text(m.group(2))),
    ("py:assert != num -> ==",
     re.compile(r"(?m)^([ \t]*assert\b[^\n]*?)!=\s*(-?\d+(?:\.\d+)?)"),
     lambda m: m.group(1) + "== " + m.group(2)),
    ("py:assert name -> not name",
     re.compile(r"^([ \t]*)assert[ \t]+([A-Za-z_][A-Za-z0-9_]*)[ \t]*$",
                re.MULTILINE),
     lambda m: "%sassert not %s" % (m.group(1), m.group(2))),
]


def _inc_num_text(num):
    try:
        if "." in num:
            return str(float(num) + 1)
        return str(int(num) + 1)
    except ValueError:
        return num


def _line_of(text, pos):
    return text.count("\n", 0, pos) + 1


def generate_mutations(text, max_mutations=DEFAULT_MAX_MUTATIONS):
    """Yield (op_name, line_no, before, after, mutated_text).

    Mutations are ordered by position in the file (deterministic).
    Never raises.
    """
    out = []
    try:
        cands = []
        for op_name, rx, repl in _OPERATORS:
            try:
                for m in rx.finditer(text):
                    cands.append((m.start(), op_name, m, repl))
            except Exception:
                continue
        cands.sort(key=lambda c: c[0])
        for _, op_name, m, repl in cands[:max_mutations]:
            try:
                new_frag = repl(m)
            except Exception:
                continue
            if new_frag == m.group(0):
                continue
            mutated = text[:m.start()] + new_frag + text[m.end():]
            out.append((op_name, _line_of(text, m.start()),
                        m.group(0).strip(), new_frag.strip(), mutated))
    except Exception:
        pass
    return out


def find_project_root(test_file):
    """Nearest ancestor with project markers, else the file's parent dir."""
    markers = ("pyproject.toml", "setup.py", "setup.cfg", "package.json",
               "go.mod", "Cargo.toml", ".git")
    try:
        d = os.path.dirname(os.path.abspath(test_file))
        while True:
            try:
                entries = set(os.listdir(d))
            except OSError:
                entries = set()
            if any(mk in entries for mk in markers):
                return d
            parent = os.path.dirname(d)
            if parent == d:
                break
            d = parent
        return os.path.dirname(os.path.abspath(test_file))
    except Exception:
        return os.getcwd()


def _copy_project(src_root, dst_parent):
    """Copy the project to a fresh temp dir, skipping junk dirs."""
    def ignore(d, names):
        return [n for n in names
                if n in SKIP_DIRS and os.path.isdir(os.path.join(d, n))]
    dst = os.path.join(dst_parent, "mutproj")
    shutil.copytree(src_root, dst, ignore=ignore,
                    ignore_dangling_symlinks=True)
    return dst


def run_one(cmd, cwd, timeout):
    """Run the test command; return 'killed' | 'survived' | 'inconclusive'.

    killed:       nonzero exit (the test caught the mutation)
    survived:     exit 0 (the test stayed green: dishonest assertion)
    inconclusive: the command could not run / timed out (fail open:
                  never counted as survived)
    Never raises.
    """
    try:
        p = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=True,
                           timeout=timeout)
    except FileNotFoundError:
        return "inconclusive"
    except subprocess.TimeoutExpired:
        return "inconclusive"
    except Exception:
        return "inconclusive"
    return "survived" if p.returncode == 0 else "killed"


def check(test_file, test_cmd, project_root=None, max_mutations=None,
          timeout=None):
    """Run the mutation check.

    Returns (exit_code, report_text). Never raises.
    """
    try:
        return _check_inner(test_file, test_cmd, project_root,
                            max_mutations, timeout)
    except Exception as e:
        return 0, "mutate-check: internal error (%s); failing open.\n" % e


def _check_inner(test_file, test_cmd, project_root, max_mutations,
                 timeout):
    max_mutations = max_mutations or DEFAULT_MAX_MUTATIONS
    timeout = timeout or DEFAULT_TIMEOUT
    if not test_cmd:
        return 0, "mutate-check: no test command given; failing open.\n"
    if not test_file or not os.path.isfile(test_file):
        return 0, ("mutate-check: test file not found: %s; failing open.\n"
                   % test_file)

    try:
        with open(test_file, "r", encoding="utf-8",
                   errors="replace") as fh:
            original = fh.read()
    except OSError as e:
        return 0, "mutate-check: cannot read test file (%s); failing open.\n" % e

    root = (os.path.abspath(project_root) if project_root
            else find_project_root(test_file))
    try:
        rel = os.path.relpath(os.path.abspath(test_file), root)
    except ValueError:
        return 0, "mutate-check: test file is outside project root; failing open.\n"
    if rel.startswith(".."):
        return 0, ("mutate-check: test file is outside project root (%s); "
                   "failing open.\n" % root)

    mutations = generate_mutations(original, max_mutations)
    lines = ["agent-guard mutate-check: %s" % test_file,
             "project root: %s" % root,
             "test command: %s" % " ".join(test_cmd),
             "mutations generated: %d" % len(mutations)]
    if not mutations:
        lines.append("no mutations applied: nothing to mutate "
                     "(or file has no supported assertions).")
        lines.append("verdict: INCONCLUSIVE (no mutations)")
        return 0, "\n".join(lines) + "\n"

    survived, killed, inconclusive = [], [], []
    work = None
    try:
        work = tempfile.mkdtemp(prefix="agent-guard-mutate-")
        for op_name, line_no, before, after, mutated in mutations:
            proj_copy = None
            try:
                proj_copy = _copy_project(root, work)
                target = os.path.join(proj_copy, rel)
                with open(target, "w", encoding="utf-8") as fh:
                    fh.write(mutated)
                verdict = run_one(test_cmd, proj_copy, timeout)
            except Exception:
                verdict = "inconclusive"
            entry = "[%s] line %d: %s -> %s" % (op_name, line_no,
                                                before, after)
            if verdict == "survived":
                survived.append(entry)
            elif verdict == "killed":
                killed.append(entry)
            else:
                inconclusive.append(entry)
    finally:
        if work:
            shutil.rmtree(work, ignore_errors=True)

    lines.append("")
    if survived:
        lines.append("SURVIVED (%d) -- dangerous: the test stayed green, "
                     "so these assertions do not cover the bug:"
                     % len(survived))
        lines.extend("  ! " + e for e in survived)
    else:
        lines.append("SURVIVED (0)")
    lines.append("KILLED: %d" % len(killed))
    if inconclusive:
        lines.append("INCONCLUSIVE: %d (command failed to run or timed out; "
                     "not counted)" % len(inconclusive))
        lines.extend("  ? " + e for e in inconclusive)
    lines.append("")
    if survived:
        lines.append("verdict: WEAK -- %d mutation(s) survived; "
                     "tighten these assertions." % len(survived))
        return 1, "\n".join(lines) + "\n"
    lines.append("verdict: STRONG -- all %d mutation(s) killed."
                 % len(killed))
    return 0, "\n".join(lines) + "\n"


def build_parser():
    p = argparse.ArgumentParser(
        prog="agent-guard mutate-check",
        description="Mutation test-honesty check: mutate assertions, "
                    "re-run the tests, report survivors.")
    p.add_argument("test_file", help="test file to mutate")
    p.add_argument("test_cmd", nargs=argparse.REMAINDER,
                   help="test command, after -- : e.g. -- pytest -q")
    p.add_argument("--project-root", default=None,
                   help="project root (default: nearest dir with "
                        "project markers)")
    p.add_argument("--max-mutations", type=int,
                   default=DEFAULT_MAX_MUTATIONS)
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                   help="per-mutation test command timeout in seconds")
    return p


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    # Split the test command off at `--` manually: argparse REMAINDER
    # greedily swallows optionals like --project-root.
    tail = []
    if "--" in argv:
        i = argv.index("--")
        tail = argv[i + 1:]
        argv = argv[:i]
    args = build_parser().parse_args(argv)
    cmd = tail or [a for a in (args.test_cmd or []) if a != "--"]
    code, report = check(args.test_file, cmd,
                         project_root=args.project_root,
                         max_mutations=args.max_mutations,
                         timeout=args.timeout)
    sys.stdout.write(report)
    return code


if __name__ == "__main__":
    sys.exit(main())
