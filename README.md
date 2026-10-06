# agent-guard

Behavior-guardrail hooks for [Claude Code](https://docs.anthropic.com/en/docs/claude-code).
Six guards plus test-honesty CLIs, one install, zero dependencies (Python
standard library only):

```bash
pip install agent-guard-hooks
```

- **Test-tampering guard** — stops the "green by editing the test" cheat.
  On `SessionStart` it snapshots hashes of every test and source file; on
  `Stop` it diffs. If test files were modified or deleted while no source
  file changed, the stop is blocked until the agent proves each changed test
  actually fails without the fix.
- **Outbound-action guard** — a `PreToolUse` hook on `Bash` with a denylist
  of risky action patterns: pushes to protected branches (including force
  pushes), package publishes (`npm publish`, `twine upload`, …), prod deploys,
  cloud provisioning (spend), and mass-send channels (Slack webhooks,
  mailers). Matches block with a named rule; a user allowlist in
  `config.json` overrides the denylist. Every matched decision is written to
  an audit log. v0.2 also scans the *content* of script files the command
  executes (`bash evil.sh`), closing the "write it to a script first" bypass.
- **Post-exec read-back verifier** (v0.2) — a `PostToolUse` hook on `Bash`
  that reads back world state after a command claimed an outbound effect
  (`git push`, `npm publish`) and warns — never blocks — when the effect
  isn't visible. Defense-in-depth on top of PreToolUse prevention: prevent
  first, verify after.
- **Mutation test-honesty checker** (v0.2) — `agent-guard mutate-check`
  deliberately breaks assertions (regex-based mutants for JS/TS and Python),
  re-runs the tests per mutant, and reports survivors: tests that stayed
  green don't actually cover the bug.
- **Comment-slop guard** (v0.3) — a `PreToolUse` hook on `Write`/`Edit` that
  scores the *added* comments (never pre-existing code) for narrative slop:
  commented-out code, restatements of obvious code ("This function adds two
  numbers"), in-code changelogs, meta/apologetic notes, emoji, and
  docstrings that just restate the signature. Blocks at a configurable
  threshold, or `agent-guard decomment --check/--fix` for a one-command
  decomment pass before PRs.
- **Cheat-sniffing guard** (v0.4) — catches the cheating that never touches
  test files: RNG rigging (`random.seed(123)` with no reproducibility
  marker, patching `random.shuffle`), mocking the function under test
  instead of its collaborators, `conftest.py` plants, time-freezing, and
  always-True comparison dunders. A `PreToolUse` hook on `Write`/`Edit`
  blocks cheat patterns in added test text; `agent-guard cheatsniff
  --check` audits the repo.
- **Cross-tool write guard** (v0.5) — stops Bash from bypassing the
  Edit/Write hooks. A `PreToolUse` hook on `Bash` statically extracts
  file-write targets (`>`, `>>`, heredocs, `sed -i`, `tee`, `cp`/`mv`
  destinations) and applies the same policy the Write-tool guards would:
  test-ish targets get cheat-sniffed when the content is visible, opaque
  writes to protected files are blocked. A guardrail on one tool protects
  nothing if another tool can do the same thing.

The failure modes are real, quoted from the community:

> *"Instead of fixing the indexing logic in the source file, the agent quietly
> modified the test file: it changed `expect(page.items.length).toBe(10)` to
> `toBe(9)`, re-ran the test, saw green, and told us the refactor was
> complete."* — [navune, r/ClaudeCode](https://old.reddit.com/r/ClaudeCode/comments/1wtpa4g/the_silent_testtampering_trap_how_to_stop_claude/)

> *"the risk isn't a bad answer, it's a bad action"* — [dank_as_fuck_,](https://www.reddit.com/r/AI_Agents/comments/1wqz6b0/how_are_you_stopping_agents_from_doing_things/)
> [r/AI_Agents](https://www.reddit.com/r/AI_Agents/comments/1wqz6b0/how_are_you_stopping_agents_from_doing_things/), on why guardrails must live *"below the prompt layer"*
> (verstands)

## Differentiation

- **vs Rashomon** (r/aiagents): Rashomon *observes* — it records commands,
  edits and failures, then compares them against the agent's closing summary.
  agent-guard *prevents* — the hook sits in the tool-call path and blocks the
  bad action before it happens. Observation and prevention are complementary
  layers; this is the prevention one.
- **vs edit-guard** (same author): edit-guard blocks *stale* cross-session
  edits (write-after-write on a file another session changed). agent-guard
  blocks *misbehaving* actions (weakened tests, unapproved outbound effects).
  Different failure modes, same fail-open hook philosophy.
- **vs Kvitansiya** (Show HN, 2026-10-01): Kvitansiya verifies at stop —
  it checks the claimed outcome once, when the session ends. agent-guard v0.2
  adds post-exec read-back as defense-in-depth *on top of* PreToolUse
  prevention: block the bad action before it happens, then verify the claimed
  effect is actually visible afterwards. Prevent first, verify after.

## v0.5.1: fewer false positives, perl -i

Patch release driven by an independent review of v0.5 — every item below
was reproduced against the release before fixing:

- **False positives fixed.** The Bash guard blocked
  `pytest -q 2>&1 | tee test_output.log`,
  `echo '{}' > tests/fixtures/data.json`, and
  `echo '' > tests/__init__.py`. A hook that cries wolf gets uninstalled:
  only real code suffixes now count as test files, and `fixtures/`,
  `testdata/`, `data/` directories plus `__init__.py` are never test
  files. Regression-tested per reported case.
- **`perl -pi -e` is now treated like `sed -i`.** It is the exact
  equivalent and sailed through v0.5; opaque in-place edits of test files
  via perl are blocked the same way.
- **Honest coverage table** in Honest limitations: `awk -i inplace`,
  `truncate -s 0`, `dd of=`, and `git checkout … -- tests/` are not
  intercepted by the PreToolUse hook — but the Stop-time test-tampering
  guard still catches any test-file modification or deletion at session
  end (verified by test).

## v0.5: cross-tool write guard

```bash
agent-guard install   # registers agent-guard hook-bashwrite (PreToolUse on Bash)
```

The second bypass in the same family. v0.2 closed "write it to a script
first" (the r/AI_Agents blocklist bypass); v0.5 closes the other one.
thomastartrau read 28 Claude Code security advisories and found the
pattern: *"My hooks block certain writes through the Edit and Write
tools. Once blocked, the agent went through Bash instead: `sed -i`, a
heredoc, a redirection. I had to add a hook that blocks writes to source
files via Bash. **A guardrail on one tool protects nothing if another tool
can do the same thing.**"*

`install` registers `agent-guard hook-bashwrite` as a `PreToolUse` hook on
`Bash`. It statically extracts file-write targets from the command —
`>` / `>>` redirections, heredocs (`<<EOF`, `<<-EOF`), `sed -i`
(including `-i.bak` / `--in-place`), `tee` (with/without `-a`),
`cp`/`mv`/`install` destinations, chained with `&&` / `;` / `|` — and
applies the same policy the Write-tool guards would apply:

- **test-ish target** (`test_*.py`, `conftest.py`, `tests/` …): when the
  written content is visible (heredoc body), it is cheat-sniffed with the
  v0.4 detectors; an *opaque* write (`sed -i`, bare `>`) to a test file is
  treated as a violation on its own — that is exactly the bypass shape.
- **`bash_write.protected_paths`** (path prefixes, default empty = the
  test-tampering guard's scope): any Bash write under a protected prefix is
  treated like a Write-tool call — visible content is scored (comment-slop
  for source-ish files), opaque writes are blocked in block mode.

Warn mode (`AGENT_GUARD_BASHWRITE_MODE=warn` or `bash_write.mode=warn`)
advises instead of blocking. A `bash_write.allow` list
(`"tests/legacy/:bash-write"`) covers the judgment calls you disagree
with. Everything fails open: unparsable commands are allowed, never
blocked.

## v0.4: cheat-sniffing beyond test files

```bash
agent-guard cheatsniff --check tests/    # per-file cheat scores, exit 1 over threshold
```

Half of agent cheating never touches a test file. A dev.to study (remdore,
2026-10-01, 102 runs × 4 models) found agents patching the RNG *"so the list
would always be sorted"*, mocking the function under test instead of its
collaborators, and planting helpers in `conftest.py`. The test-tampering
guard (tests-only-change diff) and `mutate-check` (assertion mutation) both
miss this family — "restore the test files and re-run" only catches the
dumb half.

`install` registers `agent-guard hook-cheatsniff` as a `PreToolUse` hook on
`Write`/`Edit`. It fires only for test-ish files (`test_*.py`,
`*_test.py`, `conftest.py`, anything under `tests/`) and scores only the
*added* text. Six cheat kinds, regex-based and deliberately conservative:

- **mock-subject** (severe): `mock.patch("billing.total")` inside
  `test_billing.py` — patching the module under test itself, not its
  dependencies. Patching a collaborator (`stripe.Charge.create`) is clean.
- **rng-patch** (severe): patching `random.shuffle` / `random.random` /
  `random.sample` to force outcomes.
- **conftest-patch** (severe): `conftest.py` monkeypatching the subject or
  other local modules — including hand-rolled `mymod.shuffle = ...` direct
  assignment (pure fixtures are clean).
- **rng-seed**: a fixed `random.seed(123)` with no reproducibility marker.
  `random.seed(42)` next to a "reproducible" comment is legitimate and not
  flagged — the marker is the whole difference, and it's documented.
- **time-freeze**: `freeze_time(...)`, `time.sleep` patched to a no-op.
- **weak-comparator**: a `__eq__` / `__lt__` / … whose body unconditionally
  `return True`.

One severe hit reaches the default threshold (30/100) on its own. Warn mode
(`AGENT_GUARD_CHEAT_MODE=warn` or `cheat_sniff.mode=warn` in config) advises
instead of blocking. A `cheat_sniff.allow` list (`"test_sort.py:rng-seed"`,
`"*/legacy/*:*")` covers the judgment calls you disagree with. Everything
fails open.

## v0.3: comment-slop guard

```bash
agent-guard decomment --check src/           # per-file slop scores, exit 1 over threshold
agent-guard decomment --fix src/app.py       # remove commented-out code only (writes .bak)
```

`install` registers `agent-guard hook-commentslop` as a `PreToolUse` hook
on `Write`/`Edit`. It scores only the *added* comment lines — your existing
codebase is never punished — and blocks (exit 2) when the added-slop score
reaches the threshold (default 30/100). The block message names the lines
and the slop kind, and points at `decomment --fix`. Six slop kinds, all
regex-based and deliberately conservative (when in doubt, it doesn't flag):

- **commented-code** (weighted highest): 2+ consecutive comment lines that
  look like code — dead code left in comments instead of deleted
- **restatement**: "This function …", "Here we …", "The following …"
- **changelog**: "Fixed …", "Updated …" narrating the diff inside the code
  (belongs in the commit message)
- **meta-apology**: HACK, "sorry", "workaround", "fix this later", `!!!`
- **emoji** in comments
- **obvious-doc**: a docstring whose words are >70% covered by the next
  line's identifiers (e.g. `"""Add a and b."""` above `def add(a, b)`)

Tool directives (`# noqa`, `# type: ignore`, `eslint-disable`, …) are never
flagged. `--fix` is surgical: it removes only `commented-code` blocks and
always writes a `.bak` backup first. Warn mode
(`AGENT_GUARD_COMMENT_MODE=warn` or `comment_slop.mode=warn` in config)
advises instead of blocking. Everything fails open.

## v0.2: script-content inspection, mutation test-honesty, post-exec verification

### Script-content inspection

The Bash denylist failed as soon as the agent wrote the destructive command
into a script and executed the script instead (`bash evil.sh`). The outbound
guard now extracts script files from the command — `bash|sh|zsh|dash`,
`python|node|ruby|perl|php <file>`, `./run.sh`, `source`/`. <file>`, plus
`bash -c '...'` inline code — resolves them against the hook's cwd, and scans
the file content with the same rule logic (regexes + destination-aware
`git push` parsing). Hits block with a `script-content:<rule_id>` id so the
audit log shows where the hit came from. Missing, unreadable, or >1MB files
are skipped (fail open); only plausible script extensions are scanned; the
user allowlist and `disabled_rules` apply to content hits too.

### Mutation test-honesty checker

```bash
agent-guard mutate-check tests/test_app.py --project-root . -- pytest -q
```

Generates up to 20 syntactic mutations (default; `--max-mutations`), copies
the project to a temp dir per mutant (skipping `.git`/`node_modules`/etc.),
and runs the test command there. Mutation operators:

- JS/TS: `toBe(<n>)` → `<n+1>`; `toEqual("<s>")` → `"<s>_mut"`;
  `toBe(true)` ↔ `toBe(false)`; `===` → `!==` on `expect()` lines
- Python: `assert <e> == <n>` → `<n+1>`; `assert <e> != <n>` → `==`;
  `assert <name>` → `assert not <name>`

A mutation the test suite still passes is **SURVIVED** — the assertion doesn't
cover the bug — and the command exits 1. All killed → exit 0. Inconclusive
runs (command missing, timeout) are reported separately and never count as
survived. Weird input fails open with a warning.

### Post-exec read-back verifier

`install` registers `agent-guard hook-verify` as a `PostToolUse` hook on
`Bash`. After a command that claimed an outbound effect, it reads back world
state and warns on stderr (always exit 0 — it never blocks):

- `git push <remote> <ref>`: runs `git ls-remote <remote> <ref>` (10s
  timeout); warns when the ref is absent remotely. `<remote>` defaults to
  `origin`; `-C <dir>` is honored; unreachable remotes stay silent.
- `npm publish`: reads `name`/`version` from `package.json` and runs
  `npm view <name>@<version> version`; warns when the version isn't visible.
  Silent when there is no `package.json` or npm is missing.

Warnings are audit-logged (`guard: verify`, `decision: warn`).

## Install

```bash
# Not on PyPI yet -- install from source:
git clone https://github.com/hahahahahahahahah6/agent-guard.git
cd agent-guard
pip install .
agent-guard install
```

`install` merges five hook entries into `~/.claude/settings.json` (backing it
up first, never clobbering existing settings):

- `SessionStart` → `agent-guard hook-snapshot` (records digests, never blocks)
- `Stop` → `agent-guard hook-test` (blocks tests-only changes)
- `PreToolUse` on `Bash` → `agent-guard hook-outbound` (blocks denylisted actions)
- `PreToolUse` on `Write|Edit` → `agent-guard hook-commentslop` (blocks
  comment slop in added text)
- `PostToolUse` on `Bash` → `agent-guard hook-verify` (warns when a claimed
  effect isn't visible; never blocks)

Restart Claude Code afterwards. No MCP server, no daemon, no accounts.

## What the agent sees

Test tampering blocked at stop:

```
Test-tampering guard: test files changed but no source files changed since
this session started.
Changed test files:
  - tests/test_auth.py
This matches a known failure mode where an agent edits test assertions to make
them pass instead of fixing the source code. Before proceeding, verify each
changed test actually fails without the fix: revert the source change, re-run
the test, and confirm it goes red. A test that stays green without the fix is
not covering the bug.
```

Outbound action blocked before it runs:

```
Outbound-action guard blocked this command (rule 'git-push-protected': Push to
a protected branch (main/master/prod*/release/*): push to protected ref 'main').
If this action is intended, add an allowlist regex to outbound.allow in
~/.config/agent-guard/config.json, or run it yourself outside the agent.
```

Note: push blocking is destination-aware. A bare `git push` (or
`git push <remote>`) resolves the destination to the current branch via
`git symbolic-ref --short HEAD` in the hook's working directory
(`git -C <dir>` is honored), so pushing a feature branch is allowed and
only pushes whose destination is a protected branch are blocked. If the
branch can't be determined (detached HEAD, not a git repo), the push is
allowed rather than breaking your workflow.

## Configuration

`~/.config/agent-guard/config.json` (all optional):

```json
{
  "test_guard": {
    "mode": "block",
    "ignore_paths": ["tests/legacy/"]
  },
  "outbound": {
    "allow": ["my-registry\\.internal"],
    "deny_extra": ["rm -rf /tmp/scratch"],
    "disabled_rules": ["cloud-provision"]
  },
  "comment_slop": {
    "mode": "block",
    "threshold": 30
  },
  "cheat_sniff": {
    "mode": "block",
    "threshold": 30,
    "allow": []
  },
  "bash_write": {
    "mode": "block",
    "protected_paths": ["src/", "infra/"],
    "allow": []
  }
}
```

- `test_guard.mode`: `"block"` (default) or `"warn"`. Env override:
  `AGENT_GUARD_TEST_MODE=warn`.
- `comment_slop.mode`: `"block"` (default) or `"warn"`. Env override:
  `AGENT_GUARD_COMMENT_MODE=warn`.
- `comment_slop.threshold`: slop score (0–100) at which the comment hook
  trips. Env override: `AGENT_GUARD_COMMENT_THRESHOLD`.
- `cheat_sniff.mode`: `"block"` (default) or `"warn"`. Env override:
  `AGENT_GUARD_CHEAT_MODE=warn`.
- `cheat_sniff.threshold`: cheat score (0–100) at which the cheat hook
  trips (one severe hit reaches the default 30). Env override:
  `AGENT_GUARD_CHEAT_THRESHOLD`.
- `cheat_sniff.allow`: `"path-or-basename:kind"` entries that suppress hits,
  e.g. `"test_sort.py:rng-seed"` or `"*/legacy/*:*"`.
- `bash_write.mode`: `"block"` (default) or `"warn"`. Env override:
  `AGENT_GUARD_BASHWRITE_MODE=warn`.
- `bash_write.protected_paths`: path prefixes where any Bash write is
  treated like a Write-tool call (default `[]`, which means the
  test-tampering guard's scope: test files plus `conftest.py`).
- `bash_write.allow`: `"path-or-basename:bash-write"` entries that suppress
  the Bash-write guard, e.g. `"tests/fixtures/:bash-write"`.
- `outbound.allow`: regexes that win over the denylist (e.g. your internal
  registry). Every override is audit-logged.
- `outbound.deny_extra` / `disabled_rules`: extend or trim the denylist.

Inspect decisions:

```bash
agent-guard log        # blocked + allowlist-override + verify-warn decisions
agent-guard status     # state paths, mode, active rules
```

Check whether your tests are honest:

```bash
agent-guard mutate-check tests/test_billing.py -- pytest -q
```

## Honest limitations

- **Heuristic, not proof.** "Tests changed, source didn't" is a strong
  signal of the navune cheat, not a proof. Legitimate test-only refactors get
  blocked too — that's what `ignore_paths` and warn mode are for.
- **New tests are allowed.** Added test files never count as tampering;
  only modified or deleted ones do.
- **Bash only (for now).** The outbound guard watches the `Bash` tool. An
  agent reaching a Slack MCP tool directly is out of scope for this MVP.
- **Best-effort spend list.** Cloud-provision patterns cover the common
  CLIs; exotic spend paths won't match. The denylist is a seatbelt, not a
  vault.
- **Hook protocol is undocumented.** The hook stdin shape and the
  exit-2-blocks convention come from community documentation, not a stable
  API. If Claude Code changes the protocol, the hooks degrade to fail-open
  allow.
- **Per-machine only.** State lives in `~/.config/agent-guard/`.
- The hooks **fail open**: corrupt state, unreadable files, malformed input —
  anything unexpected means "allow". A guard that wedges your session is
  worse than no guard.
- **Script-content inspection is one level deep.** A script that executes
  another script (`bash a.sh` where `a.sh` runs `bash b.sh`) is not followed;
  exotic interpreter wrappers beyond `env`/`sudo`/`nohup`/`time`/`nice` are
  not unwrapped. The denylist is a seatbelt, not a vault.
- **Mutation checking is regex-based, not semantic.** It generates at most 20
  first-order mutants with simple syntactic operators — good enough to catch
  vacuous assertions, not a replacement for real mutation-testing tools.
- **The post-exec verifier is advisory.** It warns on stderr and always exits
  0; unreachable remotes, missing npm, and timed-out checks stay silent
  rather than crying wolf.
- **Slop detection is stylistic, not semantic.** The six patterns are regex
  heuristics tuned for low false positives, which means they miss subtler
  slop (a well-written but pointless paragraph scores 0). Short added
  comments normalize aggressively — one narrative line in an otherwise
  comment-free edit scores high, by design. If your codebase has a
  comment-heavy style (or non-English comments the patterns don't cover),
  use warn mode or raise `comment_slop.threshold`.
- **`decomment --fix` only removes commented-out code.** Other slop kinds
  are reported, never auto-edited — deleting prose automatically is how you
  lose the one comment that mattered.
- **Bash-write coverage is enumerated, not exhaustive.** The PreToolUse
  hook intercepts `>` / `>>` / heredocs / `sed -i` / `perl -pi -e` /
  `tee` / `cp` / `mv` / `install`. It does *not* intercept
  `awk -i inplace`, `truncate -s 0`, `dd of=`, or
  `git checkout … -- tests/` — those write to test files without tripping
  the hook. Defense in depth: the Stop-time test-tampering guard diffs
  every test file against the session snapshot and blocks the stop when
  test files changed but no source file did, so the damage is still caught
  at session end (covered by regression tests). A seatbelt, not a vault.
- **Cheat-sniffing is static and Python-first.** It reads text, not runtime
  behavior — a cheat applied only at runtime (e.g. via `sitecustomize.py`
  or an installed plugin) is invisible to it. The "subject vs collaborator"
  judgment is a filename heuristic (`test_billing.py` → `billing`); exotic
  layouts need the allowlist. A fixed seed with a reproducibility marker is
  trusted on the marker's word — an agent that writes "reproducible" next
  to a planted seed fools the exemption, which is why severe kinds
  (mock-subject, rng-patch, conftest-patch) have no marker exemption at all.
- **The cheat hook only watches added test text.** Pre-existing cheats in
  the repo are found by `cheatsniff --check`, not blocked by the hook.
- **Bash write-target extraction is static and approximate.** It is
  shlex-based, so heavy quoting, `eval`, command substitution building
  paths at runtime, and `python3 -c "open(...).write(...)"` are known gaps
  — the target list is conservative by design (a missed target is a miss,
  never a crash). Unresolvable `$VAR` expansions, bare globs, and
  `/dev/null` are skipped, not guessed at. This is the documented
  frontier for a future version, not a finished parser.
- **Opaque Bash writes to protected files are blocked, not scored.** When
  the hook cannot see what is being written (`sed -i`, bare `>`), there is
  no content to score — block mode blocks the bypass shape itself. If that
  is too strict for your workflow, use warn mode or write through the Edit
  tool instead.

## Roadmap

- ~~**Cross-tool write guard**: stop Bash (`sed -i`, heredocs, redirections)
  from bypassing the Edit/Write hooks (thomastartrau: "a guardrail on one
  tool protects nothing if another tool can do the same thing").~~ —
  shipped in v0.5 as `hook-bashwrite`.
- ~~**Cheat-sniffing beyond test files**: catch RNG rigging, subject-mocking,
  and conftest plants (the remdore study: half of cheating never touches
  test files).~~ — shipped in v0.4 as `hook-cheatsniff` +
  `cheatsniff --check`.
- ~~**Comment-slop guard**: intercept the agent dumping conversation state into
  code comments (the "9 out of 10 of my revisions is deleting comments"
  complaint), or a one-command decomment pass before PRs.~~ — shipped in v0.3
  as `hook-commentslop` + `decomment --check/--fix`.
- ~~**Test-honesty hook**: automate the mutation idea — deliberately break an
  assertion, run once, require red~~ — shipped in v0.2 as `mutate-check`.

## Development

```bash
python3 tests/test_agent_guard.py   # 49 script checks
python3 tests/test_cheatsniff.py    # 29 script checks
python3 tests/test_bashwrite.py     # 64 script checks
python3 -m pytest tests/            # 75 pytest tests
```

142 script checks + 75 pytest tests = 217 total, all passing, still zero
dependencies.

## License

MIT
