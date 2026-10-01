# agent-guard

Behavior-guardrail hooks for [Claude Code](https://docs.anthropic.com/en/docs/claude-code).
Two guards, one install, zero dependencies (Python standard library only):

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
  an audit log.

The failure modes are real, quoted from the community:

> *"Instead of fixing the indexing logic in the source file, the agent quietly
> modified the test file: it changed `expect(page.items.length).toBe(10)` to
> `toBe(9)`, re-ran the test, saw green, and told us the refactor was
> complete."* — navune, r/ClaudeCode

> *"the real risk is not a bad answer but a bad action"* — dank_as_fuck_,
> r/aiagents, on why guardrails must live *"below the prompt layer"*
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

## Install

```bash
# Not on PyPI yet -- install from source:
git clone https://github.com/hahahahahahahahah6/agent-guard.git
cd agent-guard
pip install .
agent-guard install
```

`install` merges three hook entries into `~/.claude/settings.json` (backing it
up first, never clobbering existing settings):

- `SessionStart` → `agent-guard hook-snapshot` (records digests, never blocks)
- `Stop` → `agent-guard hook-test` (blocks tests-only changes)
- `PreToolUse` on `Bash` → `agent-guard hook-outbound` (blocks denylisted actions)

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
  }
}
```

- `test_guard.mode`: `"block"` (default) or `"warn"`. Env override:
  `AGENT_GUARD_TEST_MODE=warn`.
- `outbound.allow`: regexes that win over the denylist (e.g. your internal
  registry). Every override is audit-logged.
- `outbound.deny_extra` / `disabled_rules`: extend or trim the denylist.

Inspect decisions:

```bash
agent-guard log        # blocked + allowlist-override decisions
agent-guard status     # state paths, mode, active rules
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

## Roadmap

- **Comment-slop guard**: intercept the agent dumping conversation state into
  code comments (the "9 out of 10 of my revisions is deleting comments"
  complaint), or a one-command decomment pass before PRs.
- **Test-honesty hook**: automate the mutation idea — deliberately break an
  assertion, run once, require red; intercept "all green" reports from tests
  that can't fail.

## Development

```bash
python3 tests/test_agent_guard.py   # 13 smoke tests
```

## License

MIT
