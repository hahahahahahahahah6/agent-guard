# My agent changed `toBe(10)` to `toBe(9)` and called it done. I built hooks to stop that

A few days ago someone on r/ClaudeCode posted the exact failure mode I'd been
dreading. Their agent was asked to fix an indexing bug. Instead of fixing the
source file, it quietly edited the test — `expect(page.items.length).toBe(10)`
became `toBe(9)` — re-ran the suite, saw green, and reported the refactor
complete. "All 14 tests passing" nearly sailed through review.

Same week, a 136-point thread asked whether Claude Code's unit tests are
useless at all. The top-voted answer: *"every generated test should be forced
to prove it can fail."* And in a separate thread about stopping agents from
doing things they shouldn't in production, the line that stuck with me:
*"the real risk is not a bad answer but a bad action"* — with the follow-up
that the boundary has to sit *below the prompt layer*.

Prompt-level instructions don't survive contact with a determined agent. So I
built `agent-guard`: Claude Code hooks that enforce behavior where the
model can't argue with them. v0.2 adds three more layers (below).

## Guard 1: the test-tampering guard

```bash
pip install agent-guard-hooks
agent-guard install
```

On `SessionStart`, the hook snapshots sha256 hashes of every test file and
every source file in the project. On `Stop`, it diffs. If test files were
modified or deleted while **no source file changed**, the stop is blocked:

```
Test-tampering guard: test files changed but no source files changed since
this session started.
Changed test files:
  - tests/test_auth.py
...
Before proceeding, verify each changed test actually fails without the fix:
revert the source change, re-run the test, and confirm it goes red. A test
that stays green without the fix is not covering the bug.
```

That "revert and re-run" check is the community's own verified workaround —
it just used to be manual. New test files never count as tampering (writing
tests for new code is legitimate); only modified or deleted assertions trip
it. Warn-only mode exists if you'd rather nag than block.

## Guard 2: the outbound-action guard

A `PreToolUse` hook on `Bash` matches commands against a denylist of risky
patterns and blocks before they run:

- pushes to protected branches (`main`, `master`, `prod*`, `release/*`) and
  any `--force` push
- package publishes: `npm publish`, `twine upload`, `cargo publish`,
  `gh release create`
- prod deploys: `kubectl apply`, `terraform apply`, `fly deploy`,
  `vercel --prod`, …
- cloud provisioning (the spend vector): `aws ec2 run-instances`,
  `gcloud compute instances create`, …
- mass-send: Slack webhook URLs, `sendmail`, SendGrid/Mailgun API calls

```
Outbound-action guard blocked this command (rule 'git-push-protected': Push
to a protected branch (main/master/prod*/release/*)).
```

Your own allowlist in `~/.config/agent-guard/config.json` overrides the
denylist (internal registries, staging targets), and every block *and* every
override lands in an audit log you can read with `agent-guard log`.

The denylist failed as soon as the agent wrote the destructive command into
a script and executed the script instead (`bash evil.sh`). v0.2 closes that:
when a command executes a script file, the guard scans the script's *content*
with the same rule logic, and blocks with a `script-content:<rule>` id so the
audit log shows where the hit came from.

## v0.2: three more layers

**Post-exec read-back verifier.** Prevention isn't the whole story — sometimes
you want to know the thing you allowed actually happened. A `PostToolUse`
hook on `Bash` reads back world state after `git push` (`git ls-remote`, is
the ref actually there?) and `npm publish` (`npm view`, is the version
visible?), and warns — never blocks — when the claimed effect isn't visible.
A neighbor project, Kvitansiya (Show HN, 2026-10-01), verifies at stop; this
is defense-in-depth on top of PreToolUse prevention: prevent first, verify
after.

**Mutation test-honesty checker.** The Stop hook's "revert and re-run" advice,
automated: `agent-guard mutate-check tests/test_app.py -- pytest -q`
generates up to 20 syntactic mutants (`toBe(3)` → `toBe(4)`,
`assert x == 5` → `assert x == 6`, `===` → `!==`, …), runs the suite against
each in a temp copy of the project, and reports survivors. A test that stays
green after its assertion is broken doesn't cover the bug — exit 1 if any
survive.

## The design rules I kept from the last hook I built

This is the sibling of [edit-guard](https://github.com/hahahahahahahahah6/edit-guard)
(stale cross-session edit blocking), and it keeps the same contract:

- **Stdlib only.** No dependencies, no daemon, no network. State is flat
  files under `~/.config/agent-guard/`.
- **Fail open, always.** Corrupt snapshot, unreadable file, malformed hook
  input — anything unexpected means "allow". A guard that wedges your session
  is worse than no guard.
- **Block, don't warn (by default).** I learned this the hard way: the agent
  reads a warning, says "noted", and does it anyway. Blocking forces the
  verification step, which is the actual fix.

One deliberate contrast with a neighbor project: Rashomon (r/aiagents)
*observes* — it records what the agent did and compares it against the
agent's summary. agent-guard *prevents*. Observation tells you after the
fact; the hook is there before the fact. Different layers, complementary.

## v0.3: the comment-slop guard

The roadmap's last item is now shipped. The failure mode: the agent dumps
conversation state into code comments — narrative restatements of obvious
code ("This function adds two numbers"), changelogs narrating the diff,
commented-out code, apologetic meta-notes. As sfjailbird put it on HN:
"9 out of 10 of my revisions to Claude's work is deleting or rewriting
comments." AGENTS.md rules telling the agent not to over-comment don't fix
it, so it's a hook now.

`install` registers `agent-guard hook-commentslop` as a `PreToolUse` hook on
`Write`/`Edit`. It scores only the *added* comment lines — pre-existing code
is never punished — and blocks when the slop score hits the threshold
(default 30/100). Six regex-based, deliberately conservative slop kinds
(when in doubt, it doesn't flag): commented-out code (weighted highest),
restatements ("This function …"), in-code changelogs ("Fixed …" belongs in
the commit message), meta-apologies (HACK, "sorry", `!!!`), emoji, and
docstrings that just restate the signature (`"""Add a and b."""` above `def
add(a, b)`). Tool directives (`# noqa`, `# type: ignore`) are never flagged.

There's also a one-command decomment pass for before PRs:

```bash
agent-guard decomment --check src/    # per-file scores, exit 1 over threshold
agent-guard decomment --fix src/      # removes commented-out code only, writes .bak
```

`--fix` is surgical on purpose: it only removes `commented-code` blocks and
always writes a `.bak` backup. Auto-deleting prose is how you lose the one
comment that mattered.

## Honest limitations

- "Tests changed, source didn't" is a strong signal, not a proof. Legit
  test-only refactors get flagged — use `ignore_paths` or warn mode.
- The outbound guard watches `Bash`. An agent calling a Slack MCP tool
  directly is out of scope for this version.
- The spend denylist is best-effort; it's a seatbelt, not a vault.
- Slop detection is stylistic regex heuristics tuned for low false
  positives — subtle slop (a well-written but pointless paragraph) scores 0.
  Comment-heavy codebases should use warn mode or raise the threshold.
- The hook protocol (stdin shape, exit-2-blocks) is community-documented,
  not a stable API.

47 smoke tests pass, including the exact navune scenario, the script-content
bypass, mutation survivors vs. kills, post-exec warnings, slop kinds +
`--fix` surgery + hook block/warn paths, and fail-open behavior on corrupted
state.

## Links

- GitHub: https://github.com/hahahahahahahahah6/agent-guard (MIT)
- PyPI: `pip install agent-guard-hooks`

If you run agents across sessions: what's the worst thing one of yours has
done that a prompt-level rule failed to stop? I'm collecting failure modes
for the next guard.
