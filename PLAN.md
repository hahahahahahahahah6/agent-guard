# agent-guard — PLAN

## What
Standalone suite of Claude Code behavior-guardrail hooks. Intercepts agent
actions **below the prompt layer** (the community-consensus placement:
r/aiagents 9/28 — "the real risk is not a bad answer but a bad action",
dank_as_fuck_).

Backlog item #8, current #1 priority. Ships as its own repo/package
`agent-guard` (GitHub) / `agent-guard-hooks` (PyPI; `agent-guard` is taken).
edit-guard keeps its crisp single-purpose identity (stale cross-session edit
blocking); agent-guard is the behavior suite.

## Evidence (backlog #8)
- r/ClaudeCode 9/29 navune: agent changed `toBe(10)`→`toBe(9)` instead of
  fixing source; "All 14 tests passing" nearly passed review. Workaround was a
  manual pre-commit abort on test changes.
- r/ClaudeCode 9/28 "Do you feel that claude code unit tests are useless?"
  (136 pts / 91 comments): kuroudo_ai — "every generated test should be
  forced to prove it can fail". Consensus: independent verification must come
  from a different session than the one that wrote the code.
- r/ClaudeCode 9/29 misteraidenc: multi-session agents turn drafts into
  outbound actions/merges; verstands — boundary must sit below the prompt
  layer → hooks.
- Competitor: Rashomon (r/aiagents 9/29) records commands/edits and *compares*
  against the agent's summary. That's the **observe** layer; agent-guard is
  the **prevent** layer. Complementary, not a collision.

## MVP scope (shippable)
### (a) test-tampering guard
- `agent-guard hook-snapshot` on **SessionStart**: walk project dir, sha256 all
  test files → `~/.config/agent-guard/test-snapshot.json`.
- `agent-guard hook-test` on **Stop**: re-hash, diff vs snapshot.
  - tests-only changed, source untouched → BLOCK (exit 2): "test assertions
    changed without source changes — verify the test actually fails without
    the fix (revert the source change and re-run; a test that really covered
    the bug goes red again)."
  - both changed / nothing changed → allow.
  - missing or corrupt snapshot → fail open.
- Config escape hatch: `AGENT_GUARD_TEST_MODE=warn` or
  `config.json` → warn-only; `ignore_paths` list.

### (b) outbound-action guard
- `agent-guard hook-outbound` on **PreToolUse** (matcher `Bash`): regex
  denylist over the command string. Rules: git-push-protected
  (`main|master|prod|release/*`, plus any `--force` push), package publish
  (`npm publish`, `twine upload`, `cargo publish`, `gh release create`),
  prod deploys (`kubectl apply|delete`, `terraform apply`, `fly deploy`,
  `vercel --prod`, `serverless deploy`), cloud-provision spend
  (`aws ec2 run-instances`, `gcloud compute instances create`, …),
  mass-send (`hooks.slack.com/services`, `sendmail`, `msmtp`,
  sendgrid/mailgun API URLs).
- Match → BLOCK (exit 2) naming the rule. Allowlist override via
  `config.json` (`outbound.allow` regexes win over denylist;
  `deny_extra`, `disabled_rules` supported).
- Every evaluated decision that matched a rule (blocked or
  allowed-by-allowlist) is appended to `audit.jsonl`. Clean passthroughs are
  not logged (noise); `--verbose`/`AGENT_GUARD_VERBOSE=1` logs everything.

### Out of MVP → README roadmap
- (c) comment-slop guard, (d) mutation-style test-honesty hook.

## Architecture (edit-guard patterns reused)
- stdlib-only Python. **Fail-open everywhere**: any exception → allow (exit 0).
- State: `~/.config/agent-guard/` (`AGENT_GUARD_DIR` override).
- CLI: `agent-guard install|hook-snapshot|hook-test|hook-outbound|log|status`.
- `install` merges 3 hook entries into `~/.claude/settings.json` with backup,
  idempotent: SessionStart → `agent-guard hook-snapshot`; Stop →
  `agent-guard hook-test`; PreToolUse `Bash` → `agent-guard hook-outbound`.

## Tests (~12, all must pass)
test-tamper: tests-only→block+message; src+tests→allow; no-change→allow;
corrupt snapshot→fail-open. outbound: `git push origin main`→block;
`npm publish`→block; `twine upload dist/*`→block; benign push/feature
branch→allow; `ls`→allow; allowlist override→allow+audited; corrupt
config→fail-open; block writes audit entry. install: merges settings.json
idempotently (tmp HOME).

## Ship checklist
1. `python3 tests/test_agent_guard.py` — 12/12 green.
2. GitHub: public repo `agent-guard` via `gh-push` (handles empty-repo init).
   MIT + English README with Differentiation section (vs Rashomon:
   prevent vs observe; vs edit-guard: stale-edit vs behavior guardrails).
3. PyPI: `agent-guard-hooks` 0.1.0 via twine + `~/.config/pypi/token`.
   On 429: STOP, wait ≥1h, retry once, then leave it.
4. dev.to: write `devto-article.md`; publishing needs a browser task —
   delegate to parent (no API key in `~/.config/devto/`, only password).
5. Backlog #8 → ✅ published with links.
