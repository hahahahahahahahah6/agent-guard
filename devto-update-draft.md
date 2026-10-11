<!--
DEV.TO UPDATE DRAFT for article ID 4778977
Original URL: https://dev.to/haoli/my-agent-changed-tobe10-to-tobe9-and-called-it-done-i-built-hooks-to-stop-that-8c4
Package: agent-guard-hooks 0.6.0 (https://pypi.org/project/agent-guard-hooks/0.6.0/)
Repo: https://github.com/hahahahahahahahah6/agent-guard

PLACEMENT INSTRUCTIONS (for the agent doing the browser sync):
1. INSERT the "## v0.6" section below immediately BEFORE the existing
   "## v0.5.1: fewer false positives, perl -i" heading. The article lists
   versions newest-first (v0.5.1, v0.5, v0.4, v0.3), so v0.6 goes at the top
   of that stack.
2. REPLACE the "## Honest limitations" section with the updated version
   below (adds the two cross-tool caveats).
3. OPTIONAL: the intro paragraph still says "v0.2 adds three more layers
   (below)" — consider refreshing to "v0.6 adds cross-tool hooks, a
   gate-liveness check, and deeper tamper detection (below)". Leave the
   rest of the article untouched.
4. Test-count line near the end ("47 smoke tests pass...") — REPLACE with:
   "160 pytest tests + 53 unittest tests pass, including the navune
   scenario, cross-tool shim normalization, gate-liveness verdicts, and
   tamper-shape detection."
-->

## v0.6: the same guards on Codex and Gemini, a "did the gate actually run?" check, and deeper tamper detection

Two things happened since v0.5. First, I started running agents in Codex CLI and Gemini CLI too — and a guardrail that only exists in Claude Code protects nothing when the agent lives somewhere else. Second, I read a dev.to post that named the failure mode I was most afraid of.

> *"A gate that has quietly stopped discriminating is worse than no gate"* — yuhaolin2005, *"My Agent Migration Finished. Every Gate Looked Wired. None of Them Ran."*

Every gate looked wired. None of them ran. That's the nightmare: not a missing guard, but a guard everyone trusts that silently stopped checking. So v0.6 is built around one question: **did the gate actually run?**

### The same interception rules, on three tools

```bash
pip install agent-guard-hooks
agent-guard install --tool codex    # ~/.codex/hooks.json
agent-guard install --tool gemini   # ~/.gemini/settings.json
```

Each tool's hook system speaks a slightly different dialect, so `agent-guard shim` normalizes the payload before the guards run: Gemini's `write_file`/`replace`/`run_shell_command` become `Write`/`Edit`/`Bash`, and Codex's `apply_patch` gets its added lines extracted. The guards themselves don't change — the test-tampering rules, the outbound denylist, the cheat-sniffer all run unchanged on every tool.

Two honest caveats, because cross-tool is where these things quietly break: Codex only executes hooks you've trusted (`/hooks` pins a hash per hook — install writes the config, trust is a human step), and Gemini CLI has no blocking `Stop` event, so the test-tampering check runs at `SessionEnd` as an advisory warning there instead of a block.

### `agent-guard verify`: are the gates mounted AND did they run?

```bash
agent-guard verify --tool codex --days 7
```

```
gate check: codex  (last 7 day(s))
guard        mounted     runs  decisions  status
test         yes            2          1  LIVE
outbound     yes            0          0  SILENT
...
  ! SILENT FAILURE: 'outbound' is configured but has 0 runs in the last
    7 day(s) -- the gate looks wired but is not running.
```

Every hook invocation now records a lightweight per-day run counter, alongside the existing audit-log decisions. `verify` cross-references them against the mounted config and reports three verdicts per guard: `LIVE`, `NOT INSTALLED`, or `SILENT` — configured, zero runs, the dangerous one. Exit 1 when anything is missing or silent. Tool transcripts carry no hook-execution traces, so these two instruments are the only honest answer to "did it run?"

### Test tampering, one level deeper

The Stop guard already blocked "test files changed, no source changed." v0.6 also scores *how* the tests were changed — the three shapes that survive the diff check:

- **Weakened assertions**: `toBe(x)` → `toBeTruthy()`, `assertEqual(a, b)` → `assertTrue(a)`. Green while proving less.
- **Skipped / focused tests**: `.skip(`, `.only(`, `xit(`, `pytest.mark.skip`. A skipped failing test is a green suite that proves nothing.
- **Unreviewed snapshot updates**: `toMatchSnapshot()` touches, `.snap` files. `jest -u` makes red go green by redefining "correct".

Caught two ways: a `hook-tamper` PreToolUse hook scores added test text at edit time (`agent-guard tamper-check` for one-shot scans), and the Stop hook's block message now names the shapes it found — so the agent sees *what kind* of tampering it tried, not just "tests changed."

### How it differs

vs **Zoria-Lind behavior-enhancer-generic**: that's a general-purpose, Chinese-language interception layer — broad behavioral rules for agents. agent-guard bets the other way: narrow to one failure family (test tampering), go deep on it (snapshot diffing, cheat-sniffing, tamper shapes, mutation honesty), then carry those rules across tools with a verifier that proves the gates are actually running. Breadth of interception vs depth on test honesty.

## Honest limitations (updated for v0.6)

- "Tests changed, source didn't" is a strong signal, not a proof. Legit test-only refactors get flagged — use `ignore_paths` or warn mode.
- The outbound guard watches `Bash`. An agent calling a Slack MCP tool directly is out of scope for this version.
- The spend denylist is best-effort; it's a seatbelt, not a vault.
- Slop detection is stylistic regex heuristics tuned for low false positives — subtle slop (a well-written but pointless paragraph) scores 0. Comment-heavy codebases should use warn mode or raise the threshold.
- The hook protocol (stdin shape, exit-2-blocks) is community-documented, not a stable API.
- **Cross-tool hooks inherit each tool's limits.** Codex only runs hooks you've trusted and ignores `hooks.json` without `[features] hooks=true`; Gemini CLI can't block at session end, so the test-tampering check there warns instead of blocking. `verify` reports the wiring it can see — it can't confirm you finished Codex's trust step.
- **Tamper detection is pattern-based.** Rephrased-but-weakened assertions (the kind only a model would notice) are the semantic reviewer's job, not the regexes'.
