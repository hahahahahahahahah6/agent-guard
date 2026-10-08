# Hackathon changelog

## GitLab Transcend: Life After Code (submission due 2026-10-27)

- `.gitlab-ci.yml` (new): two-stage pipeline — **test** (`pytest` on a
  Python 3.10–3.13 matrix + a stdlib-only smoke job: `py_compile` over
  `src/` and `--help` on the CLI entry points, JUnit artifacts) and
  **guard** (`guard-self-check`: agent-guard scans its own changed files
  per commit — `cheatsniff --check` on tests, `decomment --check` on
  sources). stdlib-only shipped code; `pytest` is the only installed extra.
  README gained a "GitLab CI" section; the pipeline badge lands once the
  repo is mirrored to GitLab.com.

---

## Nebius x NVIDIA Global AI Hackathon

agent-guard predates the submission period (first released 2026-09-30).
Everything below was built during the submission period for the
**Coding & Agentic Engineering** track.

## New: Semantic reviewer (`semreview`) — the hackathon entry

- `src/agent_guard/semreview.py` (new): sends test-file diffs and shell
  commands to an NVIDIA Nemotron model on **Nebius Token Factory**
  (OpenAI-compatible `POST /chat/completions` at
  `https://api.tokenfactory.nebius.com/v1`) for a semantic
  block/warn/pass verdict with confidence, rationale, and rule hint.
- Default model: `nvidia/nemotron-3-nano-30b-a3b` (cheap, fast, JSON
  reliable); override via `AGENT_GUARD_SEMREVIEW_MODEL`.
- Catches what the regex guards miss: rephrased-but-weakened assertions,
  deleted edge cases, obfuscated exfiltration.
- Fail-open by design: no key / network error / timeout (20s) /
  token budget (~4k) / malformed model output all degrade to `warn`,
  never block. Warn mode (default) downgrades model `block` to `warn`.
- Verdicts cached by content hash (7-day TTL) in the state dir.
- stdlib only (`urllib`); zero new dependencies.
- `agent-guard semreview --diff <file> | --command "<cmd>" [--json]`
  wired in `cli.py`; decisions audit-logged.
- `tests/test_semreview.py` (new): 32 pytest tests, all against a
  deterministic mock provider or monkeypatched `urllib` — no network.
- README: new "Semantic reviewer (Nebius x NVIDIA)" section.

## Unchanged from before the period

v0.5.1 pattern guards (test-tampering, outbound denylist, cheat-sniff,
comment-slop, bash-write, mutation checker, post-exec verifier) — the
semantic reviewer is an advisory layer on top; the patterns remain the
enforcement layer.
