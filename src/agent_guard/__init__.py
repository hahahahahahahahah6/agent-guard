"""agent-guard: behavior-guardrail hooks for Claude Code, Codex CLI and
Gemini CLI.

Eight guards, zero dependencies, fail-open everywhere:
- test-tampering guard (SessionStart snapshot + Stop diff)
- outbound-action guard (PreToolUse denylist on Bash)
- comment-slop guard (PreToolUse scoring on Write/Edit)
- cheat-sniffing guard (PreToolUse on Write/Edit of test files + cheatsniff CLI)
- cross-tool write guard (PreToolUse on Bash: sed -i / heredocs / redirections
  that bypass the Edit/Write hooks)
- post-exec read-back verifier (PostToolUse on Bash, advisory)
- tamper-shape guard (weakened assertions, skipped/focused tests,
  snapshot updates + tamper-check CLI)
- gate-liveness verifier (`agent-guard verify`: are the gates mounted
  AND did they actually run?)
- legit-test-change escape hatch (`--allow-test-change`: explicit,
  audited one-shot bypass for legitimate test edits, plus per-file
  legit/ambiguous/malicious classification on the Stop hook)
plus mutate-check (mutation test-honesty CLI) and cross-tool install
(`install --tool codex|gemini`).
"""

__version__ = "0.7.0"
