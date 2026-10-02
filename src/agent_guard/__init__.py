"""agent-guard: behavior-guardrail hooks for Claude Code.

Six guards, zero dependencies, fail-open everywhere:
- test-tampering guard (SessionStart snapshot + Stop diff)
- outbound-action guard (PreToolUse denylist on Bash)
- comment-slop guard (PreToolUse scoring on Write/Edit)
- cheat-sniffing guard (PreToolUse on Write/Edit of test files + cheatsniff CLI)
- cross-tool write guard (PreToolUse on Bash: sed -i / heredocs / redirections
  that bypass the Edit/Write hooks)
- post-exec read-back verifier (PostToolUse on Bash, advisory)
plus mutate-check (mutation test-honesty CLI).
"""

__version__ = "0.5.0"
