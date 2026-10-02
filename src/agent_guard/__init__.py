"""agent-guard: behavior-guardrail hooks for Claude Code.

Five guards, zero dependencies, fail-open everywhere:
- test-tampering guard (SessionStart snapshot + Stop diff)
- outbound-action guard (PreToolUse denylist on Bash)
- comment-slop guard (PreToolUse scoring on Write/Edit)
- cheat-sniffing guard (PreToolUse on Write/Edit of test files + cheatsniff CLI)
- post-exec read-back verifier (PostToolUse on Bash, advisory)
plus mutate-check (mutation test-honesty CLI).
"""

__version__ = "0.4.0"
