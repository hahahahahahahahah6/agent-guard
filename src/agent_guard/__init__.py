"""agent-guard: behavior-guardrail hooks for Claude Code.

Two guards, zero dependencies, fail-open everywhere:
- test-tampering guard (SessionStart snapshot + Stop diff)
- outbound-action guard (PreToolUse denylist on Bash)
"""

__version__ = "0.1.0"
