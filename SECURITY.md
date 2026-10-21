# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.7.x   | :white_check_mark: |
| < 0.7   | :x:                |

Only the latest minor release line receives security fixes.

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Please report them privately via
[GitHub Security Advisories](https://github.com/hahahahahahahahah6/agent-guard/security/advisories/new).

Include:
- a description of the vulnerability and its impact,
- steps to reproduce (commands, config, minimal example),
- the version you tested against.

We will acknowledge receipt within 72 hours and aim to ship a fix
within 14 days for confirmed high-severity issues. We will credit
reporters in the release notes unless you prefer to stay anonymous.

## Scope

agent-guard is a set of local hooks for AI coding agents (Claude Code,
Codex CLI, Gemini CLI). It runs entirely on the user's machine, makes no
network calls by default, and stores no credentials. The optional
Nemotron semantic-reviewer integration (off by default) sends diffs to a
user-configured LLM endpoint only when explicitly enabled.
