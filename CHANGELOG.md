# Changelog

## 0.7.1 — 2026-11-06

- Fixed: the Stop hook now catches call-shaped assertion tampering
  (`expect(x).toBe(10)` → `toBe(9)`, `assertEqual`, `assertTrue`, …).
  Previously these never reached the assertion comparison and fell through
  to the >0.9-similarity "renamed" branch, so they were classified legit —
  v0.7.0 let the README's flagship cheat pass. A weakened value is now
  `ambiguous`, a weakened matcher (e.g. `toBe` → `toBeTruthy`) is
  `malicious`.
- Added 5 regression tests for jest / unittest assertion styles.
  Full suite: 178 passed.
- Known issues (pre-existing, not regressions): `agent-guard install`
  does not register the hook-tamper guard (`verify` reports NOT
  INSTALLED); `decomment --check` crashes on emoji input on Windows
  (fail open); 5 install/path tests fail on Windows.

## 0.7.0 — 2026-10-11

- Legit-test-change escape hatch (legit / ambiguous / malicious
  classification), cheatsniff, 12 guards.
