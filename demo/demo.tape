# agent-guard demo — the test-tampering trap, caught (60-90s).
# Renders GIF (README) and MP4 (Devpost / hackathon submission).
# Run:  vhs demo.tape            -> agent-guard-demo.mp4
#       (swap Output line)        -> agent-guard-demo.mp4

Output agent-guard-demo.gif
Set Shell bash
Set FontFamily "DejaVu Sans Mono"
Set FontSize 18
Set Width 1100
Set Height 640
Set Theme "Catppuccin Mocha"
Set Padding 16
Set TypingSpeed 35ms

Hide
Type `cd /home/hatch/workspace/agent-guard/demo/fixtures/shop && clear` Enter
Sleep 1s
Show

Type `echo '=== agent-guard: the test-tampering trap ==='` Enter
Sleep 3s

# SessionStart hook snapshots digests of every test + source file.
Type `echo '{"session_id":"vhs-demo"}' | agent-guard hook-snapshot` Enter
Sleep 1s
Type `echo '[SessionStart] snapshotted test + source digests'` Enter
Sleep 2s

# The failure mode, quoted from r/ClaudeCode: instead of fixing the
# indexing logic, the agent quietly weakens the assertion.
Type `grep -n 'toBe' tests/cart.test.js` Enter
Sleep 2.5s
Type `echo '[agent] refactor broke pagination... just weaken the test instead:'` Enter
Sleep 2s
Type `sed -i 's/toBe(10)/toBe(9)/' tests/cart.test.js && grep -n 'toBe' tests/cart.test.js` Enter
Sleep 3s

# Stop hook: test files changed, no source files changed -> BLOCKED.
Type `echo '{"session_id":"vhs-demo"}' | agent-guard hook-test; echo "blocked, exit=$?"` Enter
Sleep 6s

# Cheat-sniffing: the cheating that never touches test assertions
# (RNG rigging, mocking the subject under test).
Type `echo '=== cheatsniff: cheating that never touches assertions ==='` Enter
Sleep 2s
Type `agent-guard cheatsniff --check tests/; echo "exit=$?"` Enter
Sleep 4s

# Comment-slop guard: narrative slop in added comments.
Type `agent-guard decomment --check src/slop.py; echo "exit=$?"` Enter
Sleep 5s

# Honest tests stay green.
Type `echo '=== honest tests stay green ==='` Enter
Sleep 2s
Type `PYTHONPATH=src pytest tests/test_honest.py -q` Enter
Sleep 3s

Type `echo 'agent-guard: guardrails below the prompt layer'` Enter
Sleep 0.5s
Type `echo 'github.com/hahahahahahahahah6/agent-guard'` Enter
Sleep 4s
