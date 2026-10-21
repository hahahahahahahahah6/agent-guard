"""pytest tests for the automatic Nemotron second opinion.

Covers semreview.auto_enabled / available / build_change_context /
review_suspicious and the testguard Stop-hook integration. All network
access is mocked: AGENT_GUARD_SEMREVIEW_MOCK or an injected MockProvider.
No test touches the real Token Factory API.

Run:  python -m pytest tests/test_semreview_auto.py -q   (from repo root)
"""

import json
import os
import urllib.request

import pytest

from agent_guard import semreview, state, testguard

BLOCK_JSON = json.dumps({
    "verdict": "block", "confidence": 0.92,
    "rationale": "Assertion weakened to a near-tautology.",
    "rule_hint": "weakened-assertion",
})
PASS_JSON = json.dumps({
    "verdict": "pass", "confidence": 0.99,
    "rationale": "Benign change.", "rule_hint": "",
})


@pytest.fixture()
def tmp_state(tmp_path, monkeypatch):
    """Isolate AGENT_GUARD_DIR and clear semreview env per test."""
    d = str(tmp_path / "state")
    monkeypatch.setenv("AGENT_GUARD_DIR", d)
    monkeypatch.delenv("NEBIUS_API_KEY", raising=False)
    monkeypatch.delenv("AGENT_GUARD_SEMREVIEW_MOCK", raising=False)
    monkeypatch.delenv("AGENT_GUARD_SEMREVIEW_AUTO", raising=False)
    return d


def _cfg(**over):
    cfg = state.default_config()
    cfg["semreview"].update(over)
    return cfg


def _proj(tmp_path, old_test, new_test):
    """Project with one test file changed after the snapshot."""
    proj = tmp_path / "proj"
    (proj / "tests").mkdir(parents=True)
    (proj / "src").mkdir(parents=True)
    (proj / "src" / "app.py").write_text("def f():\n    return 1\n")
    (proj / "tests" / "test_x.py").write_text(old_test)
    testguard.snapshot(str(proj), session_id="s1")
    (proj / "tests" / "test_x.py").write_text(new_test)
    return str(proj)


WEAK_OLD = "def test_f():\n    assert f() == 1\n"
WEAK_NEW = "def test_f():\n    assert f() >= 0\n"          # -> "malicious"
LEGIT_NEW = WEAK_OLD + "\ndef test_g():\n    assert f() == 1\n"  # -> "legit"


# ---------------------------------------------------------------------------
# auto_enabled / available
# ---------------------------------------------------------------------------

def test_auto_disabled_by_default(tmp_state):
    assert semreview.auto_enabled() is False
    assert semreview.auto_enabled(_cfg()) is False


def test_auto_enabled_via_config(tmp_state):
    assert semreview.auto_enabled(_cfg(auto=True)) is True


def test_auto_env_overrides_config(tmp_state, monkeypatch):
    monkeypatch.setenv("AGENT_GUARD_SEMREVIEW_AUTO", "0")
    assert semreview.auto_enabled(_cfg(auto=True)) is False
    monkeypatch.setenv("AGENT_GUARD_SEMREVIEW_AUTO", "1")
    assert semreview.auto_enabled(_cfg(auto=False)) is True
    monkeypatch.setenv("AGENT_GUARD_SEMREVIEW_AUTO", "true")
    assert semreview.auto_enabled() is True
    monkeypatch.setenv("AGENT_GUARD_SEMREVIEW_AUTO", "bogus")
    assert semreview.auto_enabled(_cfg(auto=True)) is True  # falls back


def test_available(tmp_state, monkeypatch):
    assert semreview.available() is False
    monkeypatch.setenv("NEBIUS_API_KEY", "k")
    assert semreview.available() is True
    monkeypatch.delenv("NEBIUS_API_KEY")
    monkeypatch.setenv("AGENT_GUARD_SEMREVIEW_MOCK", PASS_JSON)
    assert semreview.available() is True


# ---------------------------------------------------------------------------
# build_change_context / review_suspicious units
# ---------------------------------------------------------------------------

def test_build_change_context():
    ctx = semreview.build_change_context(
        "tests/test_x.py",
        {"verdict": "malicious",
         "markers": [("weakened-assertion", "assert f() == 1 -> assert f() >= 0")]})
    assert "malicious" in ctx
    assert "weakened-assertion" in ctx


def test_review_suspicious_sends_diff_and_context(tmp_state, monkeypatch):
    monkeypatch.setenv("AGENT_GUARD_SEMREVIEW_MOCK", BLOCK_JSON)
    seen = []

    class Cap(semreview.MockProvider):
        def complete(self, prompt):
            seen.append(prompt)
            return super().complete(prompt)

    out = semreview.review_suspicious(
        {"tests/test_x.py": (WEAK_OLD, WEAK_NEW,
                              {"verdict": "malicious", "markers": []})},
        cfg=_cfg(), provider=Cap(BLOCK_JSON))
    assert set(out) == {"tests/test_x.py"}
    assert out["tests/test_x.py"]["verdict"] == "block"
    prompt = seen[0]
    assert "-    assert f() == 1" in prompt      # unified diff old line
    assert "+    assert f() >= 0" in prompt      # unified diff new line
    assert "pattern-guard classification" in prompt


def test_review_suspicious_skips_degraded(tmp_state, monkeypatch):
    monkeypatch.setenv("AGENT_GUARD_SEMREVIEW_MOCK", "not json at all")
    out = semreview.review_suspicious(
        {"tests/test_x.py": (WEAK_OLD, WEAK_NEW,
                              {"verdict": "malicious", "markers": []})},
        cfg=_cfg())
    assert out == {}


def test_review_suspicious_identical_text_skipped(tmp_state, monkeypatch):
    monkeypatch.setenv("AGENT_GUARD_SEMREVIEW_MOCK", BLOCK_JSON)
    out = semreview.review_suspicious(
        {"tests/test_x.py": (WEAK_OLD, WEAK_OLD,
                              {"verdict": "malicious", "markers": []})},
        cfg=_cfg())
    assert out == {}


# ---------------------------------------------------------------------------
# testguard Stop-hook integration
# ---------------------------------------------------------------------------

def _enable_auto(monkeypatch, mock_json=BLOCK_JSON):
    monkeypatch.setenv("AGENT_GUARD_SEMREVIEW_AUTO", "1")
    monkeypatch.setenv("AGENT_GUARD_SEMREVIEW_MOCK", mock_json)


def test_hook_off_by_default_no_semantic(tmp_state, tmp_path, monkeypatch):
    proj = _proj(tmp_path, WEAK_OLD, WEAK_NEW)
    detail = testguard.check_detail(proj, session_id="s1")
    assert detail["allowed"] is False  # deterministic guard still blocks
    v = detail["verdicts"]["tests/test_x.py"]
    assert "semantic" not in v
    assert "Semantic second opinion" not in detail["reason"]


def test_hook_auto_attaches_opinion(tmp_state, tmp_path, monkeypatch):
    _enable_auto(monkeypatch)
    proj = _proj(tmp_path, WEAK_OLD, WEAK_NEW)
    detail = testguard.check_detail(proj, session_id="s1")
    assert detail["allowed"] is False  # advisory: decision unchanged
    v = detail["verdicts"]["tests/test_x.py"]
    assert v["semantic"]["verdict"] == "block"
    assert v["semantic"]["confidence"] == 0.92
    assert "Semantic second opinion" in detail["reason"]
    assert "WEAK" not in detail["reason"]  # warn-mode downgrade is WARN
    assert "WARN" in detail["reason"]


def test_hook_auto_config_key_works(tmp_state, tmp_path, monkeypatch):
    cfg = _cfg(auto=True)
    os.makedirs(tmp_state, exist_ok=True)
    with open(os.path.join(tmp_state, "config.json"), "w") as fh:
        json.dump(cfg, fh)
    monkeypatch.setenv("AGENT_GUARD_SEMREVIEW_MOCK", BLOCK_JSON)
    proj = _proj(tmp_path, WEAK_OLD, WEAK_NEW)
    detail = testguard.check_detail(proj, session_id="s1")
    assert "semantic" in detail["verdicts"]["tests/test_x.py"]


def test_hook_auto_skipped_without_key_or_mock(tmp_state, tmp_path,
                                               monkeypatch):
    monkeypatch.setenv("AGENT_GUARD_SEMREVIEW_AUTO", "1")

    def _nope(req, timeout=None):
        raise AssertionError("no network without key/mock")

    monkeypatch.setattr("urllib.request.urlopen", _nope)
    proj = _proj(tmp_path, WEAK_OLD, WEAK_NEW)
    detail = testguard.check_detail(proj, session_id="s1")
    assert detail["allowed"] is False
    assert "semantic" not in detail["verdicts"]["tests/test_x.py"]
    assert "Semantic second opinion" not in detail["reason"]


def test_hook_auto_skips_legit_files(tmp_state, tmp_path, monkeypatch):
    _enable_auto(monkeypatch)
    proj = _proj(tmp_path, WEAK_OLD, LEGIT_NEW)
    detail = testguard.check_detail(proj, session_id="s1")
    assert detail["allowed"] is True  # legit change: session may stop
    v = detail["verdicts"]["tests/test_x.py"]
    assert v["verdict"] == "legit"
    assert "semantic" not in v  # legit files are never sent


def test_hook_auto_pass_verdict_does_not_unblock(tmp_state, tmp_path,
                                                 monkeypatch):
    _enable_auto(monkeypatch, PASS_JSON)
    proj = _proj(tmp_path, WEAK_OLD, WEAK_NEW)
    detail = testguard.check_detail(proj, session_id="s1")
    assert detail["allowed"] is False  # model "pass" cannot override a block
    assert detail["verdicts"]["tests/test_x.py"]["semantic"]["verdict"] \
        == "pass"


def test_hook_auto_malformed_model_output_skipped(tmp_state, tmp_path,
                                                 monkeypatch):
    _enable_auto(monkeypatch, "definitely not json")
    proj = _proj(tmp_path, WEAK_OLD, WEAK_NEW)
    detail = testguard.check_detail(proj, session_id="s1")
    assert detail["allowed"] is False
    assert "semantic" not in detail["verdicts"]["tests/test_x.py"]
    assert "Semantic second opinion" not in detail["reason"]
