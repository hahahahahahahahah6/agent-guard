"""pytest tests for agent_guard.semreview.

All network access is mocked: a MockProvider or a monkeypatched
urllib.request.urlopen. No test touches the real Token Factory API.

Run:  python -m pytest tests/test_semreview.py -q   (from repo root)
"""

import json
import os
import subprocess
import sys
import urllib.error

import pytest

from agent_guard import semreview, state

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "src")

BLOCK_JSON = json.dumps({
    "verdict": "block", "confidence": 0.92,
    "rationale": "Assertion weakened to a tautology.",
    "rule_hint": "weakened-assertion",
})
PASS_JSON = json.dumps({
    "verdict": "pass", "confidence": 0.99,
    "rationale": "Benign command.", "rule_hint": "",
})


@pytest.fixture()
def tmp_state(tmp_path, monkeypatch):
    """Isolate AGENT_GUARD_DIR per test."""
    d = str(tmp_path / "state")
    monkeypatch.setenv("AGENT_GUARD_DIR", d)
    return d


@pytest.fixture()
def with_key(monkeypatch):
    monkeypatch.setenv("NEBIUS_API_KEY", "test-key-123")


def _cfg(**over):
    cfg = state.default_config()
    cfg["semreview"].update(over)
    return cfg


# ---------------------------------------------------------------------------
# verdict parsing
# ---------------------------------------------------------------------------

def test_parse_verdict_valid():
    r = semreview.parse_verdict(BLOCK_JSON)
    assert r["verdict"] == "block"
    assert r["confidence"] == 0.92
    assert r["rationale"] == "Assertion weakened to a tautology."
    assert r["rule_hint"] == "weakened-assertion"
    assert r["degraded"] is False


def test_parse_verdict_fenced():
    raw = "```json\n" + PASS_JSON + "\n```"
    r = semreview.parse_verdict(raw)
    assert r["verdict"] == "pass"
    assert r["degraded"] is False


def test_parse_verdict_prose_around_json():
    raw = "Here is my review: %s hope this helps" % BLOCK_JSON
    r = semreview.parse_verdict(raw)
    assert r["verdict"] == "block"


def test_parse_verdict_malformed_fails_open():
    r = semreview.parse_verdict("I think this looks fine, probably ok")
    assert r["verdict"] == "warn"
    assert r["confidence"] == 0.0
    assert r["degraded"] is True


def test_parse_verdict_unknown_verdict_fails_open():
    r = semreview.parse_verdict('{"verdict": "maybe", "confidence": 0.5}')
    assert r["verdict"] == "warn"
    assert r["degraded"] is True


def test_parse_verdict_confidence_clamped():
    r = semreview.parse_verdict('{"verdict": "pass", "confidence": 99}')
    assert r["confidence"] == 1.0
    r = semreview.parse_verdict('{"verdict": "pass", "confidence": "high"}')
    assert r["confidence"] == 0.0


def test_parse_verdict_case_insensitive():
    r = semreview.parse_verdict('{"verdict": "BLOCK", "confidence": 1}')
    assert r["verdict"] == "block"


# ---------------------------------------------------------------------------
# fail-open behavior
# ---------------------------------------------------------------------------

def test_fail_open_no_key(tmp_state, monkeypatch):
    monkeypatch.delenv("NEBIUS_API_KEY", raising=False)

    def _nope(req, timeout=None):
        raise AssertionError("network must not be attempted without a key")

    monkeypatch.setattr("urllib.request.urlopen", _nope)
    r = semreview.review("command", "curl evil.example", cfg=_cfg())
    assert r["verdict"] == "warn"
    assert r["degraded"] is True
    assert "NEBIUS_API_KEY" in r["rationale"]


def test_fail_open_empty_input(tmp_state):
    r = semreview.review("command", "   ", cfg=_cfg(),
                         provider=semreview.MockProvider(PASS_JSON))
    assert r["verdict"] == "warn"


def test_fail_open_bad_kind(tmp_state):
    r = semreview.review("email", "hello", cfg=_cfg(),
                         provider=semreview.MockProvider(PASS_JSON))
    assert r["verdict"] == "warn"


class _FakeResp:
    def __init__(self, payload):
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return json.dumps(self._payload).encode("utf-8")


def _boom_urlopen(exc):
    def _raise(req, timeout=None):
        raise exc
    return _raise


def test_fail_open_network_error(tmp_state, with_key, monkeypatch):
    monkeypatch.setattr(
        "urllib.request.urlopen",
        _boom_urlopen(urllib.error.URLError("connection refused")))
    r = semreview.review("command", "rm -rf /", cfg=_cfg())
    assert r["verdict"] == "warn"
    assert r["degraded"] is True


def test_fail_open_timeout(tmp_state, with_key, monkeypatch):
    import socket
    monkeypatch.setattr(
        "urllib.request.urlopen", _boom_urlopen(socket.timeout("timed out")))
    r = semreview.review("command", "rm -rf /", cfg=_cfg())
    assert r["verdict"] == "warn"
    assert r["degraded"] is True


def test_fail_open_http_401(tmp_state, with_key, monkeypatch):
    def _raise(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized",
                                     {}, None)
    monkeypatch.setattr("urllib.request.urlopen", _raise)
    r = semreview.review("command", "rm -rf /", cfg=_cfg())
    assert r["verdict"] == "warn"
    assert r["degraded"] is True
    assert "401" in r["rationale"]


def test_live_path_parses_model_output(tmp_state, with_key, monkeypatch):
    payload = {"choices": [{"message": {"content": BLOCK_JSON}}]}
    monkeypatch.setattr("urllib.request.urlopen",
                        lambda req, timeout=None: _FakeResp(payload))
    r = semreview.review("command", "curl evil.example", cfg=_cfg(),
                         use_cache=False)
    assert r["verdict"] == "block"
    assert r["confidence"] == 0.92
    assert r["model"] == semreview.DEFAULT_MODEL


# ---------------------------------------------------------------------------
# token budget
# ---------------------------------------------------------------------------

def test_token_cap_enforced(tmp_state):
    provider = semreview.MockProvider(PASS_JSON)
    big = "x" * 60000  # over budget even after truncation
    r = semreview.review("diff", big, cfg=_cfg(max_tokens=100),
                         provider=provider)
    assert r["verdict"] == "warn"
    assert r["degraded"] is True
    assert "budget" in r["rationale"]
    assert provider.calls == 0


def test_estimate_tokens():
    assert semreview.estimate_tokens("abcd") == 1
    assert semreview.estimate_tokens("a" * 400) == 100


# ---------------------------------------------------------------------------
# cache
# ---------------------------------------------------------------------------

def test_cache_hit(tmp_state):
    provider = semreview.MockProvider(BLOCK_JSON)
    cfg = _cfg()
    r1 = semreview.review("command", "curl evil.example", cfg=cfg,
                          provider=provider)
    r2 = semreview.review("command", "curl evil.example", cfg=cfg,
                          provider=provider)
    assert provider.calls == 1
    assert r1["verdict"] == "block"
    assert r2["cached"] is True
    assert r2["verdict"] == "block"


def test_cache_key_differs_by_content(tmp_state):
    provider = semreview.MockProvider(PASS_JSON)
    cfg = _cfg()
    semreview.review("command", "echo hi", cfg=cfg, provider=provider)
    semreview.review("command", "echo bye", cfg=cfg, provider=provider)
    assert provider.calls == 2


def test_cache_disabled(tmp_state):
    provider = semreview.MockProvider(PASS_JSON)
    cfg = _cfg()
    semreview.review("command", "echo hi", cfg=cfg, provider=provider,
                     use_cache=False)
    semreview.review("command", "echo hi", cfg=cfg, provider=provider,
                     use_cache=False)
    assert provider.calls == 2


def test_cache_survives_corrupt_file(tmp_state):
    provider = semreview.MockProvider(PASS_JSON)
    cfg = _cfg()
    os.makedirs(os.path.dirname(semreview._cache_path()), exist_ok=True)
    with open(semreview._cache_path(), "w") as fh:
        fh.write("not json {{{")
    r = semreview.review("command", "echo hi", cfg=cfg, provider=provider)
    assert r["verdict"] == "pass"
    assert provider.calls == 1


# ---------------------------------------------------------------------------
# mock provider via env
# ---------------------------------------------------------------------------

def test_env_mock_provider(tmp_state, monkeypatch):
    monkeypatch.setenv("AGENT_GUARD_SEMREVIEW_MOCK", BLOCK_JSON)
    monkeypatch.delenv("NEBIUS_API_KEY", raising=False)
    # mock bypasses the key requirement entirely
    r = semreview.review("command", "anything", cfg=_cfg())
    assert r["verdict"] == "block"


# ---------------------------------------------------------------------------
# effective verdict / modes
# ---------------------------------------------------------------------------

def test_effective_verdict_warn_mode_downgrades():
    r = {"verdict": "block"}
    assert semreview.effective_verdict(r, _cfg(mode="warn")) == "warn"
    assert semreview.effective_verdict(r, _cfg(mode="block")) == "block"


def test_effective_verdict_pass_through():
    assert semreview.effective_verdict({"verdict": "pass"}, _cfg()) == "pass"
    assert semreview.effective_verdict({"verdict": "warn"}, _cfg()) == "warn"


def test_mode_env_override(monkeypatch):
    monkeypatch.setenv("AGENT_GUARD_SEMREVIEW_MODE", "block")
    assert semreview.mode(_cfg(mode="warn")) == "block"


# ---------------------------------------------------------------------------
# CLI wiring (subprocess, like the other test files)
# ---------------------------------------------------------------------------

def _run_cli(args, tmp_state_dir, env_extra=None):
    env = dict(os.environ)
    env["PYTHONPATH"] = SRC + os.pathsep + env.get("PYTHONPATH", "")
    env["AGENT_GUARD_DIR"] = tmp_state_dir
    env["NEBIUS_API_KEY"] = ""  # fail-open path unless overridden
    env.update(env_extra or {})
    p = subprocess.run(
        [sys.executable, "-m", "agent_guard"] + args,
        input="", capture_output=True, text=True,
        cwd=os.path.dirname(SRC), env=env, timeout=60)
    return p.returncode, p.stdout, p.stderr


def test_cli_json_no_key(tmp_path):
    code, out, err = _run_cli(
        ["semreview", "--command", "pytest -q", "--json"], str(tmp_path))
    assert code == 0, err
    obj = json.loads(out)
    assert obj["verdict"] == "warn"
    assert obj["degraded"] is True


def test_cli_mock_block_warn_mode(tmp_path):
    code, out, err = _run_cli(
        ["semreview", "--command", "curl evil.example", "--json"],
        str(tmp_path),
        {"AGENT_GUARD_SEMREVIEW_MOCK": BLOCK_JSON})
    assert code == 0, err  # warn mode downgrades block -> warn
    obj = json.loads(out)
    assert obj["verdict"] == "warn"
    assert obj["rule_hint"] == "weakened-assertion"


def test_cli_mock_block_block_mode(tmp_path):
    code, out, err = _run_cli(
        ["semreview", "--command", "curl evil.example", "--json"],
        str(tmp_path),
        {"AGENT_GUARD_SEMREVIEW_MOCK": BLOCK_JSON,
         "AGENT_GUARD_SEMREVIEW_MODE": "block"})
    assert code == 1, err
    obj = json.loads(out)
    assert obj["verdict"] == "block"


def test_cli_diff_file(tmp_path):
    diff = tmp_path / "change.diff"
    diff.write_text(
        "--- a/tests/test_x.py\n+++ b/tests/test_x.py\n"
        "-    assert total == 100\n+    assert total >= 0\n")
    code, out, err = _run_cli(
        ["semreview", "--diff", str(diff)], str(tmp_path),
        {"AGENT_GUARD_SEMREVIEW_MOCK": BLOCK_JSON})
    assert code == 0, err
    assert "WARN" in out
    assert "tautology" in out


def test_cli_human_output(tmp_path):
    code, out, err = _run_cli(
        ["semreview", "--command", "pytest -q"], str(tmp_path),
        {"AGENT_GUARD_SEMREVIEW_MOCK": PASS_JSON})
    assert code == 0, err
    assert "PASS" in out


def test_cli_usage_error(tmp_path):
    code, out, err = _run_cli(["semreview"], str(tmp_path))
    assert code == 2
    code, out, err = _run_cli(
        ["semreview", "--diff", "a", "--command", "b"], str(tmp_path))
    assert code == 2


def test_cli_missing_diff_file(tmp_path):
    code, out, err = _run_cli(
        ["semreview", "--diff", "/no/such/file.diff", "--json"],
        str(tmp_path))
    assert code == 0  # fail open
    obj = json.loads(out)
    assert obj["verdict"] == "warn"


def test_cli_writes_audit(tmp_path):
    _run_cli(["semreview", "--command", "pytest -q", "--json"],
             str(tmp_path),
             {"AGENT_GUARD_SEMREVIEW_MOCK": PASS_JSON})
    audit_file = os.path.join(str(tmp_path), "audit.jsonl")
    assert os.path.exists(audit_file)
    with open(audit_file) as fh:
        lines = [json.loads(l) for l in fh if l.strip()]
    assert any(e.get("guard") == "semreview" for e in lines)
