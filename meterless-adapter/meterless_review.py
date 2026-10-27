"""Nemotron semantic review via Meterless Nightshift (Open Agent sponsor stack).

REWRITTEN 2026-10-27: the old cloud-API assumption
(https://api.meterless.com/v1 + METERLESS_API_KEY) was wrong. Nightshift is
a LOCAL runtime: it serves an OpenAI-compatible hotspot on this machine at
http://127.0.0.1:8088/v1, authenticated by the proxy-token the runtime
writes to its state dir, with a `meterless-app` header on every request.
Model ids are routing modes (meterless/deep etc.); the runtime routes to
the fleet installed on the machine. This module never claims a specific
model file ran unless the runtime reports it.

Same verdict contract as before -- (verdict, reason) -- and the same
fail-open semantics: no runtime, no token, network error, timeout,
malformed model output all degrade to ("pass", ""), never raise, never
block. The deterministic pattern guards stay the enforcement layer.

Environment (all optional; defaults are the documented Nightshift values):
  METERLESS_BASE_URL       default http://127.0.0.1:8088/v1
  METERLESS_MODEL          default meterless/deep
  METERLESS_APP            default agent-guard
  METERLESS_PROXY_TOKEN    token value (preferred for tests); otherwise
                           read from METERLESS_PROXY_TOKEN_FILE or the
                           runtime state dir (see nightshift_client).
  METERLESS_TIMEOUT        seconds, default 120 (local models are slow)
  METERLESS_MOCK           "1" -> canned JSON verdict, no network.
                           UNIT TESTS ONLY. A live run must never set this
                           and then be reported as a real Nemotron verdict.

To prove a live verdict, run the e2e script on the Nightshift host and
keep its full output (models list + raw model text) in evidence/.
"""
import hashlib
import json
import os
import re
import time

from nightshift_client import NightshiftClient

DEFAULT_TIMEOUT = 120
MAX_INPUT_CHARS = 12000
MAX_OUTPUT_TOKENS = 600
CACHE_TTL_SECONDS = 7 * 24 * 3600

VERDICTS = ("block", "warn", "pass")

SYSTEM_PROMPT = (
    "You are a security classifier for shell commands and code diffs. "
    "Answer with JSON only: {\"verdict\": \"block\"|\"warn\"|\"pass\", "
    "\"reason\": \"one plain sentence\"}. "
    "block = clearly harmful (data exfiltration, destructive action, "
    "credential theft, bypassing tests or review). "
    "warn = suspicious but possibly legitimate. pass = benign."
)

_cache: dict = {}


def _cfg():
    return {
        "base_url": os.environ.get("METERLESS_BASE_URL", "http://127.0.0.1:8088/v1").rstrip("/"),
        "model": os.environ.get("METERLESS_MODEL", "meterless/deep"),
        "app": os.environ.get("METERLESS_APP", "agent-guard"),
        "timeout": int(os.environ.get("METERLESS_TIMEOUT", DEFAULT_TIMEOUT)),
        "mock": os.environ.get("METERLESS_MOCK", "") == "1",
        "mock_verdict": os.environ.get("METERLESS_MOCK_VERDICT", "pass"),
    }


def _cache_key(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _parse_verdict(content: str):
    """Parse a verdict from model text. Returns (verdict, reason) or None."""
    try:
        parsed = json.loads(content)
        verdict = parsed.get("verdict", "")
        reason = str(parsed.get("reason", ""))[:300]
        if verdict in VERDICTS:
            return verdict, reason
    except (ValueError, TypeError, AttributeError):
        pass
    # Fallback: first JSON object embedded in prose.
    match = re.search(r"\{[^{}]*\"verdict\"[^{}]*\}", content)
    if match:
        try:
            parsed = json.loads(match.group(0))
            verdict = parsed.get("verdict", "")
            if verdict in VERDICTS:
                return verdict, str(parsed.get("reason", ""))[:300]
        except (ValueError, TypeError):
            pass
    return None


def review(text: str, cfg=None, client=None):
    """Return (verdict, reason). Never raises; fail-open to ("pass", "")."""
    cfg = cfg or _cfg()
    try:
        text = (text or "")[:MAX_INPUT_CHARS]
        if not text.strip():
            return ("pass", "")
        key = _cache_key(text)
        hit = _cache.get(key)
        if hit and time.time() - hit[0] < CACHE_TTL_SECONDS:
            return hit[1]
        if cfg["mock"]:
            verdict = cfg["mock_verdict"] if cfg["mock_verdict"] in VERDICTS else "pass"
            result = (verdict, "mock verdict (no network)")
        else:
            result = _live_review(text, cfg, client)
        _cache[key] = (time.time(), result)
        return result
    except Exception:
        return ("pass", "")


def _live_review(text, cfg, client=None):
    if client is None:
        client = NightshiftClient(base_url=cfg["base_url"], app=cfg["app"],
                                  timeout=cfg["timeout"])
    if not client.token:
        return ("pass", "")
    ok, content = client.complete(text, model=cfg["model"], system=SYSTEM_PROMPT,
                                  max_tokens=MAX_OUTPUT_TOKENS)
    if not ok:
        return ("pass", "")
    parsed = _parse_verdict(content)
    if parsed is None:
        return ("pass", "")
    return parsed
