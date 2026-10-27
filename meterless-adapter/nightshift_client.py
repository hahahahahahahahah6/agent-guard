"""Real Nightshift hotspot client (Meterless, Open Agent sponsor stack).

Runs against the Nightshift runtime ON THE SAME MACHINE that hosts it:
default base http://127.0.0.1:8088/v1 (see Meterless hotspot docs).
Auth: Bearer token the runtime writes to <stateDir>/proxy-token
(Windows: %LOCALAPPDATA%\\ai.meterless.runtime\\proxy-token).
Every request also carries `meterless-app: <id>`.

Model ids are ROUTING MODES, not model files: meterless/auto, fast,
deep, cheap, local, fusion, meterless/<class>. The runtime routes to
whatever fleet is installed on that machine; this client never claims a
specific model file ran unless GET /v1/models or the response says so.

No mock here. Failures return (False, ...) / None; callers decide the
fail-open policy. The token is never printed or logged.
"""
import json
import os
import urllib.error
import urllib.request

DEFAULT_BASE_URL = "http://127.0.0.1:8088/v1"
DEFAULT_APP = "agent-guard"
DEFAULT_MODEL = "meterless/deep"
DEFAULT_TIMEOUT = 120


def find_token_file():
    explicit = os.environ.get("METERLESS_PROXY_TOKEN_FILE", "")
    if explicit:
        return explicit
    candidates = []
    local_app = os.environ.get("LOCALAPPDATA", "")
    if local_app:
        candidates.append(os.path.join(local_app, "ai.meterless.runtime", "proxy-token"))
    username = os.environ.get("USERNAME", "") or os.environ.get("USER", "")
    if username:
        candidates.append(
            os.path.join("C:\\Users", username, "AppData", "Local",
                         "ai.meterless.runtime", "proxy-token"))
    home = os.path.expanduser("~")
    candidates.append(os.path.join(home, ".local", "share", "ai.meterless.runtime", "proxy-token"))
    for path in candidates:
        if path and os.path.isfile(path):
            return path
    return candidates[0] if candidates else ""


def load_token():
    token = os.environ.get("METERLESS_PROXY_TOKEN", "").strip()
    if token:
        return token
    path = find_token_file()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def _request(base_url, path, token, app, method="GET", payload=None, timeout=DEFAULT_TIMEOUT):
    url = base_url.rstrip("/") + path
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", "Bearer " + token)
    req.add_header("meterless-app", app)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode()
            return resp.status, json.loads(raw) if raw.strip() else {}
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read().decode()
        except Exception:
            body = ""
        return exc.code, {"error": body[:500]}
    except Exception as exc:  # connection refused, timeout, DNS, ...
        return 0, {"error": str(exc)[:500]}


class NightshiftClient:
    def __init__(self, base_url=None, token=None, app=None, timeout=DEFAULT_TIMEOUT):
        self.base_url = (base_url or os.environ.get("METERLESS_BASE_URL", DEFAULT_BASE_URL)).rstrip("/")
        self.token = token if token is not None else load_token()
        self.app = app or os.environ.get("METERLESS_APP", DEFAULT_APP)
        self.timeout = int(os.environ.get("METERLESS_TIMEOUT", timeout))

    def health(self):
        # /healthz lives at the origin root, NOT under /v1.
        origin = self.base_url[:-3] if self.base_url.endswith("/v1") else self.base_url
        status, body = _request(origin, "/healthz", self.token, self.app, timeout=10)
        return status, body

    def models(self):
        status, body = _request(self.base_url, "/v1/models", self.token, self.app)
        # Some runtimes serve /models at the base root as well.
        if status == 404:
            status, body = _request(self.base_url, "/models", self.token, self.app)
        return status, body

    def complete(self, prompt, model=None, system=None, max_tokens=600):
        """Return (ok, text_or_error). Never raises for transport errors."""
        model = model or os.environ.get("METERLESS_MODEL", DEFAULT_MODEL)
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        payload = {"model": model, "messages": messages, "max_tokens": max_tokens}
        status, body = _request(self.base_url, "/chat/completions", self.token,
                                self.app, method="POST", payload=payload,
                                timeout=self.timeout)
        if status != 200:
            return False, "nightshift HTTP %s: %s" % (status, body)
        try:
            content = body["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            return False, "unexpected nightshift response shape: %s" % (str(body)[:500],)
        if not content:
            return False, "empty nightshift response"
        return True, content
