"""Alertmanager webhook -> KakaoTalk "send to me" (나에게 보내기) bridge.

Endpoints
  POST /alertmanager   Alertmanager webhook (keep this cluster-internal)
  POST /test           sends a test message (cluster-internal)
  GET  /login          starts Kakao login (expose through the gateway, LAN/VPN only)
  GET  /callback       Kakao OAuth redirect target
  GET  /healthz        liveness
  GET  /metrics        Prometheus metrics

Kakao tokens: the access token lives 6-12 hours, the refresh token 2 months. When less
than one month is left, a refresh call returns a new refresh token and the old one stops
working immediately, so every refresh result is written back to a Kubernetes Secret.
A background loop refreshes well before expiry even when no alert is sent.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import secrets
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

LOG = logging.getLogger("kakao_alert")

KAUTH = "https://kauth.kakao.com"
KAPI = "https://kapi.kakao.com"
TEXT_LIMIT = 200  # Kakao text template limit (characters)


def env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    if value:
        return value
    path = os.environ.get(name + "_FILE")
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return f.read().strip()
    return default


def http_json(method: str, url: str, data: dict | None = None, headers: dict | None = None,
              context: ssl.SSLContext | None = None, body: bytes | None = None, timeout: float = 15) -> Any:
    hdrs = dict(headers or {})
    if data is not None:
        body = urllib.parse.urlencode(data).encode()
        hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded;charset=utf-8")
    req = urllib.request.Request(url, data=body, method=method, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"{method} {url}: HTTP {e.code}: {e.read()[:500]!r}") from None
    return json.loads(raw) if raw else {}


# --------------------------------------------------------------------------- token store

class SecretStore:
    """Keeps tokens in one Kubernetes Secret, using the pod's service account."""

    SA = "/var/run/secrets/kubernetes.io/serviceaccount"

    def __init__(self, name: str, namespace: str | None = None):
        self.name = name
        self.namespace = namespace or open(f"{self.SA}/namespace", encoding="utf-8").read().strip()
        host = os.environ.get("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
        port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
        self.url = f"https://{host}:{port}/api/v1/namespaces/{self.namespace}/secrets/{name}"
        self.ctx = ssl.create_default_context(cafile=f"{self.SA}/ca.crt")

    def _headers(self, extra: dict | None = None) -> dict:
        token = open(f"{self.SA}/token", encoding="utf-8").read().strip()
        return {"Authorization": f"Bearer {token}", **(extra or {})}

    def load(self) -> dict[str, str]:
        obj = http_json("GET", self.url, headers=self._headers(), context=self.ctx)
        return {k: base64.b64decode(v).decode() for k, v in (obj.get("data") or {}).items()}

    def save(self, values: dict[str, str]) -> None:
        body = json.dumps({"stringData": values}).encode()
        http_json("PATCH", self.url, body=body, context=self.ctx,
                  headers=self._headers({"Content-Type": "application/merge-patch+json"}))


class MemoryStore:
    """Used by tests and local runs."""

    def __init__(self) -> None:
        self.data: dict[str, str] = {}

    def load(self) -> dict[str, str]:
        return dict(self.data)

    def save(self, values: dict[str, str]) -> None:
        self.data.update(values)


# --------------------------------------------------------------------------- metrics

class Metrics:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.counters: dict[tuple[str, str], int] = {}
        self.gauges: dict[str, float] = {}

    def inc(self, name: str, result: str) -> None:
        with self.lock:
            self.counters[(name, result)] = self.counters.get((name, result), 0) + 1

    def set(self, name: str, value: float) -> None:
        with self.lock:
            self.gauges[name] = value

    def render(self) -> str:
        lines = []
        with self.lock:
            for (name, result), value in sorted(self.counters.items()):
                lines.append(f'kakao_alert_{name}_total{{result="{result}"}} {value}')
            for name, value in sorted(self.gauges.items()):
                lines.append(f"kakao_alert_{name} {value}")
        return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- Kakao client

class Kakao:
    def __init__(self, store, rest_api_key: str, client_secret: str | None, redirect_uri: str,
                 link_url: str, allowed_user_id: str | None, metrics: Metrics, http=http_json):
        self.store = store
        self.key = rest_api_key
        self.secret = client_secret
        self.redirect_uri = redirect_uri
        self.link_url = link_url
        self.allowed_user_id = allowed_user_id
        self.metrics = metrics
        self.http = http
        self.lock = threading.Lock()
        self.tokens: dict[str, str] = {}
        self.states: dict[str, float] = {}

    # ---- token handling

    def load(self) -> None:
        try:
            self.tokens = self.store.load()
        except Exception:  # noqa: BLE001
            LOG.exception("cannot load tokens")
            self.tokens = {}
        self._export_token_metrics()

    def _export_token_metrics(self) -> None:
        self.metrics.set("logged_in", 1 if self.tokens.get("refresh_token") else 0)
        for key in ("access_expires_at", "refresh_expires_at"):
            if self.tokens.get(key):
                self.metrics.set(key.replace("_at", "_timestamp_seconds"), float(self.tokens[key]))

    def _apply_token_response(self, resp: dict, extra: dict[str, str] | None = None) -> None:
        now = time.time()
        update = {
            "access_token": resp["access_token"],
            "access_expires_at": str(int(now + int(resp.get("expires_in", 0)))),
        }
        if resp.get("refresh_token"):  # only present on first login and on rotation
            update["refresh_token"] = resp["refresh_token"]
            update["refresh_expires_at"] = str(int(now + int(resp.get("refresh_token_expires_in", 0))))
        update.update(extra or {})
        self.store.save(update)  # persist first: a rotated refresh token must not be lost
        self.tokens.update(update)
        self._export_token_metrics()

    def refresh(self) -> None:
        with self.lock:
            if not self.tokens.get("refresh_token"):
                raise RuntimeError("not logged in: open /login")
            data = {"grant_type": "refresh_token", "client_id": self.key,
                    "refresh_token": self.tokens["refresh_token"]}
            if self.secret:
                data["client_secret"] = self.secret
            try:
                resp = self.http("POST", f"{KAUTH}/oauth/token", data=data)
                self._apply_token_response(resp)
                self.metrics.inc("token_refresh", "ok")
                LOG.info("token refreshed (refresh token rotated: %s)", "refresh_token" in resp)
            except Exception:
                self.metrics.inc("token_refresh", "error")
                raise

    def ensure_access_token(self, min_valid_seconds: int = 600) -> str:
        if float(self.tokens.get("access_expires_at") or 0) - time.time() < min_valid_seconds:
            self.refresh()
        return self.tokens["access_token"]

    # ---- login

    def login_url(self) -> str:
        state = secrets.token_urlsafe(24)
        now = time.time()
        self.states = {s: t for s, t in self.states.items() if now - t < 600}
        self.states[state] = now
        query = urllib.parse.urlencode({"client_id": self.key, "redirect_uri": self.redirect_uri,
                                        "response_type": "code", "scope": "talk_message", "state": state})
        return f"{KAUTH}/oauth/authorize?{query}"

    def callback(self, code: str, state: str) -> str:
        if state not in self.states:
            raise PermissionError("unknown or expired state, start again at /login")
        del self.states[state]
        data = {"grant_type": "authorization_code", "client_id": self.key,
                "redirect_uri": self.redirect_uri, "code": code}
        if self.secret:
            data["client_secret"] = self.secret
        resp = self.http("POST", f"{KAUTH}/oauth/token", data=data)
        info = self.http("GET", f"{KAPI}/v1/user/access_token_info",
                         headers={"Authorization": f"Bearer {resp['access_token']}"})
        user_id = str(info.get("id"))
        # Only one Kakao account may own this bridge: the configured one, or the first
        # account that ever logged in.
        owner = self.allowed_user_id or self.tokens.get("user_id")
        if owner and owner != user_id:
            raise PermissionError(f"Kakao account {user_id} is not allowed (owner is {owner})")
        with self.lock:
            self._apply_token_response(resp, {"user_id": user_id})
        return user_id

    # ---- sending

    def send_text(self, text: str, link: str | None = None) -> None:
        link = link or self.link_url
        template = {"object_type": "text", "text": truncate(text),
                    "link": {"web_url": link, "mobile_web_url": link}, "button_title": "열기"}
        try:
            token = self.ensure_access_token()
            self.http("POST", f"{KAPI}/v2/api/talk/memo/default/send",
                      data={"template_object": json.dumps(template, ensure_ascii=False)},
                      headers={"Authorization": f"Bearer {token}"})
            self.metrics.inc("messages", "ok")
        except Exception:
            self.metrics.inc("messages", "error")
            raise


def truncate(text: str, limit: int = TEXT_LIMIT) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


# --------------------------------------------------------------------------- formatting

SEVERITY_ICON = {"critical": "🔴", "warning": "🟠", "info": "🔵"}


def format_alertmanager(payload: dict, max_lines: int = 5) -> str:
    """One short message per Alertmanager notification (one alert group)."""
    alerts = payload.get("alerts") or []
    firing = [a for a in alerts if a.get("status") == "firing"]
    resolved = [a for a in alerts if a.get("status") == "resolved"]
    lines = []
    if firing:
        sev = (firing[0].get("labels") or {}).get("severity", "")
        lines.append(f"{SEVERITY_ICON.get(sev, '🟠')} 장애 {len(firing)}건")
        lines += [describe(a) for a in firing[:max_lines]]
        if len(firing) > max_lines:
            lines.append(f"…외 {len(firing) - max_lines}건")
    if resolved:
        lines.append(f"✅ 해결 {len(resolved)}건")
        room = max(1, max_lines - min(len(firing), max_lines))
        lines += [describe(a) for a in resolved[:room]]
        if len(resolved) > room:
            lines.append(f"…외 {len(resolved) - room}건")
    return "\n".join(lines) or "(빈 알림)"


def describe(alert: dict) -> str:
    labels = alert.get("labels") or {}
    annotations = alert.get("annotations") or {}
    target = labels.get("instance") or labels.get("pool") or labels.get("namespace") or labels.get("job") or ""
    text = annotations.get("summary") or labels.get("alertname", "alert")
    return f"• {text}" + (f" ({target})" if target and target not in text else "")


# --------------------------------------------------------------------------- HTTP

def make_handler(kakao: Kakao, metrics: Metrics):
    class Handler(BaseHTTPRequestHandler):
        server_version = "kakao-alert"

        def log_message(self, fmt, *args):  # noqa: N802 - quiet default access log
            LOG.debug(fmt, *args)

        def _reply(self, code: int, body: str, ctype: str = "text/plain; charset=utf-8", headers=None):
            data = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):  # noqa: N802
            url = urllib.parse.urlparse(self.path)
            if url.path == "/healthz":
                return self._reply(200, "ok\n")
            if url.path == "/metrics":
                return self._reply(200, metrics.render(), "text/plain; version=0.0.4")
            if url.path == "/login":
                return self._reply(302, "", headers={"Location": kakao.login_url()})
            if url.path == "/callback":
                q = urllib.parse.parse_qs(url.query)
                if "error" in q:
                    return self._reply(400, f"Kakao login failed: {q.get('error_description', q['error'])[0]}\n")
                try:
                    user_id = kakao.callback(q.get("code", [""])[0], q.get("state", [""])[0])
                    kakao.send_text("✅ kakao-alert 연결됨. 이제 홈랩 알림이 여기로 와요.")
                except PermissionError as e:
                    return self._reply(403, f"{e}\n")
                except Exception as e:  # noqa: BLE001
                    LOG.exception("callback failed")
                    return self._reply(500, f"login failed: {e}\n")
                return self._reply(200, f"연결됨 (Kakao user {user_id}). 카카오톡 '나와의 채팅'을 확인하세요.\n")
            return self._reply(404, "not found\n")

        def do_POST(self):  # noqa: N802
            url = urllib.parse.urlparse(self.path)
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            try:
                if url.path == "/alertmanager":
                    kakao.send_text(format_alertmanager(json.loads(raw or b"{}")))
                    return self._reply(200, "sent\n")
                if url.path == "/test":
                    kakao.send_text("🔔 kakao-alert 테스트 메시지")
                    return self._reply(200, "sent\n")
            except Exception as e:  # noqa: BLE001 - Alertmanager retries on 5xx
                LOG.exception("send failed")
                return self._reply(502, f"send failed: {e}\n")
            return self._reply(404, "not found\n")

    return Handler


def refresher(kakao: Kakao, stop: threading.Event, interval: float) -> None:
    """Refresh at least daily (keeps the refresh token rotating) and before access expiry."""
    last = 0.0
    while not stop.wait(interval):
        if not kakao.tokens.get("refresh_token"):
            continue
        expires = float(kakao.tokens.get("access_expires_at") or 0)
        if expires - time.time() < 3600 or time.time() - last > 86400:
            try:
                kakao.refresh()
                last = time.time()
            except Exception:  # noqa: BLE001
                LOG.exception("background refresh failed")


def main() -> None:
    logging.basicConfig(level=env("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    key = env("KAKAO_REST_API_KEY")
    redirect = env("KAKAO_REDIRECT_URI")
    if not key or not redirect:
        raise SystemExit("KAKAO_REST_API_KEY and KAKAO_REDIRECT_URI are required")
    metrics = Metrics()
    store = SecretStore(env("TOKEN_SECRET_NAME", "kakao-alert-tokens"))
    kakao = Kakao(store, key, env("KAKAO_CLIENT_SECRET"), redirect,
                  env("LINK_URL", "https://alertmanager.home.arpa"), env("KAKAO_ALLOWED_USER_ID"), metrics)
    kakao.load()
    stop = threading.Event()
    threading.Thread(target=refresher, args=(kakao, stop, 300), daemon=True).start()
    port = int(env("PORT", "8080"))
    LOG.info("listening on :%d (logged in: %s)", port, bool(kakao.tokens.get("refresh_token")))
    ThreadingHTTPServer(("", port), make_handler(kakao, metrics)).serve_forever()


if __name__ == "__main__":
    main()
