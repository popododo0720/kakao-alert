import json
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import kakao_alert as ka  # noqa: E402


class FakeHTTP:
    def __init__(self):
        self.calls = []
        self.responses = {}

    def __call__(self, method, url, data=None, headers=None, **kw):
        self.calls.append((method, url, data, headers))
        key = url
        if url.endswith("/oauth/token"):
            key = "token:" + data["grant_type"]
        resp = self.responses[key]
        return resp() if callable(resp) else resp


def make(http, store=None, allowed=None):
    return ka.Kakao(store or ka.MemoryStore(), "key", "secret", "https://kakao.home.arpa/callback",
                    "https://alertmanager.home.arpa", allowed, ka.Metrics(), http=http)


class FormatTest(unittest.TestCase):
    def test_firing_and_resolved(self):
        payload = {"alerts": [
            {"status": "firing", "labels": {"alertname": "HostDown", "severity": "critical", "instance": "dns"},
             "annotations": {"summary": "Host down"}},
            {"status": "resolved", "labels": {"alertname": "PoolFull", "pool": "tank"}, "annotations": {}},
        ]}
        text = ka.format_alertmanager(payload)
        self.assertIn("🔴 장애 1건", text)
        self.assertIn("• Host down (dns)", text)
        self.assertIn("✅ 해결 1건", text)
        self.assertIn("• PoolFull (tank)", text)

    def test_many_alerts_are_summarised(self):
        alerts = [{"status": "firing", "labels": {"alertname": f"A{i}"}} for i in range(9)]
        text = ka.format_alertmanager({"alerts": alerts})
        self.assertIn("…외 4건", text)

    def test_truncate(self):
        self.assertEqual(len(ka.truncate("x" * 500)), ka.TEXT_LIMIT)


class TokenTest(unittest.TestCase):
    def test_login_owner_and_rotation(self):
        http = FakeHTTP()
        http.responses["token:authorization_code"] = {
            "access_token": "a1", "expires_in": 21599, "refresh_token": "r1", "refresh_token_expires_in": 5183999}
        http.responses[ka.KAPI + "/v1/user/access_token_info"] = {"id": 42}
        store = ka.MemoryStore()
        k = make(http, store)
        state = k.login_url().split("state=")[1]
        self.assertEqual(k.callback("code", state), "42")
        self.assertEqual(store.data["refresh_token"], "r1")
        self.assertEqual(store.data["user_id"], "42")

        # Refresh without rotation keeps the old refresh token.
        http.responses["token:refresh_token"] = {"access_token": "a2", "expires_in": 21599}
        k.refresh()
        self.assertEqual(store.data["access_token"], "a2")
        self.assertEqual(store.data["refresh_token"], "r1")

        # Rotation stores the new refresh token.
        http.responses["token:refresh_token"] = {
            "access_token": "a3", "expires_in": 21599, "refresh_token": "r2", "refresh_token_expires_in": 5183999}
        k.refresh()
        self.assertEqual(store.data["refresh_token"], "r2")

        # A different Kakao account cannot take over.
        http.responses[ka.KAPI + "/v1/user/access_token_info"] = {"id": 99}
        state = k.login_url().split("state=")[1]
        with self.assertRaises(PermissionError):
            k.callback("code", state)
        self.assertEqual(store.data["user_id"], "42")

    def test_unknown_state_rejected(self):
        with self.assertRaises(PermissionError):
            make(FakeHTTP()).callback("code", "nope")

    def test_send_refreshes_expired_access_token(self):
        http = FakeHTTP()
        http.responses["token:refresh_token"] = {"access_token": "fresh", "expires_in": 21599}
        http.responses[ka.KAPI + "/v2/api/talk/memo/default/send"] = {"result_code": 0}
        store = ka.MemoryStore()
        store.data = {"access_token": "old", "access_expires_at": str(int(time.time()) - 10), "refresh_token": "r"}
        k = make(http, store)
        k.load()
        k.send_text("hello")
        method, url, data, headers = http.calls[-1]
        self.assertEqual(headers["Authorization"], "Bearer fresh")
        template = json.loads(data["template_object"])
        self.assertEqual(template["text"], "hello")
        self.assertEqual(template["link"]["web_url"], "https://alertmanager.home.arpa")


if __name__ == "__main__":
    unittest.main()
