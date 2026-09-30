"""Unit tests for ddm_client using httpx.MockTransport."""

import json

import httpx
import pytest

from ddm_client.client import DdmClient, DdmError


def make_client(handler) -> DdmClient:
    c = DdmClient("http://test")
    c._http = httpx.Client(transport=httpx.MockTransport(handler))
    return c


def ok(data):
    return httpx.Response(200, json={"success": True, "data": data})


def test_login_stores_token():
    def h(req: httpx.Request):
        assert req.url.path == "/api/auth/login"
        body = json.loads(req.content)
        assert body == {"name": "a", "password": "b"}
        return ok({"token": "tok123", "name": "a", "roles": ["admin"],
                   "expires_at": 1})
    c = make_client(h)
    r = c.login("a", "b")
    assert r["token"] == "tok123"
    assert c.token == "tok123"


def test_auth_header_sent():
    def h(req: httpx.Request):
        assert req.headers["authorization"] == "Bearer t"
        return ok([])
    c = make_client(h)
    c.token = "t"
    assert c.services() == []


def test_error_raises_ddm_error():
    def h(req):
        return httpx.Response(403, json={"success": False, "error": "forbidden"})
    c = make_client(h)
    with pytest.raises(DdmError) as e:
        c.services()
    assert e.value.status == 403
    assert e.value.message == "forbidden"


def test_action_posts_json():
    def h(req):
        assert req.method == "POST"
        assert req.url.path == "/api/services/web/actions"
        assert json.loads(req.content) == {"action": "restart"}
        return ok({"execution_id": "abc"})
    c = make_client(h)
    assert c.action("web", "restart") == {"execution_id": "abc"}


def test_logs_passes_query_params():
    def h(req):
        q = dict(req.url.params)
        assert q["tail"] == "50"
        assert q["grep"] == "err"
        assert q["stream"] == "stderr"
        return ok([{"text": "x", "stream": "stderr", "service": "web",
                    "container": "c"}])
    c = make_client(h)
    out = c.logs("web", tail=50, grep="err", stream="stderr")
    assert len(out) == 1


def test_create_service_body():
    def h(req):
        body = json.loads(req.content)
        assert body["name"] == "x"
        assert body["compose"].startswith("services:")
        assert body["template_id"] is None
        return ok({"name": "x"})
    c = make_client(h)
    c.create_service("x", compose="services:\n  a:\n    image: alpine\n")


def test_backup_restore_body():
    def h(req):
        body = json.loads(req.content)
        assert body == {"snapshot": "abc123", "target_dir": "/tmp/r"}
        return ok({"execution_id": "e"})
    c = make_client(h)
    c.backup_restore("svc", "abc123", "/tmp/r")


def test_update_user_partial():
    def h(req):
        body = json.loads(req.content)
        assert body == {"compose_policy": "unrestricted"}
        return ok({"name": "u"})
    c = make_client(h)
    c.update_user("u", compose_policy="unrestricted")


def test_set_access_rules_shape():
    def h(req):
        body = json.loads(req.content)
        assert body == [{"type": "glob", "pattern": "web-*", "effect": "allow"}]
        return ok(True)
    c = make_client(h)
    c.set_access("u", [{"type": "glob", "pattern": "web-*", "effect": "allow"}])


def test_ws_url_contains_token():
    c = DdmClient("http://h:1", token="zz")
    url = c._ws_url("/ws/services/x/logs", {"follow": "true", "tail": 10})
    assert url.startswith("ws://h:1/ws/services/x/logs?")
    assert "token=zz" in url
    assert "tail=10" in url


def test_ws_url_https_becomes_wss():
    c = DdmClient("https://h", token="t")
    assert c._ws_url("/ws/events").startswith("wss://h/ws/events")


def test_cli_access_rules():
    from ddm_client.cli import access_rules, kvlist
    rules = access_rules(["glob:web-*", "regex:^x$"], ["exact:core"])
    assert rules == [
        {"type": "exact", "pattern": "core", "effect": "deny"},
        {"type": "glob", "pattern": "web-*", "effect": "allow"},
        {"type": "regex", "pattern": "^x$", "effect": "allow"},
    ]
    assert kvlist(["a=1", "b="]) == {"a": "1", "b": ""}
