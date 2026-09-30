"""DDPM API client.

Usage:
    client = DdmClient("http://host:8080")
    client.login("admin", "secret")
    for svc in client.services(): ...
    for line in client.follow_logs("web", grep="error"): ...
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Iterator, Optional

import httpx


class DdmError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass
class DdmClient:
    base_url: str
    token: str = ""
    timeout: float = 30.0

    def __post_init__(self) -> None:
        self.base_url = self.base_url.rstrip("/")
        self._http = httpx.Client(timeout=self.timeout)

    # -- transport -----------------------------------------------------------

    def _req(self, method: str, path: str, body: Any = None,
             params: dict | None = None) -> Any:
        headers = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        clean = {k: v for k, v in (params or {}).items()
                 if v is not None and v != ""}
        r = self._http.request(method, f"{self.base_url}{path}",
                               json=body, params=clean, headers=headers)
        try:
            data = r.json()
        except Exception:
            raise DdmError(r.status_code, f"HTTP {r.status_code}")
        if not r.is_success or data.get("success") is False:
            raise DdmError(r.status_code, data.get("error", f"HTTP {r.status_code}"))
        return data.get("data", data)

    def _ws_url(self, path: str, params: dict | None = None) -> str:
        proto = "wss" if self.base_url.startswith("https") else "ws"
        host = self.base_url.split("://", 1)[1]
        qs = [f"token={self.token}"]
        for k, v in (params or {}).items():
            if v is not None and v != "":
                qs.append(f"{k}={v}")
        return f"{proto}://{host}{path}?{'&'.join(qs)}"

    # -- auth ----------------------------------------------------------------

    def login(self, name: str, password: str) -> dict:
        r = self._req("POST", "/api/auth/login",
                      {"name": name, "password": password})
        self.token = r["token"]
        return r

    def me(self) -> dict:
        return self._req("GET", "/api/auth/me")

    def logout_all(self) -> None:
        self._req("POST", "/api/auth/logout-all")

    # -- services -------------------------------------------------------------

    def services(self) -> list[dict]:
        return self._req("GET", "/api/services")

    def service(self, name: str) -> dict:
        return self._req("GET", f"/api/services/{name}")

    def action(self, name: str, action: str) -> dict:
        """pull|up|down|restart|update|start|stop|enable|disable"""
        return self._req("POST", f"/api/services/{name}/actions",
                         {"action": action})

    def create_service(self, name: str, compose: str | None = None,
                       template_id: str | None = None,
                       vars: dict | None = None, description: str = "",
                       create_unit: bool = True, enable: bool = True,
                       start: bool = False) -> dict:
        body = {
            "name": name, "compose": compose, "template_id": template_id,
            "vars": vars or {}, "description": description,
            "create_unit": create_unit, "enable": enable, "start": start,
        }
        return self._req("POST", "/api/services", body)

    def delete_service(self, name: str, down: bool = True,
                       keep_dir: bool = False) -> None:
        self._req("DELETE", f"/api/services/{name}",
                  params={"down": str(down).lower(),
                          "keep_dir": str(keep_dir).lower()})

    # -- compose / unit -------------------------------------------------------

    def get_compose(self, name: str) -> dict:
        return self._req("GET", f"/api/services/{name}/compose")

    def put_compose(self, name: str, content: str,
                    recreate: bool = False) -> dict:
        return self._req("PUT", f"/api/services/{name}/compose",
                         {"content": content, "recreate": recreate})

    def get_unit(self, name: str) -> dict:
        return self._req("GET", f"/api/services/{name}/unit")

    def put_unit(self, name: str, content: str, restart: bool = False) -> dict:
        return self._req("PUT", f"/api/services/{name}/unit",
                         {"content": content, "restart": restart})

    def check_unit(self, name: str) -> dict:
        return self._req("GET", f"/api/services/{name}/unit/check")

    def regenerate_unit(self, name: str, enable: bool = True,
                        start: bool = False) -> dict:
        return self._req("POST", f"/api/services/{name}/unit/regenerate",
                         {"enable": enable, "start": start})

    # -- logs -----------------------------------------------------------------

    def logs(self, name: str, tail: int | None = None,
             grep: str | None = None, regex: str | None = None,
             exclude_regex: str | None = None, stream: str | None = None,
             container: str | None = None,
             since: int | None = None) -> list[dict]:
        return self._req("GET", f"/api/services/{name}/logs",
                         params={"tail": tail, "grep": grep, "regex": regex,
                                 "exclude_regex": exclude_regex,
                                 "stream": stream, "container": container,
                                 "since": since})

    async def follow_logs(self, name: str, tail: int | None = 200,
                          grep: str | None = None,
                          regex: str | None = None,
                          stream: str | None = None,
                          container: str | None = None) -> "AsyncIteratorShim":
        """Async iterator of log line dicts."""
        import websockets

        url = self._ws_url(f"/ws/services/{name}/logs", {
            "follow": "true", "tail": tail, "grep": grep, "regex": regex,
            "stream": stream, "container": container,
        })
        ws = await websockets.connect(url)
        return _WsIter(ws)

    # -- backup ---------------------------------------------------------------

    def get_backup(self, name: str) -> dict:
        return self._req("GET", f"/api/services/{name}/backup")

    def put_backup(self, name: str, config: dict) -> dict:
        return self._req("PUT", f"/api/services/{name}/backup", config)

    def backup_check(self, name: str) -> dict:
        return self._req("GET", f"/api/services/{name}/backup/check")

    def backup_provision(self, name: str) -> list[str]:
        return self._req("POST", f"/api/services/{name}/backup/provision", {})

    def backup_run(self, name: str) -> dict:
        return self._req("POST", f"/api/services/{name}/backup/run", {})

    def backup_snapshots(self, name: str) -> Any:
        return self._req("GET", f"/api/services/{name}/backup/snapshots")

    def backup_forget(self, name: str) -> dict:
        return self._req("POST", f"/api/services/{name}/backup/forget", {})

    def backup_restore(self, name: str, snapshot: str,
                       target_dir: str) -> dict:
        return self._req("POST", f"/api/services/{name}/backup/restore",
                         {"snapshot": snapshot, "target_dir": target_dir})

    # -- monitoring -----------------------------------------------------------

    def get_monitoring(self, name: str) -> dict:
        return self._req("GET", f"/api/services/{name}/monitoring")

    def put_monitoring(self, name: str, config: dict) -> dict:
        return self._req("PUT", f"/api/services/{name}/monitoring", config)

    def monitor_status(self, service: str | None = None) -> Any:
        if service:
            return self._req("GET", f"/api/monitoring/status/{service}")
        return self._req("GET", "/api/monitoring/status")

    def monitor_events(self, service: str | None = None,
                       limit: int = 100) -> list[dict]:
        return self._req("GET", "/api/monitoring/events",
                         params={"service": service, "limit": limit})

    def monitor_test(self, name: str) -> dict:
        return self._req("POST", f"/api/services/{name}/monitoring/test", {})

    def notifiers(self) -> list[dict]:
        return self._req("GET", "/api/monitoring/notifiers")

    def notifier_test(self, id: str, message: str = "ddm test") -> dict:
        return self._req("POST", f"/api/monitoring/notifiers/{id}/test",
                         {"message": message})

    # -- users ----------------------------------------------------------------

    def users(self) -> list[dict]:
        return self._req("GET", "/api/users")

    def get_user(self, name: str) -> dict:
        return self._req("GET", f"/api/users/{name}")

    def create_user(self, name: str, password: str,
                    roles: list[str] | None = None,
                    access: list[dict] | None = None,
                    features: dict | None = None,
                    compose_policy: str | None = None) -> dict:
        return self._req("POST", "/api/users", {
            "name": name, "password": password,
            "roles": roles or [], "access": access or [],
            "features": features, "compose_policy": compose_policy,
        })

    def update_user(self, name: str, roles: list[str] | None = None,
                    features: dict | None = None,
                    compose_policy: Optional[str] = ...) -> dict:  # type: ignore
        body: dict[str, Any] = {}
        if roles is not None:
            body["roles"] = roles
        if features is not None:
            body["features"] = features
        if compose_policy is not ...:
            body["compose_policy"] = compose_policy
        return self._req("PUT", f"/api/users/{name}", body)

    def delete_user(self, name: str) -> None:
        self._req("DELETE", f"/api/users/{name}")

    def set_password(self, name: str, password: str) -> None:
        self._req("PUT", f"/api/users/{name}/password",
                  {"password": password})

    def set_access(self, name: str, rules: list[dict]) -> None:
        """rules: [{"type": "glob"|"exact"|"regex", "pattern": str,
                    "effect": "allow"|"deny"}]"""
        self._req("PUT", f"/api/users/{name}/access", rules)

    # -- systemd groups + commands --------------------------------------------

    def systemd_groups(self) -> list[dict]:
        return self._req("GET", "/api/systemd/groups")

    def systemd_status(self, group: str) -> list[dict]:
        return self._req("GET", f"/api/systemd/groups/{group}/status")

    def systemd_restart_unit(self, unit: str) -> dict:
        return self._req("POST", f"/api/systemd/units/{unit}/restart")

    def systemd_unit_logs(self, unit: str, lines: int = 200) -> str:
        return self._req("GET", f"/api/systemd/units/{unit}/logs",
                         params={"lines": lines})

    def commands(self) -> list[dict]:
        return self._req("GET", "/api/commands")

    def run_command(self, section: int, item: int,
                    params: dict | None = None) -> dict:
        return self._req("POST", f"/api/commands/{section}/{item}",
                         {"params": params or {}})

    # -- misc -----------------------------------------------------------------

    def executions(self) -> list[dict]:
        return self._req("GET", "/api/executions")

    def templates(self) -> list[dict]:
        return self._req("GET", "/api/templates")

    def policy(self) -> dict:
        return self._req("GET", "/api/policy")

    def config_status(self) -> dict:
        return self._req("GET", "/api/config/status")

    def audit(self) -> list[dict]:
        return self._req("GET", "/api/audit")

    async def stream_execution(self, execution_id: str) -> "AsyncIteratorShim":
        import websockets

        url = self._ws_url(f"/ws/executions/{execution_id}")
        ws = await websockets.connect(url)
        return _WsIter(ws)


class _WsIter:
    """Async iterator over JSON WS messages."""

    def __init__(self, ws):
        self._ws = ws

    def __aiter__(self):
        return self

    async def __anext__(self):
        async for raw in self._ws:
            try:
                yield_data = json.loads(raw)
            except json.JSONDecodeError:
                continue
            return yield_data
        raise StopAsyncIteration

    async def aclose(self):
        await self._ws.close()
