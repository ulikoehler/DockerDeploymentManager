"""ddm command-line client.

Config via env vars: DDM_URL, DDM_USER, DDM_PASSWORD (or --url/--user/--password).
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import os
import sys

from .client import DdmClient, DdmError


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ddm", description="Docker Deployment Manager client")
    p.add_argument("--url", default=os.environ.get("DDM_URL", "http://localhost:8080"))
    p.add_argument("--user", default=os.environ.get("DDM_USER"))
    p.add_argument("--password", default=os.environ.get("DDM_PASSWORD"))
    p.add_argument("--token", default=os.environ.get("DDM_TOKEN"))
    p.add_argument("--json", action="store_true", help="raw JSON output")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("login")
    sub.add_parser("services")
    s = sub.add_parser("status"); s.add_argument("service", nargs="?")
    s = sub.add_parser("logs"); s.add_argument("service")
    s.add_argument("--follow", action="store_true")
    s.add_argument("--tail", type=int, default=200)
    s.add_argument("--grep"); s.add_argument("--regex"); s.add_argument("--exclude-regex")
    s.add_argument("--stream", choices=["stdout", "stderr"])
    s.add_argument("--container")
    s.add_argument("--since", type=int)

    for a in ("update", "pull", "up", "down", "restart", "start", "stop",
              "enable", "disable"):
        s = sub.add_parser(a); s.add_argument("service")

    s = sub.add_parser("create"); s.add_argument("service")
    s.add_argument("--compose", help="compose file path (or - for stdin)")
    s.add_argument("--template", dest="template_id")
    s.add_argument("--var", action="append", default=[], help="key=value")
    s.add_argument("--description", default="")
    s.add_argument("--no-unit", action="store_true")
    s.add_argument("--no-enable", action="store_true")
    s.add_argument("--start", action="store_true")

    s = sub.add_parser("delete"); s.add_argument("service")
    s.add_argument("--keep-dir", action="store_true")

    s = sub.add_parser("compose"); s.add_argument("service")
    s.add_argument("op", choices=["get", "put"])
    s.add_argument("file", nargs="?", help="put: file path or - for stdin")
    s.add_argument("--recreate", action="store_true")

    s = sub.add_parser("unit"); s.add_argument("service")
    s.add_argument("op", choices=["get", "put", "check", "regenerate", "repair"])
    s.add_argument("file", nargs="?")
    s.add_argument("--enable", action="store_true")
    s.add_argument("--restart", action="store_true")

    s = sub.add_parser("backup"); s.add_argument("service")
    s.add_argument("op", choices=["status", "check", "provision", "run",
                                  "snapshots", "forget", "restore"])
    s.add_argument("--snapshot"); s.add_argument("--target")

    s = sub.add_parser("monitor")
    s.add_argument("op", choices=["status", "events", "test"])
    s.add_argument("service", nargs="?")

    s = sub.add_parser("notify-test"); s.add_argument("id")
    s.add_argument("--message", default="ddm test notification")

    s = sub.add_parser("notify")
    s.add_argument("op", choices=["list", "add", "update", "remove"])
    s.add_argument("id", nargs="?")
    s.add_argument("--type", choices=["slack_webhook", "telegram",
                                     "email", "webhook"])
    s.add_argument("--set", action="append", default=[],
                   help="field=value, e.g. --set bot_token=… --set chat_id=123")
    s.add_argument("--json-body", help="full notifier JSON (overrides --set)")

    s = sub.add_parser("users")
    s.add_argument("op", choices=["list", "show", "add", "remove", "passwd",
                                  "access", "roles", "policy", "features"])
    s.add_argument("name", nargs="?")
    s.add_argument("--password")
    s.add_argument("--role", action="append", default=[])
    s.add_argument("--allow", action="append", default=[])
    s.add_argument("--deny", action="append", default=[])
    s.add_argument("--policy")
    s.add_argument("--feature", action="append", default=[],
                   help="key=true/false, e.g. --feature create_services=true")

    s = sub.add_parser("exec"); s.add_argument("section", type=int)
    s.add_argument("item", type=int)
    s.add_argument("--param", action="append", default=[], help="key=value")

    sub.add_parser("commands")
    sub.add_parser("events")
    sub.add_parser("audit")
    sub.add_parser("templates")
    sub.add_parser("policy-info")
    return p


def print_json(data) -> None:
    print(json.dumps(data, indent=2))


def kvlist(items: list[str]) -> dict:
    out = {}
    for i in items:
        k, _, v = i.partition("=")
        out[k] = v
    return out


def access_rules(allow: list[str], deny: list[str]) -> list[dict]:
    rules = []
    for spec in deny:
        kind, _, pat = spec.partition(":")
        rules.append({"type": kind, "pattern": pat, "effect": "deny"})
    for spec in allow:
        kind, _, pat = spec.partition(":")
        rules.append({"type": kind, "pattern": pat, "effect": "allow"})
    return rules


async def _follow(client: DdmClient, args) -> int:
    it = await client.follow_logs(
        args.service, tail=args.tail, grep=args.grep, regex=args.regex,
        stream=args.stream, container=args.container)
    async for line in it:
        tag = f"[{line.get('service', '?')}]"
        text = line.get("text", "").rstrip("\n")
        stream = line.get("stream", "stdout")
        out = sys.stderr if stream == "stderr" else sys.stdout
        print(f"{tag} {text}", file=out)


async def _stream_exec(client: DdmClient, exec_id: str) -> int:
    it = await client.stream_execution(exec_id)
    rc = 0
    async for msg in it:
        if msg.get("type") == "log_output":
            d = msg.get("data", {})
            stream = d.get("stream", "stdout")
            print(d.get("text", ""), end="",
                  file=sys.stderr if stream == "stderr" else sys.stdout)
        elif msg.get("type") == "execution_finished":
            rc = 0 if msg.get("data", {}).get("success") else 1
            break
    return rc


def get_client(args) -> DdmClient:
    c = DdmClient(args.url, token=args.token or "")
    if not c.token:
        user = args.user or input("user: ")
        pw = args.password or getpass.getpass("password: ")
        c.login(user, pw)
    return c


def main() -> int:
    args = build_parser().parse_args()
    try:
        return dispatch(args)
    except DdmError as e:
        print(f"error: {e.message}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


def dispatch(args) -> int:
    c = get_client(args)
    j = args.json

    def out(data, pretty=None):
        if j:
            print_json(data)
        elif pretty:
            pretty(data)
        else:
            print_json(data)

    cmd = args.cmd
    if cmd == "login":
        print("logged in")
    elif cmd == "services":
        svcs = c.services()
        if j:
            out(svcs)
        else:
            for s in svcs:
                print(f"{s['name']:24} {s['running']}/{s['total']} running "
                      f"unit={'yes' if s['unit']['exists'] else 'no'} "
                      f"{s.get('monitor_state') or ''}")
    elif cmd == "status":
        out(c.service(args.service) if args.service else c.services())
    elif cmd == "logs":
        if args.follow:
            return asyncio.run(_follow(c, args))
        for l in c.logs(args.service, tail=args.tail, grep=args.grep,
                        regex=args.regex, exclude_regex=args.exclude_regex,
                        stream=args.stream, container=args.container,
                        since=args.since):
            print(f"[{l.get('service')}] {l.get('text', '').rstrip()}")
    elif cmd in ("update", "pull", "up", "down", "restart", "start", "stop",
                 "enable", "disable"):
        r = c.action(args.service, cmd)
        eid = r.get("execution_id")
        print(f"execution: {eid}")
        return asyncio.run(_stream_exec(c, eid)) if eid else 0
    elif cmd == "create":
        compose = None
        if args.compose:
            compose = sys.stdin.read() if args.compose == "-" else open(args.compose).read()
        out(c.create_service(
            args.service, compose=compose, template_id=args.template_id,
            vars=kvlist(args.var), description=args.description,
            create_unit=not args.no_unit, enable=not args.no_enable,
            start=args.start))
    elif cmd == "delete":
        c.delete_service(args.service, keep_dir=args.keep_dir)
        print("deleted")
    elif cmd == "compose":
        if args.op == "get":
            print(c.get_compose(args.service)["content"])
        else:
            content = sys.stdin.read() if args.file in (None, "-") else open(args.file).read()
            out(c.put_compose(args.service, content, recreate=args.recreate))
    elif cmd == "unit":
        if args.op == "get":
            r = c.get_unit(args.service)
            print(r.get("content") or r.get("rendered_template") or "")
        elif args.op == "put":
            content = sys.stdin.read() if args.file in (None, "-") else open(args.file).read()
            out(c.put_unit(args.service, content, restart=args.restart))
        elif args.op in ("check",):
            out(c.check_unit(args.service))
        elif args.op in ("regenerate", "repair"):
            out(c.regenerate_unit(args.service, enable=True))
    elif cmd == "backup":
        ops = {
            "status": lambda: c.get_backup(args.service),
            "check": lambda: c.backup_check(args.service),
            "provision": lambda: c.backup_provision(args.service),
            "run": lambda: c.backup_run(args.service),
            "snapshots": lambda: c.backup_snapshots(args.service),
            "forget": lambda: c.backup_forget(args.service),
            "restore": lambda: c.backup_restore(args.service, args.snapshot or "latest",
                                               args.target or f"/tmp/restore-{args.service}"),
        }
        out(ops[args.op]())
    elif cmd == "monitor":
        if args.op == "status":
            out(c.monitor_status(args.service))
        elif args.op == "events":
            out(c.monitor_events(args.service))
        elif args.op == "test":
            if not args.service:
                raise DdmError(0, "monitor test needs a service")
            out(c.monitor_test(args.service))
    elif cmd == "notify-test":
        out(c.notifier_test(args.id, args.message))
    elif cmd == "notify":
        if args.op == "list":
            out(c.notifiers())
        elif args.op == "remove":
            if not args.id:
                raise DdmError(0, "notify remove needs an id")
            c.delete_notifier(args.id)
            out({"deleted": args.id})
        else:
            body = json.loads(args.json_body) if args.json_body else {}
            body.setdefault("id", args.id)
            if args.type:
                body.setdefault("type", args.type)
            for k, v in kvlist(args.set).items():
                body[k] = v
            if not body.get("id") or not body.get("type"):
                raise DdmError(0, "need --type and an id (or --json-body)")
            if args.op == "add":
                out(c.create_notifier(body))
            else:
                out(c.update_notifier(args.id or body["id"], body))
    elif cmd == "users":
        return users_cmd(c, args)
    elif cmd == "exec":
        r = c.run_command(args.section, args.item, kvlist(args.param))
        eid = r.get("execution_id")
        print(f"execution: {eid}")
        return asyncio.run(_stream_exec(c, eid)) if eid else 0
    elif cmd == "commands":
        out(c.commands())
    elif cmd == "events":
        out(c.monitor_events())
    elif cmd == "audit":
        out(c.audit())
    elif cmd == "templates":
        out(c.templates())
    elif cmd == "policy-info":
        out(c.policy())
    return 0


def users_cmd(c: DdmClient, args) -> int:
    op = args.op
    if op == "list":
        for u in c.users():
            access = ",".join(f"{r['effect']}:{r['type']}:{r['pattern']}"
                              for r in u.get("access", []))
            print(f"{u['name']:20} roles={','.join(u['roles'])} access=[{access}]")
    elif op == "show":
        print_json(c.get_user(args.name))
    elif op == "add":
        pw = args.password or getpass.getpass("password: ")
        print_json(c.create_user(args.name, pw, roles=args.role))
    elif op == "remove":
        c.delete_user(args.name)
        print("removed")
    elif op == "passwd":
        pw = args.password or getpass.getpass("password: ")
        c.set_password(args.name, pw)
        print("password updated")
    elif op == "access":
        c.set_access(args.name, access_rules(args.allow, args.deny))
        print("access updated")
    elif op == "roles":
        print_json(c.update_user(args.name, roles=args.role))
    elif op == "policy":
        print_json(c.update_user(args.name, compose_policy=args.policy))
    elif op == "features":
        feats = {k: v.lower() == "true" for k, v in kvlist(args.feature).items()}
        print_json(c.update_user(args.name, features=feats))
    return 0


if __name__ == "__main__":
    sys.exit(main())
