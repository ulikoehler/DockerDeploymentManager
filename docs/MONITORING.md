# Monitoring & alerting

Two mechanisms per service, configured in `meta.yaml` (or via
`PUT /api/services/{n}/monitoring`) plus global rules in `config.yaml`.

## Health checks

```yaml
monitoring:
  health:
    kind: docker_healthcheck   # docker_healthcheck | http | tcp | container_running
    enabled: true
    # http:  target: http://localhost:8080/healthz, expect_status: 200
    # tcp:   target: 127.0.0.1, port: 5432
    timeout_secs: 5
    interval_secs: 30
    failure_threshold: 3       # consecutive failures → down
    recovery_threshold: 2      # consecutive successes → recovered
    notify: [slack-ops]        # notifier ids; empty → monitoring.defaults.notify
    actions:
      - type: restart
        cooldown_secs: 600
        max_attempts: 3
        window_secs: 3600
```

- `docker_healthcheck` — all containers running and none `unhealthy`
  (uses the images' own HEALTHCHECK).
- `container_running` — all project containers `running`.
- `http` — GET `target` must return `expect_status` (default 200).
- `tcp` — TCP connect to `target:port`.

State machine: `ok → failing → down` (fires `alert_fired`), `→ recovered`
(fires `alert_resolved`). Transitions emit to `/ws/events` and the audit
ring; check states are shown as badges in the UI.

## Log alert rules

Long-lived `docker logs -f` watchers per service:

```yaml
  log_alerts:
    - id: errors
      regex: "(?i)(ERROR|FATAL)"
      exclude_regex: "healthcheck"      # optional
      container: "*"                    # compose service, or * for all
      context_lines: 3                  # lines of context included in the alert
      cooldown_secs: 300                # min interval between notifications
      max_per_cooldown: 5
      notify: [slack-ops]
      actions: []                       # e.g. [{type: restart}]
```

Lines are deduplicated by hash (service+rule+text), batched with context
lines, and rate-limited by `cooldown_secs`.

Global rules (`monitoring.rules`) apply to every matching service:

```yaml
monitoring:
  rules:
    - services: { glob: "*" }
      log_alerts:
        - { id: panic, regex: "(?i)panic", cooldown_secs: 300 }
```

`services` accepts `{exact: …}`, `{glob: …}`, `{regex: …}`.

## Notifiers

Secrets via `*_env` (env vars in the ddm container), never in the API
responses:

```yaml
monitoring:
  notifiers:
    - type: slack_webhook
      id: slack-ops
      url_env: SLACK_WEBHOOK_URL
    - type: telegram
      id: tg
      bot_token_env: TELEGRAM_BOT_TOKEN
      chat_id: "12345"
    - type: email
      id: mail
      smtp_host: smtp.example.com
      smtp_port: 587
      smtp_tls: starttls        # none | starttls | tls
      username_env: SMTP_USER
      password_env: SMTP_PASS
      from: ddm@example.com
      to: [ops@example.com]
    - type: webhook
      id: generic
      url: https://ntfy.example.com/ddm
      headers: { "X-Priority": "4" }
```

Test a notifier: `POST /api/monitoring/notifiers/{id}/test` or
`ddm notify-test slack-ops`.

## Auto-actions

```yaml
actions:
  - type: restart                # systemctl restart (if unit exists) else compose restart
    cooldown_secs: 600
    max_attempts: 3              # per window_secs
    window_secs: 3600
  - type: stop
    cooldown_secs: 600
  - type: exec_command           # a configured sections[s].items[i] command
    section_index: 0
    item_index: 1
    cooldown_secs: 600
```

Guard rails:

- `monitoring.allow_auto_actions: false` disables them globally.
- Per-(service, action) cooldown + max attempts per window.
- When attempts are exhausted the action is **suppressed** and an
  `auto_action`/`alert_fired` event is emitted ("exhausted").
- Every action attempt is audit-logged (`auto_restart`, …) and pushed to
  `/ws/events`.

## API / CLI

```bash
ddm monitor status [service]
ddm monitor events [service]
ddm monitor test <service>          # container health snapshot
ddm notify-test <notifier-id>
```

UI: *Monitoring* nav → live check states + notifier test buttons;
per-service *Monitoring* tab edits `meta.yaml` monitoring config.
