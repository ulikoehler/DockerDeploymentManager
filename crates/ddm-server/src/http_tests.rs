//! HTTP-level security/integration tests: a real `AppState` + router (REST
//! and MCP) driven with `tower::oneshot`, so auth, token scope, permission
//! and audit behaviour are exercised exactly as over the wire.

use crate::{
    agent, api, audit, auth, config, docker, exec, gitsync, hostexec, mcp, users, AppState,
};
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::Router;
use serde_json::Value;
use std::sync::Arc;
use tower::ServiceExt;

const PASSWORD: &str = "testpassword123";

fn config_yaml(root: &std::path::Path, webdav: bool) -> String {
    format!(
        r#"
server:
  listen: "127.0.0.1:0"
  jwt_secret_env: DDM_JWT_SECRET
  token_ttl_minutes: 120
paths:
  services_root: "{root}/svc"
  compose_file: docker-compose.yml
  host_systemd_dir: "{root}/systemd"
  host_exec: local
docker:
  socket: /var/run/docker.sock
  compose_command: [docker, compose]
logging: {{default_tail: 50, max_tail: 500, history_executions: 50}}
users_file: users.yaml
security:
  default_access: deny
  default_policy: strict
  unit_edit_requires: admin
  policies:
    strict: {{}}
gitops:
  enabled: true
  url: "https://deploy:secret123@example.com/repo.git"
  webhook_secret: "s3cret"
webdav:
  enabled: {webdav}
  max_upload_bytes: 1048576
  lock_timeout_secs: 300
systemd:
  groups:
    - id: svc
      title: services
      unit_regex: "^svc.*\\.service$"
      custom_commands:
        - type: shell
          id: inspect
          label: inspect
          program: echo
          args: ["${{unit}}"]
          work_dir_template: "{root}/svc/{{service}}"
sections:
  - title: ops
    items:
      - title: echo
        command_sequence:
          - program: echo
            args:
              - type: value
                value: hi
  - title: admin-only
    required_role: admin
    items:
      - title: echo2
        command_sequence:
          - program: echo
"#,
        root = root.display()
    )
}

struct Harness {
    app: Router<()>,
    state: AppState,
    docker: Arc<docker::MockDocker>,
    _dir: tempfile::TempDir,
}

async fn harness() -> Harness {
    harness_opts(true).await
}

/// Harness with the WebDAV surface turned off (the shipped default).
async fn harness_no_webdav() -> Harness {
    harness_opts(false).await
}

async fn harness_opts(webdav: bool) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    for svc in ["svc_a", "svc_b"] {
        let d = root.join("svc").join(svc);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            d.join("docker-compose.yml"),
            "services:\n  app:\n    image: alpine\n    command: sleep 9\n",
        )
        .unwrap();
    }
    std::fs::create_dir_all(root.join("systemd")).unwrap();

    let cfg_path = root.join("config.yaml");
    std::fs::write(&cfg_path, config_yaml(root, webdav)).unwrap();
    let cfg = config::load_config(&cfg_path).unwrap();
    let shared = Arc::new(config::SharedConfig::new(cfg, cfg_path));

    let hash = users::hash_password(PASSWORD).unwrap();
    let users_path = root.join("users.yaml");
    std::fs::write(
        &users_path,
        format!(
            r#"users:
  - name: admin
    password_hash: "{hash}"
    roles: [admin]
  - name: viewer
    password_hash: "{hash}"
    roles: [viewer]
    access:
      - {{ type: glob, pattern: "*", effect: allow }}
"#
        ),
    )
    .unwrap();
    let users = Arc::new(users::UserStore::load(&users_path).unwrap());

    let host = hostexec::build(config::HostExecKind::Local, 1);
    let docker_mock = Arc::new(docker::MockDocker::default());
    let docker: Arc<dyn docker::DockerApi> = docker_mock.clone();
    let exec = Arc::new(exec::ExecutionManager::new(50));
    let audit = Arc::new(audit::AuditLog::new(64));
    let core = Arc::new(
        agent::AgentCore::new(
            shared.clone(),
            root.to_path_buf(),
            users_path.clone(),
            auth::JwtKeys::new("test-secret".into()),
            String::new(),
            docker,
            host,
            Arc::new(gitsync::Gitsync::new()),
            &root.join("justification.log"),
        )
        .unwrap(),
    );

    let state = AppState {
        config: shared,
        users,
        agent: agent::Agent::Local(core),
        exec,
        audit,
        locks: Arc::new(crate::webdav::LockStore::new()),
        ws_tickets: Arc::new(crate::auth::TicketStore::new()),
    };
    let app = api::api_router()
        .merge(mcp::router(state.clone()))
        .with_state(state.clone());
    Harness {
        app,
        state,
        docker: docker_mock,
        _dir: dir,
    }
}

/// Harness talking to the privileged core over a real unix socket — same
/// wire protocol the production `ddm-server agent` split uses.
async fn harness_remote() -> Harness {
    let h = harness().await;
    let core = match &h.state.agent {
        agent::Agent::Local(c) => c.clone(),
        _ => unreachable!(),
    };
    let sock = h._dir.path().join("agent.sock");
    {
        let core = core.clone();
        let sock = sock.clone();
        tokio::spawn(async move {
            let _ = agent::transport::serve(core, &sock).await;
        });
    }
    for _ in 0..100 {
        if sock.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let state = AppState {
        config: h.state.config.clone(),
        users: h.state.users.clone(),
        agent: agent::Agent::Remote(agent::transport::SocketAgent::new(sock)),
        exec: h.state.exec.clone(),
        audit: h.state.audit.clone(),
        locks: Arc::new(crate::webdav::LockStore::new()),
        ws_tickets: Arc::new(crate::auth::TicketStore::new()),
    };
    let app = api::api_router()
        .merge(mcp::router(state.clone()))
        .with_state(state.clone());
    Harness {
        app,
        state,
        docker: h.docker.clone(),
        _dir: h._dir,
    }
}

/// (status, headers, parsed-json-body)
async fn call(
    app: &Router<()>,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, HeaderMap, Value) {
    let mut b = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    let req = match body {
        Some(v) => b
            .header("content-type", "application/json")
            .body(Body::from(v.to_string()))
            .unwrap(),
        None => b.body(Body::empty()).unwrap(),
    };
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, headers, json)
}

async fn login(app: &Router<()>, name: &str, password: &str) -> (StatusCode, String) {
    let (st, _, j) = call(
        app,
        "POST",
        "/api/auth/login",
        None,
        Some(serde_json::json!({"name": name, "password": password})),
    )
    .await;
    let token = j
        .pointer("/data/token")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    (st, token)
}

fn service_names(j: &Value) -> Vec<String> {
    j.pointer("/data")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|s| s["name"].as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------

#[tokio::test]
async fn unauthenticated_requests_rejected() {
    let h = harness().await;
    for uri in ["/api/services", "/api/users", "/api/audit", "/api/config"] {
        let (st, _, _) = call(&h.app, "GET", uri, None, None).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED, "{uri}");
    }
    let (st, _, _) = call(&h.app, "GET", "/api/services", Some("garbage"), None).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn login_flow() {
    let h = harness().await;
    let (st, _) = login(&h.app, "admin", "wrong").await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let (st, _) = login(&h.app, "nosuchuser", PASSWORD).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);

    let (st, token) = login(&h.app, "admin", PASSWORD).await;
    assert_eq!(st, StatusCode::OK);
    assert!(!token.is_empty());

    let (st, _, j) = call(&h.app, "GET", "/api/auth/me", Some(&token), None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(j.pointer("/data/name").unwrap(), "admin");
}

#[tokio::test]
async fn tampered_token_rejected() {
    let h = harness().await;
    let (_, token) = login(&h.app, "admin", PASSWORD).await;
    let mut parts: Vec<String> = token.split('.').map(String::from).collect();
    // flip a char inside the payload (e.g. try to escalate sub to admin)
    let mut payload = parts[1].clone().into_bytes();
    payload[0] = if payload[0] == b'A' { b'B' } else { b'A' };
    parts[1] = String::from_utf8(payload).unwrap();
    let forged = parts.join(".");
    let (st, _, _) = call(&h.app, "GET", "/api/services", Some(&forged), None).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn issue_token_scoped_services() {
    let h = harness().await;
    let (_, admin) = login(&h.app, "admin", PASSWORD).await;

    let (st, _, j) = call(
        &h.app,
        "POST",
        "/api/auth/token",
        Some(&admin),
        Some(serde_json::json!({
            "ttl_minutes": 30, "services": ["svc_a"], "actions": ["operator"],
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let scoped = j
        .pointer("/data/token")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    let exp = j.pointer("/data/expires_at").unwrap().as_i64().unwrap();
    assert!(exp - chrono::Utc::now().timestamp() <= 30 * 60);

    // list filtered to svc_a
    let (st, _, j) = call(&h.app, "GET", "/api/services", Some(&scoped), None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(service_names(&j), vec!["svc_a"]);

    // action allowed on svc_a, denied on svc_b
    let (st, _, _) = call(
        &h.app,
        "POST",
        "/api/services/svc_a/actions",
        Some(&scoped),
        Some(serde_json::json!({"action": "restart"})),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let (st, _, _) = call(
        &h.app,
        "POST",
        "/api/services/svc_b/actions",
        Some(&scoped),
        Some(serde_json::json!({"action": "restart"})),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);

    // admin-only endpoints denied: scope dropped the admin role
    let (st, _, _) = call(&h.app, "GET", "/api/users", Some(&scoped), None).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let (st, _, _) = call(&h.app, "GET", "/api/audit", Some(&scoped), None).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn issue_token_read_only() {
    let h = harness().await;
    let (_, admin) = login(&h.app, "admin", PASSWORD).await;
    let (_, _, j) = call(
        &h.app,
        "POST",
        "/api/auth/token",
        Some(&admin),
        Some(serde_json::json!({"ttl_minutes": 10, "actions": []})),
    )
    .await;
    let scoped = j
        .pointer("/data/token")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();

    let (st, _, _) = call(&h.app, "GET", "/api/services", Some(&scoped), None).await;
    assert_eq!(st, StatusCode::OK);
    let (st, _, _) = call(
        &h.app,
        "POST",
        "/api/services/svc_a/actions",
        Some(&scoped),
        Some(serde_json::json!({"action": "restart"})),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn scoped_token_cannot_mint_unscoped_token() {
    let h = harness().await;
    let (_, admin) = login(&h.app, "admin", PASSWORD).await;
    let (_, _, j) = call(
        &h.app,
        "POST",
        "/api/auth/token",
        Some(&admin),
        Some(serde_json::json!({
            "ttl_minutes": 30, "services": ["svc_a"], "actions": ["operator"],
        })),
    )
    .await;
    let scoped = j
        .pointer("/data/token")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();

    // mint with NO scope requested — must inherit the caller's scope
    let (st, _, j) = call(
        &h.app,
        "POST",
        "/api/auth/token",
        Some(&scoped),
        Some(serde_json::json!({"ttl_minutes": 60})),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let child = j
        .pointer("/data/token")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    let (st, _, j) = call(&h.app, "GET", "/api/services", Some(&child), None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        service_names(&j),
        vec!["svc_a"],
        "child token escaped scope"
    );
    let (st, _, _) = call(&h.app, "GET", "/api/audit", Some(&child), None).await;
    assert_eq!(st, StatusCode::FORBIDDEN);

    // mint with a disjoint scope — intersection is empty, sees nothing
    let (_, _, j) = call(
        &h.app,
        "POST",
        "/api/auth/token",
        Some(&scoped),
        Some(serde_json::json!({"services": ["svc_b"]})),
    )
    .await;
    let narrower = j
        .pointer("/data/token")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    let (st, _, j) = call(&h.app, "GET", "/api/services", Some(&narrower), None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(service_names(&j), Vec::<String>::new());
}

#[tokio::test]
async fn non_admin_scope_cannot_gain_privileges() {
    let h = harness().await;
    let (_, viewer) = login(&h.app, "viewer", PASSWORD).await;
    // viewer asks for admin action — token must not gain admin
    let (st, _, j) = call(
        &h.app,
        "POST",
        "/api/auth/token",
        Some(&viewer),
        Some(serde_json::json!({"ttl_minutes": 10, "actions": ["admin"]})),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let t = j
        .pointer("/data/token")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    let (st, _, _) = call(&h.app, "GET", "/api/users", Some(&t), None).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn viewer_access_rules_still_apply() {
    let h = harness().await;
    let (_, viewer) = login(&h.app, "viewer", PASSWORD).await;
    let (st, _, j) = call(&h.app, "GET", "/api/services", Some(&viewer), None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(service_names(&j).len(), 2);
    // viewer is not operator → cannot run actions
    let (st, _, _) = call(
        &h.app,
        "POST",
        "/api/services/svc_a/actions",
        Some(&viewer),
        Some(serde_json::json!({"action": "restart"})),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
}

// ---------------------------------------------------------------------------
// MCP transport security
// ---------------------------------------------------------------------------

fn mcp_headers(token: Option<&str>, session: Option<&str>) -> Vec<(&'static str, String)> {
    let mut h = vec![
        ("host", "localhost".to_string()),
        ("content-type", "application/json".to_string()),
        ("accept", "application/json, text/event-stream".to_string()),
    ];
    if let Some(t) = token {
        h.push(("authorization", format!("Bearer {t}")));
    }
    if let Some(s) = session {
        h.push(("mcp-session-id", s.to_string()));
    }
    h
}

fn mcp_req(headers: Vec<(&'static str, String)>, body: &str) -> Request<Body> {
    let mut b = Request::builder().method("POST").uri("/mcp");
    for (k, v) in headers {
        b = b.header(k, v);
    }
    b.body(Body::from(body.to_string())).unwrap()
}

/// Parse the last `data:` SSE payload from an MCP response body.
fn mcp_data(bytes: &[u8]) -> Value {
    let text = String::from_utf8_lossy(bytes);
    let last = text
        .lines()
        .filter(|l| l.starts_with("data:"))
        .filter_map(|l| l.strip_prefix("data:").map(str::trim))
        .rfind(|l| !l.is_empty())
        .unwrap_or("{}");
    serde_json::from_str(last).unwrap_or(Value::Null)
}

async fn mcp_initialize(app: &Router<()>, token: &str) -> String {
    let req = mcp_req(
        mcp_headers(Some(token), None),
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    if resp.status() != StatusCode::OK {
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        panic!("initialize failed: {}", String::from_utf8_lossy(&bytes));
    }
    let sid = resp
        .headers()
        .get("mcp-session-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let req = mcp_req(
        mcp_headers(Some(token), Some(&sid)),
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
    );
    let _ = app.clone().oneshot(req).await.unwrap();
    sid
}

async fn mcp_call(
    app: &Router<()>,
    token: &str,
    sid: &str,
    id: u64,
    tool: &str,
    args: Value,
) -> Value {
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": id, "method": "tools/call",
        "params": {"name": tool, "arguments": args},
    });
    let req = mcp_req(mcp_headers(Some(token), Some(sid)), &body.to_string());
    let resp = app.clone().oneshot(req).await.unwrap();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    mcp_data(&bytes)
}

#[tokio::test]
async fn mcp_requires_auth() {
    let h = harness().await;
    let req = mcp_req(
        mcp_headers(None, None),
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
    );
    let resp = h.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let req = mcp_req(
        mcp_headers(Some("forged"), None),
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
    );
    let resp = h.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn mcp_rejects_browser_origin() {
    let h = harness().await;
    let (_, token) = login(&h.app, "admin", PASSWORD).await;
    let mut headers = mcp_headers(Some(&token), None);
    headers.push(("origin", "https://evil.example".to_string()));
    let req = mcp_req(
        headers,
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
    );
    let resp = h.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn mcp_scope_enforced() {
    let h = harness().await;
    let (_, admin) = login(&h.app, "admin", PASSWORD).await;
    let (_, _, j) = call(
        &h.app,
        "POST",
        "/api/auth/token",
        Some(&admin),
        Some(serde_json::json!({
            "ttl_minutes": 30, "services": ["svc_a"], "actions": ["operator"],
        })),
    )
    .await;
    let scoped = j
        .pointer("/data/token")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();

    let sid = mcp_initialize(&h.app, &scoped).await;
    let r = mcp_call(
        &h.app,
        &scoped,
        &sid,
        2,
        "services_list",
        serde_json::json!({}),
    )
    .await;
    let names: Vec<String> = r["result"]["structuredContent"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|s| s["name"].as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(names, vec!["svc_a"]);

    let r = mcp_call(
        &h.app,
        &scoped,
        &sid,
        3,
        "service_action",
        serde_json::json!({"name": "svc_b", "action": "restart"}),
    )
    .await;
    assert!(r.get("error").is_some(), "out-of-scope action allowed: {r}");

    let r = mcp_call(
        &h.app,
        &scoped,
        &sid,
        4,
        "users_list",
        serde_json::json!({}),
    )
    .await;
    assert!(r.get("error").is_some(), "admin tool allowed: {r}");
}

// ---------------------------------------------------------------------------

#[tokio::test]
async fn webhook_rejects_unsigned_request() {
    let h = harness().await;
    let (st, _, _) = call(
        &h.app,
        "POST",
        "/api/gitops/webhook",
        None,
        Some(serde_json::json!({"ref": "refs/heads/main"})),
    )
    .await;
    assert!(
        st == StatusCode::BAD_REQUEST
            || st == StatusCode::UNAUTHORIZED
            || st == StatusCode::FORBIDDEN,
        "unsigned webhook accepted: {st}"
    );
}

#[tokio::test]
async fn audit_records_token_issue() {
    let h = harness().await;
    let (_, admin) = login(&h.app, "admin", PASSWORD).await;
    call(
        &h.app,
        "POST",
        "/api/auth/token",
        Some(&admin),
        Some(serde_json::json!({"ttl_minutes": 5, "services": ["svc_a"]})),
    )
    .await;
    let (st, _, j) = call(&h.app, "GET", "/api/audit", Some(&admin), None).await;
    assert_eq!(st, StatusCode::OK);
    let has = j
        .pointer("/data")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .any(|e| {
            e["action"] == "token_issue" && e["detail"].as_str().unwrap_or("").contains("svc_a")
        });
    assert!(has, "token_issue not audited");
}

// ---------------------------------------------------------------------------
// token lifecycle
// ---------------------------------------------------------------------------

#[tokio::test]
async fn logout_all_kills_all_tokens() {
    let h = harness().await;
    let (_, admin) = login(&h.app, "admin", PASSWORD).await;
    let (_, viewer) = login(&h.app, "viewer", PASSWORD).await;
    let (_, _, j) = call(
        &h.app,
        "POST",
        "/api/auth/token",
        Some(&admin),
        Some(serde_json::json!({"ttl_minutes": 10})),
    )
    .await;
    let mcp_token = j
        .pointer("/data/token")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();

    let (st, _, _) = call(&h.app, "POST", "/api/auth/logout-all", Some(&admin), None).await;
    assert_eq!(st, StatusCode::OK);

    for (who, t) in [("admin", &admin), ("viewer", &viewer), ("mcp", &mcp_token)] {
        let (st, _, _) = call(&h.app, "GET", "/api/auth/me", Some(t), None).await;
        assert_eq!(
            st,
            StatusCode::UNAUTHORIZED,
            "{who} token survived rotation"
        );
    }
}

#[tokio::test]
async fn non_admin_cannot_rotate_tokens() {
    let h = harness().await;
    let (_, viewer) = login(&h.app, "viewer", PASSWORD).await;
    let (st, _, _) = call(&h.app, "POST", "/api/auth/logout-all", Some(&viewer), None).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn deleted_users_token_dies() {
    let h = harness().await;
    let (_, admin) = login(&h.app, "admin", PASSWORD).await;
    let (_, viewer) = login(&h.app, "viewer", PASSWORD).await;
    let (st, _, _) = call(&h.app, "DELETE", "/api/users/viewer", Some(&admin), None).await;
    assert_eq!(st, StatusCode::OK);
    let (st, _, _) = call(&h.app, "GET", "/api/services", Some(&viewer), None).await;
    assert_eq!(
        st,
        StatusCode::UNAUTHORIZED,
        "deleted user's token still works"
    );
}

#[tokio::test]
async fn expired_token_rejected() {
    let h = harness().await;
    let user = h.state.users.get("admin").await.unwrap();
    // issue a token that expired in the past
    let expired = h
        .state
        .agent
        .local_core()
        .unwrap()
        .jwt
        .issue(&user, -120, None)
        .unwrap();
    let (st, _, _) = call(&h.app, "GET", "/api/services", Some(&expired), None).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn self_delete_forbidden() {
    let h = harness().await;
    let (_, admin) = login(&h.app, "admin", PASSWORD).await;
    let (st, _, _) = call(&h.app, "DELETE", "/api/users/admin", Some(&admin), None).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// injection / traversal
// ---------------------------------------------------------------------------

#[tokio::test]
async fn file_api_rejects_traversal() {
    let h = harness().await;
    let (_, admin) = login(&h.app, "admin", PASSWORD).await;
    for p in [
        "../config.yaml",
        "../../etc/passwd",
        "a/../../config.yaml",
        "%2e%2e/users.yaml",
        "/etc/passwd",
    ] {
        let uri = format!("/api/services/svc_a/files?path={p}");
        let (st, _, _) = call(&h.app, "GET", &uri, Some(&admin), None).await;
        assert!(
            st == StatusCode::BAD_REQUEST || st == StatusCode::FORBIDDEN,
            "traversal {p} returned {st}"
        );
    }
    // and via write
    let (st, _, _) = call(
        &h.app,
        "PUT",
        "/api/services/svc_a/files",
        Some(&admin),
        Some(serde_json::json!({"path": "../config.yaml", "content": "x"})),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn service_name_injection_rejected() {
    let h = harness().await;
    let (_, admin) = login(&h.app, "admin", PASSWORD).await;
    for name in ["a;rm -rf /", "$(id)", "a|b", "a&&b", "../x", "a b", "a'b"] {
        let uri = format!("/api/services/{}/logs", name.replace(' ', "%20"));
        let (st, _, _) = call(&h.app, "GET", &uri, Some(&admin), None).await;
        assert!(
            st == StatusCode::BAD_REQUEST
                || st == StatusCode::NOT_FOUND
                || st == StatusCode::FORBIDDEN,
            "name {name} returned {st}"
        );
    }
    let (st, _, _) = call(
        &h.app,
        "POST",
        "/api/services",
        Some(&admin),
        Some(serde_json::json!({"name": "a;rm", "compose": "services: {}"})),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn compose_policy_enforced() {
    let h = harness().await;
    let (_, admin) = login(&h.app, "admin", PASSWORD).await;
    // default policy is `strict` (deny_privileged etc.)
    let (st, _, j) = call(
        &h.app,
        "POST",
        "/api/services",
        Some(&admin),
        Some(serde_json::json!({
            "name": "evil",
            "compose": "services:\n  a:\n    image: alpine\n    privileged: true\n",
        })),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert!(
        j["error"].as_str().unwrap_or("").contains("policy"),
        "no policy violation reported: {j}"
    );
}

#[tokio::test]
async fn viewer_cannot_manage_users_or_files() {
    let h = harness().await;
    let (_, viewer) = login(&h.app, "viewer", PASSWORD).await;
    let (st, _, _) = call(
        &h.app,
        "POST",
        "/api/users",
        Some(&viewer),
        Some(serde_json::json!({"name": "x", "password": "longenoughpw"})),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let (st, _, _) = call(
        &h.app,
        "PUT",
        "/api/services/svc_a/files",
        Some(&viewer),
        Some(serde_json::json!({"path": "x.txt", "content": "x"})),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let (st, _, _) = call(
        &h.app,
        "PUT",
        "/api/services/svc_a/compose",
        Some(&viewer),
        Some(serde_json::json!({"content": "services: {}"})),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
}

// ---------------------------------------------------------------------------
// webhook signatures
// ---------------------------------------------------------------------------

#[tokio::test]
async fn webhook_signature_validation() {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let h = harness().await;
    let body = br#"{"ref":"refs/heads/main"}"#.to_vec();

    // forged signature → 403
    let req = Request::builder()
        .method("POST")
        .uri("/api/gitops/webhook")
        .header("x-hub-signature-256", "sha256=deadbeef")
        .header("content-type", "application/json")
        .body(Body::from(body.clone()))
        .unwrap();
    let resp = h.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // gitlab token wrong → 403
    let req = Request::builder()
        .method("POST")
        .uri("/api/gitops/webhook")
        .header("x-gitlab-token", "wrong")
        .body(Body::from(body.clone()))
        .unwrap();
    let resp = h.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // correct github HMAC → accepted
    let mut mac = Hmac::<Sha256>::new_from_slice(b"s3cret").unwrap();
    mac.update(&body);
    let sig = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
    let req = Request::builder()
        .method("POST")
        .uri("/api/gitops/webhook")
        .header("x-hub-signature-256", &sig)
        .body(Body::from(body))
        .unwrap();
    let resp = h.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ---------------------------------------------------------------------------
// misc transport
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ws_endpoints_require_auth() {
    let h = harness().await;
    for uri in ["/ws/events", "/ws/services/svc_a/logs"] {
        let (st, _, _) = call(&h.app, "GET", uri, None, None).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED, "{uri}");
    }
}

#[tokio::test]
async fn query_token_only_accepted_on_ws() {
    // `?token=` must not authenticate regular REST calls (URLs leak via
    // logs/history); it remains supported on /ws/* for WS clients.
    let h = harness().await;
    let (_, admin) = login(&h.app, "admin", PASSWORD).await;
    let uri = format!("/api/services?token={admin}");
    let (st, _, _) = call(&h.app, "GET", &uri, None, None).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);

    // On /ws/* the token is accepted — the request then fails the
    // websocket upgrade (no Upgrade headers in oneshot) but NOT with 401.
    let uri = format!("/ws/events?token={admin}");
    let (st, _, _) = call(&h.app, "GET", &uri, None, None).await;
    assert_ne!(st, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn mcp_calls_without_session_rejected() {
    let h = harness().await;
    let (_, admin) = login(&h.app, "admin", PASSWORD).await;
    // tools/call with no session id
    let req = mcp_req(
        mcp_headers(Some(&admin), None),
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"health","arguments":{}}}"#,
    );
    let resp = h.app.clone().oneshot(req).await.unwrap();
    assert!(resp.status().is_client_error(), "{}", resp.status());
    // unknown session id → 404
    let req = mcp_req(
        mcp_headers(Some(&admin), Some("does-not-exist")),
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"health","arguments":{}}}"#,
    );
    let resp = h.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn mcp_session_with_valid_token_works() {
    let h = harness().await;
    let (_, admin) = login(&h.app, "admin", PASSWORD).await;
    let sid = mcp_initialize(&h.app, &admin).await;
    let r = mcp_call(&h.app, &admin, &sid, 1, "health", serde_json::json!({})).await;
    assert_eq!(r["result"]["structuredContent"]["status"], "ok");
    // session belongs to the token: a different token must not reuse it
    let (_, viewer) = login(&h.app, "viewer", PASSWORD).await;
    let r = mcp_call(
        &h.app,
        &viewer,
        &sid,
        2,
        "users_list",
        serde_json::json!({}),
    )
    .await;
    assert!(
        r.get("error").is_some(),
        "viewer used admin session to list users: {r}"
    );
}

#[tokio::test]
async fn execution_ids_not_guessable_leak() {
    // executions history should not leak between users' tokens in a harmful
    // way — at minimum unauthenticated access must fail.
    let h = harness().await;
    let (st, _, _) = call(&h.app, "GET", "/api/executions", None, None).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// regression tests for the 2nd audit round
// ---------------------------------------------------------------------------

#[tokio::test]
async fn scoped_token_cannot_change_password() {
    // A scoped MCP token must not reset the owner's password — that would
    // mint full credentials via a fresh login and escape the scope.
    let h = harness().await;
    let (_, admin) = login(&h.app, "admin", PASSWORD).await;
    let (_, _, j) = call(
        &h.app,
        "POST",
        "/api/auth/token",
        Some(&admin),
        Some(serde_json::json!({"ttl_minutes": 10, "actions": ["admin"]})),
    )
    .await;
    let scoped = j
        .pointer("/data/token")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    let (st, _, _) = call(
        &h.app,
        "PUT",
        "/api/users/admin/password",
        Some(&scoped),
        Some(serde_json::json!({"password": "newpassword123"})),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN, "scoped token changed password");
}

#[tokio::test]
async fn self_password_change_requires_current() {
    let h = harness().await;
    let (_, viewer) = login(&h.app, "viewer", PASSWORD).await;

    // no current password → rejected
    let (st, _, _) = call(
        &h.app,
        "PUT",
        "/api/users/viewer/password",
        Some(&viewer),
        Some(serde_json::json!({"password": "brandnewpass1"})),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);

    // wrong current → rejected
    let (st, _, _) = call(
        &h.app,
        "PUT",
        "/api/users/viewer/password",
        Some(&viewer),
        Some(serde_json::json!({"password": "brandnewpass1", "current_password": "wrong"})),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);

    // correct current → accepted; new password works for login
    let (st, _, _) = call(
        &h.app,
        "PUT",
        "/api/users/viewer/password",
        Some(&viewer),
        Some(serde_json::json!({"password": "brandnewpass1", "current_password": PASSWORD})),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let (st, _) = login(&h.app, "viewer", "brandnewpass1").await;
    assert_eq!(st, StatusCode::OK);
}

#[tokio::test]
async fn login_throttle_locks_after_failures() {
    let h = harness().await;
    for _ in 0..5 {
        let (st, _, _) = call(
            &h.app,
            "POST",
            "/api/auth/login",
            None,
            Some(serde_json::json!({"name": "admin", "password": "wrong"})),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
    }
    // locked: further wrong attempts are throttled (429)
    let (st, _, _) = call(
        &h.app,
        "POST",
        "/api/auth/login",
        None,
        Some(serde_json::json!({"name": "admin", "password": "still-wrong"})),
    )
    .await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS);
    // but a correct password must still succeed — no self-DoS — and it
    // clears the lockout
    let (st, _) = login(&h.app, "admin", PASSWORD).await;
    assert_eq!(st, StatusCode::OK, "lockout blocked the real admin");
    let (st, _) = login(&h.app, "admin", PASSWORD).await;
    assert_eq!(st, StatusCode::OK, "lockout not cleared by success");
    // lockout is per-user — viewer was never throttled
    let (st, _) = login(&h.app, "viewer", PASSWORD).await;
    assert_eq!(st, StatusCode::OK);
}

#[tokio::test]
async fn command_run_requires_feature_and_role() {
    let h = harness().await;
    let (_, viewer) = login(&h.app, "viewer", PASSWORD).await;
    let (_, admin) = login(&h.app, "admin", PASSWORD).await;

    // strip run_commands from the viewer → even ungated items are 403
    let (st, _, _) = call(
        &h.app,
        "PUT",
        "/api/users/viewer",
        Some(&admin),
        Some(serde_json::json!({"features": {"run_commands": false}})),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let (st, _, _) = call(
        &h.app,
        "POST",
        "/api/commands/0/0",
        Some(&viewer),
        Some(serde_json::json!({})),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN, "ran without run_commands");

    // restore run_commands — ungated item works, admin-only section doesn't
    let (st, _, _) = call(
        &h.app,
        "PUT",
        "/api/users/viewer",
        Some(&admin),
        Some(serde_json::json!({"features": {"run_commands": true}})),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let (st, _, _) = call(
        &h.app,
        "POST",
        "/api/commands/0/0",
        Some(&viewer),
        Some(serde_json::json!({})),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let (st, _, _) = call(
        &h.app,
        "POST",
        "/api/commands/1/0",
        Some(&viewer),
        Some(serde_json::json!({})),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::FORBIDDEN,
        "role-gated section ran for viewer"
    );

    // admin runs everything
    let (st, _, j) = call(
        &h.app,
        "POST",
        "/api/commands/1/0",
        Some(&admin),
        Some(serde_json::json!({})),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(j.pointer("/data/execution_id").is_some());
}

#[tokio::test]
async fn executions_scoped_to_owner() {
    let h = harness().await;
    let (_, admin) = login(&h.app, "admin", PASSWORD).await;
    let (_, viewer) = login(&h.app, "viewer", PASSWORD).await;

    let (st, _, j) = call(
        &h.app,
        "POST",
        "/api/commands/0/0",
        Some(&admin),
        Some(serde_json::json!({})),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let eid = j.pointer("/data/execution_id").unwrap().as_str().unwrap();

    // admin sees it
    let (st, _, j) = call(&h.app, "GET", "/api/executions", Some(&admin), None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(j.pointer("/data/0/user").unwrap().as_str(), Some("admin"));

    // viewer sees neither the list entry nor the detail
    let (st, _, j) = call(&h.app, "GET", "/api/executions", Some(&viewer), None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        j["data"].as_array().unwrap().len(),
        0,
        "viewer saw admin's execution"
    );
    let (st, _, _) = call(
        &h.app,
        "GET",
        &format!("/api/executions/{eid}"),
        Some(&viewer),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn token_cannot_outlive_parent() {
    let h = harness().await;
    let (_, admin) = login(&h.app, "admin", PASSWORD).await;
    let (_, _, j) = call(
        &h.app,
        "POST",
        "/api/auth/token",
        Some(&admin),
        Some(serde_json::json!({"ttl_minutes": 1})),
    )
    .await;
    let parent = j
        .pointer("/data/token")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    let parent_exp = j.pointer("/data/expires_at").unwrap().as_i64().unwrap();

    // ask for 120 minutes; child must be capped at the parent's exp
    let (st, _, j) = call(
        &h.app,
        "POST",
        "/api/auth/token",
        Some(&parent),
        Some(serde_json::json!({"ttl_minutes": 120})),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let child_exp = j.pointer("/data/expires_at").unwrap().as_i64().unwrap();
    assert!(
        child_exp <= parent_exp,
        "child outlived parent: {child_exp} > {parent_exp}"
    );
}

// ---------------------------------------------------------------------------
// regression tests for audit round 3
// ---------------------------------------------------------------------------

#[tokio::test]
async fn systemd_unit_injection_rejected() {
    let h = harness().await;
    let (_, admin) = login(&h.app, "admin", PASSWORD).await;
    // crafted unit names that would break `cd '{work_dir}'` or arg quoting
    for bad in [
        "x';id;echo '",
        "svc a.service",
        "../x.service",
        "svc$(id).service",
        "svc`id`.service",
        "svc;x.service",
    ] {
        let enc: String = bad
            .bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_') {
                    (b as char).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect();
        for ep in ["execute", "restart", "logs"] {
            let method = if ep == "logs" { "GET" } else { "POST" };
            let uri = format!("/api/systemd/units/{enc}/{ep}");
            let body = (ep == "execute").then(|| serde_json::json!({"command_id": "inspect"}));
            let (st, _, _) = call(&h.app, method, &uri, Some(&admin), body).await;
            assert!(
                st == StatusCode::BAD_REQUEST || st == StatusCode::NOT_FOUND,
                "{ep} on {bad:?} → {st}"
            );
        }
    }
    // a legit unit matching the group regex still works (returns execution)
    let (st, _, j) = call(
        &h.app,
        "POST",
        "/api/systemd/units/svc_a.service/execute",
        Some(&admin),
        Some(serde_json::json!({"command_id": "inspect"})),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "legit unit_execute failed: {j}");
}

#[tokio::test]
async fn unknown_compose_policy_fails_closed() {
    let h = harness().await;
    let (_, admin) = login(&h.app, "admin", PASSWORD).await;
    // point admin's policy at a name that doesn't exist — previously this
    // silently disabled all compose validation
    let (st, _, _) = call(
        &h.app,
        "PUT",
        "/api/users/admin",
        Some(&admin),
        Some(serde_json::json!({"compose_policy": "nonexistent"})),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let (st, _, j) = call(
        &h.app,
        "POST",
        "/api/services",
        Some(&admin),
        Some(serde_json::json!({
            "name": "evil",
            "compose": "services:\n  a:\n    image: alpine\n    privileged: true\n",
        })),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::BAD_REQUEST,
        "unknown policy skipped validation: {j}"
    );
}

#[tokio::test]
async fn config_redacts_gitops_url_credentials() {
    let h = harness().await;
    let (_, admin) = login(&h.app, "admin", PASSWORD).await;
    let (st, _, j) = call(&h.app, "GET", "/api/config", Some(&admin), None).await;
    assert_eq!(st, StatusCode::OK);
    let url = j.pointer("/gitops/url").unwrap().as_str().unwrap();
    assert!(!url.contains("secret123"), "credentials leaked in {url}");
    assert!(url.contains("***"), "url not redacted: {url}");
}

#[tokio::test]
async fn edit_units_cannot_bypass_admin_gate() {
    let h = harness().await;
    let (_, admin) = login(&h.app, "admin", PASSWORD).await;
    let (_, viewer) = login(&h.app, "viewer", PASSWORD).await;
    // grant edit_units + unit_edit_requires=admin → must still be 403
    let (st, _, _) = call(
        &h.app,
        "PUT",
        "/api/users/viewer",
        Some(&admin),
        Some(serde_json::json!({"features": {"edit_units": true}})),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let (st, _, _) = call(
        &h.app,
        "PUT",
        "/api/services/svc_a/unit",
        Some(&viewer),
        Some(serde_json::json!({"content": "[Unit]\nDescription=x\n"})),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN, "edit_units bypassed admin gate");
}

#[tokio::test]
async fn monitoring_target_validation() {
    let h = harness().await;
    let (_, admin) = login(&h.app, "admin", PASSWORD).await;
    for bad in [
        "file:///etc/passwd",
        "gopher://x",
        "https://u:p@host/",
        "notaurl",
    ] {
        let (st, _, _) = call(
            &h.app,
            "PUT",
            "/api/services/svc_a/monitoring",
            Some(&admin),
            Some(serde_json::json!({
                "health": {"kind": "http", "target": bad},
                "log_alerts": [],
            })),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "target {bad:?} accepted");
    }
    let (st, _, _) = call(
        &h.app,
        "PUT",
        "/api/services/svc_a/monitoring",
        Some(&admin),
        Some(serde_json::json!({
            "health": {"kind": "http", "target": "http://localhost:8080/health"},
            "log_alerts": [],
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
}

// ---------------------------------------------------------------------------
// Privilege-separated transport (unix socket)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn remote_agent_login_and_calls() {
    let h = harness_remote().await;
    // auth roundtrip over the socket
    let (st, _tok) = login(&h.app, "admin", PASSWORD).await;
    assert_eq!(st, StatusCode::OK);
    let (st, tok) = login(&h.app, "admin", PASSWORD).await;
    assert_eq!(st, StatusCode::OK);
    // authenticated call + wrong creds
    let (st, _, _) = call(&h.app, "GET", "/api/services", Some(&tok), None).await;
    assert_eq!(st, StatusCode::OK);
    let (st, _) = login(&h.app, "admin", "nope-nope-nope").await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    // tampered token still dies at the agent
    let mut parts: Vec<String> = tok.split('.').map(|s| s.to_string()).collect();
    let mut payload = parts[1].clone().into_bytes();
    payload[0] = if payload[0] == b'A' { b'B' } else { b'A' };
    parts[1] = String::from_utf8(payload).unwrap();
    let forged = parts.join(".");
    let (st, _, _) = call(&h.app, "GET", "/api/services", Some(&forged), None).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    // the agent wrote a justification record for the calls above
    let log = std::fs::read_to_string(h._dir.path().join("justification.log")).unwrap();
    assert!(log.contains("\"authenticate\""), "no justification written");
}

// ---------------------------------------------------------------------------
// Agent-side structural validation (compromised-server model)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn agent_rejects_unit_path_traversal() {
    let h = harness().await;
    let (_, tok) = login(&h.app, "admin", PASSWORD).await;
    // Even with a valid admin token, the agent must not let a unit/service
    // name escape the systemd dir — this is the compromised-server case.
    for name in ["../etc/passwd", "../../x", "..", ".hidden", "a/b"] {
        let r = h
            .state
            .agent
            .call(
                crate::agent::proto::SyncVerb::UnitPathExists { unit: name.into() },
                &tok,
            )
            .await;
        assert!(r.is_err(), "UnitPathExists accepted {name}");
        let r = h
            .state
            .agent
            .call(
                crate::agent::proto::SyncVerb::UnitFileRead {
                    service: name.into(),
                },
                &tok,
            )
            .await;
        assert!(r.is_err(), "UnitFileRead accepted {name}");
    }
}

#[tokio::test]
async fn agent_policy_floor_cannot_be_bypassed() {
    let h = harness().await;
    let (_, tok) = login(&h.app, "admin", PASSWORD).await;
    // ComposeWrite with a privileged compose must be rejected by the AGENT
    // even though the token is valid — policy is no longer server-only.
    let evil = "services:\n  x:\n    image: alpine\n    privileged: true\n";
    let r = h
        .state
        .agent
        .call(
            crate::agent::proto::SyncVerb::ComposeWrite {
                service: "svc_a".into(),
                content: evil.into(),
            },
            &tok,
        )
        .await;
    assert!(r.is_err(), "privileged compose accepted by agent");
}

// ---------------------------------------------------------------------------
// Remediation regressions: privileged-file writes, compose gate, monitoring
// exec-actions, dump injection, WS origin, agent-side authorization
// ---------------------------------------------------------------------------

/// Grant the `viewer` account a feature set (admin token required).
async fn set_viewer_features(app: &Router<()>, admin: &str, features: Value) {
    let (st, _, j) = call(
        app,
        "PUT",
        "/api/users/viewer",
        Some(admin),
        Some(serde_json::json!({ "features": features })),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "could not set viewer features: {j}");
}

/// `edit_files` must not reach the files that cross a privilege boundary:
/// `meta.yaml` drives monitoring/backup config, `backup.sh` runs as root and
/// embeds repo credentials, `.restic_*` holds the repo password.
#[tokio::test]
async fn file_api_denies_privileged_service_files() {
    let h = harness().await;
    let (_, admin) = login(&h.app, "admin", PASSWORD).await;
    set_viewer_features(&h.app, &admin, serde_json::json!({"edit_files": true})).await;
    let (_, viewer) = login(&h.app, "viewer", PASSWORD).await;

    for path in ["meta.yaml", "backup.sh", ".restic_password", "sub/meta.yaml"] {
        let (st, _, j) = call(
            &h.app,
            "PUT",
            "/api/services/svc_a/files",
            Some(&viewer),
            Some(serde_json::json!({"path": path, "content": "pwned"})),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::BAD_REQUEST,
            "file write to {path} was accepted: {j}"
        );
        let (st, _, _) = call(
            &h.app,
            "GET",
            &format!("/api/services/svc_a/files?path={path}"),
            Some(&viewer),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "read of {path} was accepted");
        let (st, _, _) = call(
            &h.app,
            "DELETE",
            &format!("/api/services/svc_a/files?path={path}"),
            Some(&viewer),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "delete of {path} was accepted");
    }
    // control: an ordinary file is still editable
    let (st, _, _) = call(
        &h.app,
        "PUT",
        "/api/services/svc_a/files",
        Some(&viewer),
        Some(serde_json::json!({"path": "notes.txt", "content": "hello"})),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    // the privileged files were never created by the writes above
    let dir = h._dir.path().join("svc/svc_a");
    assert!(!dir.join("meta.yaml").exists());
    assert!(!dir.join("backup.sh").exists());
}

/// The compose file is governed by `edit_compose` + compose policy — a raw
/// file write must not bypass either.
#[tokio::test]
async fn file_write_to_compose_needs_edit_compose_and_policy() {
    let h = harness().await;
    let (_, admin) = login(&h.app, "admin", PASSWORD).await;
    set_viewer_features(&h.app, &admin, serde_json::json!({"edit_files": true})).await;
    let (_, viewer) = login(&h.app, "viewer", PASSWORD).await;

    let compose = "/api/services/svc_a/files";
    // edit_files but no edit_compose → forbidden
    let (st, _, _) = call(
        &h.app,
        "PUT",
        compose,
        Some(&viewer),
        Some(serde_json::json!({
            "path": "docker-compose.yml",
            "content": "services:\n  app:\n    image: alpine\n"
        })),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN, "compose write without edit_compose");

    set_viewer_features(
        &h.app,
        &admin,
        serde_json::json!({"edit_files": true, "edit_compose": true}),
    )
    .await;
    let (_, viewer) = login(&h.app, "viewer", PASSWORD).await;
    // with edit_compose the compose policy still applies
    let (st, _, _) = call(
        &h.app,
        "PUT",
        compose,
        Some(&viewer),
        Some(serde_json::json!({
            "path": "docker-compose.yml",
            "content": "services:\n  app:\n    image: alpine\n    privileged: true\n"
        })),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "privileged compose via file API");
    // a clean compose is fine
    let (st, _, j) = call(
        &h.app,
        "PUT",
        compose,
        Some(&viewer),
        Some(serde_json::json!({
            "path": "docker-compose.yml",
            "content": "services:\n  app:\n    image: alpine\n    command: sleep 9\n"
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{j}");
    // renaming onto the compose file would sidestep the policy check
    let (st, _, _) = call(
        &h.app,
        "POST",
        "/api/services/svc_a/files/rename",
        Some(&viewer),
        Some(serde_json::json!({"from": "notes.txt", "to": "docker-compose.yml"})),
    )
    .await;
    assert!(
        st == StatusCode::BAD_REQUEST || st == StatusCode::FORBIDDEN,
        "rename onto compose accepted: {st}"
    );
}

/// `exec_command` monitoring actions run host commands with no user context:
/// configuring them is admin-only, indices must be valid, and the target
/// must not be role-gated.
#[tokio::test]
async fn monitoring_exec_actions_require_admin() {
    let h = harness().await;
    let (_, admin) = login(&h.app, "admin", PASSWORD).await;
    set_viewer_features(&h.app, &admin, serde_json::json!({"manage_monitoring": true})).await;
    let (_, viewer) = login(&h.app, "viewer", PASSWORD).await;

    let exec_cfg = serde_json::json!({
        "health": {
            "kind": "tcp", "target": "127.0.0.1", "port": 1,
            "failure_threshold": 1,
            "actions": [{"type": "exec_command", "section_index": 0, "item_index": 0}]
        },
        "log_alerts": []
    });
    let (st, _, _) = call(
        &h.app,
        "PUT",
        "/api/services/svc_a/monitoring",
        Some(&viewer),
        Some(exec_cfg.clone()),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN, "non-admin configured exec_command");

    // admin may configure it
    let (st, _, j) = call(
        &h.app,
        "PUT",
        "/api/services/svc_a/monitoring",
        Some(&admin),
        Some(exec_cfg),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{j}");

    // but never against a role-gated command (auto-actions carry no caller)
    let (st, _, _) = call(
        &h.app,
        "PUT",
        "/api/services/svc_a/monitoring",
        Some(&admin),
        Some(serde_json::json!({
            "health": {
                "kind": "tcp", "target": "127.0.0.1", "port": 1,
                "actions": [{"type": "exec_command", "section_index": 1, "item_index": 0}]
            },
            "log_alerts": []
        })),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "role-gated exec target accepted");

    // and out-of-range indices are rejected
    let (st, _, _) = call(
        &h.app,
        "PUT",
        "/api/services/svc_a/monitoring",
        Some(&admin),
        Some(serde_json::json!({
            "health": {
                "kind": "tcp", "target": "127.0.0.1", "port": 1,
                "actions": [{"type": "exec_command", "section_index": 99, "item_index": 0}]
            },
            "log_alerts": []
        })),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "bad section index accepted");

    // plain restart actions remain available to manage_monitoring users
    let (st, _, j) = call(
        &h.app,
        "PUT",
        "/api/services/svc_a/monitoring",
        Some(&viewer),
        Some(serde_json::json!({
            "health": {
                "kind": "tcp", "target": "127.0.0.1", "port": 1,
                "actions": [{"type": "restart"}]
            },
            "log_alerts": []
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{j}");
}

/// `stdin_dumps` are rendered unquoted into a root-run script — the service
/// name and argv must be metacharacter-free, and the service must exist.
#[tokio::test]
async fn backup_dumps_reject_shell_metacharacters() {
    let h = harness().await;
    let (_, admin) = login(&h.app, "admin", PASSWORD).await;
    set_viewer_features(&h.app, &admin, serde_json::json!({"manage_backup": true})).await;
    let (_, viewer) = login(&h.app, "viewer", PASSWORD).await;

    let dump = |service: &str, cmd: Vec<&str>| {
        serde_json::json!({
            "enabled": true, "paths": [], "schedule_enabled": false,
            "stdin_dumps": [{
                "filename": "db.sql", "service": service,
                "command": cmd, "env_file": null
            }]
        })
    };
    for (what, body) in [
        (
            "service with ;",
            dump("db; touch /tmp/pwned", vec!["pg_dump"]),
        ),
        ("command substitution", dump("app", vec!["$(id)"])),
        ("backticks", dump("app", vec!["pg_dump `id`"])),
        ("pipe", dump("app", vec!["pg_dump | tee /tmp/x"])),
        ("newline", dump("app", vec!["pg_dump\nrm -rf /"])),
        ("env_file escape", {
            let mut b = dump("app", vec!["pg_dump"]);
            b["stdin_dumps"][0]["env_file"] = serde_json::json!("../../etc/shadow");
            b
        }),
    ] {
        let (st, _, j) = call(
            &h.app,
            "PUT",
            "/api/services/svc_a/backup",
            Some(&viewer),
            Some(body),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{what} accepted: {j}");
    }
    // a legitimate dump (service exists in the harness compose) is accepted
    let (st, _, j) = call(
        &h.app,
        "PUT",
        "/api/services/svc_a/backup",
        Some(&viewer),
        Some(dump("app", vec!["pg_dump", "-U", "${PGUSER}"])),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{j}");
    // a service that is not in the compose file is rejected by the agent
    // (compose membership is only knowable agent-side, so this is an
    // agent rejection rather than a 400 from the server)
    let (st, _, j) = call(
        &h.app,
        "PUT",
        "/api/services/svc_a/backup",
        Some(&viewer),
        Some(dump("nosuchservice", vec!["pg_dump"])),
    )
    .await;
    assert!(!st.is_success(), "unknown dump service accepted: {j}");
}

/// Cross-origin browser WebSocket handshakes must be rejected; same-origin
/// and non-browser clients still work.
///
/// The gate lives in the handlers (see `api::ws::ws_origin_ok`), which
/// `WebSocketUpgrade` extraction only reaches on a real hyper connection
/// carrying the `OnUpgrade` extension — that isn't reproducible through
/// `oneshot`, so the predicate is exercised directly here.
#[test]
fn ws_origin_gate_rejects_cross_origin() {
    use crate::api::ws::ws_origin_ok;
    let hdr = |pairs: &[(&str, &str)]| {
        let mut m = HeaderMap::new();
        for (k, v) in pairs {
            m.insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        m
    };
    let allowed: Vec<String> = vec!["https://ui.example.com".into()];

    // cross-origin browser handshake → rejected
    assert!(!ws_origin_ok(
        &allowed,
        &hdr(&[("origin", "http://evil.example"), ("host", "localhost:8080")])
    ));
    // same-origin → allowed
    assert!(ws_origin_ok(
        &allowed,
        &hdr(&[("origin", "http://localhost:8080"), ("host", "localhost:8080")])
    ));
    // explicitly allowlisted origin → allowed
    assert!(ws_origin_ok(
        &allowed,
        &hdr(&[
            ("origin", "https://ui.example.com"),
            ("host", "localhost:8080")
        ])
    ));
    // non-browser client (no Origin header) → unaffected
    assert!(ws_origin_ok(&allowed, &hdr(&[("host", "localhost:8080")])));
    // `null` origin (sandboxed iframe / file://) → rejected
    assert!(!ws_origin_ok(
        &allowed,
        &hdr(&[("origin", "null"), ("host", "localhost:8080")])
    ));
    // an origin with no scheme is not same-origin
    assert!(!ws_origin_ok(
        &allowed,
        &hdr(&[("origin", "localhost:8080"), ("host", "localhost:8080")])
    ));
    // a different port is a different origin
    assert!(!ws_origin_ok(
        &allowed,
        &hdr(&[("origin", "http://localhost:9999"), ("host", "localhost:8080")])
    ));
}

/// The agent must re-check authorization itself: a service-scoped token must
/// not reach another service even if the server is compromised, and feature
/// gates must hold at the agent boundary too.
#[tokio::test]
async fn agent_enforces_authorization_on_remote_transport() {
    let h = harness_remote().await;
    let (_, admin) = login(&h.app, "admin", PASSWORD).await;
    let (_, _, j) = call(
        &h.app,
        "POST",
        "/api/auth/token",
        Some(&admin),
        Some(serde_json::json!({
            "services": ["svc_a"],
            "actions": ["operator", "edit_files", "edit_compose", "manage_backup",
                        "manage_monitoring", "run_commands"]
        })),
    )
    .await;
    let scoped = j.pointer("/data/token").unwrap().as_str().unwrap().to_string();

    // scoped token: svc_a ok, svc_b denied — directly against the agent
    let ok = h
        .state
        .agent
        .call(
            crate::agent::proto::SyncVerb::ComposeRead {
                service: "svc_a".into(),
            },
            &scoped,
        )
        .await;
    assert!(ok.is_ok(), "agent denied in-scope service: {ok:?}");
    for verb in [
        crate::agent::proto::SyncVerb::ComposeRead {
            service: "svc_b".into(),
        },
        crate::agent::proto::SyncVerb::FileNode {
            service: "svc_b".into(),
            path: "".into(),
        },
        crate::agent::proto::SyncVerb::BackupGet {
            service: "svc_b".into(),
        },
    ] {
        let r = h.state.agent.call(verb.clone(), &scoped).await;
        assert!(r.is_err(), "agent allowed out-of-scope verb {verb:?}");
    }
    // the agent's service list is filtered for the scoped token
    let v = h
        .state
        .agent
        .call(crate::agent::proto::SyncVerb::ServicesList, &scoped)
        .await
        .unwrap();
    let names: Vec<String> = v
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|s| s["name"].as_str().map(String::from))
        .collect();
    assert_eq!(names, vec!["svc_a"], "agent leaked svc_b to a scoped token");

    // feature gates hold at the agent: a viewer without edit_files cannot
    // write files even with a valid token
    let (_, viewer) = login(&h.app, "viewer", PASSWORD).await;
    let r = h
        .state
        .agent
        .call(
            crate::agent::proto::SyncVerb::FileWrite {
                service: "svc_a".into(),
                path: "x.txt".into(),
                content: "x".into(),
            },
            &viewer,
        )
        .await;
    assert!(r.is_err(), "agent allowed FileWrite without edit_files");

    // ExecVerb: the viewer may run ungated commands but not the admin-only
    // section (server-side check mirrored in the agent)
    let exec = h.state.exec.clone();
    let r = h
        .state
        .agent
        .exec(
            crate::agent::proto::ExecVerb::SectionItem {
                section: 1,
                item: 0,
                params: Default::default(),
            },
            "admin-only".to_string(),
            None,
            &viewer,
            "viewer",
            &exec,
        )
        .await;
    assert!(r.is_err(), "agent ran an admin-only command for a viewer");

    // ...and a service-scoped token cannot run a command against svc_b
    let r = h
        .state
        .agent
        .exec(
            crate::agent::proto::ExecVerb::Compose {
                service: "svc_b".into(),
                op: crate::agent::proto::ComposeOp::Up,
            },
            "compose up".to_string(),
            Some("svc_b".into()),
            &scoped,
            "admin",
            &exec,
        )
        .await;
    assert!(r.is_err(), "agent ran compose for an out-of-scope service");
}

#[tokio::test]
async fn agent_never_returns_password_hashes() {
    let h = harness().await;
    let (_, tok) = login(&h.app, "admin", PASSWORD).await;
    let v = h
        .state
        .agent
        .crypto(crate::agent::proto::CryptoOp::UsersList { token: tok.clone() })
        .await
        .unwrap();
    let s = serde_json::to_string(&v).unwrap();
    assert!(
        !s.contains("$argon2"),
        "users_list leaked a password hash: {s}"
    );
    // Verify returns the user — hash must be stripped there too.
    let v = h
        .state
        .agent
        .crypto(crate::agent::proto::CryptoOp::Verify { token: tok })
        .await
        .unwrap();
    let s = serde_json::to_string(&v).unwrap();
    assert!(!s.contains("$argon2"), "verify leaked a password hash: {s}");
}

/// Compromised-server case: a token whose user was deleted must fail at the
/// AGENT boundary, not just at the server's auth extractor.
#[tokio::test]
async fn agent_rejects_deleted_users_token() {
    let h = harness().await;
    let (_, tok) = login(&h.app, "viewer", PASSWORD).await;
    // Delete the user row directly — bypasses the API entirely.
    let users_path = h._dir.path().join("users.yaml");
    let yaml = std::fs::read_to_string(&users_path).unwrap();
    let yaml = yaml.replace(
        "  - name: viewer\n    password_hash:",
        "  - name: gone\n    password_hash:",
    );
    std::fs::write(&users_path, yaml).unwrap();
    let r = h
        .state
        .agent
        .call(crate::agent::proto::SyncVerb::ServicesList, &tok)
        .await;
    assert!(r.is_err(), "deleted user's token still authorized at agent");
}

/// Role changes are enforced from the fresh user record inside the agent —
/// an old admin token must not retain agent-level admin after demotion.
#[tokio::test]
async fn demoted_admin_loses_agent_admin() {
    let h = harness().await;
    let (_, tok) = login(&h.app, "admin", PASSWORD).await;
    let users_path = h._dir.path().join("users.yaml");
    let yaml = std::fs::read_to_string(&users_path).unwrap();
    let yaml = yaml.replace("roles: [admin]", "roles: [viewer]");
    std::fs::write(&users_path, yaml).unwrap();
    let r = h
        .state
        .agent
        .crypto(crate::agent::proto::CryptoOp::UsersList { token: tok.clone() })
        .await;
    assert!(
        r.is_err(),
        "demoted admin retained agent admin via stale token"
    );
    // Minted children must not resurrect the dropped role either.
    let v = h
        .state
        .agent
        .crypto(crate::agent::proto::CryptoOp::Mint {
            token: tok,
            ttl_minutes: Some(5),
            services: None,
            actions: None,
        })
        .await;
    assert!(v.is_ok(), "mint should still work (roles narrowed)");
    let child = v.unwrap()["token"].as_str().unwrap().to_string();
    let v = h
        .state
        .agent
        .crypto(crate::agent::proto::CryptoOp::Verify { token: child })
        .await
        .unwrap();
    let roles = &v["claims"]["roles"];
    assert!(
        !serde_json::to_string(roles).unwrap().contains("admin"),
        "child token resurrected admin role: {roles}"
    );
}

/// The login response itself must not carry the password hash into the
/// unprivileged process.
#[tokio::test]
async fn authenticate_never_returns_hash() {
    let h = harness().await;
    let v = h
        .state
        .agent
        .crypto(crate::agent::proto::CryptoOp::Authenticate {
            name: "admin".into(),
            password: PASSWORD.into(),
            ip: None,
        })
        .await
        .unwrap();
    let s = serde_json::to_string(&v).unwrap();
    assert!(
        !s.contains("$argon2"),
        "authenticate leaked a password hash: {s}"
    );
}

/// users.yaml must never be written world-readable — it holds password
/// hashes.
#[tokio::test]
async fn users_file_written_private() {
    use std::os::unix::fs::PermissionsExt;
    let h = harness().await;
    let (_, tok) = login(&h.app, "admin", PASSWORD).await;
    h.state
        .agent
        .crypto(crate::agent::proto::CryptoOp::UserMutate {
            token: tok,
            op: crate::agent::proto::UserMut::Create {
                name: "newbie".into(),
                password: "sufficiently-long".into(),
                roles: vec!["viewer".into()],
                access: vec![],
                features: None,
                compose_policy: None,
            },
        })
        .await
        .unwrap();
    let mode = std::fs::metadata(h._dir.path().join("users.yaml"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    // 0640 is expected: group-read lets the unprivileged server load the
    // user list, but the file must never be world-accessible.
    assert_eq!(mode & 0o007, 0, "users.yaml is world-accessible: {mode:o}");
}

/// Local clone URLs let the privileged agent read arbitrary host repos —
/// denied unless security.allow_local_git_clone is set.
#[tokio::test]
async fn local_clone_blocked_by_default() {
    let h = harness().await;
    let (_, tok) = login(&h.app, "admin", PASSWORD).await;
    let core = h.state.agent.local_core().unwrap();
    let mut rx = core
        .exec(
            crate::agent::proto::ExecVerb::GitClone {
                service: "svc_a".into(),
                url: "file:///etc".into(),
                path: "loot".into(),
                branch: None,
            },
            "e-test".into(),
            "clone".into(),
            &tok,
        )
        .await
        .unwrap();
    // Validation happens inside the exec task — failure arrives as a frame.
    let mut failed = false;
    while let Some(msg) = rx.recv().await {
        if let crate::protocol::ServerMessage::ExecutionFinished { success, .. } = msg {
            failed = !success;
            break;
        }
    }
    assert!(failed, "local clone URL accepted without opt-in");
}

/// Secret-merge on notifier update happens inside the agent: the server
/// sends a raw patch, and "***" keeps the stored secret.
#[tokio::test]
async fn notifier_update_merges_secrets_in_agent() {
    let h = harness().await;
    let (_, tok) = login(&h.app, "admin", PASSWORD).await;
    // create a notifier carrying a secret URL
    let create = h
        .app
        .clone()
        .oneshot(
            Request::post("/api/monitoring/notifiers")
                .header("authorization", format!("Bearer {tok}"))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"type":"webhook","id":"w1","url":"https://real:secret@example.com/hook"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create.status(), 200);
    // update only the id-visible fields — url left as "***"
    let upd = h
        .app
        .clone()
        .oneshot(
            Request::put("/api/monitoring/notifiers/w1")
                .header("authorization", format!("Bearer {tok}"))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"type":"webhook","id":"w1","url":"***"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(upd.status(), 200);
    let on_disk = std::fs::read_to_string(h._dir.path().join("config.yaml")).unwrap();
    assert!(
        on_disk.contains("https://real:secret@example.com/hook"),
        "secret lost on update: {on_disk}"
    );
    // and a hostile server can't steal it: the parsed config it holds
    // (redacted view is wired in serve(); harness shares Local so check
    // the API output path) — get_config must show ***.
    let g = h
        .app
        .clone()
        .oneshot(
            Request::get("/api/config")
                .header("authorization", format!("Bearer {tok}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(g.into_body(), 1 << 20).await.unwrap();
    let s = String::from_utf8_lossy(&body);
    assert!(
        !s.contains("real:secret"),
        "config leaked notifier url: {s}"
    );
}

/// Scope `services: ["svc_a"]` must deny svc_b on EVERY endpoint class —
/// reads, actions, compose/unit writes, files, git, backup, monitoring.
#[tokio::test]
async fn scoped_token_denies_svc_b_everywhere() {
    let h = harness().await;
    let (_, admin) = login(&h.app, "admin", PASSWORD).await;
    let (_, _, j) = call(
        &h.app,
        "POST",
        "/api/auth/token",
        Some(&admin),
        Some(serde_json::json!({
            "ttl_minutes": 30,
            "services": ["svc_a"],
            "actions": ["operator", "edit_compose", "edit_units", "edit_files",
                        "manage_backup", "manage_monitoring", "create_services",
                        "run_commands", "admin", "unrestricted"]
        })),
    )
    .await;
    let scoped = j.pointer("/data/token").unwrap().as_str().unwrap().to_string();
    let deny = |st: StatusCode, what: &str| {
        assert!(
            st == StatusCode::FORBIDDEN || st == StatusCode::NOT_FOUND,
            "scoped token reached {what}: {st}"
        );
    };
    // reads
    let (st, _, _) = call(&h.app, "GET", "/api/services/svc_b", Some(&scoped), None).await;
    deny(st, "GET svc_b detail");
    let (st, _, _) = call(&h.app, "GET", "/api/services/svc_b/compose", Some(&scoped), None).await;
    deny(st, "GET svc_b compose");
    let (st, _, _) = call(&h.app, "GET", "/api/services/svc_b/unit", Some(&scoped), None).await;
    deny(st, "GET svc_b unit");
    let (st, _, _) = call(&h.app, "GET", "/api/services/svc_b/unit/check", Some(&scoped), None).await;
    deny(st, "GET svc_b unit check");
    let (st, _, _) = call(&h.app, "GET", "/api/services/svc_b/logs", Some(&scoped), None).await;
    deny(st, "GET svc_b logs");
    let (st, _, _) = call(&h.app, "GET", "/api/services/svc_b/files", Some(&scoped), None).await;
    deny(st, "GET svc_b files");
    let (st, _, _) = call(&h.app, "GET", "/api/services/svc_b/git/repos", Some(&scoped), None).await;
    deny(st, "GET svc_b git repos");
    let (st, _, _) = call(&h.app, "GET", "/api/services/svc_b/backup", Some(&scoped), None).await;
    deny(st, "GET svc_b backup");
    let (st, _, _) = call(&h.app, "GET", "/api/services/svc_b/monitoring", Some(&scoped), None).await;
    deny(st, "GET svc_b monitoring");
    // actions / exec
    let (st, _, _) = call(
        &h.app, "POST", "/api/services/svc_b/actions", Some(&scoped),
        Some(serde_json::json!({"action": "restart"})),
    ).await;
    deny(st, "svc_b action");
    let (st, _, _) = call(
        &h.app, "DELETE", "/api/services/svc_b", Some(&scoped), None,
    ).await;
    deny(st, "DELETE svc_b");
    // writes
    let (st, _, _) = call(
        &h.app, "PUT", "/api/services/svc_b/compose", Some(&scoped),
        Some(serde_json::json!({"content": "services:\n  x:\n    image: alpine\n"})),
    ).await;
    deny(st, "PUT svc_b compose");
    let (st, _, _) = call(
        &h.app, "PUT", "/api/services/svc_b/unit", Some(&scoped),
        Some(serde_json::json!({"content": "[Service]\nExecStart=/bin/true\n"})),
    ).await;
    deny(st, "PUT svc_b unit");
    let (st, _, _) = call(
        &h.app, "PUT", "/api/services/svc_b/files", Some(&scoped),
        Some(serde_json::json!({"path": "evil.txt", "content": "x"})),
    ).await;
    deny(st, "PUT svc_b file");
    let (st, _, _) = call(
        &h.app, "DELETE", "/api/services/svc_b/files?path=docker-compose.yml", Some(&scoped), None,
    ).await;
    deny(st, "DELETE svc_b file");
    let (st, _, _) = call(
        &h.app, "POST", "/api/services/svc_b/git/clone", Some(&scoped),
        Some(serde_json::json!({"url": "https://example.com/r.git", "path": "repo"})),
    ).await;
    deny(st, "svc_b git clone");
    let (st, _, _) = call(
        &h.app, "PUT", "/api/services/svc_b/backup", Some(&scoped),
        Some(serde_json::json!({"enabled": true, "paths": [], "stdin_dumps": [], "schedule_enabled": false})),
    ).await;
    deny(st, "PUT svc_b backup cfg");
    let (st, _, _) = call(
        &h.app, "POST", "/api/services/svc_b/backup/run", Some(&scoped), None,
    ).await;
    deny(st, "svc_b backup run");
    let (st, _, _) = call(
        &h.app, "PUT", "/api/services/svc_b/monitoring", Some(&scoped),
        Some(serde_json::json!({"enabled": false})),
    ).await;
    deny(st, "PUT svc_b monitoring");
}

/// The canonical usage: mint with ONLY a services scope (no actions).
/// The admin role must not silently survive and void the service scope.
#[tokio::test]
async fn services_only_scope_must_not_stay_admin() {
    let h = harness().await;
    let (_, admin) = login(&h.app, "admin", PASSWORD).await;
    let (_, _, j) = call(
        &h.app,
        "POST",
        "/api/auth/token",
        Some(&admin),
        Some(serde_json::json!({"services": ["svc_a"]})),
    )
    .await;
    let scoped = j.pointer("/data/token").unwrap().as_str().unwrap().to_string();
    // service list must be narrowed...
    let (st, _, j) = call(&h.app, "GET", "/api/services", Some(&scoped), None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(service_names(&j), vec!["svc_a"], "services scope ignored");
    // ...and svc_b endpoints must be denied
    let (st, _, _) = call(&h.app, "GET", "/api/services/svc_b", Some(&scoped), None).await;
    assert_eq!(st, StatusCode::FORBIDDEN, "scoped token reached svc_b: {st}");
    // admin-only surface must also be gone (scope narrows, never widens)
    let (st, _, _) = call(&h.app, "GET", "/api/users", Some(&scoped), None).await;
    assert_eq!(st, StatusCode::FORBIDDEN, "scoped token still admin: {st}");
}

// ---------------------------------------------------------------------------
// Container exec (docker exec inside a service's containers)
// ---------------------------------------------------------------------------

fn seed_exec_containers(h: &Harness) {
    h.docker
        .projects
        .lock()
        .unwrap()
        .extend([("c1".to_string(), "svc_a".to_string()), ("c2".to_string(), "svc_b".to_string())]);
    let mut cs = h.docker.containers.lock().unwrap();
    cs.push(docker::ContainerInfo {
        id: "c1".into(),
        name: "svc_a-app-1".into(),
        service: "app".into(),
        state: "running".into(),
        status: "Up".into(),
        health: None,
    });
    cs.push(docker::ContainerInfo {
        id: "c2".into(),
        name: "svc_b-app-1".into(),
        service: "app".into(),
        state: "running".into(),
        status: "Up".into(),
        health: None,
    });
}

async fn grant_exec_feature(h: &Harness, name: &str) {
    let name = name.to_string();
    h.state
        .users
        .mutate(move |f| {
            f.users
                .iter_mut()
                .find(|u| u.name == name)
                .unwrap()
                .features
                .exec_containers = true;
            Ok(())
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn container_exec_rights() {
    let h = harness().await;
    seed_exec_containers(&h);
    let (_, viewer) = login(&h.app, "viewer", PASSWORD).await;
    let (_, admin) = login(&h.app, "admin", PASSWORD).await;

    // No exec_containers feature → denied.
    let (st, _, _) = call(
        &h.app,
        "POST",
        "/api/services/svc_a/exec",
        Some(&viewer),
        Some(serde_json::json!({"container": "c1", "command": "id"})),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);

    // Grant the feature → allowed on an accessible service.
    grant_exec_feature(&h, "viewer").await;
    let (st, _, j) = call(
        &h.app,
        "POST",
        "/api/services/svc_a/exec",
        Some(&viewer),
        Some(serde_json::json!({"container": "c1", "command": ["id"]})),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{j}");
    assert!(j.pointer("/data/execution_id").is_some());
    // container may also be addressed by name or compose service name
    for c in ["svc_a-app-1", "app"] {
        let (st, _, j) = call(
            &h.app,
            "POST",
            "/api/services/svc_a/exec",
            Some(&viewer),
            Some(serde_json::json!({"container": c, "command": "id"})),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "{c}: {j}");
    }
    // a container that is not part of the service is refused
    let (st, _, _) = call(
        &h.app,
        "POST",
        "/api/services/svc_a/exec",
        Some(&viewer),
        Some(serde_json::json!({"container": "c2", "command": "id"})),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);

    // Bad command shapes are rejected before reaching docker.
    for bad in [
        serde_json::json!([]),
        serde_json::json!(42),
        serde_json::json!({"a": 1}),
        serde_json::json!(""),
        serde_json::json!([1, 2]),
    ] {
        let (st, _, _) = call(
            &h.app,
            "POST",
            "/api/services/svc_a/exec",
            Some(&viewer),
            Some(serde_json::json!({"container": "c1", "command": bad})),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{bad}");
    }

    // The any-container route is admin-only — even with the feature.
    let (st, _, _) = call(
        &h.app,
        "POST",
        "/api/containers/foreign9/exec",
        Some(&viewer),
        Some(serde_json::json!({"command": "id"})),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let (st, _, j) = call(
        &h.app,
        "POST",
        "/api/containers/foreign9/exec",
        Some(&admin),
        Some(serde_json::json!({"command": "id"})),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{j}");
}

/// Agent boundary (compromised server): the container's project label is
/// resolved agent-side — a svc_a-scoped token cannot exec into svc_b's
/// container, and an unmanaged container requires a real admin.
#[tokio::test]
async fn container_exec_agent_side_label_check() {
    let h = harness_remote().await;
    seed_exec_containers(&h);
    // The scoped token's fresh record is admin's — give it the feature so
    // the access check (not the feature check) is what decides.
    grant_exec_feature(&h, "admin").await;
    let (_, admin) = login(&h.app, "admin", PASSWORD).await;
    let (_, _, j) = call(
        &h.app,
        "POST",
        "/api/auth/token",
        Some(&admin),
        Some(serde_json::json!({"services": ["svc_a"], "actions": ["operator", "exec_containers"]})),
    )
    .await;
    let scoped = j.pointer("/data/token").unwrap().as_str().unwrap().to_string();
    let exec = h.state.exec.clone();
    let mk = |id: &str| crate::agent::proto::ExecVerb::ContainerExec {
        container: id.to_string(),
        command: vec!["id".to_string()],
    };

    // in-scope container → allowed and streams to completion
    let ok = h
        .state
        .agent
        .exec_collect(mk("c1"), "exec", Some("svc_a".into()), &scoped, "a", &exec)
        .await
        .unwrap();
    assert!(ok);
    // svc_b's container → denied agent-side, before the exec starts
    let r = h
        .state
        .agent
        .exec(mk("c2"), "exec".to_string(), None, &scoped, "a", &exec)
        .await;
    assert!(r.is_err(), "agent exec'd into an out-of-scope container");
    // unlabeled/unmanaged container → admin only
    let r = h
        .state
        .agent
        .exec(mk("c9"), "exec".to_string(), None, &scoped, "a", &exec)
        .await;
    assert!(r.is_err(), "unmanaged container exec allowed for non-admin");
    // ...but a real admin can exec there
    let ok = h
        .state
        .agent
        .exec_collect(mk("c9"), "exec", None, &admin, "a", &exec)
        .await
        .unwrap();
    assert!(ok);
    // a non-zero exit code is reported as a failed execution
    *h.docker.exec_exit.lock().unwrap() = 7;
    let ok = h
        .state
        .agent
        .exec_collect(mk("c1"), "exec", Some("svc_a".into()), &scoped, "a", &exec)
        .await
        .unwrap();
    assert!(!ok, "non-zero exit code reported as success");

    // The agent's own justification log records the authoritative argv and
    // the resolved project (the exec title alone comes from the server).
    let log = std::fs::read_to_string(h._dir.path().join("justification.log")).unwrap();
    assert!(log.contains("container_exec"), "no container_exec entry: {log}");
    assert!(log.contains("project: svc_a"), "project not recorded: {log}");
    assert!(log.contains("unmanaged"), "unmanaged exec not recorded: {log}");
    assert!(log.contains("id"), "argv not recorded: {log}");
}

// ---------------------------------------------------------------------------
// File streaming data plane (the WebDAV PUT/GET path)
// ---------------------------------------------------------------------------

async fn put_file(h: &Harness, token: &str, service: &str, path: &str, body: &[u8]) {
    let mut sink = h
        .state
        .agent
        .file_put(service, path, body.len() as u64, token)
        .await
        .unwrap();
    // two chunks, to exercise the incremental write path
    let mid = body.len() / 2;
    sink.write(&body[..mid]).await.unwrap();
    sink.write(&body[mid..]).await.unwrap();
    let meta = sink.finish().await.unwrap();
    assert_eq!(meta.size, body.len() as u64);
}

async fn get_file(h: &Harness, token: &str, service: &str, path: &str, off: u64, len: u64) -> (u64, Vec<u8>) {
    let (meta, sent, mut s) = h
        .state
        .agent
        .file_get(service, path, off, len, token)
        .await
        .unwrap();
    let mut got = vec![];
    tokio::io::AsyncReadExt::read_to_end(&mut s, &mut got).await.unwrap();
    assert_eq!(got.len() as u64, sent);
    (meta.size, got)
}

#[tokio::test]
async fn file_stream_roundtrip_local_and_remote() {
    for remote in [false, true] {
        let h = if remote {
            harness_remote().await
        } else {
            harness().await
        };
        let (_, admin) = login(&h.app, "admin", PASSWORD).await;
        let body = b"hello webdav \x00\x01 binary ok".to_vec();
        put_file(&h, &admin, "svc_a", "data/blob.bin", &body).await;

        // whole file
        let (size, got) = get_file(&h, &admin, "svc_a", "data/blob.bin", 0, 0).await;
        assert_eq!(size, body.len() as u64);
        assert_eq!(got, body, "remote={remote}");

        // ranged read
        let (_size, got) = get_file(&h, &admin, "svc_a", "data/blob.bin", 6, 6).await;
        assert_eq!(got, b"webdav");

        // offset past EOF yields nothing
        let (_size, got) = get_file(&h, &admin, "svc_a", "data/blob.bin", 9999, 0).await;
        assert!(got.is_empty());

        // a short body is refused and leaves nothing behind
        let mut sink = h
            .state
            .agent
            .file_put("svc_a", "data/short.bin", 100, &admin)
            .await
            .unwrap();
        sink.write(b"only-a-few").await.unwrap();
        assert!(
            sink.finish().await.is_err(),
            "truncated upload accepted (remote={remote})"
        );
        assert!(
            h.state.agent.file_stat("svc_a", "data/short.bin", &admin).await.is_err(),
            "truncated upload left a file behind (remote={remote})"
        );

        // denied / escaping targets are refused before any body is accepted
        for bad in ["meta.yaml", "backup.sh", ".restic_password", ".git/config", "../escape"] {
            assert!(
                h.state.agent.file_put("svc_a", bad, 3, &admin).await.is_err(),
                "{bad} was accepted (remote={remote})"
            );
        }

        // the agent re-checks the feature, not just the server
        let (_, viewer) = login(&h.app, "viewer", PASSWORD).await;
        assert!(
            h.state.agent.file_put("svc_a", "x.bin", 1, &viewer).await.is_err(),
            "viewer without edit_files could upload (remote={remote})"
        );

        // oversized uploads are refused at authorize time
        let big = h.state.config.get().await.webdav.max_upload_bytes + 1;
        assert!(
            h.state.agent.file_put("svc_a", "x.bin", big, &admin).await.is_err(),
            "oversized upload accepted (remote={remote})"
        );
    }
}

// ---------------------------------------------------------------------------
// WebDAV file surface (`/dav`)
// ---------------------------------------------------------------------------

/// WebDAV request helper: custom methods, custom headers, optional body.
/// Content-Length is set automatically (the agent authorizes on a declared
/// length), matching what real clients send. Returns the raw body bytes —
/// use `dav` for the lossy-UTF-8 convenience wrapper.
async fn dav_raw(
    app: &Router<()>,
    method: &str,
    uri: &str,
    token: Option<&str>,
    headers: &[(&str, &str)],
    body: Option<Vec<u8>>,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut b = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    let has_cl = headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-length"));
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    let req = match body {
        Some(v) => {
            if !has_cl {
                b = b.header("content-length", v.len().to_string());
            }
            b.body(Body::from(v)).unwrap()
        }
        None => b.body(Body::empty()).unwrap(),
    };
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let hdrs = resp.headers().clone();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    (status, hdrs, bytes.to_vec())
}

async fn dav(
    app: &Router<()>,
    method: &str,
    uri: &str,
    token: Option<&str>,
    headers: &[(&str, &str)],
    body: Option<Vec<u8>>,
) -> (StatusCode, HeaderMap, String) {
    let (st, hdrs, bytes) = dav_raw(app, method, uri, token, headers, body).await;
    (st, hdrs, String::from_utf8_lossy(&bytes).to_string())
}

async fn grant_features(
    h: &Harness,
    name: &str,
    f: impl FnOnce(&mut crate::users::UserFeatures),
) {
    let name = name.to_string();
    h.state
        .users
        .mutate(move |file| {
            let u = file.users.iter_mut().find(|u| u.name == name).unwrap();
            f(&mut u.features);
            Ok(())
        })
        .await
        .unwrap();
}

fn basic_auth(user: &str, token: &str) -> String {
    use base64::Engine;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{user}:{token}"))
    )
}

const LOCK_BODY: &str = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
<D:lockinfo xmlns:D=\"DAV:\"><D:lockscope><D:exclusive/></D:lockscope>\
<D:locktype><D:write/></D:locktype>\
<D:owner><D:href>mailto:ops@example.com</D:href></D:owner></D:lockinfo>";

#[tokio::test]
async fn webdav_gate_auth_and_listing() {
    // Off by default: not even an existence oracle.
    let h = harness_no_webdav().await;
    let (_, admin) = login(&h.app, "admin", PASSWORD).await;
    let (st, _, _) = dav(&h.app, "OPTIONS", "/dav", Some(&admin), &[], None).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, _, _) = dav(&h.app, "PROPFIND", "/dav/", Some(&admin), &[], None).await;
    assert_eq!(st, StatusCode::NOT_FOUND);

    let h = harness().await;
    // Authentication: the same JWT as the REST API, Bearer or Basic.
    let (st, _, _) = dav(&h.app, "PROPFIND", "/dav/", None, &[], None).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    let (st, _, _) = dav(
        &h.app,
        "PROPFIND",
        "/dav/",
        None,
        &[("authorization", "Digest nope")],
        None,
    )
    .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    let (st, _, _) = dav(
        &h.app,
        "PROPFIND",
        "/dav/",
        None,
        &[("authorization", "Basic !!!not-base64!!!")],
        None,
    )
    .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);

    let (_, admin) = login(&h.app, "admin", PASSWORD).await;
    let (st, hdrs, _) = dav(&h.app, "OPTIONS", "/dav", Some(&admin), &[], None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(hdrs.get("dav").unwrap(), "1, 2");
    assert!(hdrs.get("allow").unwrap().to_str().unwrap().contains("PROPFIND"));

    // The protocol itself needs `mount_files`.
    let (_, viewer) = login(&h.app, "viewer", PASSWORD).await;
    let (st, _, _) = dav(&h.app, "PROPFIND", "/dav/", Some(&viewer), &[], None).await;
    assert_eq!(st, StatusCode::FORBIDDEN);

    grant_features(&h, "viewer", |f| f.mount_files = true).await;
    let (_, viewer) = login(&h.app, "viewer", PASSWORD).await;
    let (st, _, body) = dav(
        &h.app,
        "PROPFIND",
        "/dav/",
        Some(&viewer),
        &[("depth", "1")],
        None,
    )
    .await;
    assert_eq!(st, StatusCode::MULTI_STATUS, "{body}");
    assert!(body.contains("/dav/svc_a/"), "{body}");
    assert!(body.contains("/dav/svc_b/"), "{body}");
    assert!(body.contains("<D:collection/>"), "{body}");

    // Basic auth carries the same JWT (what OS file managers can do).
    let basic = basic_auth("viewer", &viewer);
    let (st, _, body) = dav(
        &h.app,
        "PROPFIND",
        "/dav/svc_a/",
        None,
        &[("authorization", &basic), ("depth", "1")],
        None,
    )
    .await;
    assert_eq!(st, StatusCode::MULTI_STATUS, "{body}");
    assert!(body.contains("docker-compose.yml"), "{body}");

    // Depth: infinity is refused (unbounded walk = trivial DoS).
    let (st, _, _) = dav(
        &h.app,
        "PROPFIND",
        "/dav/",
        Some(&viewer),
        &[("depth", "infinity")],
        None,
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);

    // Unknown / malformed services do not leak existence.
    for uri in ["/dav/nosuch/", "/dav/UPPER/", "/dav/svc_a/../../etc"] {
        let (st, _, _) = dav(&h.app, "PROPFIND", uri, Some(&admin), &[("depth", "0")], None).await;
        assert!(
            matches!(st, StatusCode::NOT_FOUND | StatusCode::FORBIDDEN | StatusCode::BAD_REQUEST),
            "{uri} → {st}"
        );
    }

    // A scoped token sees only its own service.
    grant_features(&h, "admin", |f| {
        f.mount_files = true;
        f.edit_files = true;
    })
    .await;
    let (_, _, j) = call(
        &h.app,
        "POST",
        "/api/auth/token",
        Some(&admin),
        Some(serde_json::json!({"services": ["svc_a"], "actions": ["operator", "mount_files", "edit_files"]})),
    )
    .await;
    let scoped = j.pointer("/data/token").unwrap().as_str().unwrap().to_string();
    let (st, _, body) = dav(&h.app, "PROPFIND", "/dav/", Some(&scoped), &[("depth", "1")], None).await;
    assert_eq!(st, StatusCode::MULTI_STATUS, "{body}");
    assert!(body.contains("/dav/svc_a/"), "{body}");
    assert!(!body.contains("/dav/svc_b/"), "scoped token saw svc_b: {body}");
    let (st, _, _) = dav(&h.app, "PROPFIND", "/dav/svc_b/", Some(&scoped), &[("depth", "0")], None).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let (st, _, _) = dav(
        &h.app,
        "PUT",
        "/dav/svc_b/x.txt",
        Some(&scoped),
        &[],
        Some(b"x".to_vec()),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn webdav_methods_and_ranges() {
    let h = harness().await;
    let (_, admin) = login(&h.app, "admin", PASSWORD).await;

    let (st, _, _) = dav(
        &h.app,
        "PUT",
        "/dav/svc_a/notes.txt",
        Some(&admin),
        &[],
        Some(b"hello world".to_vec()),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);

    let (st, hdrs, body) = dav(&h.app, "GET", "/dav/svc_a/notes.txt", Some(&admin), &[], None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body, "hello world");
    let tag = hdrs.get("etag").unwrap().to_str().unwrap().to_string();
    assert!(hdrs.get("last-modified").is_some());
    assert_eq!(hdrs.get("accept-ranges").unwrap(), "bytes");

    let (st, hdrs, body) = dav(&h.app, "HEAD", "/dav/svc_a/notes.txt", Some(&admin), &[], None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(hdrs.get("content-length").unwrap(), "11");
    assert!(body.is_empty());

    // Ranges: explicit, to-EOF, suffix, unsatisfiable.
    let (st, hdrs, body) = dav(
        &h.app,
        "GET",
        "/dav/svc_a/notes.txt",
        Some(&admin),
        &[("range", "bytes=6-10")],
        None,
    )
    .await;
    assert_eq!(st, StatusCode::PARTIAL_CONTENT);
    assert_eq!(body, "world");
    assert_eq!(hdrs.get("content-range").unwrap(), "bytes 6-10/11");
    let (st, _, body) = dav(
        &h.app,
        "GET",
        "/dav/svc_a/notes.txt",
        Some(&admin),
        &[("range", "bytes=6-")],
        None,
    )
    .await;
    assert_eq!(st, StatusCode::PARTIAL_CONTENT);
    assert_eq!(body, "world");
    let (st, _, body) = dav(
        &h.app,
        "GET",
        "/dav/svc_a/notes.txt",
        Some(&admin),
        &[("range", "bytes=-5")],
        None,
    )
    .await;
    assert_eq!(st, StatusCode::PARTIAL_CONTENT);
    assert_eq!(body, "world");
    let (st, _, _) = dav(
        &h.app,
        "GET",
        "/dav/svc_a/notes.txt",
        Some(&admin),
        &[("range", "bytes=99-200")],
        None,
    )
    .await;
    assert_eq!(st, StatusCode::RANGE_NOT_SATISFIABLE);

    // Conditional requests.
    let (st, _, _) = dav(
        &h.app,
        "GET",
        "/dav/svc_a/notes.txt",
        Some(&admin),
        &[("if-none-match", &tag)],
        None,
    )
    .await;
    assert_eq!(st, StatusCode::NOT_MODIFIED);
    let (st, _, _) = dav(
        &h.app,
        "PUT",
        "/dav/svc_a/notes.txt",
        Some(&admin),
        &[("if-match", "\"0-0\"")],
        Some(b"nope".to_vec()),
    )
    .await;
    assert_eq!(st, StatusCode::PRECONDITION_FAILED);

    // Replace → 204; If-None-Match:* on an existing file → 412.
    let (st, _, _) = dav(
        &h.app,
        "PUT",
        "/dav/svc_a/notes.txt",
        Some(&admin),
        &[],
        Some(b"second".to_vec()),
    )
    .await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let (st, _, _) = dav(
        &h.app,
        "PUT",
        "/dav/svc_a/notes.txt",
        Some(&admin),
        &[("if-none-match", "*")],
        Some(b"x".to_vec()),
    )
    .await;
    assert_eq!(st, StatusCode::PRECONDITION_FAILED);

    // MKCOL, nesting, listing.
    let (st, _, _) = dav(&h.app, "MKCOL", "/dav/svc_a/sub", Some(&admin), &[], None).await;
    assert_eq!(st, StatusCode::CREATED);
    let (st, _, _) = dav(&h.app, "MKCOL", "/dav/svc_a/sub", Some(&admin), &[], None).await;
    assert_eq!(st, StatusCode::METHOD_NOT_ALLOWED);
    let (st, _, _) = dav(&h.app, "MKCOL", "/dav/svc_a/missing/deep", Some(&admin), &[], None).await;
    assert_eq!(st, StatusCode::CONFLICT, "MKCOL with a missing parent");
    let blob: Vec<u8> = (0u8..=255).collect();
    let (st, _, _) = dav(
        &h.app,
        "PUT",
        "/dav/svc_a/sub/a.bin",
        Some(&admin),
        &[],
        Some(blob.clone()),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let (_, _, got) = dav_raw(&h.app, "GET", "/dav/svc_a/sub/a.bin", Some(&admin), &[], None).await;
    assert_eq!(got, blob, "binary round-trip mangled");
    let (st, _, body) = dav(
        &h.app,
        "PROPFIND",
        "/dav/svc_a/sub/",
        Some(&admin),
        &[("depth", "1")],
        None,
    )
    .await;
    assert_eq!(st, StatusCode::MULTI_STATUS);
    assert!(body.contains("a.bin"), "{body}");
    assert!(body.contains("getcontentlength"), "{body}");

    // MOVE / COPY (file and tree), with Destination.
    let (st, _, _) = dav(
        &h.app,
        "MOVE",
        "/dav/svc_a/sub/a.bin",
        Some(&admin),
        &[("destination", "/dav/svc_a/sub/b.bin")],
        None,
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let (st, _, _) = dav(&h.app, "GET", "/dav/svc_a/sub/a.bin", Some(&admin), &[], None).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, _, _) = dav(
        &h.app,
        "COPY",
        "/dav/svc_a/sub/b.bin",
        Some(&admin),
        &[("destination", "/dav/svc_a/sub/c.bin")],
        None,
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let (st, _, _) = dav(&h.app, "GET", "/dav/svc_a/sub/c.bin", Some(&admin), &[], None).await;
    assert_eq!(st, StatusCode::OK);
    let (st, _, _) = dav(
        &h.app,
        "COPY",
        "/dav/svc_a/sub",
        Some(&admin),
        &[("destination", "/dav/svc_a/sub2")],
        None,
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let (st, _, body) = dav(
        &h.app,
        "PROPFIND",
        "/dav/svc_a/sub2/",
        Some(&admin),
        &[("depth", "1")],
        None,
    )
    .await;
    assert_eq!(st, StatusCode::MULTI_STATUS);
    assert!(body.contains("b.bin") && body.contains("c.bin"), "{body}");

    // Overwrite: F refuses an existing destination.
    let (st, _, _) = dav(
        &h.app,
        "COPY",
        "/dav/svc_a/sub/b.bin",
        Some(&admin),
        &[("destination", "/dav/svc_a/sub/c.bin"), ("overwrite", "F")],
        None,
    )
    .await;
    assert_eq!(st, StatusCode::PRECONDITION_FAILED);

    // Cross-service MOVE is refused.
    let (st, _, _) = dav(
        &h.app,
        "MOVE",
        "/dav/svc_a/sub/b.bin",
        Some(&admin),
        &[("destination", "/dav/svc_b/stolen.bin")],
        None,
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);

    // DELETE (recursive), then it is gone.
    let (st, _, _) = dav(&h.app, "DELETE", "/dav/svc_a/sub", Some(&admin), &[], None).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let (st, _, _) = dav(&h.app, "PROPFIND", "/dav/svc_a/sub/", Some(&admin), &[("depth", "0")], None).await;
    assert_eq!(st, StatusCode::NOT_FOUND);

    // Collections are not downloadable; the service root is not deletable.
    let (st, _, _) = dav(&h.app, "GET", "/dav/svc_a/", Some(&admin), &[], None).await;
    assert_eq!(st, StatusCode::METHOD_NOT_ALLOWED);
    let (st, _, _) = dav(&h.app, "DELETE", "/dav/svc_a/", Some(&admin), &[], None).await;
    assert_eq!(st, StatusCode::FORBIDDEN);

    // Uploads need a declared length and respect the cap.
    let (st, _, _) = dav(
        &h.app,
        "PUT",
        "/dav/svc_a/big.bin",
        Some(&admin),
        &[("content-length", "2097152")],
        None,
    )
    .await;
    assert_eq!(st, StatusCode::PAYLOAD_TOO_LARGE);
    let (st, _, _) = dav(&h.app, "PUT", "/dav/svc_a/nolen.bin", Some(&admin), &[("transfer-encoding", "chunked")], None).await;
    assert_eq!(st, StatusCode::LENGTH_REQUIRED);

    // PROPPATCH is not supported.
    let (st, _, _) = dav(&h.app, "PROPPATCH", "/dav/svc_a/notes.txt", Some(&admin), &[], None).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
}

/// The WebDAV surface must not become a second, weaker policy: the same
/// denials the JSON file API enforces have to hold here too.
#[tokio::test]
async fn webdav_matches_json_file_api_policy() {
    let h = harness().await;
    let (_, admin) = login(&h.app, "admin", PASSWORD).await;

    // Read-only mount: mount_files without edit_files.
    grant_features(&h, "viewer", |f| f.mount_files = true).await;
    let (_, viewer) = login(&h.app, "viewer", PASSWORD).await;
    let (st, _, _) = dav(&h.app, "GET", "/dav/svc_a/docker-compose.yml", Some(&viewer), &[], None).await;
    assert_eq!(st, StatusCode::OK);
    for (method, uri, headers, body) in [
        ("PUT", "/dav/svc_a/x.txt", vec![], Some(b"x".to_vec())),
        ("MKCOL", "/dav/svc_a/newdir", vec![], None),
        ("DELETE", "/dav/svc_a/docker-compose.yml", vec![], None),
        ("MOVE", "/dav/svc_a/docker-compose.yml", vec![("destination", "/dav/svc_a/other.yml")], None),
        ("COPY", "/dav/svc_a/docker-compose.yml", vec![("destination", "/dav/svc_a/other.yml")], None),
        ("LOCK", "/dav/svc_a/x.txt", vec![], Some(LOCK_BODY.as_bytes().to_vec())),
    ] {
        let (st, _, _) = dav(&h.app, method, uri, Some(&viewer), &headers, body).await;
        assert_eq!(st, StatusCode::FORBIDDEN, "{method} {uri} → {st}");
    }

    // Privileged filenames are denied to every method, for admins too.
    for p in [
        "meta.yaml",
        "backup.sh",
        ".restic_password",
        ".restic_inited",
        ".git/config",
        "sub/meta.yaml",
    ] {
        let uri = format!("/dav/svc_a/{p}");
        for (method, headers, body) in [
            ("PUT", vec![], Some(b"pwned".to_vec())),
            ("DELETE", vec![], None),
            ("PROPFIND", vec![("depth", "0")], None),
            ("MOVE", vec![("destination", "/dav/svc_a/moved.yaml")], None),
            ("COPY", vec![("destination", "/dav/svc_a/copied.yaml")], None),
        ] {
            let (st, _, _) = dav(&h.app, method, &uri, Some(&admin), &headers, body).await;
            assert!(
                st == StatusCode::FORBIDDEN || st == StatusCode::NOT_FOUND,
                "{method} {p} → {st}"
            );
        }
        // ...and cannot be the *destination* of a move/copy either.
        let (st, _, _) = dav(
            &h.app,
            "COPY",
            "/dav/svc_a/docker-compose.yml",
            Some(&admin),
            &[("destination", &format!("/dav/svc_a/{p}"))],
            None,
        )
        .await;
        assert!(st == StatusCode::FORBIDDEN || st == StatusCode::NOT_FOUND, "COPY onto {p} → {st}");
    }

    // Traversal, encoded traversal, and the service root.
    for uri in [
        "/dav/svc_a/../escape.txt",
        "/dav/svc_a/%2e%2e%2fescape.txt",
        "/dav/svc_a/sub/../../escape.txt",
    ] {
        let (st, _, _) = dav(&h.app, "PUT", uri, Some(&admin), &[], Some(b"x".to_vec())).await;
        assert!(
            st == StatusCode::FORBIDDEN || st == StatusCode::NOT_FOUND || st == StatusCode::BAD_REQUEST,
            "{uri} → {st}"
        );
    }
    let (st, _, _) = dav(&h.app, "DELETE", "/dav/svc_a/", Some(&admin), &[], None).await;
    assert_eq!(st, StatusCode::FORBIDDEN);

    // Compose file: `edit_compose` plus the caller's policy and the floor.
    grant_features(&h, "viewer", |f| f.edit_files = true).await;
    let (_, viewer) = login(&h.app, "viewer", PASSWORD).await;
    let (st, _, _) = dav(
        &h.app,
        "PUT",
        "/dav/svc_a/docker-compose.yml",
        Some(&viewer),
        &[],
        Some(b"services:\n  app:\n    image: alpine\n".to_vec()),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN, "edit_files alone edited the compose file");

    let privileged = b"services:\n  app:\n    image: alpine\n    privileged: true\n".to_vec();
    let (st, _, _) = dav(
        &h.app,
        "PUT",
        "/dav/svc_a/docker-compose.yml",
        Some(&admin),
        &[],
        Some(privileged.clone()),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN, "privileged compose accepted over WebDAV");
    // ...the JSON API refuses the very same body (no drift between paths).
    let (st, _, _) = call(
        &h.app,
        "PUT",
        "/api/services/svc_a/compose",
        Some(&admin),
        Some(serde_json::json!({"content": String::from_utf8_lossy(&privileged)})),
    )
    .await;
    assert!(
        st == StatusCode::BAD_REQUEST || st == StatusCode::FORBIDDEN,
        "JSON API accepted a privileged compose: {st}"
    );
    // A clean compose body is accepted by both.
    let clean = b"services:\n  app:\n    image: alpine\n    command: sleep 9\n".to_vec();
    let (st, _, _) = dav(
        &h.app,
        "PUT",
        "/dav/svc_a/docker-compose.yml",
        Some(&admin),
        &[],
        Some(clean.clone()),
    )
    .await;
    assert_eq!(st, StatusCode::NO_CONTENT, "clean compose rejected");
    // Renaming *onto* the compose file is refused (it bypasses the policy gate).
    let (st, _, _) = dav(
        &h.app,
        "MOVE",
        "/dav/svc_a/notes.txt",
        Some(&admin),
        &[("destination", "/dav/svc_a/docker-compose.yml")],
        None,
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn webdav_locks() {
    let h = harness().await;
    let (_, admin) = login(&h.app, "admin", PASSWORD).await;
    let (st, _, _) = dav(
        &h.app,
        "PUT",
        "/dav/svc_a/locked.txt",
        Some(&admin),
        &[],
        Some(b"v1".to_vec()),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);

    let (st, hdrs, body) = dav(
        &h.app,
        "LOCK",
        "/dav/svc_a/locked.txt",
        Some(&admin),
        &[("timeout", "Second-120")],
        Some(LOCK_BODY.as_bytes().to_vec()),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert!(body.contains("activelock"), "{body}");
    assert!(body.contains("mailto:ops@example.com"), "owner not echoed: {body}");
    let raw = hdrs.get("lock-token").unwrap().to_str().unwrap().to_string();
    let token = raw.trim_matches(|c| c == '<' || c == '>').to_string();
    assert!(token.starts_with("opaquelocktoken:"), "{token}");

    // A writer that does not present the token is refused.
    let (st, _, _) = dav(
        &h.app,
        "PUT",
        "/dav/svc_a/locked.txt",
        Some(&admin),
        &[],
        Some(b"v2".to_vec()),
    )
    .await;
    assert_eq!(st, StatusCode::LOCKED);
    let (st, _, _) = dav(&h.app, "DELETE", "/dav/svc_a/locked.txt", Some(&admin), &[], None).await;
    assert_eq!(st, StatusCode::LOCKED);
    // With the token it proceeds.
    let if_header = format!("(<{token}>)");
    let (st, _, _) = dav(
        &h.app,
        "PUT",
        "/dav/svc_a/locked.txt",
        Some(&admin),
        &[("if", &if_header)],
        Some(b"v2".to_vec()),
    )
    .await;
    assert_eq!(st, StatusCode::NO_CONTENT);

    // The lock is discoverable, and UNLOCK needs the token.
    let (_, _, body) = dav(
        &h.app,
        "PROPFIND",
        "/dav/svc_a/locked.txt",
        Some(&admin),
        &[("depth", "0")],
        None,
    )
    .await;
    assert!(body.contains("lockdiscovery") && body.contains(&token), "{body}");
    let (st, _, _) = dav(&h.app, "UNLOCK", "/dav/svc_a/locked.txt", Some(&admin), &[], None).await;
    assert_eq!(st, StatusCode::CONFLICT);
    let (st, _, _) = dav(
        &h.app,
        "UNLOCK",
        "/dav/svc_a/locked.txt",
        Some(&admin),
        &[("lock-token", &raw)],
        None,
    )
    .await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let (st, _, _) = dav(
        &h.app,
        "PUT",
        "/dav/svc_a/locked.txt",
        Some(&admin),
        &[],
        Some(b"v3".to_vec()),
    )
    .await;
    assert_eq!(st, StatusCode::NO_CONTENT, "still locked after UNLOCK");

    // A depth-infinity lock on a collection covers its children.
    let (st, hdrs, _body) = dav(
        &h.app,
        "LOCK",
        "/dav/svc_a/",
        Some(&admin),
        &[("depth", "infinity")],
        Some(LOCK_BODY.as_bytes().to_vec()),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let root_token = hdrs
        .get("lock-token")
        .unwrap()
        .to_str()
        .unwrap()
        .trim_matches(|c| c == '<' || c == '>')
        .to_string();
    let (st, _, _) = dav(
        &h.app,
        "PUT",
        "/dav/svc_a/child.txt",
        Some(&admin),
        &[],
        Some(b"x".to_vec()),
    )
    .await;
    assert_eq!(st, StatusCode::LOCKED, "collection lock did not cover a child");
    let (st, _, _) = dav(
        &h.app,
        "UNLOCK",
        "/dav/svc_a/",
        Some(&admin),
        &[("lock-token", &format!("<{root_token}>"))],
        None,
    )
    .await;
    assert_eq!(st, StatusCode::NO_CONTENT);

    // LOCK on an unmapped URL creates the resource (Explorer/Finder flow).
    let (st, _, _) = dav(
        &h.app,
        "LOCK",
        "/dav/svc_a/fresh.txt",
        Some(&admin),
        &[],
        Some(LOCK_BODY.as_bytes().to_vec()),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let (st, _, _) = dav(&h.app, "GET", "/dav/svc_a/fresh.txt", Some(&admin), &[], None).await;
    assert_eq!(st, StatusCode::OK);

    // Locking needs write rights — otherwise a reader could block writers.
    grant_features(&h, "viewer", |f| f.mount_files = true).await;
    let (_, viewer) = login(&h.app, "viewer", PASSWORD).await;
    let (st, _, _) = dav(
        &h.app,
        "LOCK",
        "/dav/svc_a/locked.txt",
        Some(&viewer),
        &[],
        Some(LOCK_BODY.as_bytes().to_vec()),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
}

/// The streaming data plane must behave the same over the privileged socket
/// as it does in-process.
#[tokio::test]
async fn webdav_works_over_the_privileged_socket() {
    let h = harness_remote().await;
    let (_, admin) = login(&h.app, "admin", PASSWORD).await;
    let blob: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
    let (st, _, _) = dav(
        &h.app,
        "PUT",
        "/dav/svc_a/remote.bin",
        Some(&admin),
        &[],
        Some(blob.clone()),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let (st, hdrs, got) = dav_raw(&h.app, "GET", "/dav/svc_a/remote.bin", Some(&admin), &[], None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(got, blob);
    assert_eq!(hdrs.get("content-length").unwrap(), "4096");
    let (st, _, body) = dav(
        &h.app,
        "GET",
        "/dav/svc_a/remote.bin",
        Some(&admin),
        &[("range", "bytes=0-9")],
        None,
    )
    .await;
    assert_eq!(st, StatusCode::PARTIAL_CONTENT);
    assert_eq!(body.len(), 10);
    let (st, _, _) = dav(&h.app, "DELETE", "/dav/svc_a/remote.bin", Some(&admin), &[], None).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
}

/// A symlink alias must not become a way around the denied-name policy: a
/// cloned repo (or a COPY of one) can place `data -> meta.yaml` inside the
/// service dir, and `resolve` canonicalizes that straight onto the
/// privileged file. Both transports must refuse.
#[tokio::test]
async fn symlink_alias_cannot_reach_denied_files() {
    let h = harness().await;
    let (_, admin) = login(&h.app, "admin", PASSWORD).await;
    let dir = h._dir.path().join("svc/svc_a");
    std::fs::write(dir.join("meta.yaml"), "backup: {enabled: false}\n").unwrap();
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    std::fs::write(dir.join(".git/config"), "[core]\n").unwrap();
    std::os::unix::fs::symlink("meta.yaml", dir.join("alias.yaml")).unwrap();
    std::os::unix::fs::symlink(".git", dir.join("gitdir")).unwrap();

    // WebDAV: write, read, delete, and move-destination.
    let (st, _, _) = dav(
        &h.app,
        "PUT",
        "/dav/svc_a/alias.yaml",
        Some(&admin),
        &[],
        Some(b"pwned: true\n".to_vec()),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN, "WebDAV wrote through a symlink alias");
    let (st, _, _) = dav(&h.app, "GET", "/dav/svc_a/alias.yaml", Some(&admin), &[], None).await;
    assert!(
        st == StatusCode::FORBIDDEN || st == StatusCode::NOT_FOUND,
        "WebDAV read through a symlink alias: {st}"
    );
    let (st, _, _) = dav(&h.app, "DELETE", "/dav/svc_a/alias.yaml", Some(&admin), &[], None).await;
    assert_eq!(st, StatusCode::FORBIDDEN, "WebDAV deleted through a symlink alias");
    let (st, _, _) = dav(
        &h.app,
        "COPY",
        "/dav/svc_a/docker-compose.yml",
        Some(&admin),
        &[("destination", "/dav/svc_a/alias.yaml")],
        None,
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN, "WebDAV copied onto a symlink alias");
    let (st, _, _) = dav(&h.app, "PROPFIND", "/dav/svc_a/gitdir/", Some(&admin), &[("depth", "1")], None).await;
    assert_eq!(st, StatusCode::FORBIDDEN, "WebDAV listed through a symlinked .git");

    // The JSON file API must refuse the very same paths. (It reports
    // agent-side denials as 400 by convention; WebDAV uses 403.)
    let (st, _, _) = call(
        &h.app,
        "PUT",
        "/api/services/svc_a/files",
        Some(&admin),
        Some(serde_json::json!({"path": "alias.yaml", "content": "pwned: true"})),
    )
    .await;
    assert!(
        st == StatusCode::FORBIDDEN || st == StatusCode::BAD_REQUEST,
        "JSON file API wrote through a symlink alias: {st}"
    );
    let (st, _, _) = call(
        &h.app,
        "GET",
        "/api/services/svc_a/files?path=alias.yaml",
        Some(&admin),
        None,
    )
    .await;
    assert!(
        st == StatusCode::FORBIDDEN || st == StatusCode::BAD_REQUEST,
        "JSON file API read through a symlink alias: {st}"
    );

    // The agent refuses it too, not just the HTTP layer.
    let r = h
        .state
        .agent
        .call(
            crate::agent::proto::SyncVerb::FileWrite {
                service: "svc_a".into(),
                path: "alias.yaml".into(),
                content: "pwned".into(),
            },
            &admin,
        )
        .await;
    assert!(r.is_err(), "agent wrote through a symlink alias");

    // ...and the protected file is untouched.
    let meta = std::fs::read_to_string(dir.join("meta.yaml")).unwrap();
    assert!(meta.contains("enabled: false"), "meta.yaml was overwritten: {meta}");
}
