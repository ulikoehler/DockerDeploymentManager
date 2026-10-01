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

fn config_yaml(root: &std::path::Path) -> String {
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
    _dir: tempfile::TempDir,
}

async fn harness() -> Harness {
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
    std::fs::write(&cfg_path, config_yaml(root)).unwrap();
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
    let docker: Arc<dyn docker::DockerApi> = Arc::new(docker::MockDocker::default());
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
    };
    let app = api::api_router()
        .merge(mcp::router(state.clone()))
        .with_state(state.clone());
    Harness {
        app,
        state,
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
    };
    let app = api::api_router()
        .merge(mcp::router(state.clone()))
        .with_state(state.clone());
    Harness {
        app,
        state,
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
