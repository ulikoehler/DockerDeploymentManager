use crate::users::User;
use axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::sync::RwLock;
use tracing::warn;

// ---------------------------------------------------------------------------
// JWT
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // user name
    pub roles: Vec<String>,
    pub exp: i64,
    pub iat: i64,
    /// Secret generation; incremented on logout-all to invalidate old tokens.
    pub gen: u64,
    /// Optional restrictions baked into the token (e.g. time-limited MCP
    /// tokens). Applied on top of the user's own permissions — can only
    /// narrow, never widen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<TokenScope>,
}

/// Restrictions embedded in a token. When present, the authenticated user is
/// intersected with this scope before any permission check runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenScope {
    /// If set, only these service names are accessible.
    #[serde(default)]
    pub services: Option<Vec<String>>,
    /// If set, the token keeps only these capabilities: role names
    /// (e.g. "operator", "admin"), feature flags (e.g. "edit_compose",
    /// "run_commands") and "unrestricted" (compose policy bypass).
    #[serde(default)]
    pub actions: Option<Vec<String>>,
}

/// Apply a token scope to a user, narrowing their effective permissions.
pub fn apply_token_scope(user: &mut User, scope: &TokenScope) {
    use crate::users::{AccessEffect, AccessRuleType};
    if let Some(actions) = &scope.actions {
        let has = |a: &str| actions.iter().any(|x| x == a);
        // Keep only the requested roles the user actually has (has_role
        // treats admin as having every role, so an admin scoping a token to
        // "operator" gets operator rights).
        let kept: Vec<String> = actions
            .iter()
            .filter(|a| user.has_role(a))
            .cloned()
            .collect();
        user.roles = kept;
        let f = &mut user.features;
        f.create_services &= has("create_services");
        f.edit_compose &= has("edit_compose");
        f.edit_units &= has("edit_units");
        f.run_commands &= has("run_commands");
        f.manage_backup &= has("manage_backup");
        f.manage_monitoring &= has("manage_monitoring");
        f.edit_files &= has("edit_files");
        f.exec_containers &= has("exec_containers");
        f.mount_files &= has("mount_files");
        if !has("unrestricted") && user.compose_policy.as_deref() == Some("unrestricted") {
            user.compose_policy = None; // fall back to the default policy
        }
    }
    if let Some(services) = &scope.services {
        // `admin` bypasses all service-access rules — a service-scoped token
        // must not keep it, or the scope is a silent no-op.
        user.roles.retain(|r| r != "admin");
        // Intersection semantics: the user's explicit denies still apply,
        // then exact allows for the scoped services, then deny the rest.
        let mut rules: Vec<crate::users::AccessRule> = user
            .access
            .iter()
            .filter(|r| r.effect == AccessEffect::Deny)
            .cloned()
            .collect();
        rules.extend(services.iter().map(|s| crate::users::AccessRule {
            kind: AccessRuleType::Exact,
            pattern: s.clone(),
            effect: AccessEffect::Allow,
        }));
        rules.push(crate::users::AccessRule {
            kind: AccessRuleType::Glob,
            pattern: "*".into(),
            effect: AccessEffect::Deny,
        });
        user.access = rules;
    }
}

/// Holds the JWT secret. Secret rotation invalidates all issued tokens.
pub struct JwtKeys {
    secret: RwLock<String>,
    generation: RwLock<u64>,
}

impl JwtKeys {
    pub fn new(secret: String) -> Self {
        Self {
            secret: RwLock::new(secret),
            generation: RwLock::new(0),
        }
    }

    pub fn issue(
        &self,
        user: &User,
        ttl_seconds: i64,
        scope: Option<TokenScope>,
    ) -> Result<String, jsonwebtoken::errors::Error> {
        let now = chrono::Utc::now().timestamp();
        let claims = Claims {
            sub: user.name.clone(),
            roles: user.roles.clone(),
            iat: now,
            exp: now + ttl_seconds,
            gen: *self.generation.read().unwrap(),
            scope,
        };
        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.secret.read().unwrap().as_bytes()),
        )
    }

    /// Issue a token from raw claims fields — used by the agent when
    /// minting scoped children (the caller's narrowed roles are preserved).
    pub fn issue_claims(
        &self,
        sub: &str,
        roles: Vec<String>,
        ttl_seconds: i64,
        scope: Option<TokenScope>,
    ) -> Result<String, jsonwebtoken::errors::Error> {
        let now = chrono::Utc::now().timestamp();
        let claims = Claims {
            sub: sub.to_string(),
            roles,
            iat: now,
            exp: now + ttl_seconds,
            gen: *self.generation.read().unwrap(),
            scope,
        };
        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.secret.read().unwrap().as_bytes()),
        )
    }

    pub fn verify(&self, token: &str) -> Option<Claims> {
        let claims = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.secret.read().unwrap().as_bytes()),
            &Validation::default(),
        )
        .ok()?
        .claims;
        if claims.gen != *self.generation.read().unwrap() {
            warn!("token with stale generation rejected");
            return None;
        }
        Some(claims)
    }

    /// Rotate secret + bump generation: invalidates every issued token.
    pub fn rotate(&self) {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let new_secret: String = (0..64)
            .map(|_| {
                let idx = rng.gen_range(0..62);
                b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[idx] as char
            })
            .collect();
        *self.secret.write().unwrap() = new_secret;
        *self.generation.write().unwrap() += 1;
    }
}

// ---------------------------------------------------------------------------
// Axum extractor
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user: User,
    /// Verified claims (scope already applied to `user`). Kept for
    /// introspection (e.g. `claims.scope`, `jti`) — not currently read.
    #[allow(dead_code)]
    pub claims: Claims,
    /// The raw bearer token — passed to the agent as the justification for
    /// privileged ops. Never logged.
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub success: bool,
    pub error: String,
}

pub fn error_response(status: StatusCode, msg: impl Into<String>) -> Response {
    (
        status,
        Json(ErrorBody {
            success: false,
            error: msg.into(),
        }),
    )
        .into_response()
}

pub fn forbidden() -> Response {
    error_response(StatusCode::FORBIDDEN, "forbidden")
}

pub fn bad_request(msg: impl Into<String>) -> Response {
    error_response(StatusCode::BAD_REQUEST, msg)
}

pub fn not_found(msg: impl Into<String>) -> Response {
    error_response(StatusCode::NOT_FOUND, msg)
}

pub fn internal(msg: impl Into<String>) -> Response {
    error_response(StatusCode::INTERNAL_SERVER_ERROR, msg)
}

/// One-time WebSocket tickets: `POST /api/auth/ws-ticket` mints a random
/// single-use ticket bound to the caller's session token. Browser WS
/// clients use `?ticket=` instead of `?token=` so the JWT itself never
/// appears in a URL (access logs, browser history, Referer headers).
#[derive(Default)]
pub struct TicketStore {
    inner: std::sync::Mutex<std::collections::HashMap<String, (String, std::time::Instant)>>,
}

impl TicketStore {
    const TTL: std::time::Duration = std::time::Duration::from_secs(60);

    pub fn new() -> Self {
        Self::default()
    }

    /// Mint a single-use ticket for `token`, valid for `TTL`.
    pub fn issue(&self, token: &str) -> String {
        let mut map = self.inner.lock().unwrap();
        let now = std::time::Instant::now();
        map.retain(|_, (_, exp)| *exp > now);
        let ticket = uuid::Uuid::new_v4().to_string();
        map.insert(ticket.clone(), (token.to_string(), now + Self::TTL));
        ticket
    }

    /// Consume a ticket — single-use even before expiry.
    pub fn redeem(&self, ticket: &str) -> Option<String> {
        let (token, exp) = self.inner.lock().unwrap().remove(ticket)?;
        (exp > std::time::Instant::now()).then_some(token)
    }
}

/// `?ticket=` on `/ws/*`: redeem a single-use ticket into its session
/// token. Tickets only exist where `?token=` is already accepted.
fn ticket_token(parts: &Parts, state: &crate::AppState) -> Option<String> {
    if !parts.uri.path().starts_with("/ws/") {
        return None;
    }
    let ticket = parts.uri.query().and_then(|q| {
        q.split('&').find_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            (k == "ticket").then_some(v.to_string())
        })
    })?;
    state.ws_tickets.redeem(&ticket)
}

/// Verify the bearer token in `parts` (header, `?token=`/`?ticket=` on
/// WebSocket routes), load the user and apply any token scope. Shared by
/// the `AuthUser` extractor and the MCP auth middleware.
pub async fn authenticate(parts: &Parts, state: &crate::AppState) -> Result<AuthUser, Response> {
    let token = bearer_token(parts)
        .map(str::to_owned)
        .or_else(|| ticket_token(parts, state))
        .ok_or_else(|| error_response(StatusCode::UNAUTHORIZED, "missing bearer token"))?;
    let verified: serde_json::Value = state
        .agent
        .crypto(crate::agent::proto::CryptoOp::Verify {
            token: token.to_string(),
        })
        .await
        .map_err(|e| error_response(StatusCode::UNAUTHORIZED, e.to_string()))?;
    let claims: Claims = serde_json::from_value(verified["claims"].clone())
        .map_err(|_| error_response(StatusCode::UNAUTHORIZED, "invalid token"))?;
    let mut user: User = serde_json::from_value(verified["user"].clone())
        .map_err(|_| error_response(StatusCode::UNAUTHORIZED, "unknown user"))?;
    if let Some(scope) = &claims.scope {
        apply_token_scope(&mut user, scope);
    }
    Ok(AuthUser {
        user,
        claims,
        token: token.to_string(),
    })
}

#[axum::async_trait]
impl FromRequestParts<crate::AppState> for AuthUser {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &crate::AppState,
    ) -> Result<Self, Self::Rejection> {
        authenticate(parts, state).await
    }
}

/// Extract bearer token from Authorization header or `?token=`/`access_token`
/// (needed for WebSocket clients that can't set headers).
pub fn bearer_token(parts: &Parts) -> Option<&str> {
    if let Some(v) = parts
        .headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        return Some(v);
    }
    // `?token=` is only honored on WebSocket routes — elsewhere tokens must
    // use the Authorization header so they can't leak via URLs in logs,
    // browser history or Referer headers.
    if !parts.uri.path().starts_with("/ws/") {
        return None;
    }
    parts.uri.query().and_then(|q| {
        q.split('&').find_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            matches!(k, "token" | "access_token").then_some(v)
        })
    })
}

// ---------------------------------------------------------------------------
// Login throttling
// ---------------------------------------------------------------------------

/// Per-username login failure limiter: after `MAX_FAILS` consecutive
/// failures the account is locked for `LOCKOUT`. In-memory only — a restart
/// resets it, which is acceptable since the lockout's purpose is slowing
/// online brute force, not punishing users.
pub struct LoginThrottle {
    inner: std::sync::Mutex<std::collections::HashMap<String, FailState>>,
}

struct FailState {
    count: u32,
    locked_until: Option<std::time::Instant>,
}

impl LoginThrottle {
    const MAX_FAILS: u32 = 5;
    const LOCKOUT: std::time::Duration = std::time::Duration::from_secs(60);

    pub fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// True while `name` is locked out.
    pub fn is_locked(&self, name: &str) -> bool {
        let mut map = self.inner.lock().unwrap();
        let Some(st) = map.get(name) else {
            return false;
        };
        match st.locked_until {
            Some(until) if until > std::time::Instant::now() => true,
            Some(_) => {
                map.remove(name); // lockout expired
                false
            }
            None => false,
        }
    }

    pub fn record_failure(&self, name: &str) {
        let mut map = self.inner.lock().unwrap();
        let st = map.entry(name.to_string()).or_insert(FailState {
            count: 0,
            locked_until: None,
        });
        st.count += 1;
        if st.count >= Self::MAX_FAILS {
            st.locked_until = Some(std::time::Instant::now() + Self::LOCKOUT);
        }
    }

    pub fn record_success(&self, name: &str) {
        self.inner.lock().unwrap().remove(name);
    }
}

#[derive(Debug, Serialize)]
pub struct SuccessResponse<T: Serialize> {
    pub success: bool,
    pub data: T,
}

pub fn ok<T: Serialize>(data: T) -> Json<SuccessResponse<T>> {
    Json(SuccessResponse {
        success: true,
        data,
    })
}

#[cfg(test)]
mod security_tests {
    use super::*;
    use crate::users::{User, UserFeatures};

    fn u() -> User {
        User {
            name: "alice".into(),
            password_hash: String::new(),
            roles: vec!["operator".into()],
            access: vec![],
            features: UserFeatures::default(),
            compose_policy: None,
        }
    }

    #[test]
    fn forged_signature_rejected() {
        let keys = JwtKeys::new("secret-a".into());
        let t = keys.issue(&u(), 60, None).unwrap();
        let other = JwtKeys::new("secret-b".into());
        assert!(other.verify(&t).is_none());
    }

    #[test]
    fn tampered_payload_rejected() {
        let keys = JwtKeys::new("s".into());
        let t = keys.issue(&u(), 60, None).unwrap();
        // flip a char in the payload segment
        let mut parts: Vec<String> = t.split('.').map(String::from).collect();
        let payload = parts[1].as_bytes().to_vec();
        let flip = if payload[0] == b'A' { b'B' } else { b'A' };
        let mut p = payload;
        p[0] = flip;
        parts[1] = String::from_utf8(p).unwrap();
        let forged = parts.join(".");
        assert!(keys.verify(&forged).is_none());
    }

    #[test]
    fn expired_rejected() {
        let keys = JwtKeys::new("s".into());
        let t = keys.issue(&u(), -120, None).unwrap(); // expired (past 60s leeway)
        assert!(keys.verify(&t).is_none());
    }

    #[test]
    fn rotate_invalidates_all_tokens() {
        let keys = JwtKeys::new("s".into());
        let t = keys.issue(&u(), 60, None).unwrap();
        assert!(keys.verify(&t).is_some());
        keys.rotate();
        assert!(keys.verify(&t).is_none());
    }

    #[test]
    fn alg_none_style_garbage_rejected() {
        let keys = JwtKeys::new("s".into());
        // unsigned-looking token, garbage, empty
        for t in ["eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.", "a.b.c", ""] {
            assert!(keys.verify(t).is_none());
        }
    }

    #[test]
    fn token_scope_narrows_but_never_widens() {
        use crate::config::DefaultAccess;
        use crate::permissions::can_access_service;
        use crate::users::{AccessEffect, AccessRule, AccessRuleType};

        // scope keeps only listed actions
        let mut user = u();
        user.features.edit_compose = true;
        let scope = TokenScope {
            services: Some(vec!["web1".into()]),
            actions: Some(vec!["edit_compose".into()]),
        };
        apply_token_scope(&mut user, &scope);
        assert!(!user.roles.iter().any(|r| r == "operator"));
        assert!(user.features.edit_compose);
        assert!(!user.features.run_commands);
        assert!(can_access_service(&user, "web1", DefaultAccess::Allow));
        assert!(!can_access_service(&user, "db", DefaultAccess::Allow));

        // a user's own deny beats the scope's allow (intersection)
        let mut user = u();
        user.access = vec![AccessRule {
            kind: AccessRuleType::Exact,
            pattern: "web1".into(),
            effect: AccessEffect::Deny,
        }];
        apply_token_scope(&mut user, &scope);
        assert!(!can_access_service(&user, "web1", DefaultAccess::Allow));

        // admin scoping to "operator" keeps operator rights (admin implies
        // all roles) but loses admin itself
        let mut user = u();
        user.roles = vec!["admin".into()];
        let scope2 = TokenScope {
            services: None,
            actions: Some(vec!["operator".into()]),
        };
        apply_token_scope(&mut user, &scope2);
        assert!(!user.is_admin());
        assert!(user.has_role("operator"));

        // no scope = unchanged
        let mut user = u();
        apply_token_scope(
            &mut user,
            &TokenScope {
                services: None,
                actions: None,
            },
        );
        assert_eq!(user.roles, vec!["operator"]);
        assert!(user.access.is_empty());
    }

    #[test]
    fn tickets_are_single_use() {
        let store = TicketStore::new();
        let t = store.issue("session-token");
        assert_eq!(store.redeem(&t).as_deref(), Some("session-token"));
        assert!(store.redeem(&t).is_none(), "ticket replayed");
        assert!(store.redeem("nonexistent").is_none());
    }

    #[test]
    fn bearer_from_query_only_for_ws_keys() {
        use axum::http::Request;
        let req = Request::builder()
            .uri("/ws/x?token=abc&other=1")
            .body(())
            .unwrap();
        let (parts, _) = req.into_parts();
        assert_eq!(bearer_token(&parts), Some("abc"));

        let req = Request::builder().uri("/ws/x?tok=notit").body(()).unwrap();
        let (parts, _) = req.into_parts();
        assert_eq!(bearer_token(&parts), None);

        // query tokens are ignored outside /ws/*
        let req = Request::builder()
            .uri("/api/services?token=abc")
            .body(())
            .unwrap();
        let (parts, _) = req.into_parts();
        assert_eq!(bearer_token(&parts), None);

        // header beats query
        let req = Request::builder()
            .uri("/x?token=query")
            .header(axum::http::header::AUTHORIZATION, "Bearer hdr")
            .body(())
            .unwrap();
        let (parts, _) = req.into_parts();
        assert_eq!(bearer_token(&parts), Some("hdr"));
    }
}
