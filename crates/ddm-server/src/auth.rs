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
        ttl_minutes: i64,
    ) -> Result<String, jsonwebtoken::errors::Error> {
        let now = chrono::Utc::now().timestamp();
        let claims = Claims {
            sub: user.name.clone(),
            roles: user.roles.clone(),
            iat: now,
            exp: now + ttl_minutes * 60,
            gen: *self.generation.read().unwrap(),
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
    #[allow(dead_code)]
    pub claims: Claims,
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

#[axum::async_trait]
impl FromRequestParts<crate::AppState> for AuthUser {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &crate::AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer_token(parts)
            .ok_or_else(|| error_response(StatusCode::UNAUTHORIZED, "missing bearer token"))?;
        let claims = state
            .jwt
            .verify(token)
            .ok_or_else(|| error_response(StatusCode::UNAUTHORIZED, "invalid token"))?;
        let user = state
            .users
            .get(&claims.sub)
            .await
            .ok_or_else(|| error_response(StatusCode::UNAUTHORIZED, "unknown user"))?;
        Ok(AuthUser { user, claims })
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
    parts.uri.query().and_then(|q| {
        q.split('&').find_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            matches!(k, "token" | "access_token").then_some(v)
        })
    })
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
        let t = keys.issue(&u(), 60).unwrap();
        let other = JwtKeys::new("secret-b".into());
        assert!(other.verify(&t).is_none());
    }

    #[test]
    fn tampered_payload_rejected() {
        let keys = JwtKeys::new("s".into());
        let t = keys.issue(&u(), 60).unwrap();
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
        let t = keys.issue(&u(), -120).unwrap(); // expired (past 60s leeway)
        assert!(keys.verify(&t).is_none());
    }

    #[test]
    fn rotate_invalidates_all_tokens() {
        let keys = JwtKeys::new("s".into());
        let t = keys.issue(&u(), 60).unwrap();
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
