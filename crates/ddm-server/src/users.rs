use anyhow::{Context, Result};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

// ---------------------------------------------------------------------------
// Schema (users.yaml)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UsersFile {
    #[serde(default)]
    pub users: Vec<User>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub name: String,
    pub password_hash: String,
    #[serde(default)]
    pub roles: Vec<String>,
    /// Ordered access rules; first match wins. Empty = `default_access`.
    #[serde(default)]
    pub access: Vec<AccessRule>,
    #[serde(default)]
    pub features: UserFeatures,
    /// Named compose policy, or "unrestricted" to skip validation.
    #[serde(default)]
    pub compose_policy: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRule {
    #[serde(rename = "type")]
    pub kind: AccessRuleType,
    pub pattern: String,
    #[serde(default)]
    pub effect: AccessEffect,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccessRuleType {
    Exact,
    Glob,
    Regex,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AccessEffect {
    #[default]
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserFeatures {
    #[serde(default)]
    pub create_services: bool,
    #[serde(default)]
    pub edit_compose: bool,
    #[serde(default)]
    pub edit_units: bool,
    #[serde(default = "bool_true")]
    pub run_commands: bool,
    #[serde(default)]
    pub manage_backup: bool,
    #[serde(default)]
    pub manage_monitoring: bool,
    /// Edit arbitrary files inside service dirs and manage git repos there.
    #[serde(default)]
    pub edit_files: bool,
}

fn bool_true() -> bool {
    true
}

impl Default for UserFeatures {
    fn default() -> Self {
        Self {
            create_services: false,
            edit_compose: false,
            edit_units: false,
            run_commands: true,
            manage_backup: false,
            manage_monitoring: false,
            edit_files: false,
        }
    }
}

impl AccessRuleType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Glob => "glob",
            Self::Regex => "regex",
        }
    }
}

impl User {
    pub fn is_admin(&self) -> bool {
        self.roles.iter().any(|r| r == "admin")
    }
    pub fn has_role(&self, role: &str) -> bool {
        self.is_admin() || self.roles.iter().any(|r| r == role)
    }
}

// ---------------------------------------------------------------------------
// Password hashing
// ---------------------------------------------------------------------------

pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("argon2 hash failed: {e}"))?;
    Ok(hash.to_string())
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

pub fn generate_password() -> String {
    use rand::Rng;
    const ALPHABET: &[u8] = b"abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rng = rand::thread_rng();
    (0..24)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect()
}

// ---------------------------------------------------------------------------
// User store with hot reload + atomic write-back
// ---------------------------------------------------------------------------

pub struct UserStore {
    inner: RwLock<UsersFile>,
    path: PathBuf,
}

impl UserStore {
    pub fn load(path: &Path) -> Result<Self> {
        let file = if path.exists() {
            let f = std::fs::File::open(path)
                .with_context(|| format!("opening users file {}", path.display()))?;
            serde_yaml::from_reader(f)
                .with_context(|| format!("parsing users file {}", path.display()))?
        } else {
            UsersFile::default()
        };
        Ok(Self {
            inner: RwLock::new(file),
            path: path.to_path_buf(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub async fn get(&self, name: &str) -> Option<User> {
        self.inner
            .read()
            .await
            .users
            .iter()
            .find(|u| u.name == name)
            .cloned()
    }

    pub async fn list(&self) -> Vec<User> {
        self.inner.read().await.users.clone()
    }

    /// Verify credentials; returns the user on success.
    pub async fn authenticate(&self, name: &str, password: &str) -> Option<User> {
        let user = self.get(name).await?;
        if verify_password(password, &user.password_hash) {
            Some(user)
        } else {
            warn!("failed login for user '{name}'");
            None
        }
    }

    /// Apply a mutation and persist atomically (tmp + rename under flock).
    pub async fn mutate<F>(&self, f: F) -> Result<()>
    where
        F: FnOnce(&mut UsersFile) -> Result<()>,
    {
        let mut guard = self.inner.write().await;
        let mut new_file = guard.clone();
        f(&mut new_file)?;
        write_users_atomic(&self.path, &new_file)?;
        *guard = new_file;
        Ok(())
    }

    /// Re-read from disk (after external edit / CLI write).
    pub async fn reload(&self) -> Result<()> {
        if !self.path.exists() {
            return Ok(());
        }
        let f = std::fs::File::open(&self.path)?;
        let file: UsersFile = serde_yaml::from_reader(f)?;
        *self.inner.write().await = file;
        Ok(())
    }

    /// Spawn a watcher so in-container CLI edits propagate to the daemon.
    pub fn spawn_watcher(self: &Arc<Self>) {
        let this = self.clone();
        let path = self.path.clone();
        tokio::spawn(async move {
            use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
            let (tx, mut rx) = tokio::sync::mpsc::channel(4);
            let mut watcher = match RecommendedWatcher::new(
                move |res| {
                    let _ = tx.blocking_send(res);
                },
                Config::default(),
            ) {
                Ok(w) => w,
                Err(e) => {
                    error!("users watcher init failed: {e}");
                    return;
                }
            };
            // Watch the parent dir: our own atomic rename replaces the file.
            let dir = path.parent().unwrap_or(Path::new(".")).to_path_buf();
            if let Err(e) = watcher.watch(&dir, RecursiveMode::NonRecursive) {
                error!("users watcher failed: {e}");
                return;
            }
            while rx.recv().await.is_some() {
                tokio::time::sleep(Duration::from_millis(150)).await;
                while rx.try_recv().is_ok() {}
                if let Err(e) = this.reload().await {
                    error!("users reload failed: {e:#}");
                } else {
                    info!("users file reloaded");
                }
            }
        });
    }
}

/// Write users.yaml atomically: flock + tmp file + rename.
pub fn write_users_atomic(path: &Path, file: &UsersFile) -> Result<()> {
    use fs2::FileExt;
    let dir = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir)?;
    let lock_path = dir.join(format!(".{}.lock", file_name(path)));
    let lock_file = std::fs::File::create(&lock_path)?;
    lock_file.lock_exclusive()?;

    let tmp = dir.join(format!(".{}.tmp", file_name(path)));
    {
        let f = std::fs::File::create(&tmp)?;
        serde_yaml::to_writer(f, file)?;
    }
    std::fs::rename(&tmp, path)?;
    let _ = std::fs::remove_file(&lock_path);
    Ok(())
}

fn file_name(p: &Path) -> String {
    p.file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "users.yaml".to_string())
}

// ---------------------------------------------------------------------------
// CLI-facing mutations (shared between HTTP handlers and the server CLI)
// ---------------------------------------------------------------------------

pub fn cli_add_user(
    file: &mut UsersFile,
    name: &str,
    password: &str,
    roles: Vec<String>,
) -> Result<()> {
    if file.users.iter().any(|u| u.name == name) {
        anyhow::bail!("user '{name}' already exists");
    }
    file.users.push(User {
        name: name.to_string(),
        password_hash: hash_password(password)?,
        roles,
        access: vec![],
        features: UserFeatures::default(),
        compose_policy: None,
    });
    Ok(())
}

pub fn cli_remove_user(file: &mut UsersFile, name: &str) -> Result<()> {
    let before = file.users.len();
    file.users.retain(|u| u.name != name);
    if file.users.len() == before {
        anyhow::bail!("user '{name}' not found");
    }
    Ok(())
}

pub fn cli_set_password(file: &mut UsersFile, name: &str, password: &str) -> Result<()> {
    let user = file
        .users
        .iter_mut()
        .find(|u| u.name == name)
        .ok_or_else(|| anyhow::anyhow!("user '{name}' not found"))?;
    user.password_hash = hash_password(password)?;
    Ok(())
}

/// Parse "kind:pattern" CLI syntax like `glob:web-*`, `regex:^x$`, `exact:y`.
pub fn parse_access_spec(spec: &str, effect: AccessEffect) -> Result<AccessRule> {
    let (kind, pattern) = spec
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("access rule '{spec}' must be kind:pattern"))?;
    let kind = match kind {
        "exact" | "literal" => AccessRuleType::Exact,
        "glob" => AccessRuleType::Glob,
        "regex" | "re" => AccessRuleType::Regex,
        other => anyhow::bail!("unknown access rule kind '{other}'"),
    };
    if kind == AccessRuleType::Regex {
        regex::Regex::new(pattern).context("invalid regex")?;
    }
    if kind == AccessRuleType::Glob {
        globset::Glob::new(pattern).context("invalid glob")?;
    }
    Ok(AccessRule {
        kind,
        pattern: pattern.to_string(),
        effect,
    })
}

#[cfg(test)]
mod security_tests {
    use super::*;

    #[test]
    fn wrong_password_never_verifies() {
        let h = hash_password("correct horse battery staple").unwrap();
        for pw in [
            "",
            "correct horse battery stapl",
            "correct horse battery staple ",
            "CORRECT HORSE BATTERY STAPLE",
            "\u{0}correct horse battery staple",
        ] {
            assert!(!verify_password(pw, &h), "{pw:?} verified");
        }
        assert!(verify_password("correct horse battery staple", &h));
    }

    #[test]
    fn malformed_hashes_fail_closed() {
        for h in ["", "x", "$argon2id$garbage", "plaintext", "$2y$10$fake"] {
            assert!(!verify_password("anything", h), "{h:?} verified");
        }
    }

    #[test]
    fn generated_passwords_are_strong_and_unique() {
        let a = generate_password();
        let b = generate_password();
        assert_eq!(a.len(), 24);
        assert_ne!(a, b);
        assert!(a.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn access_spec_validates_patterns_at_write_time() {
        // invalid regex/glob cannot be persisted via the CLI
        assert!(parse_access_spec("regex:(", AccessEffect::Allow).is_err());
        assert!(parse_access_spec("glob:[", AccessEffect::Allow).is_err());
        assert!(parse_access_spec("wat:x", AccessEffect::Allow).is_err());
        assert!(parse_access_spec("nocolon", AccessEffect::Allow).is_err());
        assert!(parse_access_spec("exact:svc", AccessEffect::Deny).is_ok());
        assert!(parse_access_spec("regex:^prod-", AccessEffect::Allow).is_ok());
        // empty pattern is technically a valid (match-nothing) glob — but
        // empty exact is fine too; ensure no panic
        let _ = parse_access_spec("glob:", AccessEffect::Allow);
    }

    #[tokio::test]
    async fn authenticate_rejects_unknown_and_wrong() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("users.yaml");
        let mut f = UsersFile::default();
        f.users.push(User {
            name: "bob".into(),
            password_hash: hash_password("pw1").unwrap(),
            roles: vec!["viewer".into()],
            access: vec![],
            features: UserFeatures::default(),
            compose_policy: None,
        });
        write_users_atomic(&path, &f).unwrap();
        let store = UserStore::load(&path).unwrap();
        assert!(store.authenticate("bob", "pw1").await.is_some());
        assert!(store.authenticate("bob", "wrong").await.is_none());
        assert!(store.authenticate("mallory", "pw1").await.is_none());
        assert!(store.authenticate("bob", "").await.is_none());
    }
}
