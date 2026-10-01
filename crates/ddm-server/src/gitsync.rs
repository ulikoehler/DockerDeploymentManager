//! GitOps: keep service dirs (and optionally the config dir) in sync with a
//! git repo. A mirror clone lives under `monitoring.state_dir/gitops/repo`;
//! sync = fetch + hard reset, then a recursive copy into each configured
//! target. Optional `push_changes` copies local mutations back into the
//! mirror and commits/pushes them.

use crate::config::{AppConfig, GitOpsTarget, GitOpsTargetKind};
use crate::gitops::git;
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Default, Deserialize)]
pub struct GitsyncStatus {
    pub enabled: bool,
    pub url: String,
    pub branch: String,
    pub targets: Vec<String>,
    #[serde(with = "chrono::serde::ts_seconds_option")]
    pub last_sync_at: Option<DateTime<Utc>>,
    pub last_sync_ok: Option<bool>,
    pub last_error: Option<String>,
    pub synced_rev: Option<String>,
    pub pending_push: usize,
    #[serde(with = "chrono::serde::ts_seconds_option")]
    pub last_push_at: Option<DateTime<Utc>>,
    pub push_changes: bool,
}

#[derive(Default)]
pub struct Gitsync {
    status: Mutex<GitsyncStatus>,
    /// serializes sync/push so webhook + interval can't interleave
    lock: Mutex<()>,
}

impl Gitsync {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn status(&self) -> GitsyncStatus {
        self.status.lock().await.clone()
    }

    /// Entry point: validate config then sync. Safe to call any time.
    pub async fn sync(&self, cfg: &AppConfig, config_dir: &Path) -> Result<()> {
        let _guard = self.lock.lock().await;
        let res = self
            .sync_inner(cfg, config_dir)
            .await
            .map_err(|e| scrub(e, cfg));
        let mut st = self.status.lock().await;
        st.enabled = cfg.gitops.enabled;
        st.url = redact_url(&cfg.gitops.url);
        st.branch = cfg.gitops.branch.clone();
        st.push_changes = cfg.gitops.push_changes;
        st.targets = cfg
            .gitops
            .targets
            .iter()
            .map(|t| format!("{:?}:{}", t.into, t.path))
            .collect();
        match &res {
            Ok(()) => {
                st.last_sync_at = Some(Utc::now());
                st.last_sync_ok = Some(true);
                st.last_error = None;
            }
            Err(e) => {
                st.last_sync_ok = Some(false);
                st.last_error = Some(format!("{e:#}"));
            }
        }
        res
    }

    async fn sync_inner(&self, cfg: &AppConfig, config_dir: &Path) -> Result<()> {
        let g = &cfg.gitops;
        if !g.enabled || g.url.is_empty() {
            anyhow::bail!("gitops not enabled or no url configured");
        }
        let mirror = ensure_mirror(cfg).await?;
        git(&mirror, &["fetch", "--prune", "origin"]).await?;
        git(
            &mirror,
            &["reset", "--hard", &format!("origin/{}", g.branch)],
        )
        .await?;
        let rev = git(&mirror, &["rev-parse", "--short", "HEAD"])
            .await
            .unwrap_or_default();
        self.status.lock().await.synced_rev = Some(rev.trim().to_string());
        for t in &g.targets {
            let dst = target_dir(cfg, config_dir, t);
            let src = mirror.join(&t.path);
            if !src.is_dir() {
                warn!("gitops target path '{}' missing in repo", t.path);
                continue;
            }
            let protected = protected_set(cfg, t);
            copy_tree(&src, &dst, g.prune, &protected)?;
            info!("gitops: synced {} → {}", src.display(), dst.display());
        }
        Ok(())
    }

    /// Copy dirty target files back into the mirror and commit+push.
    /// Only meaningful when `push_changes` is on (enforced by callers).
    pub async fn push(&self, cfg: &AppConfig, config_dir: &Path) -> Result<bool> {
        let _guard = self.lock.lock().await;
        self.push_inner(cfg, config_dir)
            .await
            .map_err(|e| scrub(e, cfg))
    }

    async fn push_inner(&self, cfg: &AppConfig, config_dir: &Path) -> Result<bool> {
        let g = &cfg.gitops;
        if !g.enabled || g.url.is_empty() {
            anyhow::bail!("gitops not enabled");
        }
        let mirror = mirror_dir(cfg);
        if !mirror.join(".git").exists() {
            return Ok(false); // not synced yet
        }
        // pull first to avoid non-ff pushes
        git(&mirror, &["fetch", "origin"]).await?;
        git(
            &mirror,
            &["reset", "--hard", &format!("origin/{}", g.branch)],
        )
        .await?;
        for t in &g.targets {
            let src = target_dir(cfg, config_dir, t);
            let dst = mirror.join(&t.path);
            std::fs::create_dir_all(&dst)?;
            // when pushing, the repo's users file is NOT overwritten by the
            // local one — users are per-instance state.
            let protected = protected_set(cfg, t);
            copy_tree(&src, &dst, g.prune, &protected)?;
        }
        let dirty = git(&mirror, &["status", "--porcelain"]).await?;
        if dirty.trim().is_empty() {
            self.status.lock().await.pending_push = 0;
            return Ok(false);
        }
        git(&mirror, &["add", "-A"]).await?;
        let msg = format!(
            "ddm: local changes {}",
            Utc::now().format("%Y-%m-%d %H:%M UTC")
        );
        git(
            &mirror,
            &[
                "-c",
                &format!("user.name={}", g.commit_name),
                "-c",
                &format!("user.email={}", g.commit_email),
                "commit",
                "-m",
                &msg,
            ],
        )
        .await?;
        git(&mirror, &["push", "origin", &g.branch]).await?;
        let mut st = self.status.lock().await;
        st.last_push_at = Some(Utc::now());
        st.pending_push = 0;
        info!("gitops: pushed local changes");
        Ok(true)
    }

    /// Count of dirty files (target state vs mirror).
    pub async fn pending_count(&self, cfg: &AppConfig, config_dir: &Path) -> usize {
        let mirror = mirror_dir(cfg);
        if !mirror.join(".git").exists() {
            return 0;
        }
        let mut n = 0usize;
        for t in &cfg.gitops.targets {
            n += diff_count(
                &target_dir(cfg, config_dir, t),
                &mirror.join(&t.path),
                &protected_set(cfg, t),
            );
        }
        n
    }

    /// Polling loop: interval pulls + push pending (when enabled).
    pub async fn run(self: &Arc<Self>, cfg: Arc<crate::config::SharedConfig>, config_dir: PathBuf) {
        let mut last_pull = std::time::Instant::now() - std::time::Duration::from_secs(3600);
        let mut last_push = std::time::Instant::now();
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(15)).await;
            let c = cfg.get().await;
            if !c.gitops.enabled || c.gitops.url.is_empty() {
                continue;
            }
            if c.gitops.interval_secs > 0
                && last_pull.elapsed().as_secs() >= c.gitops.interval_secs.max(30)
            {
                last_pull = std::time::Instant::now();
                if let Err(e) = self.sync(&c, &config_dir).await {
                    warn!("gitops sync failed: {e:#}");
                }
            }
            if c.gitops.push_changes
                && last_push.elapsed().as_secs() >= c.gitops.push_interval_secs.max(15)
            {
                last_push = std::time::Instant::now();
                let n = self.pending_count(&c, &config_dir).await;
                self.status.lock().await.pending_push = n;
                if n > 0 {
                    if let Err(e) = self.push(&c, &config_dir).await {
                        warn!("gitops push failed: {e:#}");
                    }
                }
            }
        }
    }
}

/// Replace the configured token (if any) with `***` in an error message so
/// credentials never reach logs or the API.
fn scrub(e: anyhow::Error, cfg: &AppConfig) -> anyhow::Error {
    let tok = cfg.gitops.token.clone().or_else(|| {
        cfg.gitops
            .token_env
            .as_ref()
            .and_then(|v| std::env::var(v).ok())
    });
    let mut msg = format!("{e:#}");
    if let Some(t) = tok {
        if !t.is_empty() {
            msg = msg.replace(&t, "***");
        }
    }
    anyhow::anyhow!(msg)
}

fn mirror_dir(cfg: &AppConfig) -> PathBuf {
    Path::new(&cfg.monitoring.state_dir)
        .join("gitops")
        .join("repo")
}

fn target_dir(cfg: &AppConfig, config_dir: &Path, t: &GitOpsTarget) -> PathBuf {
    match t.into {
        GitOpsTargetKind::Services => PathBuf::from(&cfg.paths.services_root),
        GitOpsTargetKind::Config => config_dir.to_path_buf(),
    }
}

fn remote_url(cfg: &AppConfig) -> String {
    let token = cfg.gitops.token.clone().or_else(|| {
        cfg.gitops
            .token_env
            .as_ref()
            .and_then(|e| std::env::var(e).ok())
    });
    match token {
        Some(t) if cfg.gitops.url.starts_with("https://") => format!(
            "https://x-access-token:{t}@{}",
            &cfg.gitops.url["https://".len()..]
        ),
        _ => cfg.gitops.url.clone(),
    }
}

fn redact_url(u: &str) -> String {
    match u
        .split_once("://")
        .and_then(|(s, r)| r.split_once('@').map(|(_, h)| (s, h)))
    {
        Some((s, h)) => format!("{s}://***@{h}"),
        None => u.to_string(),
    }
}

async fn ensure_mirror(cfg: &AppConfig) -> Result<PathBuf> {
    let mirror = mirror_dir(cfg);
    let url = remote_url(cfg);
    if mirror.join(".git").exists() {
        // make sure the remote URL is current (token may have rotated)
        git(&mirror, &["remote", "set-url", "origin", &url]).await?;
        return Ok(mirror);
    }
    std::fs::create_dir_all(&mirror)?;
    git(&mirror, &["init"]).await?;
    git(&mirror, &["remote", "add", "origin", &url]).await?;
    git(&mirror, &["fetch", "origin", &cfg.gitops.branch]).await?;
    if git(
        &mirror,
        &["checkout", "-b", &cfg.gitops.branch, "FETCH_HEAD"],
    )
    .await
    .is_err()
    {
        git(&mirror, &["checkout", "-f", "FETCH_HEAD"]).await?;
    }
    let upstream = format!("origin/{}", cfg.gitops.branch);
    let _ = git(
        &mirror,
        &["branch", "--set-upstream-to", &upstream, &cfg.gitops.branch],
    )
    .await;
    Ok(mirror)
}

/// Names that are always excluded from sync/push in both directions.
fn base_protected() -> std::collections::HashSet<String> {
    [".git", ".restic_password", ".restic_inited"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// Protected files for a target: the per-instance users file is never
/// synced to or from a `Config` target.
fn protected_set(cfg: &AppConfig, t: &GitOpsTarget) -> std::collections::HashSet<String> {
    let mut set = base_protected();
    if matches!(t.into, GitOpsTargetKind::Config) {
        if let Some(f) = Path::new(&cfg.users_file)
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
        {
            set.insert(f);
        }
    }
    set
}

/// Recursive copy src→dst. `prune` deletes dst entries missing from src.
/// Entries in `protected` (plus *.lock/*.tmp) are never copied or pruned.
/// Returns true if anything changed.
fn copy_tree(
    src: &Path,
    dst: &Path,
    prune: bool,
    protected: &std::collections::HashSet<String>,
) -> Result<bool> {
    let mut changed = false;
    std::fs::create_dir_all(dst)?;
    for e in std::fs::read_dir(src)? {
        let e = e?;
        let name = e.file_name().to_string_lossy().to_string();
        if skip_entry(&name) || protected.contains(&name) {
            continue;
        }
        let s = e.path();
        let d = dst.join(&name);
        if s.is_dir() {
            if copy_tree(&s, &d, prune, protected)? {
                changed = true;
            }
        } else {
            let need = match std::fs::read(&d) {
                Ok(old) => old != std::fs::read(&s)?,
                Err(_) => true,
            };
            if need {
                std::fs::copy(&s, &d)?;
                changed = true;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let m = s.metadata()?.permissions().mode();
                if d.metadata()?.permissions().mode() != m {
                    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(m))?;
                }
            }
        }
    }
    if prune {
        for e in std::fs::read_dir(dst)? {
            let e = e?;
            let name = e.file_name().to_string_lossy().to_string();
            if skip_entry(&name) || protected.contains(&name) {
                continue;
            }
            if !src.join(&name).exists() {
                let p = e.path();
                if p.is_dir() {
                    std::fs::remove_dir_all(&p)?;
                } else {
                    std::fs::remove_file(&p)?;
                }
                changed = true;
            }
        }
    }
    Ok(changed)
}

fn skip_entry(name: &str) -> bool {
    name == ".git"
        || name == ".restic_password"
        || name == ".restic_inited"
        || name.ends_with(".lock")
        || name.ends_with(".tmp")
}

/// Count files that differ/missing between src and dst (src = target).
fn diff_count(src: &Path, dst: &Path, protected: &std::collections::HashSet<String>) -> usize {
    let mut n = 0;
    let src_map = flatten(src, protected);
    let dst_map = flatten(dst, protected);
    for (k, v) in &src_map {
        match dst_map.get(k) {
            Some(d) if d == v => {}
            _ => n += 1,
        }
    }
    n
}

fn flatten(dir: &Path, protected: &std::collections::HashSet<String>) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if skip_entry(&name) || protected.contains(&name) {
                continue;
            }
            let p = e.path();
            if p.is_dir() {
                for (k, v) in flatten(&p, protected) {
                    out.insert(format!("{name}/{k}"), v);
                }
            } else if let Ok(b) = std::fs::read(&p) {
                out.insert(name, b);
            }
        }
    }
    out
}

/// Verify a webhook request. Accepts GitHub `X-Hub-Signature-256`
/// (`sha256=<hmac>`) or GitLab `X-Gitlab-Token` (plain equality).
/// Returns false when no secret is configured.
pub fn verify_webhook(
    secret: &Option<String>,
    secret_env: &Option<String>,
    sig_header: Option<&str>,
    gitlab_token: Option<&str>,
    body: &[u8],
) -> bool {
    let secret = secret
        .clone()
        .or_else(|| secret_env.as_ref().and_then(|e| std::env::var(e).ok()));
    let Some(secret) = secret else { return false };
    if secret.is_empty() {
        return false; // an empty secret must never authenticate anything
    }
    // GitLab: plain token compare (constant-time to avoid a timing oracle)
    if let Some(t) = gitlab_token {
        let (a, b) = (t.as_bytes(), secret.as_bytes());
        return !a.is_empty()
            && a.len() == b.len()
            && a.iter()
                .zip(b.iter())
                .fold(0u8, |acc, (x, y)| acc | (x ^ y))
                == 0;
    }
    // GitHub/generic: HMAC-SHA256
    if let Some(sig) = sig_header.and_then(|s| s.strip_prefix("sha256=")) {
        use hmac::{Hmac, Mac};
        type H = Hmac<sha2::Sha256>;
        let Ok(mut mac) = H::new_from_slice(secret.as_bytes()) else {
            return false;
        };
        mac.update(body);
        let expected = hex::encode(mac.finalize().into_bytes());
        // constant-time-ish compare
        return expected.len() == sig.len()
            && expected
                .as_bytes()
                .iter()
                .zip(sig.as_bytes())
                .fold(0u8, |a, (x, y)| a | (x ^ y))
                == 0;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_url_token() {
        let mut c = AppConfig::default();
        c.gitops.url = "https://github.com/x/y.git".into();
        c.gitops.token = Some("tok".into());
        assert_eq!(
            remote_url(&c),
            "https://x-access-token:tok@github.com/x/y.git"
        );
        assert_eq!(
            redact_url(&remote_url(&c)),
            "https://***@github.com/x/y.git"
        );
    }

    #[test]
    fn copy_tree_prunes_and_preserves() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(a.path().join("svc")).unwrap();
        std::fs::write(a.path().join("svc/docker-compose.yml"), "x").unwrap();
        std::fs::write(a.path().join("svc/.restic_password"), "pw").unwrap();
        std::fs::write(b.path().join("stale.txt"), "old").unwrap();
        std::fs::write(b.path().join(".restic_password"), "keep").unwrap();
        let prot = base_protected();
        assert!(copy_tree(a.path(), b.path(), true, &prot).unwrap());
        assert!(b.path().join("svc/docker-compose.yml").exists());
        assert!(b.path().join(".restic_password").exists()); // never pruned
        assert!(!b.path().join("stale.txt").exists());
        assert!(!copy_tree(a.path(), b.path(), true, &prot).unwrap());
    }

    #[test]
    fn diff_counts() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        std::fs::write(a.path().join("f"), "1").unwrap();
        let prot = base_protected();
        assert_eq!(diff_count(a.path(), b.path(), &prot), 1);
        std::fs::write(b.path().join("f"), "1").unwrap();
        assert_eq!(diff_count(a.path(), b.path(), &prot), 0);
    }

    #[test]
    fn webhook_hmac() {
        use hmac::{Hmac, Mac};
        let secret = Some("s3cret".to_string());
        let body = b"payload";
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(b"s3cret").unwrap();
        mac.update(body);
        let sig = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
        assert!(verify_webhook(&secret, &None, Some(&sig), None, body));
        assert!(!verify_webhook(
            &secret,
            &None,
            Some("sha256=bad"),
            None,
            body
        ));
        assert!(!verify_webhook(&None, &None, Some(&sig), None, body));
        // gitlab token path
        assert!(verify_webhook(&secret, &None, None, Some("s3cret"), body));
        assert!(!verify_webhook(&secret, &None, None, Some("wrong"), body));
    }
}

#[cfg(test)]
mod security_tests {
    use super::*;

    #[test]
    fn token_scrubbed_from_errors() {
        let mut c = AppConfig::default();
        c.gitops.token = Some("ghp_sup3rsecret".into());
        let e =
            anyhow::anyhow!("remote set-url https://x-access-token:ghp_sup3rsecret@h/r.git failed");
        let out = format!("{:#}", scrub(e, &c));
        assert!(!out.contains("ghp_sup3rsecret"), "{out}");
        assert!(out.contains("***"));
    }

    #[test]
    fn token_env_scrubbed_from_errors() {
        let mut c = AppConfig::default();
        c.gitops.token_env = Some("DDM_TEST_GITOPS_TOK".into());
        std::env::set_var("DDM_TEST_GITOPS_TOK", "envtok123");
        let e = anyhow::anyhow!("git fetch https://x-access-token:envtok123@h/r failed");
        let out = format!("{:#}", scrub(e, &c));
        assert!(!out.contains("envtok123"), "{out}");
    }

    #[test]
    fn remote_url_without_token_stays_plain() {
        let mut c = AppConfig::default();
        c.gitops.url = "https://github.com/x/y.git".into();
        assert_eq!(remote_url(&c), "https://github.com/x/y.git");
        // token only applies to https — ssh/file urls untouched
        c.gitops.token = Some("t".into());
        c.gitops.url = "git@h:x/y.git".into();
        assert_eq!(remote_url(&c), "git@h:x/y.git");
    }

    #[test]
    fn webhook_rejects_malformed_signatures() {
        let secret = Some("s".into());
        let body = b"x";
        for sig in [
            "",
            "sha256=",
            "md5=abc",
            "sha256=zz",
            "sha256=abc",
            "abc",
            "SHA256=aaaa",
        ] {
            assert!(
                !verify_webhook(&secret, &None, Some(sig), None, body),
                "{sig:?} accepted"
            );
        }
        // empty secret is never valid
        assert!(!verify_webhook(
            &Some(String::new()),
            &None,
            None,
            Some(""),
            body
        ));
    }

    #[test]
    fn webhook_secret_from_env() {
        std::env::set_var("DDM_TEST_GITOPS_WH", "envsecret");
        let env = Some("DDM_TEST_GITOPS_WH".to_string());
        assert!(verify_webhook(&None, &env, None, Some("envsecret"), b"x"));
        assert!(!verify_webhook(&None, &env, None, Some("wrong"), b"x"));
    }

    #[test]
    fn gitlab_and_github_secrets_not_cross_verified() {
        // a gitlab token must not satisfy an HMAC check and vice versa
        let secret = Some("tok".into());
        assert!(!verify_webhook(
            &secret,
            &None,
            Some("sha256=tok"),
            None,
            b"b"
        ));
        // correct gitlab token with a *wrong* hmac present → token wins,
        // but a wrong gitlab token + right hmac must also verify
        use hmac::{Hmac, Mac};
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(b"tok").unwrap();
        mac.update(b"b");
        let sig = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
        // gitlab path takes precedence when the header is present:
        // a correct HMAC but wrong gitlab token still fails
        assert!(!verify_webhook(
            &secret,
            &None,
            Some(&sig),
            Some("bad"),
            b"b"
        ));
    }

    #[test]
    fn users_file_protected_in_config_target() {
        let c = AppConfig {
            users_file: "myusers.yml".into(),
            ..Default::default()
        };
        let t = GitOpsTarget {
            into: GitOpsTargetKind::Config,
            path: "config".into(),
        };
        let p = protected_set(&c, &t);
        assert!(p.contains("myusers.yml"));
        assert!(p.contains(".git"));
        let t2 = GitOpsTarget {
            into: GitOpsTargetKind::Services,
            path: "s".into(),
        };
        let p2 = protected_set(&c, &t2);
        assert!(!p2.contains("myusers.yml"));
    }
}
