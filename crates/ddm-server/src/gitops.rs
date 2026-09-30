//! Git operations inside a service directory (plugin/source management).
//! Read ops (status/log/branches/repo discovery) run `git` locally — the
//! service dir is bind-mounted so files are identical on the host.
//! Mutating ops (clone/pull/fetch/checkout) run through the
//! `ExecutionManager` so their output streams over WebSocket.

use crate::files;
use anyhow::{Context, Result};
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize)]
pub struct RepoInfo {
    /// Path relative to the service dir ("." = the service dir itself).
    pub path: String,
    pub branch: String,
    pub remote: Option<String>,
    pub dirty: bool,
}

#[derive(Debug, Serialize)]
pub struct RepoStatus {
    pub path: String,
    pub branch: String,
    pub remote: Option<String>,
    /// `git status --porcelain` lines (uncommitted/untracked files).
    pub changes: Vec<String>,
    /// `git status -sb` first line e.g. "## main...origin/main [ahead 1]".
    pub tracking: String,
}

#[derive(Debug, Serialize)]
pub struct RepoBranches {
    pub current: String,
    pub local: Vec<String>,
    pub remote: Vec<String>,
}

pub const MAX_LOG: usize = 200;

/// Find git repos inside the service dir (the dir itself + up to `depth`
/// levels of subdirectories).
pub fn find_repos(service_dir: &Path, depth: usize) -> Vec<PathBuf> {
    let mut out = vec![];
    walk(service_dir, depth, &mut out);
    out
}

fn walk(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if dir.join(".git").exists() {
        out.push(dir.to_path_buf());
        return; // don't descend into a repo looking for nested repos
    }
    if depth == 0 {
        return;
    }
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            if e.path().is_dir() {
                walk(&e.path(), depth - 1, out);
            }
        }
    }
}

fn rel_path(root: &Path, repo: &Path) -> String {
    repo.strip_prefix(root)
        .map(|p| {
            let s = p.to_string_lossy().to_string();
            if s.is_empty() {
                ".".into()
            } else {
                s
            }
        })
        .unwrap_or_else(|_| ".".into())
}

/// Run `git` in `repo` and return stdout (status must be 0).
pub async fn git(repo: &Path, args: &[&str]) -> Result<String> {
    let out = tokio::process::Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .await
        .context("running git")?;
    if !out.status.success() {
        anyhow::bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

pub async fn branch(repo: &Path) -> String {
    git(repo, &["rev-parse", "--abbrev-ref", "HEAD"])
        .await
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "?".into())
}

pub async fn remote(repo: &Path) -> Option<String> {
    git(repo, &["remote", "get-url", "origin"])
        .await
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub async fn dirty(repo: &Path) -> bool {
    git(repo, &["status", "--porcelain"])
        .await
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
}

/// List all repos in the service dir with summary info.
pub async fn list_repos(service_dir: &Path) -> Vec<RepoInfo> {
    let mut out = vec![];
    for repo in find_repos(service_dir, 3) {
        out.push(RepoInfo {
            path: rel_path(service_dir, &repo),
            branch: branch(&repo).await,
            remote: remote(&repo).await,
            dirty: dirty(&repo).await,
        });
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

/// Resolve a repo path arg (""/"." = service root) to an absolute dir,
/// requiring it to actually be a repo.
pub fn resolve_repo(service_dir: &Path, rel: &str) -> Result<PathBuf> {
    let rel = if rel == "." { "" } else { rel };
    let abs = files::resolve(service_dir, rel)?;
    if !abs.join(".git").exists() {
        anyhow::bail!("'{rel}' is not a git repository");
    }
    Ok(abs)
}

pub async fn status(repo: &Path, service_dir: &Path) -> Result<RepoStatus> {
    let porcelain = git(repo, &["status", "--porcelain"]).await?;
    let tracking = git(repo, &["status", "-sb"]).await?;
    Ok(RepoStatus {
        path: rel_path(service_dir, repo),
        branch: branch(repo).await,
        remote: remote(repo).await,
        changes: porcelain.lines().map(|l| l.to_string()).collect(),
        tracking: tracking.lines().next().unwrap_or_default().to_string(),
    })
}

pub async fn log(repo: &Path, n: usize) -> Result<Vec<String>> {
    let n = n.clamp(1, MAX_LOG);
    let out = git(
        repo,
        &[
            "log",
            &format!("-{n}"),
            "--pretty=format:%h %ad %an %s",
            "--date=short",
        ],
    )
    .await?;
    Ok(out.lines().map(|l| l.to_string()).collect())
}

pub async fn branches(repo: &Path) -> Result<RepoBranches> {
    let out = git(repo, &["branch", "-a", "--format=%(refname:short)"]).await?;
    let mut local = vec![];
    let mut remote = vec![];
    for l in out.lines() {
        let b = l.trim().to_string();
        if b.is_empty() {
            continue;
        }
        if b.starts_with("origin/") || b.contains('/') {
            remote.push(b);
        } else {
            local.push(b);
        }
    }
    Ok(RepoBranches {
        current: branch(repo).await,
        local,
        remote,
    })
}

/// Validate a git ref (branch/tag/commit) — no flags, no weird chars.
pub fn valid_ref(r: &str) -> bool {
    !r.is_empty()
        && r.len() <= 200
        && !r.starts_with('-')
        && r.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_' | '.' | '@'))
        && !r.contains("..")
}

/// Validate a clone URL: https/git/ssh/scp-style/file paths allowed.
pub fn valid_clone_url(u: &str) -> bool {
    !u.is_empty()
        && u.len() <= 500
        && !u.starts_with('-')
        && (u.starts_with("https://")
            || u.starts_with("http://")
            || u.starts_with("git://")
            || u.starts_with("ssh://")
            || u.starts_with("file://")
            || u.starts_with('/')
            || u.starts_with('.')
            // scp-style git@host:path
            || u.contains('@') && u.contains(':'))
}

/// Shell script for a mutating git op, executed via the ExecutionManager.
pub fn op_script(op: &str, repo_dir: &Path, git_ref: Option<&str>) -> Result<String> {
    let dir = shell_word(&repo_dir.to_string_lossy());
    let cmd = match op {
        "pull" => "git pull --ff-only".to_string(),
        "fetch" => "git fetch --all --prune".to_string(),
        "checkout" => {
            let r = git_ref.context("checkout needs a ref")?;
            if !valid_ref(r) {
                anyhow::bail!("invalid ref '{r}'");
            }
            format!("git checkout {}", shell_word(r))
        }
        _ => anyhow::bail!("unknown git op '{op}'"),
    };
    Ok(format!("cd {dir} && {cmd}"))
}

pub fn clone_script(
    service_dir: &Path,
    url: &str,
    rel: &str,
    branch: Option<&str>,
) -> Result<String> {
    if !valid_clone_url(url) {
        anyhow::bail!("invalid clone url");
    }
    let target = if rel.is_empty() || rel == "." {
        service_dir.to_path_buf()
    } else {
        files::resolve(service_dir, rel)?
    };
    let mut cmd = format!("git clone {}", shell_word(url));
    if let Some(b) = branch {
        if !valid_ref(b) {
            anyhow::bail!("invalid branch '{b}'");
        }
        cmd.push_str(&format!(" --branch {}", shell_word(b)));
    }
    cmd.push_str(&format!(" {}", shell_word(&target.to_string_lossy())));
    Ok(format!(
        "cd {} && {cmd}",
        shell_word(&service_dir.to_string_lossy())
    ))
}

fn shell_word(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ref_validation() {
        assert!(valid_ref("main"));
        assert!(valid_ref("feature/x-y.z"));
        assert!(valid_ref("v1.2.3"));
        assert!(!valid_ref("-u root"));
        assert!(!valid_ref("a..b"));
        assert!(!valid_ref("a;rm -rf /"));
    }

    #[test]
    fn url_validation() {
        assert!(valid_clone_url("https://github.com/a/b.git"));
        assert!(valid_clone_url("git@github.com:a/b.git"));
        assert!(valid_clone_url("ssh://git@host/repo"));
        assert!(valid_clone_url("./local/path"));
        assert!(!valid_clone_url("--upload-pack=evil"));
        assert!(!valid_clone_url(""));
    }
}

#[cfg(test)]
mod security_tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn ref_injection_rejected() {
        for bad in [
            "--upload-pack=evil",
            "--exec=sh",
            "-oProxyCommand=x",
            "$(rm -rf /)",
            "`id`",
            "a;cat /etc/shadow",
            "a|nc x 1",
            "a\nevil",
            "a b",
            "a'b",
            "a\"b",
            "a..b",
            "a//../../etc",
            "HEAD@{upstream}",
            "",
            "a?b",
            "a*b",
            "a[b",
            "a~b",
            "a^b",
            "a:b",
            "a\\b",
        ] {
            assert!(!valid_ref(bad), "{bad:?} accepted as ref");
        }
        for ok in ["main", "origin/main", "feature/x_y.z@1", "v2.0"] {
            assert!(valid_ref(ok), "{ok:?} rejected");
        }
    }

    #[test]
    fn clone_url_flag_and_scheme_injection() {
        for bad in [
            "--config=core.sshCommand=evil",
            "-c x=y",
            "ext::sh -c id",
            "fd::/x",
            // javascript/data/other schemes
            "javascript:alert(1)",
            "data:text/plain,x",
            "ftp://h/x",
        ] {
            assert!(!valid_clone_url(bad), "{bad:?} accepted");
        }
    }

    #[test]
    fn checkout_script_never_emits_raw_ref() {
        let dir = Path::new("/tmp/svc");
        // even a ref that passed validation is single-quoted in the script
        let s = op_script("checkout", dir, Some("feature/x")).unwrap();
        assert!(s.contains("git checkout 'feature/x'"), "{s}");
        // hostile ref is rejected before reaching the script
        assert!(op_script("checkout", dir, Some("a;rm -rf /")).is_err());
        assert!(op_script("checkout", dir, Some("$(id)")).is_err());
        assert!(op_script("checkout", dir, Some("--orphan")).is_err());
    }

    #[test]
    fn clone_target_stays_inside_service_dir() {
        let dir = tempfile::tempdir().unwrap();
        // path escapes via clone rel are rejected by files::resolve
        assert!(clone_script(dir.path(), "https://h/r.git", "../x", None).is_err());
        assert!(clone_script(dir.path(), "https://h/r.git", "/abs", None).is_err());
        assert!(clone_script(dir.path(), "https://h/r.git", ".git/x", None).is_err());
        // url with a quote can't break out of shell_word quoting
        let s = clone_script(dir.path(), "https://h/r'evil.git", "sub", None).unwrap();
        assert!(s.contains("'https://h/r'\\''evil.git'"), "{s}");
    }

    #[test]
    fn service_dir_path_is_shell_quoted() {
        let dir = Path::new("/opt/svc with space/$(evil)");
        let s = op_script("pull", dir, None).unwrap();
        assert!(s.contains("'/opt/svc with space/$(evil)'"), "{s}");
        assert!(!s.contains("cd /opt/svc"), "{s}");
    }
}
