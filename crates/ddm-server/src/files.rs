//! Custom file & file-tree operations inside a service directory.
//! All paths are validated to stay inside the service dir (no `..`, no
//! absolute paths, symlink-checked). `.git` internals and `.restic_password`
//! are off-limits to the file API.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};

/// Max size for file reads through the API (larger → `truncated`).
pub const READ_LIMIT: u64 = 1 << 19; // 512 KiB

const DENIED_COMPONENTS: &[&str] = &[".git"];
/// Files that cross a privilege boundary: `.restic_*` hold repo secrets,
/// `meta.yaml` drives monitoring auto-actions and backup config, and
/// `backup.sh` is executed as root by a host systemd timer (and embeds
/// repository credentials). They must never be reachable through the
/// file API — use the dedicated endpoints instead.
const DENIED_FILES: &[&str] = &[
    ".restic_password",
    ".restic_inited",
    "meta.yaml",
    "backup.sh",
];

#[derive(Debug, Serialize, Deserialize)]
pub struct FileEntry {
    pub name: String,
    pub kind: String, // "dir" | "file" | "symlink" | "other"
    pub size: u64,
    /// Unix seconds — WebDAV `getlastmodified`/`getetag` need it.
    #[serde(default)]
    pub mtime: i64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum FileNode {
    Dir {
        path: String,
        entries: Vec<FileEntry>,
    },
    File {
        path: String,
        size: u64,
        content: String,
        truncated: bool,
    },
    Binary {
        path: String,
        size: u64,
    },
}

fn denied(rel: &str) -> bool {
    let p = Path::new(rel);
    for c in p.components() {
        if let Component::Normal(s) = c {
            if DENIED_COMPONENTS.contains(&s.to_string_lossy().as_ref()) {
                return true;
            }
        }
    }
    p.file_name()
        .map(|n| DENIED_FILES.contains(&n.to_string_lossy().as_ref()))
        .unwrap_or(false)
}

/// Resolve a user-supplied relative path against `root`, guaranteeing the
/// result is inside `root` (canonicalizing symlinks for existing parts).
pub fn resolve(root: &Path, rel: &str) -> Result<PathBuf> {
    if rel.starts_with('/') || rel.starts_with('\\') || rel.contains('\\') {
        anyhow::bail!("path must be a relative POSIX path");
    }
    if denied(rel) {
        anyhow::bail!("access to '{rel}' is not allowed");
    }
    let mut clean = PathBuf::new();
    for c in Path::new(rel).components() {
        match c {
            Component::Normal(s) => clean.push(s),
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) | Component::ParentDir => {
                anyhow::bail!("path escapes the service directory")
            }
        }
    }
    let root_canon = root
        .canonicalize()
        .with_context(|| format!("canonicalizing {}", root.display()))?;
    let joined = root_canon.join(&clean);
    // For existing paths resolve fully; otherwise canonicalize the deepest
    // existing ancestor to catch symlinks in the middle of the path.
    let canon = if joined.exists() {
        joined.canonicalize()?
    } else {
        let mut anc = joined.as_path();
        while !anc.exists() {
            anc = anc
                .parent()
                .ok_or_else(|| anyhow::anyhow!("path escapes the service directory"))?;
        }
        let anc_canon = anc.canonicalize()?;
        anc_canon.join(joined.strip_prefix(anc).unwrap())
    };
    if !canon.starts_with(&root_canon) {
        anyhow::bail!("path escapes the service directory");
    }
    // The denied-name policy has to hold for the *resolved* path, not just
    // the input: a symlink alias inside the service dir (`data -> meta.yaml`,
    // which a cloned repo can deliver) would otherwise canonicalize straight
    // onto a privileged file and be read/written through it.
    if let Ok(rel_canon) = canon.strip_prefix(&root_canon) {
        if denied(&rel_canon.to_string_lossy()) {
            anyhow::bail!("access to '{rel}' is not allowed");
        }
    }
    Ok(canon)
}

fn display_rel(root: &Path, abs: &Path) -> String {
    abs.strip_prefix(root)
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default()
}

/// Unix seconds of a path's mtime (0 when unavailable).
pub fn mtime_secs(m: &std::fs::Metadata) -> i64 {
    m.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn kind_of(ft: &std::fs::FileType) -> &'static str {
    if ft.is_dir() {
        "dir"
    } else if ft.is_symlink() {
        "symlink"
    } else if ft.is_file() {
        "file"
    } else {
        "other"
    }
}

/// Metadata for one path, without reading content. Uses `symlink_metadata`
/// so a symlink is reported as such instead of being followed.
pub fn stat(root: &Path, rel: &str) -> Result<crate::agent::proto::FileMeta> {
    let abs = resolve(root, rel)?;
    let m = match std::fs::symlink_metadata(&abs) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            anyhow::bail!("'{rel}' does not exist")
        }
        Err(e) => return Err(e.into()),
    };
    Ok(crate::agent::proto::FileMeta {
        kind: kind_of(&m.file_type()).to_string(),
        size: m.len(),
        mtime: mtime_secs(&m),
    })
}

/// List a directory: denied names are filtered out (they are neither
/// readable nor writable, so they must not be advertised either).
pub fn list(root: &Path, rel: &str) -> Result<Vec<FileEntry>> {
    let abs = resolve(root, rel)?;
    let meta = std::fs::symlink_metadata(&abs)?;
    if !meta.is_dir() {
        anyhow::bail!("'{rel}' is not a directory");
    }
    let mut entries = vec![];
    for e in std::fs::read_dir(&abs)? {
        let e = e?;
        if denied(&e.file_name().to_string_lossy()) {
            continue;
        }
        let ft = e.file_type()?;
        let m = std::fs::symlink_metadata(e.path())?;
        entries.push(FileEntry {
            name: e.file_name().to_string_lossy().to_string(),
            kind: kind_of(&ft).to_string(),
            size: m.len(),
            mtime: mtime_secs(&m),
        });
    }
    entries.sort_by(|a, b| {
        (a.kind != "dir")
            .cmp(&(b.kind != "dir"))
            .then(a.name.cmp(&b.name))
    });
    Ok(entries)
}

// ---------------------------------------------------------------------------
// Streaming writes (WebDAV data plane)
// ---------------------------------------------------------------------------

/// A write staged in a sibling temp file, committed by an atomic rename.
/// Between `stage_write` and `commit_staged` the caller can inspect the
/// staged bytes (the compose-policy gate needs the content) and abort.
pub struct StagedWrite {
    pub tmp: PathBuf,
    pub abs: PathBuf,
    pub written: u64,
}

impl StagedWrite {
    /// Discard the staged bytes (no-op after a successful commit).
    pub fn abort(&self) {
        let _ = std::fs::remove_file(&self.tmp);
    }
}

/// Stream `reader` into a sibling temp file for `rel`, bounded by `max`.
/// Parent directories are created; the target must not be an existing
/// directory. Nothing is visible under the final name until commit.
pub async fn stage_write(
    root: &Path,
    rel: &str,
    reader: &mut (impl tokio::io::AsyncRead + Unpin),
    max: u64,
) -> Result<StagedWrite> {
    let abs = resolve(root, rel)?;
    if abs.is_dir() {
        anyhow::bail!("'{rel}' is a directory");
    }
    if let Some(parent) = abs.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = tmp_sibling(&abs);
    let mut f = tokio::fs::File::create(&tmp).await?;
    // Read one byte past the cap so an over-size upload is detected rather
    // than silently truncated.
    let mut limited = tokio::io::AsyncReadExt::take(reader, max + 1);
    let written = match tokio::io::copy(&mut limited, &mut f).await {
        Ok(n) => n,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(e.into());
        }
    };
    if written > max {
        let _ = std::fs::remove_file(&tmp);
        anyhow::bail!("file exceeds the maximum size");
    }
    Ok(StagedWrite { tmp, abs, written })
}

/// fsync + atomic rename of a staged write.
pub fn commit_staged(s: StagedWrite) -> Result<()> {
    // Durability: flush the file, then rename, then fsync the directory so
    // the new name survives a crash.
    let f = std::fs::OpenOptions::new().write(true).open(&s.tmp)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&s.tmp, &s.abs)?;
    if let Some(dir) = s.abs.parent() {
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

/// Sibling temp name for an atomic rename (same filesystem).
pub fn tmp_sibling(abs: &Path) -> PathBuf {
    abs.with_file_name(format!(
        ".{}.tmp",
        abs.file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default()
    ))
}

pub fn read_node(root: &Path, rel: &str) -> Result<FileNode> {
    let abs = resolve(root, rel)?;
    let root_canon = root.canonicalize()?;
    let meta = std::fs::symlink_metadata(&abs)?;
    if meta.is_dir() {
        Ok(FileNode::Dir {
            path: display_rel(&root_canon, &abs),
            entries: list(&root_canon, rel)?,
        })
    } else if meta.is_file() {
        let size = meta.len();
        if size > READ_LIMIT {
            // return truncated head
            use std::io::Read;
            let mut f = std::fs::File::open(&abs)?;
            let mut buf = vec![0u8; READ_LIMIT as usize];
            let n = f.read(&mut buf)?;
            buf.truncate(n);
            return classify(&root_canon, &abs, size, buf, true);
        }
        let bytes = std::fs::read(&abs)?;
        classify(&root_canon, &abs, size, bytes, false)
    } else {
        anyhow::bail!("not a regular file or directory");
    }
}

fn classify(
    root: &Path,
    abs: &Path,
    size: u64,
    bytes: Vec<u8>,
    truncated: bool,
) -> Result<FileNode> {
    let rel = display_rel(root, abs);
    match String::from_utf8(bytes) {
        Ok(content) if !content.contains('\0') => Ok(FileNode::File {
            path: rel,
            size,
            content,
            truncated,
        }),
        _ => Ok(FileNode::Binary { path: rel, size }),
    }
}

/// Atomically write `content` to `rel` (creates parent dirs).
pub fn write_file(root: &Path, rel: &str, content: &str) -> Result<()> {
    let abs = resolve(root, rel)?;
    if abs.is_dir() {
        anyhow::bail!("'{rel}' is a directory");
    }
    if let Some(parent) = abs.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = abs.with_file_name(format!(
        ".{}.tmp",
        abs.file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default()
    ));
    std::fs::write(&tmp, content)?;
    std::fs::rename(&tmp, &abs)?;
    Ok(())
}

pub fn mkdir(root: &Path, rel: &str) -> Result<()> {
    let abs = resolve(root, rel)?;
    if abs.exists() {
        anyhow::bail!("'{rel}' already exists");
    }
    std::fs::create_dir_all(&abs)?;
    Ok(())
}

pub fn rename(root: &Path, from: &str, to: &str) -> Result<()> {
    let src = resolve(root, from)?;
    if !src.exists() {
        anyhow::bail!("'{from}' does not exist");
    }
    let dst = resolve(root, to)?;
    if dst.exists() {
        anyhow::bail!("'{to}' already exists");
    }
    std::fs::rename(&src, &dst)?;
    Ok(())
}

/// Copy a file or directory tree (WebDAV COPY). The destination must not
/// exist. Symlinks are copied *verbatim* rather than followed — reading
/// through an escaping link is already refused by `resolve`, so duplicating
/// one grants no new reach. Denied names are skipped inside a tree, so a
/// copy can never plant a second `meta.yaml`/`backup.sh`.
pub fn copy(root: &Path, from: &str, to: &str) -> Result<()> {
    let src = resolve(root, from)?;
    std::fs::symlink_metadata(&src).with_context(|| format!("'{from}' does not exist"))?;
    let dst = resolve(root, to)?;
    if std::fs::symlink_metadata(&dst).is_ok() {
        anyhow::bail!("'{to}' already exists");
    }
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)?;
    }
    copy_entry(&src, &dst)
}

fn copy_entry(src: &Path, dst: &Path) -> Result<()> {
    let meta = std::fs::symlink_metadata(src)?;
    let ft = meta.file_type();
    if ft.is_symlink() {
        let target = std::fs::read_link(src)?;
        std::os::unix::fs::symlink(&target, dst)?;
        return Ok(());
    }
    if ft.is_dir() {
        std::fs::create_dir_all(dst)?;
        for e in std::fs::read_dir(src)? {
            let e = e?;
            if denied(&e.file_name().to_string_lossy()) {
                continue;
            }
            copy_entry(&e.path(), &dst.join(e.file_name()))?;
        }
        return Ok(());
    }
    std::fs::copy(src, dst)?;
    Ok(())
}

/// Delete a file or directory (recursive). Refuses to delete the service
/// root itself and the compose file is NOT protected (explicit action).
pub fn delete(root: &Path, rel: &str) -> Result<()> {
    if rel.is_empty() || rel == "." {
        anyhow::bail!("refusing to delete the service root");
    }
    let abs = resolve(root, rel)?;
    let meta =
        std::fs::symlink_metadata(&abs).with_context(|| format!("'{rel}' does not exist"))?;
    if meta.is_dir() {
        std::fs::remove_dir_all(&abs)?;
    } else {
        std::fs::remove_file(&abs)?;
    }
    Ok(())
}

/// After `git clone` into `target` (inside service dir `root`): remove the
/// artifacts a clone must not deliver — denied filenames at the service-dir
/// top level and symlinks that escape `root`. Called agent-side; a cloned
/// repo is attacker-controlled content.
pub fn sanitize_clone(root: &Path, target: &Path) {
    sanitize_dir(root, target, 0);
}

fn sanitize_dir(root: &Path, dir: &Path, depth: u32) {
    if depth > 32 {
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    let mut entries: Vec<_> = rd.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let p = e.path();
        let ft = match e.file_type() {
            Ok(f) => f,
            Err(_) => continue,
        };
        if ft.is_symlink() {
            match p.canonicalize() {
                Ok(c) if c.starts_with(root) => {}
                _ => {
                    let _ = std::fs::remove_file(&p);
                }
            }
            continue;
        }
        if ft.is_dir() {
            // never descend into a `.git` — it's a repo, not content
            if e.file_name() != ".git" {
                sanitize_dir(root, &p, depth + 1);
            }
            continue;
        }
        if dir == root {
            let name = e.file_name();
            if DENIED_FILES.contains(&name.to_string_lossy().as_ref()) {
                let _ = std::fs::remove_file(&p);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree() -> tempfile::TempDir {
        let t = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(t.path().join("a/b")).unwrap();
        std::fs::write(t.path().join("a/b/f.txt"), "hi").unwrap();
        t
    }

    #[test]
    fn resolve_rejects_escapes() {
        let t = tree();
        assert!(resolve(t.path(), "../x").is_err());
        assert!(resolve(t.path(), "a/../../x").is_err());
        assert!(resolve(t.path(), "/etc/passwd").is_err());
        assert!(resolve(t.path(), "a\\..\\x").is_err());
        assert!(resolve(t.path(), ".git/config").is_err());
        assert!(resolve(t.path(), "sub/.git/hooks/x").is_err());
        assert!(resolve(t.path(), ".restic_password").is_err());
        assert!(resolve(t.path(), "a/b/f.txt").is_ok());
        assert!(resolve(t.path(), "new/deep/file.txt").is_ok());
    }

    #[test]
    fn resolve_blocks_symlink_escape() {
        let t = tree();
        std::os::unix::fs::symlink("/etc", t.path().join("link")).unwrap();
        assert!(resolve(t.path(), "link/passwd").is_err());
    }

    #[test]
    fn read_write_delete() {
        let t = tree();
        match read_node(t.path(), "a").unwrap() {
            FileNode::Dir { entries, .. } => assert_eq!(entries[0].name, "b"),
            _ => panic!(),
        }
        match read_node(t.path(), "a/b/f.txt").unwrap() {
            FileNode::File { content, .. } => assert_eq!(content, "hi"),
            _ => panic!(),
        }
        write_file(t.path(), "x/y/z.txt", "new").unwrap();
        assert_eq!(
            std::fs::read_to_string(t.path().join("x/y/z.txt")).unwrap(),
            "new"
        );
        rename(t.path(), "x/y", "x/moved").unwrap();
        assert!(t.path().join("x/moved/z.txt").exists());
        delete(t.path(), "x").unwrap();
        assert!(!t.path().join("x").exists());
        assert!(delete(t.path(), "").is_err());
        assert!(write_file(t.path(), ".git/x", "no").is_err());
    }

    /// Denied names are not even listed: a service dir holding privileged
    /// files must not advertise them through the file tree.
    #[test]
    fn denied_files_are_not_listed() {
        let t = tree();
        std::fs::write(t.path().join("meta.yaml"), "x").unwrap();
        std::fs::write(t.path().join("backup.sh"), "x").unwrap();
        std::fs::write(t.path().join("visible.txt"), "x").unwrap();
        let names: Vec<String> = match read_node(t.path(), "").unwrap() {
            FileNode::Dir { entries, .. } => entries.into_iter().map(|e| e.name).collect(),
            _ => panic!("expected dir"),
        };
        assert!(names.contains(&"visible.txt".to_string()));
        assert!(!names.contains(&"meta.yaml".to_string()), "{names:?}");
        assert!(!names.contains(&"backup.sh".to_string()), "{names:?}");
    }

    /// A cloned repo is attacker-controlled content: escaping symlinks and
    /// privileged filenames it delivered must be removed afterwards.
    #[cfg(unix)]
    #[test]
    fn sanitize_clone_strips_escapes_and_privileged_files() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret"), "x").unwrap();
        let repo = root.path().join("repo");
        std::fs::create_dir_all(repo.join("sub")).unwrap();
        std::fs::write(repo.join("ok.txt"), "ok").unwrap();
        std::fs::write(repo.join("sub/keep.txt"), "keep").unwrap();
        // escapes the service dir → must go
        std::os::unix::fs::symlink(outside.path(), repo.join("escape")).unwrap();
        std::os::unix::fs::symlink(outside.path().join("secret"), repo.join("sub/leak")).unwrap();
        // a link that stays inside is harmless and kept
        std::os::unix::fs::symlink(repo.join("ok.txt"), repo.join("inside")).unwrap();
        // privileged filename delivered by the clone at the service root
        std::fs::write(root.path().join("meta.yaml"), "from-repo").unwrap();

        sanitize_clone(root.path(), &repo);
        sanitize_clone(root.path(), root.path());

        assert!(repo.join("ok.txt").exists());
        assert!(repo.join("sub/keep.txt").exists());
        assert!(!repo.join("escape").exists(), "escaping symlink kept");
        assert!(!repo.join("sub/leak").exists(), "nested escaping symlink kept");
        assert!(repo.join("inside").exists(), "in-tree symlink removed");
        assert!(!root.path().join("meta.yaml").exists(), "meta.yaml kept");
    }
}

#[cfg(test)]
mod security_tests {
    use super::*;
    use std::fs;

    #[test]
    fn traversal_variants_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        for rel in [
            "..",
            "../x",
            "a/../../x",
            "a/../..",
            "..\\x",
            "a\\b",
            "/etc/passwd",
            "\\abs",
            "a/b/../../../etc",
            "x/./../../y",
            "dir/../..",
        ] {
            assert!(resolve(root, rel).is_err(), "{rel:?} resolved");
        }
    }

    #[test]
    fn denied_paths_anywhere_in_tree() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        for rel in [
            ".git",
            ".git/config",
            "sub/.git/HEAD",
            "a/b/.git/x",
            ".restic_password",
            "data/.restic_password",
            ".restic_inited",
            "x/.restic_inited",
        ] {
            assert!(resolve(root, rel).is_err(), "{rel:?} allowed");
        }
    }

    /// A symlink alias inside the service dir must not become a way around
    /// the denied-name policy: `data -> meta.yaml` canonicalizes onto the
    /// privileged file, and a cloned repo can deliver exactly that.
    #[test]
    fn resolve_denied_names_via_symlink_aliases() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("meta.yaml"), "backup: {enabled: false}\n").unwrap();
        fs::write(root.join("backup.sh"), "#!/bin/sh\n").unwrap();
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::write(root.join(".git/config"), "[core]\n").unwrap();
        std::os::unix::fs::symlink("meta.yaml", root.join("alias.yaml")).unwrap();
        std::os::unix::fs::symlink("backup.sh", root.join("alias.sh")).unwrap();
        std::os::unix::fs::symlink(".git", root.join("gitdir")).unwrap();
        fs::create_dir_all(root.join("sub")).unwrap();
        std::os::unix::fs::symlink("../meta.yaml", root.join("sub/up.yaml")).unwrap();

        for rel in ["alias.yaml", "alias.sh", "gitdir/config", "sub/up.yaml"] {
            assert!(resolve(root, rel).is_err(), "{rel:?} resolved through an alias");
            assert!(read_node(root, rel).is_err(), "{rel:?} readable through an alias");
            assert!(
                write_file(root, rel, "pwned").is_err(),
                "{rel:?} writable through an alias"
            );
        }
        // ...and the protected files are untouched.
        assert!(fs::read_to_string(root.join("meta.yaml"))
            .unwrap()
            .contains("enabled: false"));
        assert_eq!(fs::read_to_string(root.join("backup.sh")).unwrap(), "#!/bin/sh\n");
        // An ordinary in-dir symlink still works (only denied targets are cut).
        fs::write(root.join("plain.txt"), "ok").unwrap();
        std::os::unix::fs::symlink("plain.txt", root.join("alias.txt")).unwrap();
        assert!(resolve(root, "alias.txt").is_ok());
        assert!(read_node(root, "alias.txt").is_ok());
    }

    #[test]
    fn nested_symlink_escape_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("secret.txt"), "x").unwrap();
        // mid-path symlink: sub/link -> outside, resolve "sub/link/secret.txt"
        fs::create_dir(root.join("sub")).unwrap();
        std::os::unix::fs::symlink(outside.path(), root.join("sub/link")).unwrap();
        assert!(resolve(root, "sub/link/secret.txt").is_err());
        // even deeper nonexistent tail
        assert!(resolve(root, "sub/link/a/b/c").is_err());
        // file itself is a symlink
        std::os::unix::fs::symlink(outside.path().join("secret.txt"), root.join("leak.txt"))
            .unwrap();
        assert!(resolve(root, "leak.txt").is_err());
    }

    #[test]
    fn dot_segments_inside_stay_inside() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir(root.join("a")).unwrap();
        fs::write(root.join("a/f"), "x").unwrap();
        // "a/./f" is fine — CurDir components are dropped
        assert!(resolve(root, "a/./f").unwrap().ends_with("a/f"));
        // "a/../a/f" — ParentDir rejected even though it resolves inside
        assert!(resolve(root, "a/../a/f").is_err());
    }

    #[test]
    fn empty_and_dot_resolve_to_root_not_escape() {
        let dir = tempfile::tempdir().unwrap();
        let r = resolve(dir.path(), "").unwrap();
        assert_eq!(r, dir.path().canonicalize().unwrap());
        let r = resolve(dir.path(), ".").unwrap();
        assert_eq!(r, dir.path().canonicalize().unwrap());
    }
}
