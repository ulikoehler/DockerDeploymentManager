use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub at: chrono::DateTime<chrono::Utc>,
    pub user: String,
    pub action: String,
    pub target: String,
    pub detail: String,
}

/// In-memory audit ring buffer (bounded), optionally backed by a JSONL
/// file so the trail survives restarts. The file is append-only; on
/// startup the last `cap` lines are loaded back.
pub struct AuditLog {
    inner: Mutex<VecDeque<AuditEntry>>,
    cap: usize,
    path: Option<PathBuf>,
}

impl AuditLog {
    pub fn new(cap: usize) -> Self {
        Self {
            inner: Mutex::new(VecDeque::new()),
            cap,
            path: None,
        }
    }

    /// Enable JSONL persistence at `path` and reload prior entries.
    /// Failures to read are non-fatal — auditing must never break the
    /// server; a missing/unreadable file just starts empty.
    pub fn with_file(mut self, path: PathBuf) -> Self {
        if let Ok(text) = std::fs::read_to_string(&path) {
            let mut entries: Vec<AuditEntry> = text
                .lines()
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect();
            if entries.len() > self.cap {
                entries.drain(..entries.len() - self.cap);
            }
            *self.inner.lock().unwrap() = entries.into_iter().collect();
        }
        self.path = Some(path);
        self
    }

    pub fn record(&self, user: &str, action: &str, target: &str, detail: impl Into<String>) {
        let entry = AuditEntry {
            at: chrono::Utc::now(),
            user: user.to_string(),
            action: action.to_string(),
            target: target.to_string(),
            detail: detail.into(),
        };
        tracing::info!(user, action, target, "audit");
        let mut g = self.inner.lock().unwrap();
        if g.len() >= self.cap {
            g.pop_front();
        }
        g.push_back(entry.clone());
        drop(g);
        self.persist(&entry);
    }

    fn persist(&self, entry: &AuditEntry) {
        let Some(path) = &self.path else { return };
        let Ok(mut line) = serde_json::to_string(entry) else {
            return;
        };
        line.push('\n');
        // Best-effort append — create parent dirs once; ignore errors.
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let _ = f.write_all(line.as_bytes());
        }
        // Bound the file: once it grows past ~4× the ring cap worth of
        // entries, rewrite it keeping only the newest `cap` lines.
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.len() > 4 * self.cap as u64 * 256 {
                self.trim_file(path);
            }
        }
    }

    fn trim_file(&self, path: &PathBuf) {
        let Ok(text) = std::fs::read_to_string(path) else {
            return;
        };
        let keep: Vec<&str> = text.lines().rev().take(self.cap).collect();
        let mut out = keep.into_iter().rev().collect::<Vec<_>>().join("\n");
        out.push('\n');
        let _ = std::fs::write(path, out);
    }

    pub fn entries(&self) -> Vec<AuditEntry> {
        self.inner.lock().unwrap().iter().cloned().collect()
    }
}
