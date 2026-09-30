use serde::Serialize;
use std::collections::VecDeque;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    pub at: chrono::DateTime<chrono::Utc>,
    pub user: String,
    pub action: String,
    pub target: String,
    pub detail: String,
}

/// In-memory audit ring buffer (bounded).
pub struct AuditLog {
    inner: Mutex<VecDeque<AuditEntry>>,
    cap: usize,
}

impl AuditLog {
    pub fn new(cap: usize) -> Self {
        Self {
            inner: Mutex::new(VecDeque::new()),
            cap,
        }
    }

    pub fn record(&self, user: &str, action: &str, target: &str, detail: impl Into<String>) {
        let mut g = self.inner.lock().unwrap();
        if g.len() >= self.cap {
            g.pop_front();
        }
        let entry = AuditEntry {
            at: chrono::Utc::now(),
            user: user.to_string(),
            action: action.to_string(),
            target: target.to_string(),
            detail: detail.into(),
        };
        tracing::info!(user, action, target, "audit");
        g.push_back(entry);
    }

    pub fn entries(&self) -> Vec<AuditEntry> {
        self.inner.lock().unwrap().iter().cloned().collect()
    }
}
