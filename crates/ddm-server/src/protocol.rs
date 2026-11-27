use serde::{Deserialize, Serialize};

/// Wire messages broadcast to websocket subscribers of an execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum ServerMessage {
    ExecutionStarted {
        id: String,
        title: String,
    },
    LogOutput {
        id: String,
        text: String,
        stream: String,
    },
    ExecutionFinished {
        id: String,
        success: bool,
    },
}

/// Human-readable summary of what an execution ran — operation kind, a
/// one-line detail (command line, container, snapshot, …) and the target
/// container when set. Recorded at adoption time from the exec verb.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExecMeta {
    pub kind: Option<String>,
    pub detail: Option<String>,
    pub container: Option<String>,
}

/// Snapshot of a finished (or running) execution for the history API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionInfo {
    pub id: String,
    pub title: String,
    pub service: Option<String>,
    pub user: String,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub finished_at: Option<chrono::DateTime<chrono::Utc>>,
    pub success: Option<bool>,
    /// Absent in records written before execution details were tracked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<ExecMeta>,
}

/// Push events for the global WS /ws/events channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum EventMessage {
    MonitorState {
        service: String,
        check: String,
        state: String,
    },
    AlertFired {
        event: AlertEvent,
    },
    AlertResolved {
        event: AlertEvent,
    },
    AutoAction {
        service: String,
        action: String,
        result: String,
    },
    ConfigReloaded {
        ok: bool,
        error: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertEvent {
    pub id: String,
    pub service: String,
    pub kind: String, // "health" | "log"
    pub rule: String,
    pub state: String, // firing | resolved
    pub message: String,
    pub detail: Option<String>,
    pub at: chrono::DateTime<chrono::Utc>,
}
