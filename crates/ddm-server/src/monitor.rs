use crate::config::SharedConfig;
use crate::config::{
    AppConfig, AutoAction, HealthCheckConfig, HealthCheckKind, LogAlertConfig, MonitorDefaults,
};
use crate::docker::{ContainerInfo, DockerApi};
use crate::hostexec::HostExec;
use crate::permissions::matcher_matches;
use crate::protocol::{AlertEvent, EventMessage};
use crate::services::discover_services;
use anyhow::{Context, Result};
use futures::StreamExt;
use regex::Regex;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, Mutex};
use tokio::task::JoinHandle;
use tracing::{error, warn};
use uuid::Uuid;

/// Which compose services/containers a log alert applies to ("*" = all).
#[derive(Debug, Clone)]
struct EffectiveLogAlert {
    id: String,
    regex: Regex,
    exclude: Option<Regex>,
    container: String,
    notify: Vec<String>,
    cooldown_secs: u64,
    #[allow(dead_code)]
    max_per_cooldown: u32,
    context_lines: usize,
    actions: Vec<AutoAction>,
}

#[derive(Debug, Clone)]
struct EffectiveHealth {
    kind: HealthCheckKind,
    target: Option<String>,
    port: Option<u16>,
    expect_status: Option<u16>,
    timeout_secs: u64,
    interval_secs: u64,
    failure_threshold: u32,
    recovery_threshold: u32,
    notify: Vec<String>,
    actions: Vec<AutoAction>,
}

/// Monitor state for persistence + API reporting.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CheckStatus {
    pub id: String,
    pub kind: String,
    pub state: String, // ok | failing | down | recovered | suppressed
    pub failures: u32,
    pub last_ok: Option<chrono::DateTime<chrono::Utc>>,
    pub last_match: Option<String>,
    pub suppressed: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct ServiceMonitorState {
    pub checks: Vec<CheckStatus>,
}

/// The monitor supervisor. Reconciles desired checks vs running tasks.
pub struct Monitor {
    cfg: Arc<SharedConfig>,
    docker: Arc<dyn DockerApi>,
    host: Arc<dyn HostExec>,
    core: Arc<crate::agent::AgentCore>,
    events: broadcast::Sender<EventMessage>,
    states: Mutex<HashMap<String, ServiceMonitorState>>,
    tasks: Mutex<HashMap<String, Vec<JoinHandle<()>>>>,
    history: Mutex<VecDeque<AlertEvent>>,
    /// action attempt timestamps: key → instants within window
    action_attempts: Mutex<HashMap<String, VecDeque<Instant>>>,
    /// last notification instant per alert key
    notify_cooldown: Mutex<HashMap<String, Instant>>,
    /// seen line hashes for dedup
    dedup: Mutex<HashSet<u64>>,
}

impl Monitor {
    pub fn new(
        cfg: Arc<SharedConfig>,
        docker: Arc<dyn DockerApi>,
        host: Arc<dyn HostExec>,
        events: broadcast::Sender<EventMessage>,
        core: Arc<crate::agent::AgentCore>,
    ) -> Arc<Self> {
        Arc::new(Self {
            cfg,
            docker,
            host,
            core,
            events,
            states: Mutex::new(HashMap::new()),
            tasks: Mutex::new(HashMap::new()),
            history: Mutex::new(VecDeque::with_capacity(512)),
            action_attempts: Mutex::new(HashMap::new()),
            notify_cooldown: Mutex::new(HashMap::new()),
            dedup: Mutex::new(HashSet::new()),
        })
    }

    /// Supervisor loop: reconcile desired checks vs running tasks every 20s.
    pub async fn run(self: &Arc<Self>) {
        let mut rx = self.cfg.changes.subscribe();
        loop {
            if let Err(e) = self.reconcile().await {
                error!("monitor reconcile failed: {e:#}");
            }
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(20)) => {}
                _ = rx.recv() => {}
            }
        }
    }

    /// Effective per-service monitoring config = meta.yaml merged with
    /// global rules (services matcher) + defaults.
    async fn desired(
        &self,
    ) -> Result<HashMap<String, (Option<EffectiveHealth>, Vec<EffectiveLogAlert>)>> {
        let cfg = self.cfg.get().await;
        if !cfg.monitoring.enabled {
            return Ok(HashMap::new());
        }
        let mut out: HashMap<String, (Option<EffectiveHealth>, Vec<EffectiveLogAlert>)> =
            HashMap::new();
        for svc in discover_services(&cfg) {
            let mut health = None;
            let mut alerts = vec![];
            if let Some(m) = &svc.meta.monitoring {
                if let Some(h) = &m.health {
                    health = effective_health(h, &cfg.monitoring.defaults, &cfg.monitoring);
                }
                for a in &m.log_alerts {
                    alerts.push(effective_alert(a, &cfg.monitoring.defaults));
                }
            }
            // global rules
            for rule in &cfg.monitoring.rules {
                if matcher_matches(&rule.services, &svc.name) {
                    for a in &rule.log_alerts {
                        alerts.push(effective_alert(a, &cfg.monitoring.defaults));
                    }
                }
            }
            let alerts: Vec<_> = alerts.into_iter().flatten().collect();
            if health.is_some() || !alerts.is_empty() {
                out.insert(svc.name.clone(), (health, alerts));
            }
        }
        Ok(out)
    }

    async fn reconcile(self: &Arc<Self>) -> Result<()> {
        let desired = self.desired().await?;
        let mut tasks = self.tasks.lock().await;
        // stop tasks for services no longer monitored
        let keys: Vec<String> = tasks.keys().cloned().collect();
        for k in keys {
            if !desired.contains_key(&k) {
                if let Some(ts) = tasks.remove(&k) {
                    for t in ts {
                        t.abort();
                    }
                }
            }
        }
        // (re)start tasks for services without a running set. Watchers are
        // restarted on each config broadcast because run() calls reconcile.
        for (name, (health, alerts)) in desired {
            let entry = tasks.entry(name.clone()).or_default();
            if entry.is_empty() {
                self.spawn_service(&name, health, alerts, entry);
            }
        }
        Ok(())
    }

    fn spawn_service(
        self: &Arc<Self>,
        name: &str,
        health: Option<EffectiveHealth>,
        alerts: Vec<EffectiveLogAlert>,
        entry: &mut Vec<JoinHandle<()>>,
    ) {
        if let Some(h) = health {
            let this = Arc::clone(self);
            let svc = name.to_string();
            entry.push(tokio::spawn(async move {
                this.health_loop(svc, h).await;
            }));
        }
        if !alerts.is_empty() {
            let this = Arc::clone(self);
            let svc = name.to_string();
            entry.push(tokio::spawn(async move {
                this.log_watch_loop(svc, alerts).await;
            }));
        }
    }

    // ------------------------------------------------------------------
    // Health checks
    // ------------------------------------------------------------------

    async fn health_loop(self: &Arc<Self>, service: String, check: EffectiveHealth) {
        let interval = Duration::from_secs(check.interval_secs.max(5));
        let mut failures = 0u32;
        let mut successes = 0u32;
        let mut state = "ok".to_string();
        loop {
            let ok = self.run_health(&service, &check).await;
            match ok {
                Ok(true) => {
                    successes += 1;
                    if state != "ok" && successes >= check.recovery_threshold {
                        state = "ok".into();
                        failures = 0;
                        self.emit(
                            &service,
                            "health",
                            &format!("{:?}", check.kind),
                            "resolved",
                            "check recovered".into(),
                            None,
                            &check.notify,
                        )
                        .await;
                    }
                    self.update(
                        &service,
                        &format!("{:?}", check.kind),
                        "health",
                        &state,
                        failures,
                        None,
                    )
                    .await;
                }
                Ok(false) | Err(_) => {
                    successes = 0;
                    failures += 1;
                    let new_state = if failures >= check.failure_threshold {
                        "down"
                    } else {
                        "failing"
                    };
                    if new_state != state {
                        state = new_state.into();
                        if state == "down" {
                            self.emit(
                                &service,
                                "health",
                                &format!("{:?}", check.kind),
                                "firing",
                                format!("health check failed {} times", failures),
                                None,
                                &check.notify,
                            )
                            .await;
                            self.run_actions(&service, &check.actions, failures).await;
                        }
                    }
                    self.update(
                        &service,
                        &format!("{:?}", check.kind),
                        "health",
                        &state,
                        failures,
                        None,
                    )
                    .await;
                }
            }
            tokio::time::sleep(interval).await;
        }
    }

    async fn run_health(&self, service: &str, check: &EffectiveHealth) -> Result<bool> {
        let containers = self.docker.project_containers(service).await?;
        match check.kind {
            HealthCheckKind::ContainerRunning => {
                Ok(!containers.is_empty() && containers.iter().all(|c| c.state == "running"))
            }
            HealthCheckKind::DockerHealthcheck => {
                if containers.is_empty() {
                    return Ok(false);
                }
                for c in &containers {
                    if c.state != "running" {
                        return Ok(false);
                    }
                    if let Some(h) = &c.health {
                        if h == "unhealthy" {
                            return Ok(false);
                        }
                        // "starting"/None treated as ok-ish until unhealthy
                    }
                }
                Ok(true)
            }
            HealthCheckKind::Tcp => {
                let host = check.target.clone().unwrap_or_else(|| "127.0.0.1".into());
                let port = check.port.context("tcp check needs port")?;
                let addr = format!("{host}:{port}");
                let timeout = Duration::from_secs(check.timeout_secs);
                match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await {
                    Ok(Ok(_)) => Ok(true),
                    _ => Ok(false),
                }
            }
            HealthCheckKind::Http => {
                let url = check.target.clone().context("http check needs url")?;
                let expect = check.expect_status.unwrap_or(200);
                let timeout = Duration::from_secs(check.timeout_secs);
                let client = reqwest::Client::builder().timeout(timeout).build()?;
                match client.get(&url).send().await {
                    Ok(r) => Ok(r.status().as_u16() == expect),
                    Err(_) => Ok(false),
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Log watchers
    // ------------------------------------------------------------------

    async fn log_watch_loop(self: &Arc<Self>, service: String, alerts: Vec<EffectiveLogAlert>) {
        loop {
            if let Err(e) = self.watch_logs_once(&service, &alerts).await {
                warn!("log watch for {service} failed: {e:#}; retrying in 10s");
            }
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    }

    async fn watch_logs_once(&self, service: &str, alerts: &[EffectiveLogAlert]) -> Result<()> {
        let containers = self.docker.project_containers(service).await?;
        if containers.is_empty() {
            return Ok(());
        }
        let mut streams = Vec::new();
        for c in &containers {
            if c.state != "running" {
                continue;
            }
            match self.docker.logs(&c.id, 0, None, true).await {
                Ok(s) => streams.push((c.clone(), s)),
                Err(e) => warn!("cannot attach logs for {}: {e}", c.name),
            }
        }
        if streams.is_empty() {
            return Ok(());
        }
        // Merge container log streams into one task-local loop.
        let (tx, mut rx) =
            tokio::sync::mpsc::channel::<(ContainerInfo, crate::docker::LogLine)>(512);
        for (c, mut s) in streams {
            let txc = tx.clone();
            tokio::spawn(async move {
                while let Some(line) = s.next().await {
                    if let Ok(l) = line {
                        if txc.send((c.clone(), l)).await.is_err() {
                            break;
                        }
                    }
                }
            });
        }
        drop(tx);
        let mut context_buffers: HashMap<String, VecDeque<String>> = HashMap::new();
        while let Some((c, line)) = rx.recv().await {
            for a in alerts {
                if a.container != "*" && a.container != c.service {
                    continue;
                }
                let text = line.text.trim_end();
                // maintain context buffer per alert
                let buf = context_buffers.entry(a.id.clone()).or_default();
                let matches = a.regex.is_match(text)
                    && !a
                        .exclude
                        .as_ref()
                        .map(|x| x.is_match(text))
                        .unwrap_or(false);
                if matches {
                    // dedup by hash of service+rule+line
                    let h = fxhash(&format!("{}|{}|{}", service, a.id, text));
                    if !self.mark_seen(h).await {
                        let excerpt = {
                            let mut v: Vec<String> = buf.iter().cloned().collect();
                            v.push(text.to_string());
                            v.join("\n")
                        };
                        self.handle_log_match(service, a, text, excerpt).await;
                    }
                } else {
                    buf.push_back(text.to_string());
                    while buf.len() > a.context_lines {
                        buf.pop_front();
                    }
                }
            }
        }
        Ok(())
    }

    async fn mark_seen(&self, h: u64) -> bool {
        let mut d = self.dedup.lock().await;
        if d.len() > 100_000 {
            d.clear();
        }
        !d.insert(h)
    }

    async fn handle_log_match(
        &self,
        service: &str,
        a: &EffectiveLogAlert,
        line: &str,
        excerpt: String,
    ) {
        // notify cooldown + rate limit
        let key = format!("{service}:{}", a.id);
        {
            let mut cd = self.notify_cooldown.lock().await;
            let now = Instant::now();
            if let Some(last) = cd.get(&key) {
                if now.duration_since(*last) < Duration::from_secs(a.cooldown_secs) {
                    self.update(service, &a.id, "log", "firing", 0, Some(line.to_string()))
                        .await;
                    return;
                }
            }
            cd.insert(key, now);
        }
        self.emit(
            service,
            "log",
            &a.id,
            "firing",
            format!("log pattern '{}' matched", a.id),
            Some(excerpt),
            &a.notify,
        )
        .await;
        self.update(service, &a.id, "log", "firing", 0, Some(line.to_string()))
            .await;
        self.run_actions(service, &a.actions, 0).await;
    }

    // ------------------------------------------------------------------
    // Actions
    // ------------------------------------------------------------------

    async fn run_actions(&self, service: &str, actions: &[AutoAction], failures: u32) {
        let cfg = self.cfg.get().await;
        if !cfg.monitoring.allow_auto_actions {
            return;
        }
        for act in actions {
            let (name, cooldown, max_attempts, window) = match act {
                AutoAction::Restart {
                    cooldown_secs,
                    max_attempts,
                    window_secs,
                    ..
                } => (
                    "restart".to_string(),
                    cooldown_secs.unwrap_or(300),
                    max_attempts.unwrap_or(3),
                    window_secs.unwrap_or(900),
                ),
                AutoAction::Stop { cooldown_secs } => {
                    ("stop".to_string(), cooldown_secs.unwrap_or(600), 1, 3600)
                }
                AutoAction::ExecCommand { cooldown_secs, .. } => (
                    "exec_command".to_string(),
                    cooldown_secs.unwrap_or(600),
                    3,
                    3600,
                ),
            };
            let key = format!("{service}:{name}");
            let (allowed, exhausted) = {
                let mut m = self.action_attempts.lock().await;
                let now = Instant::now();
                let e = m.entry(key.clone()).or_default();
                while e
                    .front()
                    .map(|t| now.duration_since(*t) > Duration::from_secs(window))
                    .unwrap_or(false)
                {
                    e.pop_front();
                }
                let within_cooldown = e
                    .back()
                    .map(|t| now.duration_since(*t) < Duration::from_secs(cooldown))
                    .unwrap_or(false);
                if within_cooldown || e.len() >= max_attempts as usize {
                    (false, e.len() >= max_attempts as usize && !within_cooldown)
                } else {
                    e.push_back(now);
                    (true, false)
                }
            };
            if exhausted {
                self.emit(
                    service,
                    "action",
                    &name,
                    "firing",
                    format!(
                        "auto-action '{name}' exhausted ({max_attempts}/{window}s); suppressed"
                    ),
                    None,
                    &[],
                )
                .await;
            }
            if !allowed {
                continue;
            }
            let result = self.execute_action(service, act, &cfg, failures).await;
            let _ = self.events.send(EventMessage::AutoAction {
                service: service.to_string(),
                action: name.clone(),
                result: result.clone(),
            });
            self.core.justify_internal(
                "system",
                &format!("auto_{name}"),
                &format!("{service}: {result}"),
            );
        }
    }

    async fn execute_action(
        &self,
        service: &str,
        act: &AutoAction,
        cfg: &AppConfig,
        _failures: u32,
    ) -> String {
        match act {
            AutoAction::Restart { .. } => {
                // prefer the managed systemd unit if present, else compose restart
                let unit = format!("{service}.service");
                let unit_path = crate::systemd::unit_path(cfg, service);
                if unit_path.exists() {
                    match self.host.run("systemctl", &["restart".into(), unit]).await {
                        Ok(o) if o.success() => "systemctl restart ok".into(),
                        Ok(o) => format!("systemctl restart failed: {}", o.stderr),
                        Err(e) => format!("restart failed: {e:#}"),
                    }
                } else {
                    compose_action(cfg, service, "restart").await
                }
            }
            AutoAction::Stop { .. } => compose_action(cfg, service, "stop").await,
            AutoAction::ExecCommand {
                section_index,
                item_index,
                ..
            } => {
                let item = cfg
                    .sections
                    .get(*section_index)
                    .and_then(|s| s.items.get(*item_index))
                    .cloned();
                match item {
                    Some(item) => {
                        let id = self.core.exec_internal(
                            item,
                            HashMap::new(),
                            Some(service.to_string()),
                            "monitor",
                        );
                        format!("triggered execution {id}")
                    }
                    None => "invalid command index".into(),
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // State / events
    // ------------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    async fn emit(
        &self,
        service: &str,
        kind: &str,
        rule: &str,
        state: &str,
        message: String,
        detail: Option<String>,
        notify_ids: &[String],
    ) {
        let ev = AlertEvent {
            id: Uuid::new_v4().to_string(),
            service: service.to_string(),
            kind: kind.to_string(),
            rule: rule.to_string(),
            state: state.to_string(),
            message,
            detail,
            at: chrono::Utc::now(),
        };
        // notifications (best-effort): only the rule's notifier ids
        let cfg = self.cfg.get().await;
        let notif = crate::notify::Notification::from_event(&ev);
        for n in cfg.monitoring.notifiers.iter() {
            if !notify_ids.is_empty() && !notify_ids.iter().any(|i| i == n.id()) {
                continue;
            }
            let n2 = n.clone();
            let n3 = notif.clone();
            tokio::spawn(async move {
                let _ = crate::notify::send(&n2, &n3).await;
            });
        }
        {
            let mut h = self.history.lock().await;
            if h.len() >= 512 {
                h.pop_front();
            }
            h.push_back(ev.clone());
        }
        let msg = if state == "resolved" {
            EventMessage::AlertResolved { event: ev }
        } else {
            EventMessage::AlertFired { event: ev }
        };
        let _ = self.events.send(msg);
    }

    async fn update(
        &self,
        service: &str,
        id: &str,
        kind: &str,
        state: &str,
        failures: u32,
        last_match: Option<String>,
    ) {
        let mut states = self.states.lock().await;
        let entry = states.entry(service.to_string()).or_default();
        let status = entry
            .checks
            .iter_mut()
            .find(|c| c.id == id && c.kind == kind);
        let status = match status {
            Some(s) => s,
            None => {
                entry.checks.push(CheckStatus {
                    id: id.to_string(),
                    kind: kind.to_string(),
                    state: "ok".into(),
                    failures: 0,
                    last_ok: None,
                    last_match: None,
                    suppressed: false,
                });
                entry.checks.last_mut().unwrap()
            }
        };
        status.state = state.to_string();
        status.failures = failures;
        if state == "ok" {
            status.last_ok = Some(chrono::Utc::now());
        }
        if let Some(m) = last_match {
            status.last_match = Some(m);
        }
        let _ = self.events.send(EventMessage::MonitorState {
            service: service.to_string(),
            check: id.to_string(),
            state: state.to_string(),
        });
    }

    /// Public API snapshot.
    pub async fn status(&self) -> HashMap<String, ServiceMonitorState> {
        self.states.lock().await.clone()
    }

    pub async fn events(&self) -> Vec<AlertEvent> {
        self.history.lock().await.iter().cloned().collect()
    }

    /// Subscribe to the live monitoring event stream (WS /ws/events).
    pub fn subscribe_events(&self) -> broadcast::Receiver<EventMessage> {
        self.events.subscribe()
    }
}

fn effective_health(
    h: &HealthCheckConfig,
    defaults: &MonitorDefaults,
    mon: &crate::config::MonitoringConfig,
) -> Option<EffectiveHealth> {
    if !h.enabled {
        return None;
    }
    Some(EffectiveHealth {
        kind: h.kind,
        target: h.target.clone(),
        port: h.port,
        expect_status: h.expect_status,
        timeout_secs: h.timeout_secs.unwrap_or(5),
        interval_secs: h.interval_secs.unwrap_or(mon.check_interval_secs),
        failure_threshold: h.failure_threshold.unwrap_or(defaults.failure_threshold),
        recovery_threshold: h.recovery_threshold.unwrap_or(2),
        notify: if h.notify.is_empty() {
            defaults.notify.clone()
        } else {
            h.notify.clone()
        },
        actions: h.actions.clone(),
    })
}

fn effective_alert(a: &LogAlertConfig, defaults: &MonitorDefaults) -> Option<EffectiveLogAlert> {
    Some(EffectiveLogAlert {
        id: a.id.clone(),
        regex: Regex::new(&a.regex).ok()?,
        exclude: a.exclude_regex.as_deref().and_then(|r| Regex::new(r).ok()),
        container: a.container.clone(),
        notify: if a.notify.is_empty() {
            defaults.notify.clone()
        } else {
            a.notify.clone()
        },
        cooldown_secs: a.cooldown_secs.unwrap_or(defaults.cooldown_secs),
        max_per_cooldown: a.max_per_cooldown.unwrap_or(5),
        context_lines: a.context_lines.unwrap_or(3),
        actions: a.actions.clone(),
    })
}

fn fxhash(s: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

/// Run a compose action (restart/stop) in-container against a service dir.
async fn compose_action(cfg: &AppConfig, service: &str, action: &str) -> String {
    use crate::docker::compose_argv;
    let (prog, mut args) = compose_argv(&cfg.docker.compose_command, &[]);
    args.push("-f".into());
    let dir = std::path::Path::new(&cfg.paths.services_root).join(service);
    let compose = crate::services::find_compose_file(&dir, &cfg.paths.compose_file)
        .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
        .unwrap_or_else(|| "docker-compose.yml".into());
    args.push(compose);
    args.push(action.to_string());
    match tokio::process::Command::new(&prog)
        .args(&args)
        .current_dir(&dir)
        .output()
        .await
    {
        Ok(o) if o.status.success() => format!("compose {action} ok"),
        Ok(o) => format!(
            "compose {action} failed: {}",
            String::from_utf8_lossy(&o.stderr)
        ),
        Err(e) => format!("compose {action} spawn failed: {e}"),
    }
}
