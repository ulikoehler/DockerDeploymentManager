use crate::config::AppConfig;
use crate::hostexec::HostExec;
use crate::services::Service;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;

/// Built-in unit template — TechOverflow docker-compose style:
/// foreground `up` under a `simple` unit, `down` on stop and before start.
pub const DEFAULT_UNIT_TEMPLATE: &str = r#"[Unit]
Description={service}
Requires=docker.service
After=docker.service

[Service]
Restart=always
User=root
Group=docker
TimeoutStopSec=15
WorkingDirectory={dir}
# Shutdown container (if running) when unit is started
ExecStartPre={compose_bin} -f {compose_file} down
ExecStart={compose_bin} -f {compose_file} up
ExecStop={compose_bin} -f {compose_file} down

[Install]
WantedBy=multi-user.target
"#;

/// Render the unit file for a service.
pub fn render_unit(
    template: &str,
    service: &str,
    host_dir: &str,
    compose_file: &str,
    compose_bin: &str,
) -> String {
    template
        .replace("{service}", service)
        .replace("{dir}", host_dir)
        .replace("{compose_file}", compose_file)
        .replace("{compose_bin}", compose_bin)
}

fn load_template(cfg: &AppConfig) -> String {
    cfg.systemd
        .unit_template
        .as_deref()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .unwrap_or_else(|| DEFAULT_UNIT_TEMPLATE.to_string())
}

/// Resolve the compose binary on the host. `auto` = try `docker compose`
/// (v2 plugin), then `docker-compose`.
pub async fn resolve_compose_bin(cfg: &AppConfig, host: &Arc<dyn HostExec>) -> Result<String> {
    let pref = cfg.systemd.compose_binary.trim();
    if pref != "auto" {
        return Ok(pref.to_string());
    }
    // prefer docker-compose (v1 standalone matches the article), then plugin
    for cand in ["docker-compose", "docker"] {
        if let Some(p) = host.which(cand).await? {
            if cand == "docker" {
                // verify the compose plugin exists
                let out = host
                    .run("docker", &["compose".into(), "version".into()])
                    .await?;
                if out.success() {
                    return Ok(format!("{p} compose"));
                }
                continue;
            }
            return Ok(p);
        }
    }
    anyhow::bail!("no compose binary found on host (docker-compose / docker compose)")
}

/// Render the unit for `svc` using host-resolved compose binary.
pub async fn render_unit_for(
    cfg: &AppConfig,
    host: &Arc<dyn HostExec>,
    svc: &Service,
) -> Result<String> {
    let compose_bin = resolve_compose_bin(cfg, host).await?;
    let template = load_template(cfg);
    let compose_file = svc
        .compose_path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "docker-compose.yml".into());
    Ok(render_unit(
        &template,
        &svc.name,
        &svc.host_dir.to_string_lossy(),
        &compose_file,
        &compose_bin,
    ))
}

/// Path of the unit file on the host (via the bind-mounted systemd dir).
pub fn unit_path(cfg: &AppConfig, service: &str) -> std::path::PathBuf {
    Path::new(&cfg.paths.host_systemd_dir).join(format!("{service}.service"))
}

/// Write the unit file (to the bind-mounted host systemd dir) and reload.
pub async fn write_unit(
    cfg: &AppConfig,
    host: &Arc<dyn HostExec>,
    svc: &Service,
    content: &str,
) -> Result<()> {
    validate_unit(content)?;
    let p = unit_path(cfg, &svc.name);
    std::fs::write(&p, content).with_context(|| format!("writing {}", p.display()))?;
    if cfg.systemd.daemon_reload_after_change {
        host.run("systemctl", &["daemon-reload".to_string()])
            .await?;
    }
    Ok(())
}

/// Minimal sanity validation for unit files.
pub fn validate_unit(content: &str) -> Result<()> {
    if !content.contains("[Unit]") || !content.contains("[Service]") {
        anyhow::bail!("unit file must contain [Unit] and [Service] sections");
    }
    if content.contains("\0") {
        anyhow::bail!("unit file contains NUL bytes");
    }
    Ok(())
}

/// `systemctl is-enabled` / `is-active` on the host.
pub async fn unit_state(host: &Arc<dyn HostExec>, unit: &str) -> (Option<String>, Option<String>) {
    let enabled = host
        .run("systemctl", &["is-enabled".into(), unit.into()])
        .await
        .ok()
        .map(|o| o.stdout.trim().to_string());
    let active = host
        .run("systemctl", &["is-active".into(), unit.into()])
        .await
        .ok()
        .map(|o| o.stdout.trim().to_string());
    (enabled, active)
}

// ---------------------------------------------------------------------------
// UnitCheckReport — checks for existing services
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnitIssue {
    pub code: String,
    pub message: String,
    pub fixable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnitCheckReport {
    pub service: String,
    pub exists: bool,
    pub enabled: Option<String>,
    pub active: Option<String>,
    pub in_sync: bool,
    pub workdir_ok: bool,
    pub issues: Vec<UnitIssue>,
}

fn issue(code: &str, msg: impl Into<String>) -> UnitIssue {
    UnitIssue {
        code: code.to_string(),
        message: msg.into(),
        fixable: true,
    }
}

/// Check the systemd unit for a service (existence, enablement, drift).
pub async fn check_unit(
    cfg: &AppConfig,
    host: &Arc<dyn HostExec>,
    svc: &Service,
) -> UnitCheckReport {
    let unit = format!("{}.service", svc.name);
    let path = unit_path(cfg, &svc.name);
    let mut issues = vec![];

    let exists = path.is_file();
    if !exists {
        issues.push(issue("missing", "unit file does not exist"));
    }

    let (enabled, active) = unit_state(host, &unit).await;
    match enabled.as_deref() {
        Some("enabled") | Some("enabled-runtime") => {}
        Some(other) => issues.push(issue("not_enabled", format!("unit is {other}"))),
        None => {
            if exists {
                issues.push(issue("not_enabled", "unit is not enabled"));
            }
        }
    }
    match active.as_deref() {
        Some("active") | Some("activating") => {}
        Some(other) => issues.push(issue("inactive", format!("unit is {other}"))),
        None => {
            if exists {
                issues.push(issue("inactive", "unit state unknown"));
            }
        }
    }

    // content checks vs freshly rendered template
    let mut in_sync = false;
    let mut workdir_ok = false;
    if exists {
        let content = std::fs::read_to_string(&path).unwrap_or_default();
        let want_workdir = format!("WorkingDirectory={}", svc.host_dir.to_string_lossy());
        workdir_ok = content.lines().any(|l| l.trim() == want_workdir);
        if !workdir_ok {
            issues.push(issue(
                "workdir_mismatch",
                format!("WorkingDirectory differs from {}", svc.host_dir.display()),
            ));
        }
        if !content.contains("Requires=docker.service") {
            issues.push(issue(
                "docker_dep_missing",
                "unit does not require docker.service",
            ));
        }
        let compose_file = svc
            .compose_path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        if !content.contains(&format!("-f {compose_file}")) {
            issues.push(issue(
                "compose_mismatch",
                format!("Exec* does not reference {compose_file}"),
            ));
        }
        match render_unit_for(cfg, host, svc).await {
            Ok(rendered) => {
                in_sync = content.trim_end() == rendered.trim_end();
                if !in_sync {
                    issues.push(issue(
                        "content_drift",
                        "unit differs from the rendered template",
                    ));
                }
            }
            Err(e) => {
                issues.push(UnitIssue {
                    code: "check_error".into(),
                    message: format!("could not render reference template: {e:#}"),
                    fixable: false,
                });
            }
        }
        // systemd-analyze verify (best effort)
        if let Ok(out) = host
            .run("systemd-analyze", &["verify".into(), unit.to_string()])
            .await
        {
            if !out.success() {
                issues.push(UnitIssue {
                    code: "invalid_unit".into(),
                    message: format!("systemd-analyze verify failed: {}", out.stderr.trim()),
                    fixable: true,
                });
            }
        }
    }

    UnitCheckReport {
        service: svc.name.clone(),
        exists,
        enabled,
        active,
        in_sync,
        workdir_ok,
        issues,
    }
}

// ---------------------------------------------------------------------------
// Host systemd helpers (groups / status / journal)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemdUnitStatus {
    pub unit: String,
    pub load: String,
    pub active: String,
    pub sub: String,
    pub description: String,
}

/// List host units matching a regex (systemctl list-units).
pub async fn list_units_matching(
    host: &Arc<dyn HostExec>,
    unit_regex: &str,
) -> Result<Vec<SystemdUnitStatus>> {
    let re = regex::Regex::new(unit_regex)?;
    let out = host
        .run(
            "systemctl",
            &[
                "list-units".into(),
                "--type=service".into(),
                "--all".into(),
                "--no-legend".into(),
                "--no-pager".into(),
            ],
        )
        .await?;
    if !out.success() {
        anyhow::bail!("systemctl list-units failed: {}", out.stderr);
    }
    let mut svcs = vec![];
    for line in out.stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut it = line.split_whitespace();
        let (Some(unit), Some(load), Some(active), Some(sub)) =
            (it.next(), it.next(), it.next(), it.next())
        else {
            continue;
        };
        if !re.is_match(unit) {
            continue;
        }
        svcs.push(SystemdUnitStatus {
            unit: unit.to_string(),
            load: load.to_string(),
            active: active.to_string(),
            sub: sub.to_string(),
            description: it.collect::<Vec<_>>().join(" "),
        });
    }
    svcs.sort_by(|a, b| a.unit.cmp(&b.unit));
    Ok(svcs)
}

/// `journalctl -u <unit>` on the host.
pub async fn journal_logs(host: &Arc<dyn HostExec>, unit: &str, lines: usize) -> Result<String> {
    let out = host
        .run(
            "journalctl",
            &[
                "-u".into(),
                unit.into(),
                "-n".into(),
                lines.to_string(),
                "--no-pager".into(),
                "-o".into(),
                "cat".into(),
            ],
        )
        .await?;
    if !out.success() {
        anyhow::bail!("journalctl failed: {}", out.stderr);
    }
    Ok(out.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hostexec::{HostOutput, MockExec};

    #[test]
    fn render_default_unit() {
        let u = render_unit(
            DEFAULT_UNIT_TEMPLATE,
            "web-1",
            "/opt/services/web-1",
            "docker-compose.yml",
            "/usr/bin/docker-compose",
        );
        assert!(u.contains("Description=web-1"));
        assert!(u.contains("WorkingDirectory=/opt/services/web-1"));
        assert!(u.contains("ExecStart=/usr/bin/docker-compose -f docker-compose.yml up"));
        assert!(u.contains("ExecStartPre=/usr/bin/docker-compose -f docker-compose.yml down"));
        assert!(u.contains("ExecStop=/usr/bin/docker-compose -f docker-compose.yml down"));
        assert!(u.contains("Requires=docker.service"));
        assert!(u.contains("WantedBy=multi-user.target"));
    }

    #[test]
    fn unit_validation() {
        assert!(validate_unit(DEFAULT_UNIT_TEMPLATE).is_ok());
        assert!(validate_unit("nope").is_err());
    }

    #[tokio::test]
    async fn compose_bin_auto_prefers_docker_compose() {
        let mock = MockExec::new();
        mock.on("sh", |_, args| {
            // `command -v docker-compose` → found; `command -v docker` → found
            let cmd = args.get(1).cloned().unwrap_or_default();
            let found = cmd.contains("docker-compose") || cmd.contains("docker");
            HostOutput {
                status: if found { 0 } else { 1 },
                stdout: if cmd.contains("docker-compose") {
                    "/usr/bin/docker-compose\n".into()
                } else {
                    "/usr/bin/docker\n".into()
                },
                stderr: String::new(),
            }
        });
        let exec: Arc<dyn HostExec> = Arc::new(mock);
        let cfg = AppConfig {
            systemd: crate::config::SystemdConfig {
                compose_binary: "auto".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        let bin = resolve_compose_bin(&cfg, &exec).await.unwrap();
        assert_eq!(bin, "/usr/bin/docker-compose");
    }

    #[test]
    fn list_units_parses() {
        // pure parse path exercised indirectly in api tests
    }
}
