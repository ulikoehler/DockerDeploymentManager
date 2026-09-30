use crate::config::{ComposePolicy, ListRuleMode};
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::Serialize;
use serde_yaml::Value;

#[derive(Debug, Clone, Serialize)]
pub struct PolicyViolation {
    /// YAML-ish path like services.web.privileged
    pub path: String,
    pub rule: String,
    pub message: String,
}

impl PolicyViolation {
    fn new(path: impl Into<String>, rule: &str, msg: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            rule: rule.to_string(),
            message: msg.into(),
        }
    }
}

fn build_globset(patterns: &[String]) -> Option<GlobSet> {
    let mut b = GlobSetBuilder::new();
    for p in patterns {
        b.add(Glob::new(p).ok()?);
    }
    b.build().ok()
}

fn truthy(v: &Value) -> bool {
    matches!(v, Value::Bool(true)) || matches!(v, Value::String(s) if s == "true" || s == "yes")
}

fn is_hostish(v: &Value) -> bool {
    matches!(v, Value::String(s) if s == "host" || s.starts_with("service:") || s.starts_with("container:"))
}

/// Validate a compose YAML document against `policy`.
/// Returns violations (empty = ok). Unparseable YAML = one violation.
pub fn validate_compose(compose_yaml: &str, policy: &ComposePolicy) -> Vec<PolicyViolation> {
    let doc: Value = match serde_yaml::from_str(compose_yaml) {
        Ok(v) => v,
        Err(e) => {
            return vec![PolicyViolation::new(
                "$",
                "parse",
                format!("invalid YAML: {e}"),
            )]
        }
    };
    if !doc.is_mapping() {
        return vec![PolicyViolation::new(
            "$",
            "parse",
            "compose file must be a mapping",
        )];
    }

    let mut out = Vec::new();
    let services = doc
        .get("services")
        .and_then(|s| s.as_mapping())
        .cloned()
        .unwrap_or_default();

    if services.len() > policy.max_services_per_compose {
        out.push(PolicyViolation::new(
            "services",
            "max_services",
            format!(
                "{} services exceeds max_services_per_compose={}",
                services.len(),
                policy.max_services_per_compose
            ),
        ));
    }

    for (sname, svc) in &services {
        let name = sname.as_str().unwrap_or("?").to_string();
        let base = format!("services.{name}");
        let Some(smap) = svc.as_mapping() else {
            out.push(PolicyViolation::new(
                &base,
                "shape",
                "service must be a mapping",
            ));
            continue;
        };

        check_service(&name, &base, smap, policy, &mut out);
    }
    out
}

fn check_service(
    name: &str,
    base: &str,
    smap: &serde_yaml::Mapping,
    policy: &ComposePolicy,
    out: &mut Vec<PolicyViolation>,
) {
    let get = |k: &str| smap.get(Value::String(k.to_string()));

    // privileged
    if policy.deny_privileged && get("privileged").map(truthy).unwrap_or(false) {
        out.push(PolicyViolation::new(
            format!("{base}.privileged"),
            "deny_privileged",
            "privileged: true is not allowed",
        ));
    }

    // host namespaces
    if policy.deny_host_namespaces {
        for k in [
            "pid",
            "network_mode",
            "ipc",
            "uts",
            "userns_mode",
            "cgroup",
            "cgroup_parent",
        ] {
            if let Some(v) = get(k) {
                if is_hostish(v) || matches!(v, Value::String(s) if s == "host") {
                    out.push(PolicyViolation::new(
                        format!("{base}.{k}"),
                        "deny_host_namespaces",
                        format!("{k} host/service/container mode is not allowed"),
                    ));
                }
            }
        }
    }

    // root user
    if policy.deny_root_user {
        if let Some(u) = get("user") {
            let is_root = matches!(u, Value::String(s) if s == "root" || s == "0" || s.starts_with("0:"))
                || matches!(u, Value::Number(n) if n.as_u64() == Some(0));
            if is_root {
                out.push(PolicyViolation::new(
                    format!("{base}.user"),
                    "deny_root_user",
                    "running as root is not allowed by policy",
                ));
            }
        }
    }

    // isolation overrides
    if policy.deny_isolation_overrides {
        if let Some(so) = get("security_opt").and_then(|v| v.as_sequence()) {
            for item in so {
                if let Some(s) = item.as_str() {
                    if s.starts_with("no-new-privileges:false")
                        || s.starts_with("apparmor:unconfined")
                        || s.starts_with("seccomp:unconfined")
                        || s.starts_with("seccomp=unconfined")
                        || s.starts_with("label:disable")
                    {
                        out.push(PolicyViolation::new(
                            format!("{base}.security_opt"),
                            "deny_isolation_overrides",
                            format!("security_opt '{s}' disables isolation"),
                        ));
                    }
                }
            }
        }
        if get("cap_drop")
            .and_then(|v| v.as_sequence())
            .map(|seq| seq.iter().any(|i| i.as_str() == Some("ALL")))
            .unwrap_or(false)
        {
            // dropping ALL is fine/good; nothing to flag
        }
    }

    // cap_add
    if let Some(caps) = get("cap_add") {
        let items: Vec<String> = match caps {
            Value::Sequence(seq) => seq
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect(),
            Value::String(s) => vec![s.clone()],
            _ => vec![],
        };
        for cap in items {
            if policy.cap_add.rejected(&cap).is_some() {
                let mode = match policy.cap_add.mode {
                    ListRuleMode::Allowlist => "not in cap_add allowlist",
                    ListRuleMode::Denylist => "denied by cap_add denylist",
                };
                out.push(PolicyViolation::new(
                    format!("{base}.cap_add"),
                    "cap_add",
                    format!("cap_add '{cap}' {mode}"),
                ));
            }
        }
    }

    // sysctls
    if let Some(sysctls) = get("sysctls") {
        let keys: Vec<String> = match sysctls {
            Value::Mapping(m) => m
                .keys()
                .filter_map(|k| k.as_str().map(String::from))
                .collect(),
            Value::Sequence(seq) => seq
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .map(|s| s.split('=').next().unwrap_or(&s).to_string())
                .collect(),
            _ => vec![],
        };
        for k in keys {
            if policy.sysctls.rejected(&k).is_some() {
                out.push(PolicyViolation::new(
                    format!("{base}.sysctls"),
                    "sysctls",
                    format!("sysctl '{k}' not permitted by policy"),
                ));
            }
        }
    }

    // devices
    if policy.deny_devices {
        if let Some(d) = get("devices") {
            if matches!(d, Value::Sequence(s) if !s.is_empty()) || d.as_str().is_some() {
                out.push(PolicyViolation::new(
                    format!("{base}.devices"),
                    "deny_devices",
                    "device mappings are not allowed",
                ));
            }
        }
    }

    // image registry allowlist
    if !policy.allowed_registries.is_empty() {
        if let Some(Value::String(img)) = get("image") {
            let registry = img.split('/').next().unwrap_or("");
            let ok = policy
                .allowed_registries
                .iter()
                .any(|r| registry.starts_with(r.as_str()) || img.starts_with(r.as_str()));
            if !ok {
                out.push(PolicyViolation::new(
                    format!("{base}.image"),
                    "allowed_registries",
                    format!("image '{img}' not from an allowed registry"),
                ));
            }
        }
    }

    // ports: host side must be within range
    if let Some(ports) = get("ports").and_then(|v| v.as_sequence()) {
        for (i, p) in ports.iter().enumerate() {
            let path = format!("{base}.ports[{i}]");
            check_port(&path, p, policy, out);
        }
    }

    // volumes: bind-mount rules
    if let Some(vols) = get("volumes").and_then(|v| v.as_sequence()) {
        for (i, v) in vols.iter().enumerate() {
            let path = format!("{base}.volumes[{i}]");
            check_volume(&path, name, v, policy, out);
        }
    }

    // extends/include escapes
    for k in ["extends", "include"] {
        if let Some(v) = get(k) {
            check_extends(&format!("{base}.{k}"), v, out);
        }
    }
}

fn host_port_of_short(spec: &str) -> Option<u16> {
    // forms: "80", "8080:80", "127.0.0.1:8080:80", "8080:80/tcp"
    let no_proto = spec.split('/').next().unwrap_or(spec);
    let parts: Vec<&str> = no_proto.split(':').collect();
    let host = match parts.as_slice() {
        [_container] => return None, // container-only, no host port
        [host, _container] => *host,
        [_ip, host, _container] => *host,
        _ => return None,
    };
    host.split('-').next().and_then(|h| h.parse().ok())
}

fn check_port(path: &str, v: &Value, policy: &ComposePolicy, out: &mut Vec<PolicyViolation>) {
    let (lo, hi) = policy.allowed_port_range;
    let host_port = match v {
        Value::String(s) => host_port_of_short(s),
        Value::Number(n) => n.as_u64().map(|x| x as u16), // container-only → None ok
        Value::Mapping(m) => m.get(Value::String("published".to_string())).and_then(|p| {
            p.as_str()
                .and_then(|s| s.parse().ok())
                .or_else(|| p.as_u64().map(|x| x as u16))
        }),
        _ => None,
    };
    if let Some(hp) = host_port {
        if hp < lo || hp > hi {
            out.push(PolicyViolation::new(
                path,
                "allowed_port_range",
                format!("host port {hp} outside allowed range {lo}-{hi}"),
            ));
        }
    }
}

/// Determine whether a short-form volume string is a bind mount, and split.
/// Returns (is_bind, source, target).
fn parse_short_volume(spec: &str) -> (bool, Option<String>, Option<String>) {
    if spec.starts_with('/') || spec.starts_with('.') || spec.starts_with('~') {
        let parts: Vec<&str> = spec.splitn(3, ':').collect();
        match parts.as_slice() {
            [src] => (true, Some(src.to_string()), None),
            [src, tgt, ..] => (true, Some(src.to_string()), Some(tgt.to_string())),
            _ => (false, None, None),
        }
    } else {
        // named volume or container-path-only
        (false, None, spec.split(':').next().map(String::from))
    }
}

fn check_volume(
    path: &str,
    _service: &str,
    v: &Value,
    policy: &ComposePolicy,
    out: &mut Vec<PolicyViolation>,
) {
    let (is_bind, source, target) = match v {
        Value::String(s) => parse_short_volume(s),
        Value::Mapping(m) => {
            let ty = m
                .get(Value::String("type".to_string()))
                .and_then(|t| t.as_str())
                .unwrap_or("volume");
            let src = m
                .get(Value::String("source".to_string()))
                .or_else(|| m.get(Value::String("src".to_string())))
                .and_then(|s| s.as_str())
                .map(String::from);
            let tgt = m
                .get(Value::String("target".to_string()))
                .or_else(|| m.get(Value::String("dst".to_string())))
                .and_then(|s| s.as_str())
                .map(String::from);
            (ty == "bind", src, tgt)
        }
        _ => (false, None, None),
    };

    if !is_bind {
        return;
    }
    let src = source.clone().unwrap_or_default();

    // never allow secrets-bearing or socket mounts
    if src.ends_with(".restic_password") || src.ends_with("/.restic_password") {
        out.push(PolicyViolation::new(
            path,
            "deny_secret_mount",
            "mounting .restic_password into a container is forbidden",
        ));
    }
    if policy.deny_docker_socket && (src == "/var/run/docker.sock" || src.ends_with("/docker.sock"))
    {
        out.push(PolicyViolation::new(
            path,
            "deny_docker_socket",
            "mounting the docker socket is not allowed",
        ));
    }
    if src.contains("..") {
        out.push(PolicyViolation::new(
            path,
            "no_path_escape",
            "bind source must not contain '..'",
        ));
    }
    if src.starts_with('~') {
        out.push(PolicyViolation::new(
            path,
            "no_home_expand",
            "bind source must not use '~' (unpredictable as root)",
        ));
    }

    // allowed sources (empty list = deny all binds)
    if let Some(gs) = build_globset(&policy.allowed_bind_sources) {
        if !gs.is_match(&src) {
            out.push(PolicyViolation::new(
                path,
                "allowed_bind_sources",
                format!("bind source '{src}' is outside allowed_bind_sources"),
            ));
        }
    } else if !policy.allowed_bind_sources.is_empty() {
        out.push(PolicyViolation::new(
            path,
            "allowed_bind_sources",
            "invalid allowed_bind_sources globs in policy",
        ));
    }

    // denied targets
    if let Some(tgt) = &target {
        if let Some(gs) = build_globset(&policy.deny_bind_targets) {
            if gs.is_match(tgt) {
                out.push(PolicyViolation::new(
                    path,
                    "deny_bind_targets",
                    format!("bind target '{tgt}' matches a denied target"),
                ));
            }
        }
    }
}

fn check_extends(path: &str, v: &Value, out: &mut Vec<PolicyViolation>) {
    // file references must not escape the service dir
    let files: Vec<String> = match v {
        Value::Mapping(m) => m
            .get(Value::String("file".to_string()))
            .and_then(|f| f.as_str())
            .map(|s| vec![s.to_string()])
            .unwrap_or_default(),
        Value::String(s) => vec![s.clone()],
        Value::Sequence(seq) => seq
            .iter()
            .filter_map(|i| i.as_str().map(String::from))
            .collect(),
        _ => vec![],
    };
    for f in files {
        if f.starts_with('/') || f.contains("..") {
            out.push(PolicyViolation::new(
                path,
                "no_external_extends",
                format!("extends/include file '{f}' must stay inside the service dir"),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ComposePolicy, ListRule};

    fn policy() -> ComposePolicy {
        ComposePolicy {
            allowed_bind_sources: vec!["/services/**".into(), "/data/**".into()],
            cap_add: ListRule::allowlist(vec!["NET_BIND_SERVICE".into()]),
            ..ComposePolicy::strict_defaults()
        }
    }

    fn violations(y: &str) -> Vec<PolicyViolation> {
        validate_compose(y, &policy())
    }

    #[test]
    fn clean_compose_passes() {
        let y = r#"
services:
  web:
    image: nginx:alpine
    volumes:
      - /services/web/data:/usr/share/nginx/html
    ports:
      - "8080:80"
"#;
        assert!(violations(y).is_empty(), "{:?}", violations(y));
    }

    #[test]
    fn privileged_denied() {
        let y = "services:\n  x:\n    image: a\n    privileged: true\n";
        assert!(violations(y).iter().any(|v| v.rule == "deny_privileged"));
    }

    #[test]
    fn host_network_denied() {
        let y = "services:\n  x:\n    image: a\n    network_mode: host\n";
        assert!(violations(y)
            .iter()
            .any(|v| v.rule == "deny_host_namespaces"));
    }

    #[test]
    fn docker_sock_denied() {
        let y = "services:\n  x:\n    image: a\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n";
        assert!(violations(y).iter().any(|v| v.rule == "deny_docker_socket"));
    }

    #[test]
    fn bind_outside_allowed_denied() {
        let y = "services:\n  x:\n    image: a\n    volumes:\n      - /etc/passwd:/etc/passwd\n";
        let v = violations(y);
        assert!(v.iter().any(|v| v.rule == "allowed_bind_sources"));
        assert!(v.iter().any(|v| v.rule == "deny_bind_targets"));
    }

    #[test]
    fn named_volume_ok() {
        let y =
            "services:\n  x:\n    image: a\n    volumes:\n      - data:/data\nvolumes:\n  data:\n";
        assert!(violations(y).is_empty(), "{:?}", violations(y));
    }

    #[test]
    fn cap_add_allowlist() {
        let y = "services:\n  x:\n    image: a\n    cap_add: [SYS_ADMIN]\n";
        assert!(violations(y).iter().any(|v| v.rule == "cap_add"));
        let y2 = "services:\n  x:\n    image: a\n    cap_add: [NET_BIND_SERVICE]\n";
        assert!(violations(y2).is_empty(), "{:?}", violations(y2));
    }

    #[test]
    fn low_port_denied() {
        let y = "services:\n  x:\n    image: a\n    ports:\n      - \"80:8080\"\n";
        assert!(violations(y).iter().any(|v| v.rule == "allowed_port_range"));
    }

    #[test]
    fn restic_password_mount_denied() {
        let y = "services:\n  x:\n    image: a\n    volumes:\n      - /services/x/.restic_password:/pw\n";
        assert!(violations(y).iter().any(|v| v.rule == "deny_secret_mount"));
    }

    #[test]
    fn path_escape_denied() {
        let y = "services:\n  x:\n    image: a\n    volumes:\n      - ../outside:/data\n";
        assert!(violations(y).iter().any(|v| v.rule == "no_path_escape"));
    }

    #[test]
    fn invalid_yaml_reported() {
        assert!(!violations("{{{{").is_empty());
    }

    #[test]
    fn extends_escape_denied() {
        let y =
            "services:\n  x:\n    extends:\n      file: ../other/compose.yml\n      service: a\n";
        assert!(violations(y)
            .iter()
            .any(|v| v.rule == "no_external_extends"));
    }
}
