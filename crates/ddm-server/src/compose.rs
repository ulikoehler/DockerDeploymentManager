use crate::config::ServiceTemplate;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::Path;

/// Read a service's compose file.
pub fn read_compose(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))
}

/// Atomically replace a compose file.
pub fn write_compose(path: &Path, content: &str) -> Result<()> {
    let tmp = path.with_extension("yml.tmp");
    std::fs::write(&tmp, content)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Render a service template's compose file with variables.
/// Substitutes ${var}, {service}, {dir}.
pub fn render_template(
    tpl: &ServiceTemplate,
    service: &str,
    host_dir: &str,
    vars: &HashMap<String, String>,
) -> Result<String> {
    let raw = std::fs::read_to_string(&tpl.compose_template)
        .with_context(|| format!("reading compose template {}", tpl.compose_template))?;
    let mut out = raw;
    // Built-in substitutions available to every template.
    let builtins = [
        ("service_name", service),
        ("service", service),
        ("name", service),
        ("dir", host_dir),
        ("host_dir", host_dir),
    ];
    for (k, v) in builtins {
        out = out.replace(&format!("${{{k}}}"), v);
        out = out.replace(&format!("{{{{{k}}}}}"), v);
    }
    for v in &tpl.vars {
        let val = vars
            .get(&v.name)
            .cloned()
            .or_else(|| v.default.clone())
            .unwrap_or_default();
        if v.required && val.is_empty() {
            anyhow::bail!("template variable '{}' is required", v.name);
        }
        out = out.replace(&format!("${{{}}}", v.name), &val);
        out = out.replace(&format!("{{{{{}}}}}", v.name), &val);
    }
    Ok(out)
}

/// Parse a compose file into YAML to check it's structurally valid.
pub fn parse_check(content: &str) -> Result<serde_yaml::Value> {
    let v: serde_yaml::Value = serde_yaml::from_str(content).context("invalid YAML")?;
    if !v.is_mapping() {
        anyhow::bail!("compose file must be a YAML mapping");
    }
    if v.get("services").is_none() {
        anyhow::bail!("compose file has no 'services' section");
    }
    Ok(v)
}

/// Public hostnames a parsed compose file declares. Only `labels` values
/// and domain-ish `environment` entries are scanned — that is where
/// Traefik/Caddy/nginx-proxy style routers read the hostname a service
/// answers on. Image references, volume names, paths and commands are
/// not routing config and are deliberately not scanned.
pub fn declared_domains(v: &serde_yaml::Value) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(services) = v.get("services").and_then(|s| s.as_mapping()) {
        for (_, svc) in services {
            collect_domains(svc, &mut out);
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Environment keys that plausibly carry a public hostname
/// (`VIRTUAL_HOST`, `APP_DOMAIN`, `FQDN`, ...). Substring match on the
/// lowercased key keeps this independent of naming conventions.
fn env_key_is_domainish(key: &str) -> bool {
    let k = key.to_lowercase();
    ["host", "domain", "fqdn", "hostname", "vhost", "server_name"]
        .iter()
        .any(|needle| k.contains(needle))
}

fn collect_domains(node: &serde_yaml::Value, out: &mut Vec<String>) {
    match node {
        serde_yaml::Value::Mapping(m) => {
            for (k, val) in m {
                let key = k.as_str().unwrap_or("");
                match key {
                    // `labels` may be a mapping or a ["k=v", ...] sequence;
                    // every value is fair game for hostname extraction.
                    "labels" => scan_label_set(val, out),
                    // `environment` is scanned only for domain-ish keys —
                    // arbitrary env values (URLs to third parties etc.)
                    // are not declarations of this service's hostname.
                    "environment" => scan_env_set(val, out),
                    _ => collect_domains(val, out),
                }
            }
        }
        serde_yaml::Value::Sequence(seq) => {
            for item in seq {
                collect_domains(item, out);
            }
        }
        _ => {}
    }
}

fn scan_label_set(val: &serde_yaml::Value, out: &mut Vec<String>) {
    match val {
        serde_yaml::Value::Mapping(m) => {
            for (_, v) in m {
                push_scalars(v, out);
            }
        }
        serde_yaml::Value::Sequence(seq) => {
            for item in seq {
                if let Some(s) = item.as_str() {
                    // "key=value" or bare "key" — scan the value part.
                    let v = s.split_once('=').map(|(_, r)| r).unwrap_or(s);
                    extract_hostnames(v, out);
                }
            }
        }
        _ => push_scalars(val, out),
    }
}

fn scan_env_set(val: &serde_yaml::Value, out: &mut Vec<String>) {
    match val {
        serde_yaml::Value::Mapping(m) => {
            for (k, v) in m {
                if k.as_str().map(env_key_is_domainish).unwrap_or(false) {
                    push_scalars(v, out);
                }
            }
        }
        serde_yaml::Value::Sequence(seq) => {
            for item in seq {
                if let Some(s) = item.as_str() {
                    let (k, v) = s.split_once('=').unwrap_or((s, ""));
                    if env_key_is_domainish(k) {
                        extract_hostnames(v, out);
                    }
                }
            }
        }
        _ => {}
    }
}

fn push_scalars(v: &serde_yaml::Value, out: &mut Vec<String>) {
    match v {
        serde_yaml::Value::String(s) => extract_hostnames(s, out),
        serde_yaml::Value::Sequence(seq) => {
            for item in seq {
                push_scalars(item, out);
            }
        }
        _ => {}
    }
}

/// Extract dotted hostname candidates from arbitrary text. Requires at
/// least one dot and an all-alpha final label, which excludes IPv4
/// addresses, versions (`1.2.3`) and bare names (`db`, `localhost`).
/// Ports and surrounding punctuation are naturally excluded.
fn extract_hostnames(text: &str, out: &mut Vec<String>) {
    use std::sync::OnceLock;
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(
            r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}",
        )
        .unwrap()
    });
    for m in re.find_iter(text) {
        out.push(m.as_str().to_lowercase());
    }
}

#[cfg(test)]
mod domain_tests {
    use super::*;

    fn domains(yaml: &str) -> Vec<String> {
        declared_domains(&parse_check(yaml).unwrap())
    }

    #[test]
    fn finds_traefik_caddy_and_env_hosts() {
        let y = r#"
services:
  app:
    image: ghcr.io/acme/app:1.0
    labels:
      traefik.http.routers.app.rule: "Host(`app.example.com`) || Host(`api.example.com`)"
      caddy: "admin.example.com"
      com.example.version: "1.2.3"
    environment:
      VIRTUAL_HOST: "www.example.com, example.com"
      DATABASE_URL: "postgres://u:p@db.internal:5432/app"
      PLAIN: "no dots here"
"#;
        let d = domains(y);
        assert!(d.contains(&"app.example.com".to_string()), "{d:?}");
        assert!(d.contains(&"api.example.com".to_string()), "{d:?}");
        assert!(d.contains(&"admin.example.com".to_string()), "{d:?}");
        assert!(d.contains(&"www.example.com".to_string()), "{d:?}");
        assert!(d.contains(&"example.com".to_string()), "{d:?}");
        // registry host and non-domain env values are not routing config
        assert!(!d.iter().any(|x| x.contains("ghcr.io")), "{d:?}");
        assert!(!d.iter().any(|x| x.contains("db.internal")), "{d:?}");
        assert!(!d.iter().any(|x| x == "1.2.3"), "{d:?}");
    }

    #[test]
    fn env_sequence_and_map_forms() {
        let y = r#"
services:
  a:
    image: nginx
    environment: ["APP_DOMAIN=foo.example.com", "OTHER=x"]
  b:
    image: nginx
    labels: ["traefik.http.routers.b.rule=Host(`b.example.com`)"]
"#;
        let d = domains(y);
        assert!(d.contains(&"foo.example.com".to_string()), "{d:?}");
        assert!(d.contains(&"b.example.com".to_string()), "{d:?}");
    }
}
