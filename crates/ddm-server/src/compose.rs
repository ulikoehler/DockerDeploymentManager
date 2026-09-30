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
    out = out.replace("{service}", service);
    out = out.replace("{dir}", host_dir);
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
