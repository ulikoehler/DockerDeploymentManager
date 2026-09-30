use crate::config::{AppConfig, ServiceMeta};
use crate::permissions::valid_service_name;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// A managed service = a directory under services_root with a compose file.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Service {
    pub name: String,
    /// Path inside the container.
    pub dir: PathBuf,
    /// Path as seen on the host (for unit WorkingDirectory, backup.sh).
    pub host_dir: PathBuf,
    pub compose_path: PathBuf,
    pub meta: ServiceMeta,
}

pub const META_FILE: &str = "meta.yaml";

/// Locate a compose file in `dir` honoring `compose_file` preference then
/// common alternatives.
pub fn find_compose_file(dir: &Path, preferred: &str) -> Option<PathBuf> {
    for name in [preferred, "compose.yaml", "compose.yml", "docker-compose.yaml"] {
        let p = dir.join(name);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

pub fn load_meta(dir: &Path) -> ServiceMeta {
    let p = dir.join(META_FILE);
    std::fs::File::open(&p)
        .ok()
        .and_then(|f| serde_yaml::from_reader(f).ok())
        .unwrap_or_default()
}

pub fn save_meta(dir: &Path, meta: &ServiceMeta) -> Result<()> {
    let tmp = dir.join(format!(".{META_FILE}.tmp"));
    {
        let f = std::fs::File::create(&tmp)?;
        serde_yaml::to_writer(f, meta)?;
    }
    std::fs::rename(&tmp, dir.join(META_FILE))?;
    Ok(())
}

/// All services under services_root (dirs containing a compose file).
pub fn discover_services(cfg: &AppConfig) -> Vec<Service> {
    let root = Path::new(&cfg.paths.services_root);
    let mut out = vec![];
    let Ok(rd) = std::fs::read_dir(root) else {
        return out;
    };
    for entry in rd.flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        let Some(compose_path) = find_compose_file(&dir, &cfg.paths.compose_file) else {
            continue;
        };
        let name = entry.file_name().to_string_lossy().to_string();
        let host_dir = Path::new(cfg.paths.host_services_root()).join(&name);
        let meta = load_meta(&dir);
        out.push(Service {
            name,
            dir,
            host_dir,
            compose_path,
            meta,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Get a single service by name (with traversal-safe validation).
pub fn get_service(cfg: &AppConfig, name: &str) -> Result<Service> {
    if !valid_service_name(name) {
        anyhow::bail!("invalid service name '{name}'");
    }
    let dir = Path::new(&cfg.paths.services_root).join(name);
    let compose_path = find_compose_file(&dir, &cfg.paths.compose_file)
        .ok_or_else(|| anyhow::anyhow!("service '{name}' has no compose file"))?;
    Ok(Service {
        name: name.to_string(),
        host_dir: Path::new(cfg.paths.host_services_root()).join(name),
        dir: dir.clone(),
        compose_path,
        meta: load_meta(&dir),
    })
}

/// Create the service dir; fails if it already exists.
pub fn create_service_dir(cfg: &AppConfig, name: &str) -> Result<PathBuf> {
    if !valid_service_name(name) {
        anyhow::bail!("invalid service name '{name}'");
    }
    let dir = Path::new(&cfg.paths.services_root).join(name);
    if dir.exists() {
        anyhow::bail!("service '{name}' already exists");
    }
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    Ok(dir)
}

/// Atomically write a file inside a service dir.
pub fn write_service_file(dir: &Path, name: &str, content: &str, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let tmp = dir.join(format!(".{name}.tmp"));
    std::fs::write(&tmp, content)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
    std::fs::rename(&tmp, dir.join(name))?;
    Ok(())
}

/// Validate a meta.yaml backup `paths` entry: relative, no escapes.
pub fn valid_rel_path(p: &str) -> bool {
    !p.is_empty()
        && !p.starts_with('/')
        && !Path::new(p)
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rel_path_validation() {
        assert!(valid_rel_path("data"));
        assert!(valid_rel_path("a/b/c"));
        assert!(!valid_rel_path("/abs"));
        assert!(!valid_rel_path("../escape"));
        assert!(!valid_rel_path("a/../b"));
        assert!(!valid_rel_path(""));
    }
}
