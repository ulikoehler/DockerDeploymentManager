//! Offline CLI: `ddm-server <subcommand>` — user management etc. that works
//! even when the HTTP server is down (`docker compose exec ddm ddm-server ...`).

use crate::config::{load_config, resolve_users_path};
use crate::users::{self, AccessEffect, User, UsersFile};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "ddm-server", version, about = "Docker Deployment Manager")]
pub struct Cli {
    /// Path to config.yaml
    #[arg(short, long, global = true, default_value = "/etc/ddm/config.yaml")]
    pub config: PathBuf,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run the HTTP/WebSocket daemon.
    Serve,

    /// Run the privileged security agent (unix socket; see docs/SECURITY.md).
    Agent,

    /// Manage users (operates directly on users.yaml; the daemon hot-reloads).
    User {
        #[command(subcommand)]
        cmd: UserCmd,
    },

    /// Print an argon2 hash of a password (for hand-editing users.yaml).
    Hash {
        /// Password; prompted interactively when omitted.
        password: Option<String>,
    },

    /// Validate the config file and exit.
    CheckConfig,

    /// Render the systemd unit template for a service dir (debugging).
    UnitTemplate {
        /// Service name.
        name: String,
        /// Host-side service directory.
        #[arg(long)]
        dir: String,
    },
}

#[derive(Subcommand)]
pub enum UserCmd {
    /// List all users.
    List,
    /// Show one user.
    Show { name: String },
    /// Add a user.
    Add {
        name: String,
        #[arg(long, value_delimiter = ',')]
        role: Vec<String>,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        generate: bool,
        #[arg(long)]
        prompt: bool,
    },
    /// Remove a user.
    Remove { name: String },
    /// Set a user's password.
    Passwd {
        name: String,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        generate: bool,
        #[arg(long)]
        prompt: bool,
    },
    /// Replace a user's roles.
    SetRoles {
        name: String,
        #[arg(long, value_delimiter = ',')]
        role: Vec<String>,
    },
    /// Replace a user's service access rules.
    /// Rules are `kind:pattern` with kind in {exact, glob, regex}.
    SetAccess {
        name: String,
        #[arg(long)]
        allow: Vec<String>,
        #[arg(long)]
        deny: Vec<String>,
    },
    /// Set feature flags.
    SetFeatures {
        name: String,
        #[arg(long)]
        create_services: Option<bool>,
        #[arg(long)]
        edit_compose: Option<bool>,
        #[arg(long)]
        edit_units: Option<bool>,
        #[arg(long)]
        run_commands: Option<bool>,
        #[arg(long)]
        manage_backup: Option<bool>,
        #[arg(long)]
        manage_monitoring: Option<bool>,
    },
    /// Set the compose policy name ("strict", "relaxed", "unrestricted", ...).
    SetPolicy { name: String, policy: String },
}

fn load_users_file(config_path: &Path) -> Result<(UsersFile, PathBuf)> {
    let cfg = load_config(config_path)
        .with_context(|| "cannot read config — use --config to point at config.yaml")?;
    let users_path = resolve_users_path(config_path, &cfg);
    let file = if users_path.exists() {
        let f = std::fs::File::open(&users_path)
            .with_context(|| format!("opening {}", users_path.display()))?;
        serde_yaml::from_reader(f).with_context(|| format!("parsing {}", users_path.display()))?
    } else {
        UsersFile::default()
    };
    Ok((file, users_path))
}

fn save_users_file(path: &Path, file: &UsersFile) -> Result<()> {
    users::write_users_atomic(path, file)
}

fn resolve_password(
    password: &Option<String>,
    generate: bool,
    prompt: bool,
) -> Result<(String, bool)> {
    if let Some(p) = password {
        return Ok((p.clone(), false));
    }
    if generate {
        return Ok((users::generate_password(), true));
    }
    if prompt || true {
        let p = read_password_tty()?;
        return Ok((p, false));
    }
    unreachable!()
}

fn read_password_tty() -> Result<String> {
    eprint!("Password: ");
    std::io::stderr().flush()?;
    let mut s = String::new();
    std::io::stdin().read_line(&mut s)?;
    let p = s.trim().to_string();
    if p.len() < 8 {
        anyhow::bail!("password must be at least 8 characters");
    }
    Ok(p)
}

fn audit_stderr(action: &str, target: &str, detail: &str) {
    eprintln!("[audit] {action} {target} {detail}");
}

fn find<'a>(file: &'a mut UsersFile, name: &str) -> Result<&'a mut User> {
    file.users
        .iter_mut()
        .find(|u| u.name == name)
        .ok_or_else(|| anyhow::anyhow!("user '{name}' not found"))
}

pub fn run_user_command(config_path: &Path, cmd: &UserCmd) -> Result<()> {
    let (mut file, path) = load_users_file(config_path)?;
    match cmd {
        UserCmd::List => {
            for u in &file.users {
                let access: Vec<String> = u
                    .access
                    .iter()
                    .map(|r| format!("{}:{}", r.kind.as_str(), r.pattern))
                    .collect();
                println!(
                    "{}\troles={}\taccess=[{}]\tpolicy={}",
                    u.name,
                    u.roles.join(","),
                    access.join(","),
                    u.compose_policy.as_deref().unwrap_or("-"),
                );
            }
        }
        UserCmd::Show { name } => {
            let u = file
                .users
                .iter()
                .find(|u| u.name == *name)
                .ok_or_else(|| anyhow::anyhow!("user '{name}' not found"))?;
            println!(
                "{}",
                serde_yaml::to_string(&serde_json::json!({
                    "name": u.name,
                    "roles": u.roles,
                    "access": u.access,
                    "features": u.features,
                    "compose_policy": u.compose_policy,
                }))?
            );
        }
        UserCmd::Add {
            name,
            role,
            password,
            generate,
            prompt,
        } => {
            let roles = if role.is_empty() {
                vec!["viewer".to_string()]
            } else {
                role.clone()
            };
            let (pw, generated) = resolve_password(password, *generate, *prompt)?;
            users::cli_add_user(&mut file, name, &pw, roles)?;
            save_users_file(&path, &file)?;
            audit_stderr("user_add", name, "");
            if generated {
                println!("generated password for {name}: {pw}");
            }
            println!("user '{name}' added");
        }
        UserCmd::Remove { name } => {
            users::cli_remove_user(&mut file, name)?;
            save_users_file(&path, &file)?;
            audit_stderr("user_remove", name, "");
            println!("user '{name}' removed");
        }
        UserCmd::Passwd {
            name,
            password,
            generate,
            prompt,
        } => {
            let (pw, generated) = resolve_password(password, *generate, *prompt)?;
            users::cli_set_password(&mut file, name, &pw)?;
            save_users_file(&path, &file)?;
            audit_stderr("user_passwd", name, "");
            if generated {
                println!("generated password for {name}: {pw}");
            }
            println!("password updated");
        }
        UserCmd::SetRoles { name, role } => {
            find(&mut file, name)?.roles = role.clone();
            save_users_file(&path, &file)?;
            audit_stderr("user_roles", name, &role.join(","));
            println!("roles updated");
        }
        UserCmd::SetAccess { name, allow, deny } => {
            let mut rules = vec![];
            for spec in deny {
                rules.push(users::parse_access_spec(spec, AccessEffect::Deny)?);
            }
            for spec in allow {
                rules.push(users::parse_access_spec(spec, AccessEffect::Allow)?);
            }
            find(&mut file, name)?.access = rules;
            save_users_file(&path, &file)?;
            audit_stderr("user_access", name, "");
            println!("access rules updated");
        }
        UserCmd::SetFeatures {
            name,
            create_services,
            edit_compose,
            edit_units,
            run_commands,
            manage_backup,
            manage_monitoring,
        } => {
            let u = find(&mut file, name)?;
            let f = &mut u.features;
            if let Some(v) = create_services {
                f.create_services = *v;
            }
            if let Some(v) = edit_compose {
                f.edit_compose = *v;
            }
            if let Some(v) = edit_units {
                f.edit_units = *v;
            }
            if let Some(v) = run_commands {
                f.run_commands = *v;
            }
            if let Some(v) = manage_backup {
                f.manage_backup = *v;
            }
            if let Some(v) = manage_monitoring {
                f.manage_monitoring = *v;
            }
            save_users_file(&path, &file)?;
            audit_stderr("user_features", name, "");
            println!("features updated");
        }
        UserCmd::SetPolicy { name, policy } => {
            find(&mut file, name)?.compose_policy = if policy == "default" {
                None
            } else {
                Some(policy.clone())
            };
            save_users_file(&path, &file)?;
            audit_stderr("user_policy", name, policy);
            println!("policy updated");
        }
    }
    Ok(())
}

pub fn run_check_config(config_path: &Path) -> Result<()> {
    let cfg = load_config(config_path)?;
    let users_path = resolve_users_path(config_path, &cfg);
    println!("config OK: {}", config_path.display());
    println!("users file: {}", users_path.display());
    Ok(())
}

pub fn run_unit_template(config_path: &Path, name: &str, dir: &str) -> Result<()> {
    let cfg = load_config(config_path)?;
    if !crate::permissions::valid_service_name(name) {
        anyhow::bail!("invalid service name '{name}'");
    }
    let compose_bin = match cfg.systemd.compose_binary.trim() {
        "auto" => "docker compose".to_string(),
        other => other.to_string(),
    };
    let out = crate::systemd::render_unit(
        crate::systemd::DEFAULT_UNIT_TEMPLATE,
        name,
        dir,
        &cfg.paths.compose_file,
        &compose_bin,
    );
    print!("{out}");
    Ok(())
}

pub fn run_hash(password: Option<String>) -> Result<()> {
    let pw = match password {
        Some(p) => p.clone(),
        None => read_password_tty()?,
    };
    println!("{}", users::hash_password(&pw)?);
    Ok(())
}
