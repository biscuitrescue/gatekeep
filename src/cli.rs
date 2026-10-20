//! Command-line interface.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};

use crate::agent::{self, AgentConfig, Source};
use crate::dashboard::{self, Dashboard};
use crate::date::Date;
use crate::deploy;
use crate::git;
use crate::key::PublicKey;
use crate::policy::{KeyEntry, Policy, Severity, User, is_valid_name};

const POLICY_CI_TEMPLATE: &str = include_str!("../examples/policy/.github/workflows/gatekeep.yml");

#[derive(Parser)]
#[command(
    name = "gk",
    version,
    about = "Git-native, policy-as-code SSH access management"
)]
pub struct Cli {
    /// Policy directory (contains users/ and servers/).
    #[arg(long, short, global = true, env = "GK_POLICY", default_value = ".")]
    pub policy: PathBuf,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Create a new policy directory (and Git repository).
    Init {
        /// Directory to create; defaults to --policy.
        dir: Option<PathBuf>,
        /// Don't run `git init`.
        #[arg(long)]
        no_git: bool,
        /// Also write a GitHub Actions workflow that validates pull requests
        /// and publishes the dashboard.
        #[arg(long)]
        ci: bool,
    },
    /// Check the policy for errors and warnings.
    Validate {
        /// Treat warnings as errors.
        #[arg(long)]
        strict: bool,
    },
    /// Manage people and service accounts.
    #[command(subcommand)]
    User(UserCommand),
    /// Manage device keys.
    #[command(subcommand)]
    Key(KeyCommand),
    /// Show who can log in where.
    Access {
        #[arg(long)]
        user: Option<String>,
        #[arg(long)]
        server: Option<String>,
    },
    /// Render authorized_keys files for a server.
    Generate {
        /// Server name; defaults to this machine's hostname.
        #[arg(long)]
        server: Option<String>,
        /// Only this unix login.
        #[arg(long)]
        login: Option<String>,
        /// Install one file per login into this directory instead of printing.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Build the static HTML dashboard.
    Dashboard {
        #[arg(long, default_value = "site")]
        out: PathBuf,
    },
    /// Validate, then commit all policy changes to Git.
    Commit {
        #[arg(long, short)]
        message: String,
    },
    /// Run on servers: sync the policy and install keys.
    #[command(subcommand)]
    Agent(AgentCommand),
}

#[derive(Subcommand)]
pub enum UserCommand {
    /// Add a user.
    Add {
        name: String,
        #[arg(long)]
        email: Option<String>,
        /// Group membership; repeatable.
        #[arg(long = "group", short)]
        groups: Vec<String>,
    },
    /// Disable a user everywhere, keeping their keys on record.
    Disable { name: String },
    /// Re-enable a disabled user.
    Enable { name: String },
    /// List users.
    List,
}

#[derive(Subcommand)]
pub enum KeyCommand {
    /// Register a device key (or every key in a .pub / authorized_keys file).
    Add {
        user: String,
        /// Device name. Defaults to the host part of each key's comment.
        #[arg(long)]
        device: Option<String>,
        /// Public key line, e.g. "ssh-ed25519 AAAA... me@laptop".
        #[arg(long, conflicts_with = "file", required_unless_present = "file")]
        key: Option<String>,
        /// Read keys from a file.
        #[arg(long)]
        file: Option<PathBuf>,
        /// Expiry date (YYYY-MM-DD).
        #[arg(long)]
        expires: Option<String>,
    },
    /// Replace a device's key, e.g. after re-keying a laptop.
    Rotate {
        user: String,
        #[arg(long)]
        device: String,
        #[arg(long)]
        key: String,
        #[arg(long)]
        expires: Option<String>,
    },
    /// Remove a device key. Git history keeps the record.
    Revoke {
        user: String,
        #[arg(long)]
        device: String,
    },
    /// List keys.
    List {
        #[arg(long)]
        user: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum AgentCommand {
    /// Write an agent config file.
    Init(Box<AgentInit>),
    /// Sync forever (or once) and install authorized_keys files.
    Run {
        #[arg(long, short, env = "GK_AGENT_CONFIG", default_value = agent::DEFAULT_CONFIG)]
        config: PathBuf,
        /// Sync a single time and exit non-zero on failure (for cron/CI).
        #[arg(long)]
        once: bool,
    },
}

#[derive(Args)]
#[command(group = clap::ArgGroup::new("source").required(true).args(["git_url", "local"]))]
pub struct AgentInit {
    #[arg(long, short, env = "GK_AGENT_CONFIG", default_value = agent::DEFAULT_CONFIG)]
    config: PathBuf,
    /// Overwrite an existing config.
    #[arg(long)]
    force: bool,
    /// Server name in the policy; defaults to the hostname at runtime.
    #[arg(long)]
    server: Option<String>,
    #[arg(long, default_value = agent::DEFAULT_OUTPUT_DIR)]
    output_dir: PathBuf,
    #[arg(long, default_value_t = agent::DEFAULT_INTERVAL_SECS)]
    interval: u64,
    /// Policy Git repository URL.
    #[arg(long)]
    git_url: Option<String>,
    #[arg(long, default_value = "main", requires = "git_url")]
    branch: String,
    /// SSH deploy key for the Git remote.
    #[arg(long, requires = "git_url")]
    ssh_key: Option<PathBuf>,
    #[arg(long, default_value = agent::DEFAULT_CHECKOUT_DIR, requires = "git_url")]
    checkout_dir: PathBuf,
    /// Policy path inside the repository.
    #[arg(long, requires = "git_url")]
    subdir: Option<PathBuf>,
    /// Use a local policy directory instead of Git.
    #[arg(long)]
    local: Option<PathBuf>,
}

pub fn run(cli: Cli) -> Result<()> {
    let policy_dir = cli.policy;
    let today = Date::today();
    match cli.command {
        Command::Init { dir, no_git, ci } => init(&dir.unwrap_or(policy_dir), no_git, ci),
        Command::Validate { strict } => validate(&policy_dir, today, strict),
        Command::User(cmd) => user(&policy_dir, cmd),
        Command::Key(cmd) => key(&policy_dir, cmd, today),
        Command::Access { user, server } => access(&policy_dir, user, server),
        Command::Generate { server, login, out } => {
            generate(&policy_dir, server, login, out, today)
        }
        Command::Dashboard { out } => {
            let policy = Policy::load(&policy_dir)?;
            let path = dashboard::write(
                &out,
                &Dashboard {
                    policy: &policy,
                    today,
                    revision: git::revision(&policy_dir),
                    history: git::log(&policy_dir, 20),
                },
            )?;
            println!("wrote {}", path.display());
            Ok(())
        }
        Command::Commit { message } => commit(&policy_dir, &message, today),
        Command::Agent(AgentCommand::Init(args)) => agent_init(*args),
        Command::Agent(AgentCommand::Run { config, once }) => {
            agent::run(&AgentConfig::load(&config)?, once)
        }
    }
}

fn init(dir: &Path, no_git: bool, ci: bool) -> Result<()> {
    Policy::scaffold(dir)?;
    if !no_git && !git::is_repo(dir) {
        git::init(dir)?;
        println!("initialised Git repository in {}", dir.display());
    }
    if ci {
        let path = dir.join(".github/workflows/gatekeep.yml");
        if path.exists() {
            println!("kept existing {}", path.display());
        } else {
            std::fs::create_dir_all(path.parent().unwrap())?;
            std::fs::write(&path, POLICY_CI_TEMPLATE)?;
            println!("wrote {}", path.display());
        }
    }
    println!(
        "policy ready in {}. Next: `gk user add <name>` and create servers/<name>.toml",
        dir.display()
    );
    Ok(())
}

fn validate(dir: &Path, today: Date, strict: bool) -> Result<()> {
    let policy = Policy::load(dir)?;
    let issues = policy.validate(today);
    for issue in &issues {
        eprintln!("{issue}");
    }
    let errors = issues
        .iter()
        .filter(|i| i.severity == Severity::Error)
        .count();
    let warnings = issues.len() - errors;
    let summary = format!(
        "{} users, {} servers: {errors} error(s), {warnings} warning(s)",
        policy.users.len(),
        policy.servers.len()
    );
    if errors > 0 || (strict && warnings > 0) {
        bail!("policy is invalid: {summary}");
    }
    println!("policy is valid: {summary}");
    Ok(())
}

fn user(dir: &Path, cmd: UserCommand) -> Result<()> {
    let mut policy = Policy::load(dir)?;
    match cmd {
        UserCommand::Add {
            name,
            email,
            groups,
        } => {
            if !is_valid_name(&name) {
                bail!("invalid user name {name:?}: use lowercase letters, digits, '.', '_' or '-'");
            }
            if let Some(bad) = groups.iter().find(|g| !is_valid_name(g)) {
                bail!("invalid group name {bad:?}");
            }
            if policy.users.contains_key(&name) {
                bail!("user {name:?} already exists");
            }
            let user = User {
                name: name.clone(),
                email,
                groups,
                ..User::default()
            };
            policy.save_user(&user)?;
            println!("added user {name}");
        }
        UserCommand::Disable { name } => {
            let user = policy.user_mut(&name)?;
            user.disabled = true;
            let user = user.clone();
            policy.save_user(&user)?;
            println!("disabled {name}: their keys are removed from every server on the next sync");
        }
        UserCommand::Enable { name } => {
            let user = policy.user_mut(&name)?;
            user.disabled = false;
            let user = user.clone();
            policy.save_user(&user)?;
            println!("enabled {name}");
        }
        UserCommand::List => {
            for user in policy.users.values() {
                println!(
                    "{:<20} {:<8} {:<3} keys  groups: {}{}",
                    user.name,
                    if user.disabled { "disabled" } else { "active" },
                    user.keys.len(),
                    if user.groups.is_empty() {
                        "-".into()
                    } else {
                        user.groups.join(",")
                    },
                    user.email
                        .as_deref()
                        .map(|e| format!("  <{e}>"))
                        .unwrap_or_default()
                );
            }
        }
    }
    Ok(())
}

/// Turns a key comment like `alice@Work-Laptop` into a device name (`work-laptop`).
fn device_from_comment(comment: &str) -> Option<String> {
    let host = comment.rsplit('@').next().unwrap_or(comment);
    let mut name: String = host
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "._-".contains(c) {
                c
            } else {
                '-'
            }
        })
        .collect();
    name = name
        .trim_start_matches(|c: char| !c.is_ascii_alphanumeric())
        .to_owned();
    name.truncate(64);
    while name.contains("..") {
        name = name.replace("..", ".");
    }
    is_valid_name(&name).then_some(name)
}

fn check_expiry(expires: &Option<String>) -> Result<()> {
    if let Some(e) = expires {
        e.parse::<Date>().context("--expires")?;
    }
    Ok(())
}

fn key(dir: &Path, cmd: KeyCommand, today: Date) -> Result<()> {
    let mut policy = Policy::load(dir)?;
    match cmd {
        KeyCommand::Add {
            user,
            device,
            key,
            file,
            expires,
        } => {
            check_expiry(&expires)?;
            let lines: Vec<String> = match (key, file) {
                (Some(k), _) => vec![k],
                (None, Some(path)) => std::fs::read_to_string(&path)
                    .with_context(|| format!("couldn't read {}", path.display()))?
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .map(str::to_owned)
                    .collect(),
                (None, None) => unreachable!("clap requires --key or --file"),
            };
            if lines.is_empty() {
                bail!("no keys found");
            }
            let multiple = lines.len() > 1;
            let entry_user = policy.user_mut(&user)?;
            let mut added = Vec::new();
            for (i, line) in lines.iter().enumerate() {
                let parsed = PublicKey::parse(line).with_context(|| format!("key {}", i + 1))?;
                let device_name = match (&device, &parsed.comment) {
                    (Some(d), _) if multiple => format!("{d}-{}", i + 1),
                    (Some(d), _) => d.clone(),
                    (None, Some(c)) => device_from_comment(c).with_context(|| {
                        format!("can't derive a device name from comment {c:?}; pass --device")
                    })?,
                    (None, None) => bail!("key {} has no comment; pass --device", i + 1),
                };
                if !is_valid_name(&device_name) {
                    bail!("invalid device name {device_name:?}");
                }
                if entry_user.keys.iter().any(|k| k.device == device_name) {
                    bail!(
                        "{user} already has a key for device {device_name:?}; use `gk key rotate`"
                    );
                }
                entry_user.keys.push(KeyEntry {
                    device: device_name.clone(),
                    key: line.clone(),
                    expires: expires.clone(),
                    added: Some(today.to_string()),
                });
                added.push(format!("{user}/{device_name} ({})", parsed.fingerprint()));
            }
            let snapshot = entry_user.clone();
            policy.save_user(&snapshot)?;
            for a in added {
                println!("added {a}");
            }
            report_issues_for(&Policy::load(dir)?, &format!("users/{user}.toml"), today);
        }
        KeyCommand::Rotate {
            user,
            device,
            key,
            expires,
        } => {
            check_expiry(&expires)?;
            let parsed = PublicKey::parse(&key)?;
            let entry_user = policy.user_mut(&user)?;
            let entry = entry_user
                .keys
                .iter_mut()
                .find(|k| k.device == device)
                .with_context(|| format!("{user} has no device {device:?}"))?;
            entry.key = key;
            entry.expires = expires;
            entry.added = Some(today.to_string());
            let snapshot = entry_user.clone();
            policy.save_user(&snapshot)?;
            println!("rotated {user}/{device} to {}", parsed.fingerprint());
            report_issues_for(&Policy::load(dir)?, &format!("users/{user}.toml"), today);
        }
        KeyCommand::Revoke { user, device } => {
            let entry_user = policy.user_mut(&user)?;
            let before = entry_user.keys.len();
            entry_user.keys.retain(|k| k.device != device);
            if entry_user.keys.len() == before {
                bail!("{user} has no device {device:?}");
            }
            let snapshot = entry_user.clone();
            policy.save_user(&snapshot)?;
            println!("revoked {user}/{device}");
        }
        KeyCommand::List { user } => {
            if let Some(u) = &user {
                if !policy.users.contains_key(u) {
                    bail!("no such user {u:?}");
                }
            }
            for u in policy
                .users
                .values()
                .filter(|u| user.as_ref().is_none_or(|n| *n == u.name))
            {
                for k in &u.keys {
                    let (algo, fp) = match k.public_key() {
                        Ok(p) => (p.algorithm.to_string(), p.fingerprint().to_owned()),
                        Err(_) => ("invalid".into(), "-".into()),
                    };
                    let status = if u.disabled {
                        "user-disabled"
                    } else if k.is_expired(today) {
                        "expired"
                    } else {
                        "active"
                    };
                    println!(
                        "{:<16} {:<16} {:<22} {:<51} expires {:<10} {status}",
                        u.name,
                        k.device,
                        algo,
                        fp,
                        k.expires.as_deref().unwrap_or("never")
                    );
                }
            }
        }
    }
    Ok(())
}

/// Prints validation issues for one file after an edit.
fn report_issues_for(policy: &Policy, location: &str, today: Date) {
    for issue in policy
        .validate(today)
        .iter()
        .filter(|i| i.location == location)
    {
        eprintln!("{issue}");
    }
}

fn access(dir: &Path, user: Option<String>, server: Option<String>) -> Result<()> {
    let policy = Policy::load(dir)?;
    if let Some(u) = &user {
        if !policy.users.contains_key(u) {
            bail!("no such user {u:?}");
        }
    }
    if let Some(s) = &server {
        if !policy.servers.contains_key(s) {
            bail!("no such server {s:?}");
        }
    }
    let rows: Vec<_> = policy
        .access()
        .into_iter()
        .filter(|a| user.as_ref().is_none_or(|u| *u == a.user))
        .filter(|a| server.as_ref().is_none_or(|s| *s == a.server))
        .collect();
    if rows.is_empty() {
        println!("no access");
        return Ok(());
    }
    println!("{:<20} {:<16} {:<20} VIA", "SERVER", "LOGIN", "USER");
    for a in rows {
        println!(
            "{:<20} {:<16} {:<20} {}",
            a.server,
            a.login,
            a.user,
            a.via.join(", ")
        );
    }
    Ok(())
}

fn generate(
    dir: &Path,
    server: Option<String>,
    login: Option<String>,
    out: Option<PathBuf>,
    today: Date,
) -> Result<()> {
    let policy = Policy::load(dir)?;
    let server = match server {
        Some(s) => s,
        None => {
            let name = agent::hostname()?;
            eprintln!("using hostname {name:?} as the server name; pass --server to override");
            name
        }
    };
    let errors: Vec<_> = policy
        .validate(today)
        .into_iter()
        .filter(|i| i.severity == Severity::Error)
        .collect();
    if !errors.is_empty() {
        for e in &errors {
            eprintln!("{e}");
        }
        bail!("refusing to generate from an invalid policy");
    }

    let mut logins = policy.deployed_keys(&server, today)?;
    if let Some(l) = &login {
        logins.retain(|name, _| name == l);
        if logins.is_empty() {
            bail!("server {server:?} has no login {l:?}");
        }
    }
    let revision = git::revision(dir);
    match out {
        Some(out) => {
            let report = deploy::install(&out, &server, &logins, revision.as_deref())?;
            println!("{}: {}", out.display(), report.summary());
        }
        None => {
            for (name, keys) in &logins {
                print!(
                    "{}",
                    deploy::render(&server, name, keys, revision.as_deref())
                );
            }
        }
    }
    Ok(())
}

fn commit(dir: &Path, message: &str, today: Date) -> Result<()> {
    validate(dir, today, false)?;
    if !git::is_repo(dir) {
        bail!(
            "{} is not inside a Git repository; run `gk init` or `git init`",
            dir.display()
        );
    }
    if git::commit_all(dir, message)? {
        println!("committed {}", git::revision(dir).unwrap_or_default());
    } else {
        println!("nothing to commit");
    }
    Ok(())
}

fn agent_init(args: AgentInit) -> Result<()> {
    if args.config.exists() && !args.force {
        bail!(
            "{} already exists; pass --force to overwrite",
            args.config.display()
        );
    }
    let source = match (args.git_url, args.local) {
        (Some(url), None) => Source::Git {
            url,
            branch: args.branch,
            ssh_key: args.ssh_key,
            checkout_dir: args.checkout_dir,
            subdir: args.subdir,
        },
        (None, Some(path)) => Source::Local { path },
        _ => unreachable!("clap enforces exactly one source"),
    };
    let config = AgentConfig {
        server: args.server,
        output_dir: args.output_dir,
        interval_secs: args.interval,
        source,
    };
    config.save(&args.config)?;
    println!("wrote {}", args.config.display());
    println!(
        "point sshd at it with `AuthorizedKeysFile {}/%u`, then run `gk agent run --config {}`",
        config.output_dir.display(),
        args.config.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn derives_device_names_from_comments() {
        assert_eq!(
            device_from_comment("alice@Work-Laptop").as_deref(),
            Some("work-laptop")
        );
        assert_eq!(
            device_from_comment("yubikey 5c").as_deref(),
            Some("yubikey-5c")
        );
        assert_eq!(device_from_comment("@@@"), None);
        assert_eq!(device_from_comment("a@..b").as_deref(), Some("b"));
    }
}
