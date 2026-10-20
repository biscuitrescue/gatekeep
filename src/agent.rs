//! Server-side agent: pulls the policy, validates it and installs the
//! `authorized_keys` files for this server.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::date::Date;
use crate::deploy::{self, Report};
use crate::git;
use crate::policy::{Policy, Severity, write_toml};

pub const DEFAULT_CONFIG: &str = "/etc/gatekeep/agent.toml";
pub const DEFAULT_OUTPUT_DIR: &str = "/etc/ssh/authorized_keys.d";
pub const DEFAULT_CHECKOUT_DIR: &str = "/var/lib/gatekeep/policy";
pub const DEFAULT_INTERVAL_SECS: u64 = 60;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    /// Server name in the policy. Defaults to the machine's hostname.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(default = "default_output_dir")]
    pub output_dir: PathBuf,
    #[serde(default = "default_interval")]
    pub interval_secs: u64,
    pub source: Source,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum Source {
    /// Clone/fetch a Git repository.
    Git {
        url: String,
        #[serde(default = "default_branch")]
        branch: String,
        /// Deploy key used for SSH remotes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ssh_key: Option<PathBuf>,
        #[serde(default = "default_checkout_dir")]
        checkout_dir: PathBuf,
        /// Policy location inside the repository, if not at its root.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        subdir: Option<PathBuf>,
    },
    /// Read a directory kept up to date by something else.
    Local { path: PathBuf },
}

fn default_output_dir() -> PathBuf {
    DEFAULT_OUTPUT_DIR.into()
}
fn default_interval() -> u64 {
    DEFAULT_INTERVAL_SECS
}
fn default_branch() -> String {
    "main".into()
}
fn default_checkout_dir() -> PathBuf {
    DEFAULT_CHECKOUT_DIR.into()
}

impl AgentConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| {
            format!(
                "couldn't read agent config {}; create it with `gk agent init`",
                path.display()
            )
        })?;
        toml::from_str(&text).with_context(|| format!("invalid agent config {}", path.display()))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        write_toml(path, self)
    }

    pub fn server_name(&self) -> Result<String> {
        match &self.server {
            Some(name) => Ok(name.clone()),
            None => hostname(),
        }
    }
}

pub fn hostname() -> Result<String> {
    let name = hostname::get().context("couldn't read hostname")?;
    let name = name.to_string_lossy();
    // Policy names are lowercase and unqualified.
    Ok(name.split('.').next().unwrap_or(&name).to_lowercase())
}

/// Fetches the policy, validates it and installs keys once.
pub fn sync_once(config: &AgentConfig, today: Date) -> Result<(Report, Option<String>)> {
    let (dir, revision) = match &config.source {
        Source::Git {
            url,
            branch,
            ssh_key,
            checkout_dir,
            subdir,
        } => {
            let rev = git::sync(url, branch, checkout_dir, ssh_key.as_deref())
                .with_context(|| format!("couldn't sync policy from {url} ({branch})"))?;
            let dir = match subdir {
                Some(sub) => checkout_dir.join(sub),
                None => checkout_dir.clone(),
            };
            (dir, Some(rev))
        }
        Source::Local { path } => (path.clone(), git::revision(path)),
    };

    let policy = Policy::load(&dir)?;
    let errors: Vec<String> = policy
        .validate(today)
        .into_iter()
        .filter(|i| i.severity == Severity::Error)
        .map(|i| i.to_string())
        .collect();
    if !errors.is_empty() {
        bail!(
            "refusing to apply invalid policy ({} error(s)); existing keys left untouched:\n  {}",
            errors.len(),
            errors.join("\n  ")
        );
    }

    let server = config.server_name()?;
    let logins = policy.deployed_keys(&server, today)?;
    let report = deploy::install(&config.output_dir, &server, &logins, revision.as_deref())?;
    Ok((report, revision))
}

/// Runs the sync loop until SIGINT/SIGTERM. With `once`, syncs a single
/// time and returns its error, if any.
pub fn run(config: &AgentConfig, once: bool) -> Result<()> {
    if once {
        let (report, rev) = sync_once(config, Date::today())?;
        log(&format!(
            "applied policy {}: {}",
            rev.as_deref().unwrap_or("(no git)"),
            report.summary()
        ));
        return Ok(());
    }

    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    ctrlc::set_handler(move || flag.store(true, Ordering::SeqCst))
        .context("couldn't install signal handler")?;

    log(&format!(
        "starting: server {}, output {}, every {}s",
        config.server_name()?,
        config.output_dir.display(),
        config.interval_secs
    ));
    let mut last_rev: Option<String> = None;
    while !stop.load(Ordering::SeqCst) {
        match sync_once(config, Date::today()) {
            Ok((report, rev)) => {
                if rev != last_rev || !report.written.is_empty() || !report.removed.is_empty() {
                    log(&format!(
                        "applied policy {}: {}",
                        rev.as_deref().unwrap_or("(no git)"),
                        report.summary()
                    ));
                }
                last_rev = rev;
            }
            Err(e) => log(&format!("sync failed: {e:#}")),
        }
        for _ in 0..config.interval_secs.max(1) {
            if stop.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    log("stopping");
    Ok(())
}

fn log(message: &str) {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let day = Date::from_days((secs / 86_400) as i64);
    let t = secs % 86_400;
    eprintln!(
        "{day}T{:02}:{:02}:{:02}Z gk-agent: {message}",
        t / 3600,
        t / 60 % 60,
        t % 60
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_git_config_with_defaults() {
        let config: AgentConfig = toml::from_str(
            r#"
            [source]
            type = "git"
            url = "git@github.com:corp/access.git"
            "#,
        )
        .unwrap();
        assert_eq!(config.output_dir, PathBuf::from(DEFAULT_OUTPUT_DIR));
        assert_eq!(config.interval_secs, DEFAULT_INTERVAL_SECS);
        match config.source {
            Source::Git {
                branch,
                checkout_dir,
                ..
            } => {
                assert_eq!(branch, "main");
                assert_eq!(checkout_dir, PathBuf::from(DEFAULT_CHECKOUT_DIR));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn rejects_unknown_fields() {
        let err = toml::from_str::<AgentConfig>(
            "[source]\ntype = \"local\"\npath = \"/p\"\nssh_key = \"x\"\n",
        )
        .unwrap_err();
        assert!(err.to_string().contains("ssh_key"), "{err}");
    }

    #[test]
    fn round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.toml");
        let config = AgentConfig {
            server: Some("web-1".into()),
            output_dir: "/tmp/keys".into(),
            interval_secs: 5,
            source: Source::Local {
                path: "/srv/policy".into(),
            },
        };
        config.save(&path).unwrap();
        assert_eq!(AgentConfig::load(&path).unwrap(), config);
    }
}
