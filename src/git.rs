//! Thin wrapper over the `git` binary.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    pub hash: String,
    pub author: String,
    pub date: String,
    pub subject: String,
}

fn git(dir: &Path) -> Command {
    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(dir);
    cmd
}

fn run(mut cmd: Command) -> Result<String> {
    let output = cmd
        .output()
        .context("couldn't run git; is it installed and on PATH?")?;
    if !output.status.success() {
        bail!(
            "git failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

pub fn is_repo(dir: &Path) -> bool {
    let mut cmd = git(dir);
    cmd.args(["rev-parse", "--is-inside-work-tree"]);
    run(cmd).is_ok_and(|out| out == "true")
}

pub fn init(dir: &Path) -> Result<()> {
    let mut cmd = git(dir);
    cmd.args(["init", "--quiet"]);
    run(cmd).map(drop)
}

/// Short hash of `HEAD`, if `dir` is in a repository with at least one commit.
pub fn revision(dir: &Path) -> Option<String> {
    let mut cmd = git(dir);
    cmd.args(["rev-parse", "--short", "HEAD"]);
    run(cmd).ok()
}

/// Recent commits touching `dir`, newest first.
pub fn log(dir: &Path, limit: usize) -> Vec<Commit> {
    let mut cmd = git(dir);
    cmd.args([
        "log",
        &format!("-n{limit}"),
        "--date=short",
        "--format=%h%x1f%an%x1f%ad%x1f%s",
        "--",
        ".",
    ]);
    let Ok(out) = run(cmd) else {
        return Vec::new();
    };
    out.lines()
        .filter_map(|line| {
            let mut parts = line.splitn(4, '\x1f');
            Some(Commit {
                hash: parts.next()?.to_owned(),
                author: parts.next()?.to_owned(),
                date: parts.next()?.to_owned(),
                subject: parts.next()?.to_owned(),
            })
        })
        .collect()
}

/// Stages everything under `dir` and commits it. Returns `false` when there
/// was nothing to commit.
pub fn commit_all(dir: &Path, message: &str) -> Result<bool> {
    let mut add = git(dir);
    add.args(["add", "--all", "--", "."]);
    run(add)?;

    let mut status = git(dir);
    status.args(["status", "--porcelain", "--", "."]);
    if run(status)?.is_empty() {
        return Ok(false);
    }

    let mut commit = git(dir);
    commit.args(["commit", "--quiet", "-m", message, "--", "."]);
    run(commit)?;
    Ok(true)
}

/// Clones `url` into `dest`, or hard-resets an existing checkout to the
/// remote branch tip, discarding local changes. Returns the new revision.
pub fn sync(url: &str, branch: &str, dest: &Path, ssh_key: Option<&Path>) -> Result<String> {
    // Host keys are pinned on first contact in a file next to the checkout,
    // so the agent doesn't depend on root's ~/.ssh.
    let known_hosts = dest.with_extension("known_hosts");
    let with_key = |mut cmd: Command| {
        if let Some(key) = ssh_key {
            cmd.env(
                "GIT_SSH_COMMAND",
                format!(
                    "ssh -i '{}' -o IdentitiesOnly=yes -o BatchMode=yes \
                     -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile='{}'",
                    key.display(),
                    known_hosts.display()
                ),
            );
        }
        cmd
    };

    if dest.join(".git").exists() {
        let mut fetch = git(dest);
        fetch.args(["fetch", "--quiet", "--depth=1", url, branch]);
        run(with_key(fetch))?;
        let mut reset = git(dest);
        reset.args(["reset", "--quiet", "--hard", "FETCH_HEAD"]);
        run(reset)?;
    } else {
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut clone = Command::new("git");
        clone
            .args(["clone", "--quiet", "--depth=1", "--branch", branch, url])
            .arg(dest);
        run(with_key(clone))?;
    }
    revision(dest).context("checkout has no HEAD revision")
}
