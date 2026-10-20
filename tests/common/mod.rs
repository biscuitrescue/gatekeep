#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;

use assert_cmd::Command;
use tempfile::TempDir;

pub const ALICE_LAPTOP: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAmKxq7w3LYLq9/o8LH8jKZr9v0RovlSnlbNWEUlCH3b alice@laptop";
pub const BOB_DESKTOP: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOhSC0UA0DzaFND0hy22S59lcDrvIAvZCS0BTsd6CeIc bob@desktop";
pub const CAROL_LAPTOP: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIif44nJno4ymAZUAqSam2l+vNKhUvpQxa8s0U68jaLW carol@Work-Laptop";

pub const TODAY: &str = "2026-10-20";

/// Git environment isolated from the developer's config (signing, hooks...).
pub fn git_env(cmd: &mut StdCommand) -> &mut StdCommand {
    cmd.env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "Test")
        .env("GIT_AUTHOR_EMAIL", "test@example.com")
        .env("GIT_COMMITTER_NAME", "Test")
        .env("GIT_COMMITTER_EMAIL", "test@example.com")
}

/// `gk` with a fixed date and isolated Git config, run inside `cwd`.
pub fn gk(cwd: &Path) -> Command {
    let mut std = StdCommand::new(env!("CARGO_BIN_EXE_gk"));
    std.current_dir(cwd)
        .env("GK_TODAY", TODAY)
        .env_remove("GK_POLICY")
        .env_remove("GK_AGENT_CONFIG");
    git_env(&mut std);
    Command::from_std(std)
}

pub fn git(dir: &Path, args: &[&str]) -> String {
    let out = git_env(StdCommand::new("git").arg("-C").arg(dir).args(args))
        .output()
        .expect("git runs");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// A fresh policy with alice (devs), bob (ops) and server web-1.
pub struct Fixture {
    pub tmp: TempDir,
}

impl Fixture {
    pub fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let f = Self { tmp };
        gk(f.root()).args(["init", "policy"]).assert().success();
        gk(&f.policy())
            .args([
                "user",
                "add",
                "alice",
                "--group",
                "devs",
                "--email",
                "alice@example.com",
            ])
            .assert()
            .success();
        gk(&f.policy())
            .args(["user", "add", "bob", "--group", "ops"])
            .assert()
            .success();
        gk(&f.policy())
            .args([
                "key",
                "add",
                "alice",
                "--device",
                "laptop",
                "--key",
                ALICE_LAPTOP,
            ])
            .assert()
            .success();
        gk(&f.policy())
            .args(["key", "add", "bob", "--key", BOB_DESKTOP])
            .assert()
            .success();
        f.write_server(
            "web-1",
            "[logins.deploy]\ngroups = [\"devs\"]\n\n[logins.root]\ngroups = [\"ops\"]\n",
        );
        f
    }

    pub fn root(&self) -> &Path {
        self.tmp.path()
    }

    pub fn policy(&self) -> PathBuf {
        self.tmp.path().join("policy")
    }

    pub fn write_server(&self, name: &str, toml: &str) {
        fs::write(self.policy().join(format!("servers/{name}.toml")), toml).unwrap();
    }

    pub fn path(&self, rel: &str) -> PathBuf {
        self.tmp.path().join(rel)
    }

    pub fn read(&self, rel: &str) -> String {
        fs::read_to_string(self.path(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
    }
}
