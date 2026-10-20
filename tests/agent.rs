mod common;

use std::fs;

use common::*;
use predicates::str::contains;

fn agent_init(f: &Fixture, source_args: &[&str]) {
    gk(f.root())
        .args([
            "agent",
            "init",
            "--config",
            "agent.toml",
            "--server",
            "web-1",
            "--output-dir",
            "keys",
        ])
        .args(source_args)
        .assert()
        .success()
        .stdout(contains("AuthorizedKeysFile"));
}

#[test]
fn agent_init_writes_config_and_refuses_to_overwrite() {
    let f = Fixture::new();
    agent_init(&f, &["--local", "policy"]);
    let config = f.read("agent.toml");
    assert!(config.contains("type = \"local\""), "{config}");
    assert!(config.contains("server = \"web-1\""), "{config}");

    gk(f.root())
        .args([
            "agent",
            "init",
            "--config",
            "agent.toml",
            "--local",
            "policy",
        ])
        .assert()
        .failure()
        .stderr(contains("--force"));
    gk(f.root())
        .args([
            "agent",
            "init",
            "--config",
            "agent.toml",
            "--local",
            "policy",
            "--force",
        ])
        .assert()
        .success();

    // exactly one source is required
    gk(f.root())
        .args(["agent", "init", "--config", "other.toml"])
        .assert()
        .failure();
}

#[test]
fn agent_run_requires_a_config() {
    let f = Fixture::new();
    gk(f.root())
        .args(["agent", "run", "--once", "--config", "missing.toml"])
        .assert()
        .failure()
        .stderr(contains("gk agent init"));
}

#[test]
fn agent_once_from_local_directory() {
    let f = Fixture::new();
    agent_init(&f, &["--local", "policy"]);
    gk(f.root())
        .args(["agent", "run", "--once", "--config", "agent.toml"])
        .assert()
        .success()
        .stderr(contains("2 written"));
    assert!(f.read("keys/deploy").contains("alice@laptop"));
    assert!(f.read("keys/root").contains("bob@desktop"));
}

#[test]
fn agent_keeps_last_good_keys_when_policy_breaks() {
    let f = Fixture::new();
    agent_init(&f, &["--local", "policy"]);
    gk(f.root())
        .args(["agent", "run", "--once", "-c", "agent.toml"])
        .assert()
        .success();
    let before = f.read("keys/deploy");

    f.write_server("web-1", "[logins.deploy]\nusers = [\"ghost\"]\n");
    gk(f.root())
        .args(["agent", "run", "--once", "-c", "agent.toml"])
        .assert()
        .failure()
        .stderr(contains("refusing to apply invalid policy"))
        .stderr(contains("unknown user \"ghost\""));
    assert_eq!(f.read("keys/deploy"), before);
    assert!(f.path("keys/root").exists());
}

#[test]
fn agent_errors_when_server_is_not_in_policy() {
    let f = Fixture::new();
    gk(f.root())
        .args([
            "agent",
            "init",
            "-c",
            "agent.toml",
            "--server",
            "web-9",
            "--output-dir",
            "keys",
            "--local",
            "policy",
        ])
        .assert()
        .success();
    fs::create_dir_all(f.path("keys")).unwrap();
    fs::write(f.path("keys/deploy"), "# Managed by gatekeep\nkeep me\n").unwrap();
    gk(f.root())
        .args(["agent", "run", "--once", "-c", "agent.toml"])
        .assert()
        .failure()
        .stderr(contains("\"web-9\" is not defined"));
    assert!(
        f.path("keys/deploy").exists(),
        "a typo in the server name must not wipe access"
    );
}

#[test]
fn agent_syncs_from_git_and_applies_revocations() {
    let f = Fixture::new();
    let p = f.policy();
    gk(&p).args(["commit", "-m", "initial"]).assert().success();

    // Publish the policy to a bare "remote".
    let remote = f.path("remote.git");
    git(
        f.root(),
        &["init", "--quiet", "--bare", remote.to_str().unwrap()],
    );
    git(
        &p,
        &[
            "push",
            "--quiet",
            remote.to_str().unwrap(),
            "HEAD:refs/heads/main",
        ],
    );
    let url = format!("file://{}", remote.display());

    agent_init(
        &f,
        &[
            "--git-url",
            &url,
            "--branch",
            "main",
            "--checkout-dir",
            "checkout",
        ],
    );
    let rev1 = git(&p, &["rev-parse", "--short", "HEAD"]);
    gk(f.root())
        .args(["agent", "run", "--once", "-c", "agent.toml"])
        .assert()
        .success()
        .stderr(contains(format!("applied policy {rev1}")));
    let deploy = f.read("keys/deploy");
    assert!(deploy.contains("alice@laptop"));
    assert!(deploy.contains(&format!("policy revision: {rev1}")));

    // Revoke alice and drop the root login, then push.
    gk(&p)
        .args(["key", "revoke", "alice", "--device", "laptop"])
        .assert()
        .success();
    f.write_server("web-1", "[logins.deploy]\ngroups = [\"devs\"]\n");
    gk(&p)
        .args(["commit", "-m", "offboard alice laptop; drop root"])
        .assert()
        .success();
    git(
        &p,
        &[
            "push",
            "--quiet",
            remote.to_str().unwrap(),
            "HEAD:refs/heads/main",
        ],
    );

    gk(f.root())
        .args(["agent", "run", "--once", "-c", "agent.toml"])
        .assert()
        .success()
        .stderr(contains("1 removed"));
    assert!(!f.read("keys/deploy").contains("alice@laptop"));
    assert!(
        !f.path("keys/root").exists(),
        "managed file for dropped login is removed"
    );
}
