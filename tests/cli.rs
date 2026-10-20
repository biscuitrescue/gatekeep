mod common;

use std::fs;

use common::*;
use predicates::prelude::*;
use predicates::str::contains;

#[test]
fn init_creates_layout_git_repo_and_ci_workflow() {
    let tmp = tempfile::tempdir().unwrap();
    gk(tmp.path())
        .args(["init", "corp-access", "--ci"])
        .assert()
        .success()
        .stdout(contains("initialised Git repository"));
    let root = tmp.path().join("corp-access");
    assert!(root.join("users").is_dir());
    assert!(root.join("servers").is_dir());
    assert!(root.join(".git").is_dir());
    let workflow = fs::read_to_string(root.join(".github/workflows/gatekeep.yml")).unwrap();
    assert!(workflow.contains("gk validate"));

    gk(&root)
        .arg("validate")
        .assert()
        .success()
        .stdout(contains("0 users, 0 servers"));
}

#[test]
fn commands_fail_cleanly_outside_a_policy() {
    let tmp = tempfile::tempdir().unwrap();
    gk(tmp.path())
        .arg("validate")
        .assert()
        .failure()
        .code(1)
        .stderr(contains("not a gatekeep policy directory"));
}

#[test]
fn query_generate_and_revoke_flow() {
    let f = Fixture::new();
    let p = f.policy();

    gk(&p)
        .arg("validate")
        .assert()
        .success()
        .stdout(contains("2 users, 1 servers"));

    gk(&p)
        .args(["access", "--user", "alice"])
        .assert()
        .success()
        .stdout(
            contains("web-1")
                .and(contains("deploy"))
                .and(contains("group devs")),
        );

    gk(&p)
        .args(["generate", "--server", "web-1", "--login", "deploy"])
        .assert()
        .success()
        .stdout(contains("# Managed by gatekeep"))
        .stdout(contains("alice@laptop"))
        .stdout(contains("bob@").not());

    gk(&p)
        .args(["generate", "--server", "web-1", "--out", "../keys"])
        .assert()
        .success()
        .stdout(contains("2 written"));
    assert!(f.read("keys/deploy").contains("alice@laptop"));
    // bob's device name came from the key comment
    assert!(f.read("keys/root").contains("bob@desktop"));

    gk(&p)
        .args(["key", "revoke", "alice", "--device", "laptop"])
        .assert()
        .success();
    gk(&p)
        .args(["generate", "--server", "web-1", "--out", "../keys"])
        .assert()
        .success();
    assert!(!f.read("keys/deploy").contains("alice@laptop"));

    gk(&p)
        .args(["key", "revoke", "alice", "--device", "laptop"])
        .assert()
        .failure()
        .stderr(contains("no device \"laptop\""));
}

#[test]
fn disabling_a_user_removes_access_everywhere() {
    let f = Fixture::new();
    let p = f.policy();
    gk(&p).args(["user", "disable", "bob"]).assert().success();

    gk(&p)
        .args(["access", "--user", "bob"])
        .assert()
        .success()
        .stdout(contains("no access"));
    gk(&p)
        .args(["generate", "--server", "web-1", "--login", "root"])
        .assert()
        .success()
        .stdout(contains("bob@").not());
    gk(&p)
        .args(["key", "list", "--user", "bob"])
        .assert()
        .success()
        .stdout(contains("user-disabled"));

    gk(&p).args(["user", "enable", "bob"]).assert().success();
    gk(&p)
        .args(["generate", "--server", "web-1", "--login", "root"])
        .assert()
        .stdout(contains("bob@desktop"));
}

#[test]
fn key_import_from_authorized_keys_file() {
    let f = Fixture::new();
    let p = f.policy();
    let file = f.path("old_authorized_keys");
    fs::write(
        &file,
        format!(
            "# legacy file\n\n{CAROL_LAPTOP}\nno-pty {}\n",
            BOB_DESKTOP.replace("bob@desktop", "carol@desk")
        ),
    )
    .unwrap();

    gk(&p)
        .args(["user", "add", "carol", "-g", "devs"])
        .assert()
        .success();
    gk(&p)
        .args(["key", "add", "carol", "--file"])
        .arg(&file)
        .args(["--expires", "2027-01-01"])
        .assert()
        .success()
        .stdout(contains("added carol/work-laptop"))
        .stdout(contains("added carol/desk"));

    let user = fs::read_to_string(p.join("users/carol.toml")).unwrap();
    assert!(user.contains("device = \"work-laptop\""), "{user}");
    assert!(user.contains("expires = \"2027-01-01\""), "{user}");
    assert!(user.contains(&format!("added = \"{TODAY}\"")), "{user}");

    // carol/desk reuses bob's key material: validation must reject it.
    gk(&p)
        .arg("validate")
        .assert()
        .failure()
        .stderr(contains("same key as bob/desktop"));
    gk(&p)
        .args(["generate", "--server", "web-1"])
        .assert()
        .failure()
        .stderr(contains("refusing to generate"));
}

#[test]
fn rotate_replaces_key_material() {
    let f = Fixture::new();
    let p = f.policy();
    let new_key = CAROL_LAPTOP.replace("carol@Work-Laptop", "alice@laptop-2026");
    gk(&p)
        .args([
            "key", "rotate", "alice", "--device", "laptop", "--key", &new_key,
        ])
        .assert()
        .success()
        .stdout(contains("rotated alice/laptop to SHA256:"));
    let out = gk(&p)
        .args(["generate", "--server", "web-1", "--login", "deploy"])
        .output()
        .unwrap();
    let out = String::from_utf8(out.stdout).unwrap();
    assert!(out.contains("AAAAIIif44nJno4"), "{out}");
    assert!(!out.contains("AAAAIAmKxq7w3LY"), "{out}");
}

#[test]
fn validate_reports_errors_and_strict_fails_on_warnings() {
    let f = Fixture::new();
    let p = f.policy();
    f.write_server(
        "db-1",
        "[logins.postgres]\nusers = [\"mallory\"]\ngroups = [\"dba\"]\n",
    );
    gk(&p)
        .arg("validate")
        .assert()
        .failure()
        .stderr(contains(
            "error: servers/db-1.toml: login \"postgres\": unknown user \"mallory\"",
        ))
        .stderr(contains("warning: servers/db-1.toml"));

    f.write_server("db-1", "[logins.postgres]\ngroups = [\"dba\"]\n");
    gk(&p).arg("validate").assert().success();
    gk(&p).args(["validate", "--strict"]).assert().failure();
}

#[test]
fn mutations_reject_bad_input() {
    let f = Fixture::new();
    let p = f.policy();
    gk(&p)
        .args(["user", "add", "Alice Smith"])
        .assert()
        .failure()
        .stderr(contains("invalid user name"));
    gk(&p)
        .args(["user", "add", "alice"])
        .assert()
        .failure()
        .stderr(contains("already exists"));
    gk(&p)
        .args(["user", "disable", "nobody"])
        .assert()
        .failure()
        .stderr(contains("no such user"));
    gk(&p)
        .args([
            "key",
            "add",
            "alice",
            "--device",
            "x",
            "--key",
            "ssh-ed25519 no*pe",
        ])
        .assert()
        .failure()
        .stderr(contains("base64"));
    gk(&p)
        .args([
            "key",
            "add",
            "alice",
            "--device",
            "laptop",
            "--key",
            CAROL_LAPTOP,
        ])
        .assert()
        .failure()
        .stderr(contains("gk key rotate"));
    gk(&p)
        .args([
            "key",
            "add",
            "alice",
            "--device",
            "new",
            "--key",
            CAROL_LAPTOP,
            "--expires",
            "tomorrow",
        ])
        .assert()
        .failure()
        .stderr(contains("--expires"));
}

#[test]
fn commit_validates_then_records_history() {
    let f = Fixture::new();
    let p = f.policy();
    gk(&p)
        .args(["commit", "-m", "onboard alice and bob"])
        .assert()
        .success()
        .stdout(contains("committed"));
    assert_eq!(
        git(&p, &["log", "-1", "--format=%s"]),
        "onboard alice and bob"
    );
    gk(&p)
        .args(["commit", "-m", "noop"])
        .assert()
        .success()
        .stdout(contains("nothing to commit"));

    f.write_server("db-1", "[logins.postgres]\nusers = [\"mallory\"]\n");
    gk(&p).args(["commit", "-m", "broken"]).assert().failure();
    assert_eq!(
        git(&p, &["log", "-1", "--format=%s"]),
        "onboard alice and bob"
    );
}

#[test]
fn dashboard_includes_access_keys_and_history() {
    let f = Fixture::new();
    let p = f.policy();
    gk(&p)
        .args(["commit", "-m", "initial policy"])
        .assert()
        .success();
    gk(&p)
        .args(["dashboard", "--out", "../site"])
        .assert()
        .success()
        .stdout(contains("index.html"));
    let html = f.read("site/index.html");
    assert!(html.starts_with("<!doctype html>"));
    for needle in [
        "alice@example.com",
        "<th>web-1</th>",
        "SHA256:",
        "initial policy",
        "valid",
    ] {
        assert!(html.contains(needle), "missing {needle}");
    }
}

#[test]
fn bundled_example_policy_is_valid() {
    let examples = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/policy");
    gk(std::path::Path::new(examples))
        .args(["validate", "--strict"])
        .assert()
        .success()
        .stdout(contains("5 users, 3 servers"));
}
