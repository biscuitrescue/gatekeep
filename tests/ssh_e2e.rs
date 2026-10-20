//! Real OpenSSH round trip: gatekeep installs keys, an unprivileged sshd reads
//! them, and `ssh` either gets in or is refused.
//!
//! Skipped (with a note) when `sshd`, `ssh` or `ssh-keygen` are missing.
//! Set `GK_REQUIRE_SSH_E2E=1` to make a missing toolchain a failure (CI does),
//! or `GK_SKIP_SSH_E2E=1` to skip it outright.

mod common;

use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use common::*;

/// Set to anything but empty or `0`.
fn flag(name: &str) -> bool {
    std::env::var(name).is_ok_and(|v| !v.is_empty() && v != "0")
}

fn find(bin: &str) -> Option<PathBuf> {
    [
        "/usr/sbin",
        "/usr/bin",
        "/usr/local/sbin",
        "/usr/local/bin",
        "/opt/homebrew/sbin",
    ]
    .iter()
    .map(|d| Path::new(d).join(bin))
    .find(|p| p.exists())
}

struct Sshd {
    child: Child,
    port: u16,
}

impl Drop for Sshd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_sshd(sshd: &Path, dir: &Path, keys_dir: &Path) -> Sshd {
    let host_key = dir.join("host_ed25519");
    assert!(
        Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&host_key)
            .status()
            .unwrap()
            .success()
    );
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let config = dir.join("sshd_config");
    fs::write(
        &config,
        format!(
            "Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nPidFile {}\n\
             AuthorizedKeysFile {}/%u\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n\
             PubkeyAuthentication yes\nStrictModes no\nUsePAM no\n",
            host_key.display(),
            dir.join("sshd.pid").display(),
            keys_dir.display()
        ),
    )
    .unwrap();
    let child = Command::new(sshd)
        .args(["-D", "-e", "-f"])
        .arg(&config)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start sshd");

    let deadline = Instant::now() + Duration::from_secs(10);
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "sshd did not start");
        std::thread::sleep(Duration::from_millis(100));
    }
    Sshd { child, port }
}

fn can_login(identity: &Path, login: &str, port: u16) -> bool {
    Command::new("ssh")
        .args([
            "-F",
            "/dev/null",
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
        ])
        .args([
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
        ])
        .args(["-o", "LogLevel=ERROR", "-p", &port.to_string(), "-i"])
        .arg(identity)
        .arg(format!("{login}@127.0.0.1"))
        .arg("true")
        .stdin(Stdio::null())
        .status()
        .unwrap()
        .success()
}

fn keygen(path: &Path) -> String {
    assert!(
        Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-C", "test", "-f"])
            .arg(path)
            .status()
            .unwrap()
            .success()
    );
    fs::read_to_string(path.with_extension("pub"))
        .unwrap()
        .trim()
        .to_owned()
}

#[test]
fn sshd_honours_gatekeep_keys() {
    if flag("GK_SKIP_SSH_E2E") {
        eprintln!("skipping: GK_SKIP_SSH_E2E is set");
        return;
    }
    let tools = (find("sshd"), find("ssh"), find("ssh-keygen"));
    let (Some(sshd), Some(_), Some(_)) = tools else {
        assert!(
            !flag("GK_REQUIRE_SSH_E2E"),
            "GK_REQUIRE_SSH_E2E is set but OpenSSH tools are missing"
        );
        eprintln!("skipping: sshd/ssh/ssh-keygen not found");
        return;
    };
    // An unprivileged sshd only accepts logins as the user running it.
    let login = std::env::var("USER").unwrap_or_else(|_| {
        String::from_utf8(Command::new("id").arg("-un").output().unwrap().stdout)
            .unwrap()
            .trim()
            .to_owned()
    });

    let f = Fixture::new();
    let p = f.policy();
    let alice_id = f.path("alice_id");
    let carol_id = f.path("carol_id");
    let alice_pub = keygen(&alice_id);
    let carol_pub = keygen(&carol_id);

    gk(&p)
        .args(["user", "add", "carol", "-g", "devs"])
        .assert()
        .success();
    gk(&p)
        .args([
            "key", "add", "alice", "--device", "e2e", "--key", &alice_pub,
        ])
        .assert()
        .success();
    // Long expired by the real clock. The agent below runs with its clock
    // pinned to 2000-01-01, so it deploys the key: sshd itself must refuse it.
    gk(&p)
        .args([
            "key",
            "add",
            "carol",
            "--device",
            "e2e",
            "--key",
            &carol_pub,
            "--expires",
            "2001-01-01",
        ])
        .assert()
        .success();
    f.write_server("e2e", &format!("[logins.{login}]\ngroups = [\"devs\"]\n"));

    let keys = f.path("keys");
    gk(f.root())
        .args([
            "agent",
            "init",
            "-c",
            "agent.toml",
            "--server",
            "e2e",
            "--local",
            "policy",
            "--output-dir",
        ])
        .arg(&keys)
        .assert()
        .success();
    gk(f.root())
        .env("GK_TODAY", "2000-01-01")
        .args(["agent", "run", "--once", "-c", "agent.toml"])
        .assert()
        .success();
    assert!(
        f.read(&format!("keys/{login}"))
            .contains("expiry-time=\"20010101\"")
    );

    let server = start_sshd(&sshd, f.root(), &keys);
    assert!(
        can_login(&alice_id, &login, server.port),
        "alice should get in"
    );
    assert!(
        !can_login(&carol_id, &login, server.port),
        "sshd must enforce expiry-time"
    );

    gk(&p).args(["user", "disable", "alice"]).assert().success();
    gk(f.root())
        .env("GK_TODAY", "2000-01-01")
        .args(["agent", "run", "--once", "-c", "agent.toml"])
        .assert()
        .success();
    assert!(
        !can_login(&alice_id, &login, server.port),
        "disabled user is locked out"
    );
}
