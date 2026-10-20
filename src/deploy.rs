//! Rendering and atomically installing `authorized_keys` files.
//!
//! Output is one file per unix login (`<dir>/<login>`), matching an sshd
//! setting of `AuthorizedKeysFile /etc/ssh/authorized_keys.d/%u`.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::policy::{DeployedKey, is_valid_login};

/// First line of every file gatekeep writes. Files without it are never removed.
pub const MARKER: &str = "# Managed by gatekeep";

pub fn render(server: &str, login: &str, keys: &[DeployedKey], revision: Option<&str>) -> String {
    let mut out = format!("{MARKER}. Do not edit: changes are overwritten on the next sync.\n");
    out.push_str(&format!("# server: {server}  login: {login}"));
    if let Some(rev) = revision {
        out.push_str(&format!("  policy revision: {rev}"));
    }
    out.push('\n');
    for key in keys {
        out.push_str(&key.authorized_keys_line());
        out.push('\n');
    }
    out
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub written: Vec<String>,
    pub unchanged: Vec<String>,
    pub removed: Vec<String>,
}

impl Report {
    pub fn summary(&self) -> String {
        format!(
            "{} written, {} unchanged, {} removed",
            self.written.len(),
            self.unchanged.len(),
            self.removed.len()
        )
    }
}

/// Writes one file per login into `dir` and removes managed files for logins
/// that no longer exist in the policy.
pub fn install(
    dir: &Path,
    server: &str,
    logins: &BTreeMap<String, Vec<DeployedKey>>,
    revision: Option<&str>,
) -> Result<Report> {
    fs::create_dir_all(dir).with_context(|| format!("couldn't create {}", dir.display()))?;
    let mut report = Report::default();

    for (login, keys) in logins {
        if !is_valid_login(login) {
            bail!("refusing to write invalid login name {login:?}");
        }
        let path = dir.join(login);
        let content = render(server, login, keys, revision);
        if fs::read_to_string(&path).is_ok_and(|old| old == content) {
            report.unchanged.push(login.clone());
            continue;
        }
        write_atomic(dir, login, &content)?;
        report.written.push(login.clone());
    }

    let mut entries: Vec<_> = fs::read_dir(dir)
        .with_context(|| format!("couldn't read {}", dir.display()))?
        .filter_map(|e| e.ok())
        .collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if logins.contains_key(&name) || name.starts_with('.') || !entry.path().is_file() {
            continue;
        }
        let managed = fs::read_to_string(entry.path()).is_ok_and(|c| c.starts_with(MARKER));
        if managed {
            fs::remove_file(entry.path())
                .with_context(|| format!("couldn't remove {}", entry.path().display()))?;
            report.removed.push(name);
        }
    }
    Ok(report)
}

fn write_atomic(dir: &Path, login: &str, content: &str) -> Result<()> {
    let tmp = dir.join(format!(".{login}.gk-tmp"));
    let path = dir.join(login);
    fs::write(&tmp, content).with_context(|| format!("couldn't write {}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // sshd's StrictModes rejects group/world-writable key files.
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o644))?;
    }
    fs::rename(&tmp, &path).with_context(|| format!("couldn't replace {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::tests::fixture;

    fn keys() -> BTreeMap<String, Vec<DeployedKey>> {
        fixture()
            .deployed_keys("web-1", "2026-10-20".parse().unwrap())
            .unwrap()
    }

    #[test]
    fn renders_header_and_keys() {
        let out = render("web-1", "deploy", &keys()["deploy"], Some("abc1234"));
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[0].starts_with(MARKER));
        assert_eq!(
            lines[1],
            "# server: web-1  login: deploy  policy revision: abc1234"
        );
        assert!(lines[2].ends_with("alice@laptop"));
        assert!(lines[3].ends_with("carol@laptop"));
        assert_eq!(lines.len(), 4);
    }

    #[test]
    fn installs_updates_and_prunes_only_managed_files() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("handmade"), "ssh-ed25519 AAAA manual\n").unwrap();
        fs::write(
            dir.path().join("olduser"),
            format!("{MARKER}\nssh-ed25519 AAAA x\n"),
        )
        .unwrap();

        let mut logins = keys();
        let report = install(dir.path(), "web-1", &logins, None).unwrap();
        assert_eq!(report.written, vec!["deploy", "root"]);
        assert_eq!(report.removed, vec!["olduser"]);
        assert!(dir.path().join("handmade").exists());

        let again = install(dir.path(), "web-1", &logins, None).unwrap();
        assert_eq!(again.unchanged, vec!["deploy", "root"]);
        assert!(again.written.is_empty());

        logins.remove("root");
        let pruned = install(dir.path(), "web-1", &logins, None).unwrap();
        assert_eq!(pruned.removed, vec!["root"]);
        assert!(!dir.path().join("root").exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.path().join("deploy"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o644);
        }
    }

    #[test]
    fn refuses_path_traversal() {
        let dir = tempfile::tempdir().unwrap();
        let mut logins = BTreeMap::new();
        logins.insert("../evil".to_string(), Vec::new());
        assert!(install(dir.path(), "web-1", &logins, None).is_err());
    }
}
