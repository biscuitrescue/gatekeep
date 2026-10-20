//! Policy repository model.
//!
//! A policy is a directory (usually a Git repository) laid out as:
//!
//! ```text
//! users/<name>.toml     one file per person or service account, with their device keys
//! servers/<name>.toml   one file per server, mapping unix logins to users/groups
//! ```

mod access;
mod validate;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::date::Date;
use crate::key::PublicKey;

pub use access::{Access, DeployedKey};
pub use validate::{EXPIRY_WARNING_DAYS, Issue, Severity};

pub const USERS_DIR: &str = "users";
pub const SERVERS_DIR: &str = "servers";

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    /// Taken from the file name, never serialized.
    #[serde(skip)]
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
    /// Disabled users keep their history but are deployed nowhere.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disabled: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<KeyEntry>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyEntry {
    /// Device the private key lives on, e.g. `laptop` or `yubikey`.
    pub device: String,
    /// OpenSSH public key line: `[options] <type> <base64> [comment]`.
    pub key: String,
    /// Optional `YYYY-MM-DD`; the key stops being deployed on this date.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub added: Option<String>,
}

impl KeyEntry {
    pub fn public_key(&self) -> Result<PublicKey> {
        PublicKey::parse(&self.key)
    }

    pub fn expiry(&self) -> Result<Option<Date>> {
        self.expires.as_deref().map(str::parse).transpose()
    }

    /// True when the key has an expiry date that is today or earlier.
    pub fn is_expired(&self, today: Date) -> bool {
        matches!(self.expiry(), Ok(Some(expiry)) if expiry <= today)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Server {
    #[serde(skip)]
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Unix login name -> who may log in as it.
    #[serde(default)]
    pub logins: BTreeMap<String, Grant>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Policy {
    pub root: PathBuf,
    pub users: BTreeMap<String, User>,
    pub servers: BTreeMap<String, Server>,
}

impl Policy {
    pub fn load(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        let users_dir = root.join(USERS_DIR);
        let servers_dir = root.join(SERVERS_DIR);
        if !users_dir.is_dir() && !servers_dir.is_dir() {
            bail!(
                "{} is not a gatekeep policy directory (no {USERS_DIR}/ or {SERVERS_DIR}/); run `gk init` first",
                root.display()
            );
        }

        let users = load_dir(&users_dir, |name, mut user: User| {
            user.name = name;
            user
        })?;
        let servers = load_dir(&servers_dir, |name, mut server: Server| {
            server.name = name;
            server
        })?;
        Ok(Self {
            root,
            users,
            servers,
        })
    }

    /// Creates an empty policy layout at `root`.
    pub fn scaffold(root: impl AsRef<Path>) -> Result<()> {
        let root = root.as_ref();
        for dir in [USERS_DIR, SERVERS_DIR] {
            let path = root.join(dir);
            fs::create_dir_all(&path)
                .with_context(|| format!("couldn't create {}", path.display()))?;
            let keep = path.join(".gitkeep");
            if !keep.exists() {
                fs::write(&keep, "")?;
            }
        }
        Ok(())
    }

    pub fn user_path(&self, name: &str) -> PathBuf {
        self.root.join(USERS_DIR).join(format!("{name}.toml"))
    }

    pub fn server_path(&self, name: &str) -> PathBuf {
        self.root.join(SERVERS_DIR).join(format!("{name}.toml"))
    }

    pub fn user_mut(&mut self, name: &str) -> Result<&mut User> {
        self.users
            .get_mut(name)
            .with_context(|| format!("no such user {name:?}"))
    }

    pub fn save_user(&self, user: &User) -> Result<()> {
        if !is_valid_name(&user.name) {
            bail!("invalid user name {:?}", user.name);
        }
        write_toml(&self.user_path(&user.name), user)
    }

    pub fn save_server(&self, server: &Server) -> Result<()> {
        if !is_valid_name(&server.name) {
            bail!("invalid server name {:?}", server.name);
        }
        write_toml(&self.server_path(&server.name), server)
    }

    /// Members of `group` (disabled users included).
    pub fn group_members(&self, group: &str) -> impl Iterator<Item = &User> {
        self.users
            .values()
            .filter(move |u| u.groups.iter().any(|g| g == group))
    }

    /// Every group mentioned by a user, sorted.
    pub fn groups(&self) -> Vec<String> {
        let mut groups: Vec<String> = self
            .users
            .values()
            .flat_map(|u| u.groups.iter().cloned())
            .collect();
        groups.sort();
        groups.dedup();
        groups
    }
}

fn load_dir<T, F>(dir: &Path, finish: F) -> Result<BTreeMap<String, T>>
where
    T: serde::de::DeserializeOwned,
    F: Fn(String, T) -> T,
{
    let mut out = BTreeMap::new();
    if !dir.is_dir() {
        return Ok(out);
    }
    let mut paths: Vec<PathBuf> = fs::read_dir(dir)
        .with_context(|| format!("couldn't read {}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|e| e == "toml"))
        .collect();
    paths.sort();

    for path in paths {
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .with_context(|| format!("non UTF-8 file name {}", path.display()))?
            .to_owned();
        let text = fs::read_to_string(&path)
            .with_context(|| format!("couldn't read {}", path.display()))?;
        let value: T =
            toml::from_str(&text).with_context(|| format!("invalid TOML in {}", path.display()))?;
        out.insert(name.clone(), finish(name, value));
    }
    Ok(out)
}

pub(crate) fn write_toml<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("couldn't create {}", parent.display()))?;
    }
    let text = toml::to_string_pretty(value).context("couldn't serialize TOML")?;
    fs::write(path, text).with_context(|| format!("couldn't write {}", path.display()))
}

/// Names for users, devices, groups and servers: `[a-z0-9][a-z0-9._-]{0,63}`.
pub fn is_valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    name.len() <= 64
        && !name.contains("..")
        && chars
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "._-".contains(c))
}

/// Unix login names: `[a-z_][a-z0-9_-]{0,31}`. These become file names on
/// servers, so the check also rules out path traversal.
pub fn is_valid_login(name: &str) -> bool {
    let mut chars = name.chars();
    name.len() <= 32
        && chars
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c == '_')
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "_-".contains(c))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::key::tests::ED25519;

    pub fn fixture() -> Policy {
        let user = |name: &str, groups: &[&str], keys: Vec<KeyEntry>| User {
            name: name.into(),
            groups: groups.iter().map(|g| g.to_string()).collect(),
            keys,
            ..User::default()
        };
        let key = |device: &str, key: &str| KeyEntry {
            device: device.into(),
            key: key.into(),
            expires: None,
            added: None,
        };
        let mut users = BTreeMap::new();
        for u in [
            user("alice", &["devs"], vec![key("laptop", ED25519)]),
            user(
                "bob",
                &["ops"],
                vec![key(
                    "desktop",
                    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOhSC0UA0DzaFND0hy22S59lcDrvIAvZCS0BTsd6CeIc",
                )],
            ),
            user(
                "carol",
                &["devs", "ops"],
                vec![key(
                    "laptop",
                    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIif44nJno4ymAZUAqSam2l+vNKhUvpQxa8s0U68jaLW",
                )],
            ),
        ] {
            users.insert(u.name.clone(), u);
        }

        let mut logins = BTreeMap::new();
        logins.insert(
            "deploy".into(),
            Grant {
                groups: vec!["devs".into()],
                users: vec![],
            },
        );
        logins.insert(
            "root".into(),
            Grant {
                groups: vec!["ops".into()],
                users: vec![],
            },
        );
        let mut servers = BTreeMap::new();
        servers.insert(
            "web-1".into(),
            Server {
                name: "web-1".into(),
                description: None,
                logins,
            },
        );
        Policy {
            root: PathBuf::from("."),
            users,
            servers,
        }
    }

    #[test]
    fn name_rules() {
        for ok in ["alice", "web-1", "a.b_c", "9lives"] {
            assert!(is_valid_name(ok), "{ok}");
        }
        for bad in [
            "",
            "Alice",
            "-x",
            "a/b",
            "..",
            "a..b",
            "a b",
            &"x".repeat(65),
        ] {
            assert!(!is_valid_name(bad), "{bad}");
        }
    }

    #[test]
    fn login_rules() {
        for ok in ["root", "deploy", "_svc", "git-ro"] {
            assert!(is_valid_login(ok), "{ok}");
        }
        for bad in ["", "Root", "1abc", "../etc", "a/b", "a.b", &"x".repeat(33)] {
            assert!(!is_valid_login(bad), "{bad}");
        }
    }

    #[test]
    fn round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        Policy::scaffold(dir.path()).unwrap();
        let mut policy = fixture();
        policy.root = dir.path().to_path_buf();
        for user in policy.users.values() {
            policy.save_user(user).unwrap();
        }
        for server in policy.servers.values() {
            policy.save_server(server).unwrap();
        }

        let loaded = Policy::load(dir.path()).unwrap();
        assert_eq!(loaded.users, policy.users);
        assert_eq!(loaded.servers, policy.servers);
        assert_eq!(loaded.groups(), vec!["devs", "ops"]);
    }

    #[test]
    fn load_rejects_unknown_fields_and_missing_layout() {
        let dir = tempfile::tempdir().unwrap();
        assert!(Policy::load(dir.path()).is_err());

        Policy::scaffold(dir.path()).unwrap();
        fs::write(dir.path().join("users/alice.toml"), "groupz = [\"devs\"]\n").unwrap();
        let err = format!("{:#}", Policy::load(dir.path()).unwrap_err());
        assert!(
            err.contains("alice.toml") && err.contains("groupz"),
            "{err}"
        );
    }

    #[test]
    fn expiry_is_inclusive() {
        let entry = KeyEntry {
            device: "d".into(),
            key: ED25519.into(),
            expires: Some("2026-06-01".into()),
            added: None,
        };
        assert!(!entry.is_expired("2026-05-31".parse().unwrap()));
        assert!(entry.is_expired("2026-06-01".parse().unwrap()));
    }
}
