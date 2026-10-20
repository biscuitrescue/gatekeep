use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};

use super::Policy;
use crate::date::Date;
use crate::key::{PublicKey, Strength};

/// One resolved permission: `user` may log in to `server` as `login`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Access {
    pub server: String,
    pub login: String,
    pub user: String,
    /// Why: `"direct"` and/or `"group <name>"`.
    pub via: Vec<String>,
}

/// A key that will be written to a login's `authorized_keys`.
#[derive(Debug, Clone)]
pub struct DeployedKey {
    pub user: String,
    pub device: String,
    pub key: PublicKey,
    pub expires: Option<Date>,
}

impl DeployedKey {
    /// The `authorized_keys` line. Expiry is also enforced by sshd itself via
    /// `expiry-time`, so a key dies on time even if the agent stops syncing.
    pub fn authorized_keys_line(&self) -> String {
        let mut options: Vec<String> = self.key.options.iter().cloned().collect();
        if let Some(expiry) = self.expires {
            options.push(format!(
                "expiry-time=\"{}\"",
                expiry.to_string().replace('-', "")
            ));
        }
        let prefix = if options.is_empty() {
            String::new()
        } else {
            format!("{} ", options.join(","))
        };
        format!(
            "{prefix}{} {}@{}",
            self.key.openssh(),
            self.user,
            self.device
        )
    }
}

impl Policy {
    /// Every (server, login, user) permission, sorted. Disabled and unknown
    /// users are left out.
    pub fn access(&self) -> Vec<Access> {
        let mut out = Vec::new();
        for server in self.servers.values() {
            for (login, grant) in &server.logins {
                let mut via: BTreeMap<&str, Vec<String>> = BTreeMap::new();
                for user in &grant.users {
                    via.entry(user).or_default().push("direct".into());
                }
                for group in &grant.groups {
                    for member in self.group_members(group) {
                        via.entry(&member.name)
                            .or_default()
                            .push(format!("group {group}"));
                    }
                }
                for (user, via) in via {
                    if self.users.get(user).is_some_and(|u| !u.disabled) {
                        out.push(Access {
                            server: server.name.clone(),
                            login: login.clone(),
                            user: user.to_owned(),
                            via,
                        });
                    }
                }
            }
        }
        out
    }

    /// Keys to install on `server`, per login. Every login defined for the
    /// server is present, even when it ends up with no keys. Keys that are
    /// expired, unparsable or forbidden are skipped.
    pub fn deployed_keys(
        &self,
        server: &str,
        today: Date,
    ) -> Result<BTreeMap<String, Vec<DeployedKey>>> {
        let Some(definition) = self.servers.get(server) else {
            bail!("server {server:?} is not defined in the policy");
        };
        let mut out: BTreeMap<String, Vec<DeployedKey>> = definition
            .logins
            .keys()
            .map(|login| (login.clone(), Vec::new()))
            .collect();

        for access in self.access().into_iter().filter(|a| a.server == server) {
            let user = &self.users[&access.user];
            let keys = out.entry(access.login).or_default();
            for entry in &user.keys {
                let (Ok(key), Ok(expires)) = (entry.public_key(), entry.expiry()) else {
                    continue;
                };
                if matches!(key.strength(), Strength::Forbidden(_)) || entry.is_expired(today) {
                    continue;
                }
                keys.push(DeployedKey {
                    user: user.name.clone(),
                    device: entry.device.clone(),
                    key,
                    expires,
                });
            }
        }

        for keys in out.values_mut() {
            let mut seen = BTreeSet::new();
            keys.retain(|k| seen.insert(k.key.fingerprint().to_owned()));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::tests::rsa_key;
    use crate::policy::KeyEntry;
    use crate::policy::tests::fixture;

    fn today() -> Date {
        "2026-10-20".parse().unwrap()
    }

    fn deployed(policy: &Policy, login: &str) -> Vec<String> {
        policy.deployed_keys("web-1", today()).unwrap()[login]
            .iter()
            .map(|k| format!("{}/{}", k.user, k.device))
            .collect()
    }

    #[test]
    fn resolves_groups_and_direct_grants() {
        let mut policy = fixture();
        policy
            .servers
            .get_mut("web-1")
            .unwrap()
            .logins
            .get_mut("deploy")
            .unwrap()
            .users
            .push("carol".into());

        let access = policy.access();
        let carol_deploy = access
            .iter()
            .find(|a| a.user == "carol" && a.login == "deploy")
            .unwrap();
        assert_eq!(carol_deploy.via, vec!["direct", "group devs"]);
        assert_eq!(
            deployed(&policy, "deploy"),
            vec!["alice/laptop", "carol/laptop"]
        );
        assert_eq!(
            deployed(&policy, "root"),
            vec!["bob/desktop", "carol/laptop"]
        );
    }

    #[test]
    fn skips_disabled_expired_and_forbidden_keys() {
        let mut policy = fixture();
        policy.users.get_mut("carol").unwrap().disabled = true;
        let alice = policy.users.get_mut("alice").unwrap();
        alice.keys[0].expires = Some("2026-10-20".into());
        alice.keys.push(KeyEntry {
            device: "ancient".into(),
            key: rsa_key(1024),
            expires: None,
            added: None,
        });
        alice.keys.push(KeyEntry {
            device: "new".into(),
            key: rsa_key(4096),
            expires: Some("2027-01-31".into()),
            added: None,
        });

        assert_eq!(deployed(&policy, "deploy"), vec!["alice/new"]);
        assert_eq!(deployed(&policy, "root"), vec!["bob/desktop"]);
        assert!(policy.access().iter().all(|a| a.user != "carol"));
    }

    #[test]
    fn renders_lines_with_options_and_expiry() {
        let mut policy = fixture();
        let alice = policy.users.get_mut("alice").unwrap();
        alice.keys[0].key = format!("from=\"10.0.0.0/8\" {}", alice.keys[0].key);
        alice.keys[0].expires = Some("2027-03-01".into());

        let keys = policy.deployed_keys("web-1", today()).unwrap();
        let line = keys["deploy"][0].authorized_keys_line();
        assert!(
            line.starts_with("from=\"10.0.0.0/8\",expiry-time=\"20270301\" ssh-ed25519 AAAA"),
            "{line}"
        );
        assert!(line.ends_with(" alice@laptop"), "{line}");
        assert!(
            !line.contains("alice-laptop"),
            "original comment must be replaced: {line}"
        );
    }

    #[test]
    fn unknown_server_is_an_error() {
        assert!(fixture().deployed_keys("nope", today()).is_err());
    }
}
