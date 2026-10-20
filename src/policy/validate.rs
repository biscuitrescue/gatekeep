use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use super::{Policy, SERVERS_DIR, USERS_DIR, is_valid_login, is_valid_name};
use crate::date::Date;
use crate::key::Strength;

/// Keys expiring within this many days produce a warning.
pub const EXPIRY_WARNING_DAYS: i64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Error,
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    pub severity: Severity,
    /// Policy file the issue was found in, relative to the policy root.
    pub location: String,
    pub message: String,
}

impl fmt::Display for Issue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let level = match self.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };
        write!(f, "{level}: {}: {}", self.location, self.message)
    }
}

struct Issues(Vec<Issue>);

impl Issues {
    fn push(&mut self, severity: Severity, location: &str, message: impl Into<String>) {
        self.0.push(Issue {
            severity,
            location: location.to_owned(),
            message: message.into(),
        });
    }
    fn error(&mut self, location: &str, message: impl Into<String>) {
        self.push(Severity::Error, location, message);
    }
    fn warn(&mut self, location: &str, message: impl Into<String>) {
        self.push(Severity::Warning, location, message);
    }
}

impl Policy {
    /// Checks the whole policy. Errors must be fixed before the policy is
    /// deployed; warnings are informational.
    pub fn validate(&self, today: Date) -> Vec<Issue> {
        let mut issues = Issues(Vec::new());
        // fingerprint -> first "user/device" that used it
        let mut seen_keys: BTreeMap<String, String> = BTreeMap::new();

        for user in self.users.values() {
            let loc = format!("{USERS_DIR}/{}.toml", user.name);
            if !is_valid_name(&user.name) {
                issues.error(&loc, format!("invalid user name {:?}", user.name));
            }
            for group in &user.groups {
                if !is_valid_name(group) {
                    issues.error(&loc, format!("invalid group name {group:?}"));
                }
            }

            let mut devices = BTreeSet::new();
            for entry in &user.keys {
                let what = format!("key {:?}", entry.device);
                if !is_valid_name(&entry.device) {
                    issues.error(&loc, format!("invalid device name {:?}", entry.device));
                }
                if !devices.insert(entry.device.as_str()) {
                    issues.error(&loc, format!("duplicate device {:?}", entry.device));
                }

                match entry.public_key() {
                    Err(e) => issues.error(&loc, format!("{what}: {e:#}")),
                    Ok(key) => {
                        match key.strength() {
                            Strength::Ok => {}
                            Strength::Weak(why) => issues.warn(&loc, format!("{what}: {why}")),
                            Strength::Forbidden(why) => {
                                issues.error(&loc, format!("{what}: {why}"))
                            }
                        }
                        let owner = format!("{}/{}", user.name, entry.device);
                        if let Some(first) =
                            seen_keys.insert(key.fingerprint().to_owned(), owner.clone())
                        {
                            issues.error(
                                &loc,
                                format!(
                                    "{what}: same key as {first} ({}); every device needs its own key",
                                    key.fingerprint()
                                ),
                            );
                        }
                    }
                }

                for (field, value) in [("expires", &entry.expires), ("added", &entry.added)] {
                    if let Some(Err(e)) = value.as_deref().map(str::parse::<Date>) {
                        issues.error(&loc, format!("{what}: {field}: {e}"));
                    }
                }
                if let Ok(Some(expiry)) = entry.expiry() {
                    let days = today.days_until(expiry);
                    if days <= 0 {
                        issues.warn(&loc, format!("{what}: expired on {expiry}, not deployed"));
                    } else if days <= EXPIRY_WARNING_DAYS && !user.disabled {
                        issues.warn(
                            &loc,
                            format!("{what}: expires in {days} day(s) on {expiry}"),
                        );
                    }
                }
            }
        }

        let groups: BTreeSet<String> = self.groups().into_iter().collect();
        for server in self.servers.values() {
            let loc = format!("{SERVERS_DIR}/{}.toml", server.name);
            if !is_valid_name(&server.name) {
                issues.error(&loc, format!("invalid server name {:?}", server.name));
            }
            if server.logins.is_empty() {
                issues.warn(&loc, "no logins defined; nobody can log in");
            }
            for (login, grant) in &server.logins {
                if !is_valid_login(login) {
                    issues.error(&loc, format!("invalid unix login name {login:?}"));
                }
                if grant.groups.is_empty() && grant.users.is_empty() {
                    issues.warn(&loc, format!("login {login:?} grants nobody"));
                }
                for user in &grant.users {
                    match self.users.get(user) {
                        None => {
                            issues.error(&loc, format!("login {login:?}: unknown user {user:?}"))
                        }
                        Some(u) if u.disabled => {
                            issues.warn(&loc, format!("login {login:?}: user {user:?} is disabled"))
                        }
                        Some(_) => {}
                    }
                }
                for group in &grant.groups {
                    if !groups.contains(group) {
                        issues.warn(
                            &loc,
                            format!("login {login:?}: group {group:?} has no members"),
                        );
                    }
                }
            }
        }

        let mut issues = issues.0;
        issues.sort_by(|a, b| (a.severity, &a.location).cmp(&(b.severity, &b.location)));
        issues
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::tests::{ED25519, rsa_key};
    use crate::policy::KeyEntry;
    use crate::policy::tests::fixture;

    fn today() -> Date {
        "2026-10-20".parse().unwrap()
    }

    fn messages(policy: &Policy, severity: Severity) -> Vec<String> {
        policy
            .validate(today())
            .into_iter()
            .filter(|i| i.severity == severity)
            .map(|i| i.to_string())
            .collect()
    }

    #[test]
    fn fixture_is_clean() {
        assert_eq!(fixture().validate(today()), vec![]);
    }

    #[test]
    fn flags_shared_and_broken_keys() {
        let mut policy = fixture();
        let bob = policy.users.get_mut("bob").unwrap();
        bob.keys.push(KeyEntry {
            device: "stolen".into(),
            key: ED25519.into(),
            expires: None,
            added: None,
        });
        bob.keys.push(KeyEntry {
            device: "desktop".into(),
            key: "ssh-ed25519 garbage!".into(),
            expires: Some("someday".into()),
            added: None,
        });
        let errors = messages(&policy, Severity::Error);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("same key as alice/laptop")),
            "{errors:?}"
        );
        assert!(
            errors
                .iter()
                .any(|e| e.contains("duplicate device \"desktop\"")),
            "{errors:?}"
        );
        assert!(
            errors.iter().any(|e| e.contains("not valid base64")),
            "{errors:?}"
        );
        assert!(
            errors
                .iter()
                .any(|e| e.contains("expires: expected YYYY-MM-DD")),
            "{errors:?}"
        );
    }

    #[test]
    fn grades_key_strength_and_expiry() {
        let mut policy = fixture();
        let alice = policy.users.get_mut("alice").unwrap();
        alice.keys[0].expires = Some("2026-11-01".into());
        alice.keys.push(KeyEntry {
            device: "old".into(),
            key: rsa_key(1024),
            expires: Some("2026-01-01".into()),
            added: None,
        });
        let errors = messages(&policy, Severity::Error);
        let warnings = messages(&policy, Severity::Warning);
        assert!(
            errors.iter().any(|e| e.contains("only 1024 bits")),
            "{errors:?}"
        );
        assert!(
            warnings.iter().any(|w| w.contains("expires in 12 day(s)")),
            "{warnings:?}"
        );
        assert!(
            warnings.iter().any(|w| w.contains("expired on 2026-01-01")),
            "{warnings:?}"
        );
    }

    #[test]
    fn checks_server_references() {
        let mut policy = fixture();
        let web = policy.servers.get_mut("web-1").unwrap();
        let deploy = web.logins.get_mut("deploy").unwrap();
        deploy.users.push("mallory".into());
        deploy.groups.push("nobody-here".into());
        web.logins
            .insert("../../etc/passwd".into(), Default::default());

        let errors = messages(&policy, Severity::Error);
        let warnings = messages(&policy, Severity::Warning);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("unknown user \"mallory\"")),
            "{errors:?}"
        );
        assert!(
            errors.iter().any(|e| e.contains("invalid unix login")),
            "{errors:?}"
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("\"nobody-here\" has no members")),
            "{warnings:?}"
        );
        assert!(
            warnings.iter().any(|w| w.contains("grants nobody")),
            "{warnings:?}"
        );
    }

    #[test]
    fn errors_sort_before_warnings() {
        let mut policy = fixture();
        policy.users.get_mut("alice").unwrap().keys[0].expires = Some("2026-10-25".into());
        policy.users.get_mut("bob").unwrap().keys[0].key = "nope".into();
        let issues = policy.validate(today());
        assert_eq!(issues[0].severity, Severity::Error);
        assert_eq!(issues.last().unwrap().severity, Severity::Warning);
    }
}
