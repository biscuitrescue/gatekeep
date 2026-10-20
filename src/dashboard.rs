//! Static, self-contained HTML dashboard for a policy.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::date::Date;
use crate::git::Commit;
use crate::key::Strength;
use crate::policy::{EXPIRY_WARNING_DAYS, KeyEntry, Policy, Severity, User};

pub struct Dashboard<'a> {
    pub policy: &'a Policy,
    pub today: Date,
    pub revision: Option<String>,
    pub history: Vec<Commit>,
}

pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tone {
    Good,
    Warn,
    Bad,
    Muted,
}

impl Tone {
    fn class(self) -> &'static str {
        match self {
            Tone::Good => "good",
            Tone::Warn => "warn",
            Tone::Bad => "bad",
            Tone::Muted => "muted",
        }
    }
}

fn key_status(user: &User, entry: &KeyEntry, today: Date) -> (String, Tone) {
    let key = match entry.public_key() {
        Ok(key) => key,
        Err(_) => return ("invalid".into(), Tone::Bad),
    };
    if let Strength::Forbidden(_) = key.strength() {
        return ("forbidden".into(), Tone::Bad);
    }
    if user.disabled {
        return ("user disabled".into(), Tone::Muted);
    }
    match entry.expiry() {
        Err(_) => return ("bad expiry".into(), Tone::Bad),
        Ok(Some(expiry)) => {
            let days = today.days_until(expiry);
            if days <= 0 {
                return ("expired".into(), Tone::Bad);
            }
            if days <= EXPIRY_WARNING_DAYS {
                return (format!("expires in {days}d"), Tone::Warn);
            }
        }
        Ok(None) => {}
    }
    if let Strength::Weak(_) = key.strength() {
        return ("weak".into(), Tone::Warn);
    }
    ("active".into(), Tone::Good)
}

fn pill(text: &str, tone: Tone) -> String {
    format!(
        r#"<span class="pill {}">{}</span>"#,
        tone.class(),
        escape(text)
    )
}

pub fn render(ctx: &Dashboard) -> String {
    let policy = ctx.policy;
    let today = ctx.today;
    let issues = policy.validate(today);
    let errors = issues
        .iter()
        .filter(|i| i.severity == Severity::Error)
        .count();
    let warnings = issues.len() - errors;
    let access = policy.access();

    let active_users = policy.users.values().filter(|u| !u.disabled).count();
    let mut active_keys = 0;
    let mut attention = 0;
    let mut key_rows = String::new();
    for user in policy.users.values() {
        for entry in &user.keys {
            let (status, tone) = key_status(user, entry, today);
            match tone {
                Tone::Good => active_keys += 1,
                Tone::Warn => {
                    active_keys += 1;
                    attention += 1
                }
                Tone::Bad => attention += 1,
                Tone::Muted => {}
            }
            let (algo, fingerprint) = match entry.public_key() {
                Ok(k) => {
                    let mut algo = k.algorithm.to_string();
                    if let Some(bits) = k.bits() {
                        let _ = write!(algo, " ({bits})");
                    }
                    if k.algorithm.is_hardware() {
                        algo.push_str(" · hardware");
                    }
                    (algo, k.fingerprint().to_owned())
                }
                Err(_) => ("?".into(), "unparsable".into()),
            };
            let _ = write!(
                key_rows,
                "<tr><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td></tr>",
                escape(&user.name),
                escape(&entry.device),
                escape(&algo),
                escape(&fingerprint),
                escape(entry.expires.as_deref().unwrap_or("never")),
                pill(&status, tone),
            );
        }
    }

    // user -> server -> logins
    let mut matrix: BTreeMap<&str, BTreeMap<&str, Vec<&str>>> = BTreeMap::new();
    for a in &access {
        matrix
            .entry(&a.user)
            .or_default()
            .entry(&a.server)
            .or_default()
            .push(&a.login);
    }
    let servers: Vec<&str> = policy.servers.keys().map(String::as_str).collect();
    let mut matrix_html = String::from("<tr><th>User</th>");
    for s in &servers {
        let _ = write!(matrix_html, "<th>{}</th>", escape(s));
    }
    matrix_html.push_str("</tr>");
    for user in policy.users.values() {
        let _ = write!(matrix_html, "<tr><td>{}", escape(&user.name));
        if let Some(email) = &user.email {
            let _ = write!(matrix_html, " <span class=\"sub\">{}</span>", escape(email));
        }
        if user.disabled {
            matrix_html.push(' ');
            matrix_html.push_str(&pill("disabled", Tone::Muted));
        }
        matrix_html.push_str("</td>");
        for s in &servers {
            let logins = matrix
                .get(user.name.as_str())
                .and_then(|m| m.get(s))
                .map(|l| l.iter().map(|l| escape(l)).collect::<Vec<_>>().join(", "))
                .unwrap_or_default();
            if logins.is_empty() {
                matrix_html.push_str(r#"<td class="none">—</td>"#);
            } else {
                let _ = write!(matrix_html, "<td><code>{logins}</code></td>");
            }
        }
        matrix_html.push_str("</tr>");
    }

    let mut server_html = String::new();
    for server in policy.servers.values() {
        let _ = write!(
            server_html,
            "<div class=\"card\"><h3>{}</h3>",
            escape(&server.name)
        );
        if let Some(d) = &server.description {
            let _ = write!(server_html, "<p class=\"sub\">{}</p>", escape(d));
        }
        server_html.push_str("<dl>");
        for (login, grant) in &server.logins {
            let who: Vec<String> = access
                .iter()
                .filter(|a| a.server == server.name && &a.login == login)
                .map(|a| escape(&a.user))
                .collect();
            let mut rule: Vec<String> = grant
                .groups
                .iter()
                .map(|g| format!("@{}", escape(g)))
                .collect();
            rule.extend(grant.users.iter().map(|u| escape(u)));
            let _ = write!(
                server_html,
                "<dt><code>{}</code> <span class=\"sub\">{}</span></dt><dd>{}</dd>",
                escape(login),
                rule.join(", "),
                if who.is_empty() {
                    "<span class=\"none\">nobody</span>".into()
                } else {
                    who.join(", ")
                }
            );
        }
        server_html.push_str("</dl></div>");
    }

    let mut issues_html = String::new();
    if issues.is_empty() {
        issues_html.push_str(r#"<p class="sub">No issues. The policy is valid.</p>"#);
    } else {
        issues_html.push_str("<ul class=\"issues\">");
        for issue in &issues {
            let tone = if issue.severity == Severity::Error {
                Tone::Bad
            } else {
                Tone::Warn
            };
            let label = if tone == Tone::Bad {
                "error"
            } else {
                "warning"
            };
            let _ = write!(
                issues_html,
                "<li>{} <code>{}</code> {}</li>",
                pill(label, tone),
                escape(&issue.location),
                escape(&issue.message)
            );
        }
        issues_html.push_str("</ul>");
    }

    let mut history_html = String::new();
    if ctx.history.is_empty() {
        history_html
            .push_str(r#"<p class="sub" style="padding: 0 12px">No Git history available.</p>"#);
    } else {
        history_html
            .push_str("<table><tr><th>Commit</th><th>Date</th><th>Author</th><th>Change</th></tr>");
        for c in &ctx.history {
            let _ = write!(
                history_html,
                "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td></tr>",
                escape(&c.hash),
                escape(&c.date),
                escape(&c.author),
                escape(&c.subject)
            );
        }
        history_html.push_str("</table>");
    }

    let status = if errors > 0 {
        pill(&format!("{errors} error(s)"), Tone::Bad)
    } else {
        pill("valid", Tone::Good)
    };
    let revision = ctx
        .revision
        .as_deref()
        .map(|r| format!(" · revision <code>{}</code>", escape(r)))
        .unwrap_or_default();

    format!(
        r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GateKeep Access</title>
<style>
:root {{
  --bg: #f7f7f5; --surface: #ffffff; --text: #1d1d1b; --sub: #6b6b66; --line: #e3e2dd;
  --good: #1f7a4d; --good-bg: #e3f3ea; --warn: #8a5a00; --warn-bg: #fbefd5;
  --bad: #b3261e; --bad-bg: #fbe4e2; --muted-bg: #ecebe7; --accent: #2f5bd3;
}}
@media (prefers-color-scheme: dark) {{
  :root {{
    --bg: #161615; --surface: #1f1f1d; --text: #ecebe7; --sub: #9c9b95; --line: #33332f;
    --good: #6fd19d; --good-bg: #173527; --warn: #f0c26b; --warn-bg: #3a2d10;
    --bad: #ff8a80; --bad-bg: #3d1a17; --muted-bg: #2b2b28; --accent: #8fa9ff;
  }}
}}
* {{ box-sizing: border-box; }}
body {{ margin: 0; background: var(--bg); color: var(--text);
  font: 14px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }}
main {{ max-width: 1100px; margin: 0 auto; padding: 24px 16px 64px; }}
h1 {{ font-size: 22px; margin: 0 0 4px; }}
h2 {{ font-size: 16px; margin: 32px 0 12px; }}
h3 {{ font-size: 15px; margin: 0 0 4px; }}
.sub {{ color: var(--sub); }}
code {{ font: 12.5px ui-monospace, SFMono-Regular, Menlo, monospace; }}
.tiles {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin-top: 20px; }}
.tile, .card {{ background: var(--surface); border: 1px solid var(--line); border-radius: 10px; padding: 14px 16px; }}
.tile .n {{ font-size: 26px; font-weight: 600; font-variant-numeric: tabular-nums; }}
.cards {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 12px; }}
.scroll {{ overflow-x: auto; background: var(--surface); border: 1px solid var(--line); border-radius: 10px; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ text-align: left; padding: 8px 12px; border-bottom: 1px solid var(--line); white-space: nowrap; }}
th {{ font-weight: 600; color: var(--sub); font-size: 12px; text-transform: uppercase; letter-spacing: .03em; }}
tr:last-child td {{ border-bottom: 0; }}
.none {{ color: var(--sub); }}
dl {{ margin: 8px 0 0; }} dt {{ margin-top: 8px; }} dd {{ margin: 2px 0 0 0; }}
.pill {{ display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 12px; font-weight: 500; }}
.pill.good {{ color: var(--good); background: var(--good-bg); }}
.pill.warn {{ color: var(--warn); background: var(--warn-bg); }}
.pill.bad {{ color: var(--bad); background: var(--bad-bg); }}
.pill.muted {{ color: var(--sub); background: var(--muted-bg); }}
.issues {{ list-style: none; padding: 0; margin: 0; }} .issues li {{ padding: 6px 0; }}
input[type=search] {{ width: 100%; max-width: 320px; padding: 7px 10px; margin-bottom: 10px; border-radius: 8px;
  border: 1px solid var(--line); background: var(--surface); color: var(--text); font: inherit; }}
</style>
</head>
<body>
<main>
<h1>GateKeep access</h1>
<div class="sub">Generated {today}{revision} · {status}</div>

<div class="tiles">
  <div class="tile"><div class="sub">Active users</div><div class="n">{active_users}</div><div class="sub">{disabled} disabled</div></div>
  <div class="tile"><div class="sub">Deployable keys</div><div class="n">{active_keys}</div><div class="sub">{total_keys} registered</div></div>
  <div class="tile"><div class="sub">Servers</div><div class="n">{server_count}</div><div class="sub">{grant_count} access grants</div></div>
  <div class="tile"><div class="sub">Keys needing attention</div><div class="n">{attention}</div><div class="sub">expired, expiring, weak or invalid</div></div>
  <div class="tile"><div class="sub">Policy issues</div><div class="n">{issue_count}</div><div class="sub">{errors} errors, {warnings} warnings</div></div>
</div>

<h2>Issues</h2>
{issues_html}

<h2>Access matrix</h2>
<div class="scroll"><table>{matrix_html}</table></div>

<h2>Servers</h2>
<div class="cards">{server_html}</div>

<h2>Keys and devices</h2>
<input type="search" id="filter" placeholder="Filter by user, device, fingerprint…" aria-label="Filter keys">
<div class="scroll"><table id="keys">
<thead><tr><th>User</th><th>Device</th><th>Type</th><th>Fingerprint</th><th>Expires</th><th>Status</th></tr></thead>
<tbody>{key_rows}</tbody>
</table></div>

<h2>Recent policy changes</h2>
<div class="scroll">{history_html}</div>
</main>
<script>
document.getElementById("filter").addEventListener("input", function (e) {{
  var q = e.target.value.toLowerCase();
  document.querySelectorAll("#keys tbody tr").forEach(function (row) {{
    row.style.display = row.textContent.toLowerCase().indexOf(q) === -1 ? "none" : "";
  }});
}});
</script>
</body>
</html>
"##,
        disabled = policy.users.len() - active_users,
        total_keys = policy.users.values().map(|u| u.keys.len()).sum::<usize>(),
        server_count = policy.servers.len(),
        grant_count = access.len(),
        issue_count = issues.len(),
    )
}

/// Writes `index.html` into `out_dir` and returns its path.
pub fn write(out_dir: &Path, ctx: &Dashboard) -> Result<PathBuf> {
    fs::create_dir_all(out_dir)
        .with_context(|| format!("couldn't create {}", out_dir.display()))?;
    let path = out_dir.join("index.html");
    fs::write(&path, render(ctx)).with_context(|| format!("couldn't write {}", path.display()))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::tests::fixture;

    #[test]
    fn escapes_html() {
        assert_eq!(
            escape(r#"<a href="x">'&'</a>"#),
            "&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;"
        );
    }

    #[test]
    fn renders_policy_overview() {
        let mut policy = fixture();
        policy.users.get_mut("bob").unwrap().disabled = true;
        policy.users.get_mut("alice").unwrap().email = Some("<script>alert(1)</script>".into());
        policy.users.get_mut("carol").unwrap().keys[0].expires = Some("2026-10-25".into());
        let html = render(&Dashboard {
            policy: &policy,
            today: "2026-10-20".parse().unwrap(),
            revision: Some("abc1234".into()),
            history: vec![Commit {
                hash: "abc1234".into(),
                author: "Ops <bot>".into(),
                date: "2026-10-19".into(),
                subject: "revoke bob".into(),
            }],
        });
        assert!(html.contains("<title>GateKeep Access</title>"));
        assert!(html.contains("abc1234"));
        assert!(html.contains("expires in 5d"));
        assert!(html.contains("user disabled"));
        assert!(html.contains("Ops &lt;bot&gt;"));
        assert!(!html.contains("<script>alert"));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(html.contains("<th>web-1</th>"));
    }
}
