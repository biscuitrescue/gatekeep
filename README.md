# GateKeep

GateKeep (`gk`) is a Git-native, policy-as-code tool for managing SSH access
across a fleet of Linux and BSD servers. One Git repository is the central
authority: it records every person, every device key and every server login.
A small agent on each server pulls that repository and installs the matching
`authorized_keys` files.

- **Review access like code.** Access changes are pull requests. CI validates
  them, and the Git history shows who had access, when, and who approved it.
- **One key per device.** Keys are registered per device (laptop, YubiKey, CI
  runner), so you can revoke one lost laptop without touching anything else.
- **Offboarding in one command.** `gk user disable bob` removes Bob's keys from
  every server on the next sync.
- **Expiry enforced twice.** Expired keys are never deployed, and every key with
  an expiry date also gets OpenSSH's `expiry-time` option. sshd refuses the key
  on time even if the agent has stopped syncing.
- **Fail-safe agent.** If the policy is invalid, unreachable or doesn't define
  the server, the agent keeps the last good keys and logs the error. It never
  touches files it didn't write.
- **Dashboard.** A static HTML page shows the access matrix, every key with its
  fingerprint and expiry status, validation issues and recent policy changes.

## How it works

```
 admins ──PR──▶ policy repo (Git) ──CI: gk validate──▶ main
                                                        │
              ┌──────────── git fetch every 60s ────────┤
              ▼                                         ▼
     web-1: gk agent                           db-1: gk agent
     /etc/ssh/authorized_keys.d/deploy         /etc/ssh/authorized_keys.d/postgres
     /etc/ssh/authorized_keys.d/root           /etc/ssh/authorized_keys.d/root
```

## Install

Download a binary from the [releases page](https://github.com/biscuitrescue/gatekeep/releases)
(Linux musl x86_64/aarch64, macOS x86_64/arm64), or build from source with
Rust 1.85+:

```bash
cargo install --locked --git https://github.com/biscuitrescue/gatekeep gk
```

`git` must be on `PATH` for `gk commit` and for agents that sync from Git.

## Policy repository

```
users/<name>.toml      a person or service account, with one key per device
servers/<name>.toml    a server: which users or groups may log in as which unix login
```

The file name is the identity. Names use lowercase letters, digits, `.`, `_` and `-`.

```toml
# users/alice.toml
email = "alice@example.com"
groups = ["devs"]
# disabled = true      # turns off all access but keeps the record

[[keys]]
device = "laptop"
key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA..."
added = "2026-03-02"

[[keys]]
device = "desktop"
key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA..."
expires = "2027-03-31"  # not deployed from this date; sshd enforces it too
```

```toml
# servers/web-1.toml
description = "Public web frontend"

[logins.deploy]          # unix account on the server
groups = ["devs"]
users = ["ci"]

[logins.root]
groups = ["ops"]
```

`key` accepts a full `authorized_keys` line, so you can add restrictions such
as `from="10.20.0.0/16" ssh-ed25519 AAAA...`. Groups are defined by user
membership. A complete example is in [`examples/policy`](examples/policy).

### Validation

`gk validate` exits non-zero on errors:

| Errors (block deployment) | Warnings |
| --- | --- |
| unparsable key, or key type that doesn't match the key data | RSA keys under 3072 bits |
| DSA keys, RSA keys under 2048 bits | key expired, or expiring within 30 days |
| the same key on two devices or users | group referenced by a server has no members |
| duplicate device names, invalid dates | login that grants nobody, or server with no logins |
| unknown user in a server grant | disabled user granted directly |
| invalid user, group, device, server or unix login names | |

`--strict` makes warnings fail too.

## CLI

```bash
gk init corp-access --ci             # new policy repo plus a GitHub Actions workflow
cd corp-access                       # or pass --policy DIR / set GK_POLICY

gk user add alice --email alice@example.com --group devs
gk key add alice --device laptop --key "$(cat ~/.ssh/id_ed25519.pub)"
gk key add bob --file old_authorized_keys      # import; device names come from key comments
gk key rotate alice --device laptop --key "ssh-ed25519 AAAA... new"
gk key revoke alice --device laptop
gk user disable bob                  # offboard everywhere
gk user list
gk key list --user alice

gk validate
gk access --user alice               # where can alice log in?
gk access --server web-1             # who can log in to web-1?
gk generate --server web-1           # print the authorized_keys files
gk generate --server web-1 --out ./keys
gk dashboard --out site              # site/index.html
gk commit -m "onboard alice"         # validate, then git commit
```

Edits go to the working tree. Commit and push them as a pull request, or
use `gk commit`.

## Agent

On each server:

```bash
sudo gk agent init \
  --server web-1 \
  --git-url git@github.com:example-corp/ssh-access.git \
  --branch main \
  --ssh-key /etc/gatekeep/deploy_key
```

This writes `/etc/gatekeep/agent.toml`; see [`examples/agent.toml`](examples/agent.toml)
for all options. Use `--local DIR` instead of `--git-url` if something else
keeps the policy up to date. Then point sshd at the generated files in
`/etc/ssh/sshd_config`:

```
AuthorizedKeysFile /etc/ssh/authorized_keys.d/%u
```

Run it as a service with [`examples/gatekeep-agent.service`](examples/gatekeep-agent.service),
or from cron with `gk agent run --once`, which exits non-zero on failure.

Every sync:

1. fetches the branch. With `--ssh-key`, it uses that read-only deploy key and
   pins the Git host key on first contact;
2. loads and validates the policy, and stops without changing anything if
   there are errors;
3. writes `<output_dir>/<login>` for every login of this server. Writes are
   atomic, files are mode 0644, and each file records the policy revision in
   its header;
4. removes files for logins that no longer exist, but only files carrying the
   `# Managed by gatekeep` header.

> **Keep a break-glass path.** Keep console access, or one login that isn't
> managed by gatekeep, until you've confirmed the agent works on a server.
> Changing `AuthorizedKeysFile` replaces `~/.ssh/authorized_keys` unless you
> list both paths.

## CI/CD

This repository:

| Workflow | Trigger | What it does |
| --- | --- | --- |
| [`ci.yml`](.github/workflows/ci.yml) | push to master, pull requests | fmt, clippy `-D warnings`, tests on Linux and macOS (Linux includes a real sshd login test), MSRV 1.85, end-to-end demo script |
| [`release.yml`](.github/workflows/release.yml) | tag `v*` | checks the tag matches `Cargo.toml`, tests, builds four binaries with checksums, publishes a GitHub release |
| [`dashboard.yml`](.github/workflows/dashboard.yml) | push to master | publishes the dashboard for the **example** policy to GitHub Pages (enable Pages → Source: GitHub Actions) |

To cut a release, bump `version` in `Cargo.toml`, then run
`git tag v0.2.0 && git push origin v0.2.0`.

Your policy repository: `gk init --ci` writes `.github/workflows/gatekeep.yml`,
which validates every pull request, posts the access diff to the job summary,
and rebuilds the dashboard daily as a private workflow artifact.

> The dashboard lists every user, server and who has root. Don't publish a real
> company's dashboard to a public Pages site.

## Development

```bash
scripts/dev.sh check       # fmt + clippy + tests, same as CI
scripts/dev.sh demo        # throwaway policy repo: validate, generate, agent sync, offboard, dashboard
scripts/dev.sh dashboard   # serve the example dashboard on http://127.0.0.1:8000
scripts/dev.sh agent       # run the agent loop against examples/policy into .local/
scripts/dev.sh install     # cargo install into ~/.cargo/bin
```

Tests:

- unit tests live next to the code in `src/`;
- CLI and agent integration tests are in `tests/`;
- `tests/ssh_e2e.rs` starts an unprivileged `sshd` and checks real logins,
  including disabled users and `expiry-time`. It skips itself when OpenSSH is
  missing; `GK_REQUIRE_SSH_E2E=1` makes that a failure.

`GK_TODAY=YYYY-MM-DD` pins the date used for expiry checks.

## Roadmap

- [ ] Signed policy commits, verified by the agent before applying
- [ ] OpenSSH certificate authority mode (short-lived certs instead of keys)
- [ ] Per-grant options (`from=`, `command=`) on server logins
- [ ] GitHub/GitLab team sync for groups
- [ ] FreeBSD/OpenBSD builds tested in CI

## License

BSD 3-Clause © 2025 Karttikeya Sinha. See [LICENSE.md](LICENSE.md).
