# GateKeep

Gatekeep is a *Git-native, policy-as-code platform* for managing SSH access across Linux and BSD servers — using declarative TOML files, version control, and lightweight agents.

It replaces fragile scripts and manual key syncing with a secure, auditable, and developer-first approach to server access.

---

## ✨ Features
- 🔐 **Policy-as-Code**: Define SSH access in simple, structured TOML.
- 🧠 **Smart Agents**: Each server runs a lightweight daemon to pull and apply access policy.
- 🧾 **Audit-Ready**: Git history provides a full changelog of who had access and when.
- 🔁 **Key Rotation**: Keys can have expiry metadata and auto-rotation plans.
- 💻 **CLI Tool**: Query access, test policies, and generate `authorized_keys` files locally.
- 🔒 **Secure Sync** (planned): Signed policies and cryptographic validation.
- 💡 **Self-Hosted or SaaS** (planned): Bring your own Git or use Gatekeep Cloud.

---

## 📁 Project Structure
```bash
gatekeep/
├── agent/      # C++ agent daemon
├── backend/    # (Planned) Audit, auth, key signing server
├── cli/        # Rust CLI tool (gatekeep)
├── core/       # Shared logic: TOML parsing, policy evaluation
├── docs/       # Architecture, design, schema
├── policies/   # Sample TOML policies for dev/demo
├── README.md
```

```toml
# policies/<server>.toml
[users.alice]
key = "ssh-ed25519 AAAAC3Nza... alice@laptop"
groups = ["devs"]

[users.bob]
key = "ssh-rsa AAAAB3... bob@home"
groups = ["ops"]

[servers.web-1]
allow = ["devs"]

[servers.db-1]
allow = ["ops"]
```

# Setup
```bash
# Clone the repo
git clone https://github.com/biscuitrescue/gatekeep.git
cd gatekeep

# Build the CLI
cargo build

# Generate authorized_keys for a server
./target/release/gk generate --server web-1 --policy ../policies/access.toml #TODO: add proper cmds
```

# ⚙️ Agent
A minimal daemon installed on every server:

- Pulls latest policy (from Git or API)
- Generates keys using the core logic
- Writes them to /etc/ssh/authorized_keys.d/
- Optionally verifies signatures 
- Runs as a systemd service or cronjob

# 🗺 Roadmap

- [ ] Agent policy signature verification
- [ ] FIDO2/WebAuthn support for agents
- [ ] Gatekeep Web UI (read-only dashboard)
- [ ] GitHub/GitLab integration
- [ ] Audit log backend API
- [ ] SaaS + On-prem deployment support

# 📜 License
BSDv3 License © 2025
