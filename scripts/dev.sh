#!/usr/bin/env bash
# Local development helper for gatekeep.
#
#   scripts/dev.sh check        fmt + clippy + tests, same as CI
#   scripts/dev.sh demo         end-to-end demo in a throwaway policy repo
#   scripts/dev.sh dashboard    build the dashboard and serve it on localhost
#   scripts/dev.sh agent        run the agent loop against the example policy
#   scripts/dev.sh install      install `gk` into ~/.cargo/bin
#
# Environment: PORT (dashboard, default 8000), GK_POLICY (policy for
# `dashboard`, default examples/policy), KEEP=1 keeps the demo directory.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE="$ROOT/.local"
GK="$ROOT/target/debug/gk"

step() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

build() {
    cargo build --quiet --manifest-path "$ROOT/Cargo.toml"
}

cmd_check() {
    cd "$ROOT"
    step "cargo fmt --check"
    cargo fmt --all -- --check
    step "cargo clippy"
    cargo clippy --all-targets --locked -- -D warnings
    step "cargo test"
    cargo test --locked
    echo
    echo "all checks passed"
}

cmd_demo() {
    build
    local dir
    dir="$(mktemp -d "${TMPDIR:-/tmp}/gatekeep-demo.XXXXXX")"
    if [[ "${KEEP:-0}" != 1 ]]; then
        # shellcheck disable=SC2064 # expand now: $dir is local to this function
        trap "rm -rf '$dir'" EXIT
    fi
    local policy="$dir/policy"

    step "create policy repo from examples/policy"
    "$GK" init "$policy"
    cp -R "$ROOT/examples/policy/users" "$ROOT/examples/policy/servers" "$policy/"
    "$GK" -p "$policy" commit -m "initial access policy"

    step "validate"
    "$GK" -p "$policy" validate

    step "who can reach web-1?"
    "$GK" -p "$policy" access --server web-1

    step "authorized_keys for web-1 / deploy"
    "$GK" -p "$policy" generate --server web-1 --login deploy

    step "agent: sync once from Git into $dir/keys"
    "$GK" agent init --config "$dir/agent.toml" --server web-1 \
        --output-dir "$dir/keys" --git-url "file://$policy" \
        --branch "$(git -C "$policy" rev-parse --abbrev-ref HEAD)" \
        --checkout-dir "$dir/checkout" >/dev/null
    "$GK" agent run --once --config "$dir/agent.toml"
    ls -l "$dir/keys"

    step "offboard carol, commit, sync again"
    "$GK" -p "$policy" user disable carol
    "$GK" -p "$policy" commit -m "offboard carol"
    "$GK" agent run --once --config "$dir/agent.toml"
    if grep -q carol@ "$dir/keys/deploy"; then
        echo "carol still has access!" >&2
        exit 1
    fi
    echo "carol removed from web-1"

    step "dashboard"
    "$GK" -p "$policy" dashboard --out "$dir/site"

    if [[ "${KEEP:-0}" == 1 ]]; then
        echo
        echo "demo kept in $dir"
    fi
}

cmd_dashboard() {
    build
    local policy="${GK_POLICY:-$ROOT/examples/policy}"
    local out="$STATE/site"
    "$GK" -p "$policy" dashboard --out "$out"
    local port="${PORT:-8000}"
    step "serving $out on http://127.0.0.1:$port (Ctrl-C to stop)"
    python3 -m http.server "$port" --bind 127.0.0.1 --directory "$out"
}

cmd_agent() {
    build
    mkdir -p "$STATE"
    local config="$STATE/agent.toml"
    if [[ ! -f "$config" ]]; then
        "$GK" agent init --config "$config" --server web-1 --interval 10 \
            --output-dir "$STATE/authorized_keys.d" --local "$ROOT/examples/policy"
    fi
    step "agent writing to $STATE/authorized_keys.d (Ctrl-C to stop)"
    "$GK" agent run --config "$config"
}

cmd_install() {
    cargo install --locked --path "$ROOT"
}

usage() {
    sed -n '2,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

case "${1:-}" in
    check) cmd_check ;;
    demo) cmd_demo ;;
    dashboard) cmd_dashboard ;;
    agent) cmd_agent ;;
    install) cmd_install ;;
    -h | --help | help | "") usage ;;
    *)
        usage >&2
        exit 2
        ;;
esac
