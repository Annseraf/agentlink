#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ "$(uname -s)" != Linux ]]; then
    echo "AgentLink setup requires Linux." >&2
    exit 1
fi

if ! command -v cargo >/dev/null && [[ -x "$HOME/.cargo/bin/cargo" ]]; then
    export PATH="$HOME/.cargo/bin:$PATH"
fi
if ! command -v cargo >/dev/null || ! command -v cc >/dev/null; then
    echo "Install stable Rust and a C compiler before running setup." >&2
    exit 1
fi

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
export AGENTLINK_STATE_DIR="${AGENTLINK_STATE_DIR:-$PWD/.agentlink}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target}"
cargo build --release --locked --jobs "${CARGO_BUILD_JOBS:-2}"
binary="$CARGO_TARGET_DIR/release/agentlink"
"$binary" bootstrap
exec "$binary" serve
