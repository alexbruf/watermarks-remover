#!/usr/bin/env bash
# Build the WASM package into ./pkg (ES module, works in browsers, Workers, Deno, Node).
set -euo pipefail
cd "$(dirname "$0")"
cargo build -p wm-wasm --target wasm32-unknown-unknown --release
wasm-bindgen --target web --out-dir pkg --out-name watermarks_remover \
  target/wasm32-unknown-unknown/release/wm_wasm.wasm
if command -v wasm-opt >/dev/null; then
  wasm-opt -Oz -o pkg/watermarks_remover_bg.wasm pkg/watermarks_remover_bg.wasm
fi
ls -l pkg/*.wasm
