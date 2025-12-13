#!/bin/sh
cargo build --target wasm32-unknown-unknown -p memaead
cargo build --target wasm32-unknown-unknown -p memalloc
cargo build --target wasm32-unknown-unknown -p memrand
cargo build --target wasm32-unknown-unknown -p memutil
cargo build --target wasm32-unknown-unknown -p membuffer
cargo build --target wasm32-unknown-unknown -p memcodec
cargo build --target wasm32-unknown-unknown -p memcodec_core
cargo build --target wasm32-unknown-unknown -p memcodec_derive
cargo build --target wasm32-unknown-unknown -p memguard
cargo build --target wasm32-unknown-unknown -p memsecret
cargo build --target wasm32-unknown-unknown -p memzer_core
cargo build --target wasm32-unknown-unknown -p memzer_derive
cargo build --features no_std --target wasm32-unknown-unknown -p memvault
cargo build --features no_std --target wasm32-unknown-unknown -p memvault_core
cargo build --target wasm32-unknown-unknown -p memvault_derive

cargo build --target wasm32-unknown-unknown -p wasm-demo
