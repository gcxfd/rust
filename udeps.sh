#!/usr/bin/env bash
set -e

_DIR=$(dirname $(realpath "$0"))

cd $_DIR

if ! hash cargo-udeps 2>/dev/null; then
cargo install cargo-udeps --locked
fi

cargo +nightly udeps
