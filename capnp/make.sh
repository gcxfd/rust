#!/usr/bin/env bash

set -e


if ! hash capnpc-rust 2>/dev/null; then
cd /tmp
git clone git@github.com:capnproto/capnproto-rust.git --depth=1
cd capnproto-rust
cargo build --release
sudo mv target/release/capnpc-rust /usr/local/bin
fi

_DIR=$(dirname $(realpath "$0"))

cd $_DIR

fd -0 -e capnp|xargs -0 capnp compile -orust:.
