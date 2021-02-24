#!/usr/bin/env bash

set -e

_DIR=$(dirname $(realpath "$0"))

cd $_DIR

RUST_BACKTRACE=1 cargo +nightly watch -x run
