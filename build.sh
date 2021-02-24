RUSTFLAGS="-C target-feature=+avx,+fma,+aes,+sse2,+sse4.1,+sse3,+ssse3" RUST_BACKTRACE=1 \
cargo +nightly build --release

