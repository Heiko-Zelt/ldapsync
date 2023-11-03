export RUSTFLAGS="-C target-feature=+crt-static"
cargo build -r --target aarch64-unknown-linux-gnu
