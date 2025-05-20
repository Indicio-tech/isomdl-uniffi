# Make output directory
mkdir -p out/python

# Add targets
rustup target add x86_64-apple-darwin aarch64-apple-darwin x86_64-pc-windows-gnu x86_64-unknown-linux-gnu

# Build macOS binaries
cargo build --release --target x86_64-apple-darwin --lib
cargo build --release --target aarch64-apple-darwin --lib

# Merge into universal macOS binary
lipo -create \
    target/x86_64-apple-darwin/release/libisomdl_uniffi.dylib \
    target/aarch64-apple-darwin/release/libisomdl_uniffi.dylib \
    -output out/python/libisomdl_uniffi.dylib

# Build windows binary
cargo build --release --target x86_64-pc-windows-gnu --lib
cp target/x86_64-pc-windows-gnu/release/isomdl_uniffi.dll out/python/isomdl_uniffi.dll

# Install cross-rs for building linux
cargo install cross --git https://github.com/cross-rs/cross

# Build linux binary
cross build --release --target x86_64-unknown-linux-gnu --lib
cp target/x86_64-unknown-linux-gnu/release/libisomdl_uniffi.so out/python/libisomdl_uniffi.so

# Generate uniffi bindings
cargo run --features=uniffi/cli --bin uniffi-bindgen generate --library target/x86_64-apple-darwin/release/libisomdl_uniffi.dylib --language python --out-dir out/python