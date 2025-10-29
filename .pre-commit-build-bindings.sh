#!/bin/bash
# Pre-commit hook to build Python bindings
# This script checks if Rust code or build files have changed and rebuilds bindings

set -e

echo "🔧 Building Rust crate..."
cd rust

# Build the Rust library in release mode
cargo build --release

echo "🐍 Generating Python bindings..."
# Determine the library extension based on OS
if [[ "$OSTYPE" == "darwin"* ]]; then
    LIB_EXT="dylib"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    LIB_EXT="so"
else
    LIB_EXT="dll"
fi

# Generate Python bindings
cargo run --bin uniffi-bindgen generate \
    --library target/release/libisomdl_uniffi.$LIB_EXT \
    --language python \
    --out-dir out/python

echo "✅ Python bindings built successfully!"
