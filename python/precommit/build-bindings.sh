#!/bin/bash
# Pre-commit hook to build Python bindings
# This script checks if Rust code or build files have changed and rebuilds bindings

set -e

echo "🔧 Building Rust crate..."
# Navigate to project root then to rust directory
cd "$(dirname "$0")/../.."
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
# Rust converts hyphens to underscores in library names
LIBRARY_NAME="libisomdl_uniffi"
echo "🔧 Generating bindings with: target/release/${LIBRARY_NAME}.$LIB_EXT"
ls -la target/release/${LIBRARY_NAME}.$LIB_EXT || {
    echo "❌ Library file not found!"
    echo "🔍 Looking for alternative names..."
    ls -la target/release/lib* 2>/dev/null || echo "No lib* files found"
    find target/release/ -name "*.so" -o -name "*.dylib" -o -name "*.dll" 2>/dev/null || echo "No shared libraries found"
    exit 1
}

cargo run --bin uniffi-bindgen generate \
    --library target/release/${LIBRARY_NAME}.$LIB_EXT \
    --language python \
    --out-dir out/python

# Copy the shared library to the Python output directory
echo "📦 Copying shared library to Python bindings directory..."
cp target/release/${LIBRARY_NAME}.$LIB_EXT out/python/

echo "✅ Python bindings built successfully!"

# Debug: List what was created
echo "📁 Contents of rust/out/python/:"
ls -la out/python/ || echo "   Directory not found!"
