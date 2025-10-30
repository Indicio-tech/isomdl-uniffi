#!/bin/bash
# Pre-commit hook to build Python bindings
# This script checks if Rust code or build files have changed and rebuilds bindings

set -e

echo "🔧 Building Rust crate..."
# Navigate to project root then to rust directory
cd "$(dirname "$0")/../.."
cd rust

# Build the Rust library in release mode
# Note: We need to preserve symbols for UniFFI, so build without stripping
echo "🔧 Building library for UniFFI bindgen (preserving symbols)..."
RUSTFLAGS="-C strip=none" cargo build --release

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

echo "🔧 Testing uniffi-bindgen binary..."
cargo run --bin uniffi-bindgen --help >/dev/null || {
    echo "❌ uniffi-bindgen binary not working!"
    exit 1
}

echo "🔧 Running uniffi-bindgen to generate Python bindings..."
echo "Command: cargo run --bin uniffi-bindgen generate --library target/release/${LIBRARY_NAME}.$LIB_EXT --language python --out-dir out/python"

if ! cargo run --bin uniffi-bindgen generate \
    --library target/release/${LIBRARY_NAME}.$LIB_EXT \
    --language python \
    --out-dir out/python 2>&1; then
    EXIT_CODE=$?
    echo "❌ uniffi-bindgen failed!"
    echo "Exit code: $EXIT_CODE"
    exit 1
fi

echo "🔍 Checking what uniffi-bindgen generated..."
ls -la out/python/ || {
    echo "❌ Output directory not created!"
    exit 1
}

# Verify the Python module was generated
if [ ! -f "out/python/isomdl_uniffi.py" ]; then
    echo "❌ Python module file not generated!"
    echo "🔍 Contents of out/python/:"
    find out/python/ -type f || echo "No files found"
    exit 1
fi

echo "✅ Python module generated successfully"

# Copy the shared library to the Python output directory
echo "📦 Copying shared library to Python bindings directory..."
cp target/release/${LIBRARY_NAME}.$LIB_EXT out/python/

echo "✅ Python bindings built successfully!"

# Debug: List what was created
echo "📁 Contents of rust/out/python/:"
ls -la out/python/ || echo "   Directory not found!"

# Verify both files exist
echo "🔍 Verifying binding files:"
if [ -f "out/python/isomdl_uniffi.py" ]; then
    echo "  ✅ isomdl_uniffi.py exists ($(wc -l < out/python/isomdl_uniffi.py) lines)"
else
    echo "  ❌ isomdl_uniffi.py missing!"
fi

if [ -f "out/python/${LIBRARY_NAME}.$LIB_EXT" ]; then
    echo "  ✅ ${LIBRARY_NAME}.$LIB_EXT exists ($(ls -lh out/python/${LIBRARY_NAME}.$LIB_EXT | awk '{print $5}'))"
else
    echo "  ❌ ${LIBRARY_NAME}.$LIB_EXT missing!"
fi
