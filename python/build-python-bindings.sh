#!/bin/bash
set -e

echo "Building isomdl-uniffi Python bindings..."

# Navigate to rust directory (go up from python/ to project root, then to rust/)
cd "$(dirname "$0")/../rust"

# Note: This script builds for the current platform only.
# For cross-platform builds (macOS universal, Linux, Windows), see:
# https://github.com/cross-rs/cross for cross-compilation setup

# Build the Rust library
echo "Building Rust library..."
cargo build --release --lib

# Create output directory
mkdir -p out/python

# Determine library file based on platform
if [[ "$OSTYPE" == "darwin"* ]]; then
    LIB_FILE="libisomdl_uniffi.dylib"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    LIB_FILE="libisomdl_uniffi.so"
elif [[ "$OSTYPE" == "msys" ]]; then
    LIB_FILE="isomdl_uniffi.dll"
else
    echo "Unsupported platform: $OSTYPE"
    exit 1
fi

# Copy the library to output directory
cp "target/release/$LIB_FILE" "out/python/"

# Generate Python bindings
echo "Generating Python bindings..."
cargo run --features=uniffi/cli --bin uniffi-bindgen generate \
    --library "target/release/$LIB_FILE" \
    --language python \
    --out-dir out/python

# Create Python package files
echo "Creating Python package files..."
cat > out/python/setup.py << 'EOF'
from setuptools import setup
import platform
import os

# Determine the correct library file based on platform
if platform.system() == "Darwin":
    lib_file = "libisomdl_uniffi.dylib"
elif platform.system() == "Linux":
    lib_file = "libisomdl_uniffi.so"
elif platform.system() == "Windows":
    lib_file = "isomdl_uniffi.dll"
else:
    raise RuntimeError(f"Unsupported platform: {platform.system()}")

# Check if the library file exists
if not os.path.exists(lib_file):
    raise FileNotFoundError(f"Required library file {lib_file} not found. Please build the Rust library first.")

setup(
    name="isomdl-uniffi",
    version="0.1.0",
    description="Python bindings for ISO 18013-5 Mobile Driver's License library",
    long_description="Python bindings for ISO 18013-5 Mobile Driver's License library using UniFFI",
    long_description_content_type="text/plain",
    author="Indicio",
    author_email="dev@indicio.tech",
    url="https://github.com/Indicio-tech/isomdl-uniffi",
    packages=[""],
    package_dir={"": "."},
    package_data={"": ["isomdl_uniffi.py", lib_file]},
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Security :: Cryptography",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Rust",
        "Operating System :: OS Independent",
    ],
    keywords=["iso18013-5", "mdl", "mobile-drivers-license", "digital-identity", "verifiable-credentials"],
)
EOF

cat > out/python/pyproject.toml << 'EOF'
[build-system]
requires = ["setuptools>=45", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "isomdl-uniffi"
version = "0.1.0"
description = "Python bindings for ISO 18013-5 Mobile Driver's License library"
authors = [
    {name = "Indicio", email = "dev@indicio.tech"}
]
license = "Apache-2.0"
requires-python = ">=3.8"
keywords = ["iso18013-5", "mdl", "mobile-drivers-license", "digital-identity", "verifiable-credentials"]
EOF

cat > out/python/MANIFEST.in << 'EOF'
include *.dylib
include *.so
include *.dll
include isomdl_uniffi.py
EOF

echo ""
echo "✅ Python bindings built successfully!"
echo ""
echo "Generated files are in: rust/out/python/"
echo ""
echo "To test the bindings:"
echo "  ./test-bindings.py"
echo ""
echo "To install in development mode:"
echo "  cd rust/out/python && pip install -e ."
echo ""
echo "To build a distributable wheel:"
echo "  cd rust/out/python && python -m build"
echo ""