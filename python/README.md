# Python Components

This directory contains all Python-related components for the isomdl-uniffi project.

## Structure

```
python/
├── pyproject.toml              # Python package configuration
├── setup.py                    # Setup script with custom build integration
├── build.py                    # Build wrapper script
├── uv.lock                     # UV package manager lock file (if using UV)
├── INSTALL.md                  # Installation instructions
├── test-bindings.py            # Simple binding test script
├── isomdl_uniffi/              # Generated Python package
├── isomdl_uniffi.egg-info/     # Package metadata
├── precommit/                  # Pre-commit hooks and scripts
│   ├── build-bindings.sh       # Core build script for Rust library and Python bindings
│   ├── run-tests.sh            # Run Python tests script
│   └── README.md               # Pre-commit setup documentation
└── tests/                      # Comprehensive test suite
    ├── run_tests.py            # Test runner
    ├── test_*.py               # Individual test modules
    ├── isomdl_uniffi_tests.egg-info/  # Test package metadata
    └── README.md               # Detailed test documentation
```

## Quick Start

### Installation from GitHub Releases

For production use, install pre-built wheels from GitHub releases:

```bash
# Install the latest release for your platform
pip install https://github.com/Indicio-tech/isomdl-uniffi/releases/download/v0.1.0/isomdl_uniffi-0.1.0-<platform>.whl

# Examples for specific platforms:
# Linux (x86_64)
pip install https://github.com/Indicio-tech/isomdl-uniffi/releases/download/v0.1.0/isomdl_uniffi-0.1.0-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl

# macOS (Intel/Apple Silicon universal2)
pip install https://github.com/Indicio-tech/isomdl-uniffi/releases/download/v0.1.0/isomdl_uniffi-0.1.0-cp311-cp311-macosx_11_0_universal2.whl

# Windows (x86_64)
pip install https://github.com/Indicio-tech/isomdl-uniffi/releases/download/v0.1.0/isomdl_uniffi-0.1.0-cp311-cp311-win_amd64.whl
```

**Note:** Replace `v0.1.0` with the desired version tag and `cp311` with your Python version (`cp39`, `cp310`, `cp311`, or `cp312`).

### 1. Build Python Bindings (Development)

For local development, build the bindings from source:

**Using UV (recommended):**
```bash
# Install dependencies and build
cd python
uv sync --extra dev
uv run python build.py
```

**Using standard Python:**
```bash
# Build Rust library and generate Python bindings
cd python
python3 build.py
```

**Direct build script:**
```bash
# Use the core build script directly
./python/precommit/build-bindings.sh
```

### 2. Run Tests

```bash
# Run quick test
./python/test-bindings.py

# Or run the comprehensive test suite
./python/precommit/run-tests.sh

# Or manually run tests
cd python/tests
python3 run_tests.py
```

## Development

The Python components use modern Python packaging with `pyproject.toml` configuration and are integrated with the project's CI/CD pipeline for automated testing across multiple Python versions (3.9-3.12).

For detailed test information, see [`tests/README.md`](tests/README.md).
