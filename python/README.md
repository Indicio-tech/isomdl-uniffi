# Python Components

This directory contains all Python-related components for the isomdl-uniffi project.

## Structure

```
python/
├── pyproject.toml          # Python package configuration
├── test-bindings.py        # Simple binding test script
├── precommit/              # Pre-commit hooks and scripts
│   ├── build-bindings.sh   # Build Python bindings script
│   ├── run-tests.sh        # Run Python tests script
│   └── README.md           # Pre-commit setup documentation
└── tests/                  # Comprehensive test suite
    ├── run_tests.py        # Test runner
    ├── test_*.py           # Individual test modules
    └── README.md           # Detailed test documentation
```

## Quick Start

### 1. Build Python Bindings

From the project root:

```bash
# Build Rust library and generate Python bindings
./build-python-bindings.sh
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