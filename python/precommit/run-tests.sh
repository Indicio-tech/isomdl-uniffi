#!/bin/bash
# Pre-commit hook to run Python tests
# This script runs the test suite to ensure all tests pass

set -e

echo "🧪 Running Python tests..."

# Navigate to project root
cd "$(dirname "$0")/../.."

# Check if bindings are built
if [ ! -d "rust/out/python" ]; then
    if [ -n "$CI" ]; then
        echo "❌ Python bindings not found in CI environment!"
        echo "   This indicates an issue with artifact download."
        exit 1
    else
        echo "⚠️  Python bindings not found. Building first..."
        ./python/precommit/build-bindings.sh
    fi
fi

# Run the test suite
# Use UV if available, otherwise fallback to python
if command -v uv >/dev/null 2>&1; then
    cd python
    uv run pytest tests/ -q --tb=short
    cd ..
elif command -v python3 >/dev/null 2>&1; then
    python3 python/tests/run_tests.py
elif command -v python >/dev/null 2>&1; then
    python python/tests/run_tests.py
else
    echo "❌ Python not found. Please install Python 3."
    exit 1
fi

echo "✅ All Python tests passed!"
