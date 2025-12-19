#!/bin/bash
# Copyright (c) 2025 Indicio
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# This software may be modified and distributed under the terms
# of either the Apache License, Version 2.0 or the MIT license.
# See the LICENSE-APACHE and LICENSE-MIT files for details.

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

# Ensure built bindings are discoverable by Python
export PYTHONPATH="$(pwd)/rust/out/python:${PYTHONPATH:-}"

# Run the test suite
# Use UV if available, otherwise fallback to python
if command -v uv >/dev/null 2>&1; then
    cd python
    uv sync --extra dev  # Install dev dependencies including pytest
    uv run pytest tests/ -q --tb=short -m "not cross_language"
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
