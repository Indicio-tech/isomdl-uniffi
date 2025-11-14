# Copyright (c) 2025 Indicio
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# This software may be modified and distributed under the terms
# of either the Apache License, Version 2.0 or the MIT license.
# See the LICENSE-APACHE and LICENSE-MIT files for details.

"""
Pytest configuration and fixtures for isomdl-uniffi tests.
"""

import sys
from pathlib import Path

import pytest


@pytest.fixture(scope="session")
def mdl_module():
    """
    Import and provide the isomdl_uniffi module for all tests.

    This fixture handles the complex import logic needed to find the
    Rust-generated Python bindings and makes them available to all tests.
    """
    # Find the project root by looking for the rust directory
    current_dir = Path.cwd()
    project_root = current_dir

    # Look for rust directory to identify project root
    max_levels = 5  # Prevent infinite loop
    for _ in range(max_levels):
        rust_dir = project_root / "rust"
        if rust_dir.exists() and rust_dir.is_dir():
            break
        parent = project_root.parent
        if parent == project_root:  # Reached filesystem root
            break
        project_root = parent
    else:
        # Fallback to the old method if rust directory not found
        test_dir = Path(__file__).parent
        python_dir = test_dir.parent  # python directory
        project_root = python_dir.parent  # actual project root

    # Try to import from the generated bindings directory
    bindings_path = project_root / "rust" / "out" / "python"

    if not bindings_path.exists():
        pytest.fail(
            f"Python bindings not found at {bindings_path}. Please run the build script first."
        )

    # Add the bindings directory to Python path
    sys.path.insert(0, str(bindings_path))

    try:
        import isomdl_uniffi

        return isomdl_uniffi
    except ImportError as e:
        pytest.fail(f"Failed to import isomdl_uniffi: {e}")


@pytest.fixture(scope="function")
def key_pair(mdl_module):
    """Provide a fresh P256KeyPair for each test that needs one."""
    return mdl_module.P256KeyPair()


@pytest.fixture(scope="function")
def test_mdl(mdl_module, key_pair):
    """Provide a test MDL for each test that needs one."""
    return mdl_module.generate_test_mdl(key_pair)
