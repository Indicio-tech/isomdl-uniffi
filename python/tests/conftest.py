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

# Ensure we can import utils from the same directory
sys.path.append(str(Path(__file__).parent))
from utils import get_mdl_module, get_project_root


@pytest.fixture(scope="session")
def project_root():
    """
    Provide the project root path for all tests.
    """
    return get_project_root()


@pytest.fixture(scope="session")
def mdl_module(project_root):
    """
    Import and provide the isomdl_uniffi module for all tests.

    This fixture handles the complex import logic needed to find the
    Rust-generated Python bindings and makes them available to all tests.
    """
    return get_mdl_module(project_root)


@pytest.fixture(scope="function")
def key_pair(mdl_module):
    """Provide a fresh P256KeyPair for each test that needs one."""
    return mdl_module.P256KeyPair()


@pytest.fixture(scope="function")
def test_mdl(mdl_module, key_pair):
    """Provide a test MDL for each test that needs one."""
    return mdl_module.generate_test_mdl(key_pair)
