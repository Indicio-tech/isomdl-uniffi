#!/usr/bin/env python3
# Copyright (c) 2025 Indicio
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# This software may be modified and distributed under the terms
# of either the Apache License, Version 2.0 or the MIT license.
# See the LICENSE-APACHE and LICENSE-MIT files for details.

"""
Simple test runner for isomdl-uniffi Python bindings.

This script runs tests from the command line after bindings are generated.
The main test logic is in tests/run_tests.py which handles bindings import
and all test execution.

Test suite includes:
- Basic functionality tests (key generation, MDL creation)
- MDL operation tests (serialization, CBOR operations)
- Presentation session tests (QR code generation, BLE)
- Reader functionality tests (session establishment, verification)

Usage:
    ./test-bindings.py
"""

import os
import sys

if __name__ == "__main__":
    # Add the tests directory to the path
    tests_path = os.path.join(os.path.dirname(__file__), "tests")
    sys.path.insert(0, os.path.abspath(tests_path))

    # Import and run the main test runner
    from run_tests import run_all_tests

    success = run_all_tests()
    sys.exit(0 if success else 1)
