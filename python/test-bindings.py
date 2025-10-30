#!/usr/bin/env python3
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

import sys
import os

if __name__ == "__main__":
    # Add the tests directory to the path
    tests_path = os.path.join(os.path.dirname(__file__), "tests")
    sys.path.insert(0, os.path.abspath(tests_path))

    # Import and run the main test runner
    from run_tests import run_all_tests

    success = run_all_tests()
    sys.exit(0 if success else 1)
