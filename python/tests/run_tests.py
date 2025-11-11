#!/usr/bin/env python3
"""
Test suite for isomdl-uniffi Python bindings.

This module provides utilities to run the test suite using pytest.
"""

import sys
from pathlib import Path


def run_all_tests():
    """
    Run all tests using pytest.

    Returns:
        bool: True if all tests pass, False otherwise.
    """
    print("=" * 60)
    print("isomdl-uniffi Python Bindings Test Suite")
    print("=" * 60)

    try:
        import pytest
    except ImportError:
        print("❌ pytest is required to run tests!")
        print("   Install it with: pip install pytest pytest-cov")
        return False

    # Find test directory
    test_dir = Path(__file__).parent

    print("🧪 Running tests with pytest...")
    print()

    # Run pytest with configuration
    exit_code = pytest.main([str(test_dir), "-v", "--tb=short", "--disable-warnings"])

    success = exit_code == 0

    print("\n" + "=" * 60)
    if success:
        print("✅ All tests passed!")
    else:
        print("❌ Some tests failed!")

    return success


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
