#!/usr/bin/env python3
"""
Test suite for isomdl-uniffi Python bindings.

This module provides utilities to run the test suite after the Python bindings
have been generated.
"""

import importlib.util
import os
import sys
import traceback


def import_bindings():
    """
    Import the generated Python bindings from the expected location.

    Returns:
        The imported isomdl_uniffi module, or None if import fails.
    """
    # Find the project root by looking for the rust directory
    # Start from current working directory and move up
    current_dir = os.getcwd()
    project_root = current_dir

    # Look for rust directory to identify project root
    max_levels = 5  # Prevent infinite loop
    for _ in range(max_levels):
        rust_dir = os.path.join(project_root, "rust")
        if os.path.exists(rust_dir) and os.path.isdir(rust_dir):
            break
        parent = os.path.dirname(project_root)
        if parent == project_root:  # Reached filesystem root
            break
        project_root = parent
    else:
        # Fallback to the old method if rust directory not found
        test_dir = os.path.dirname(os.path.abspath(__file__))
        python_dir = os.path.dirname(test_dir)  # python directory
        project_root = os.path.dirname(python_dir)  # actual project root

    # Try to import from the generated bindings directory
    bindings_path = os.path.join(project_root, "rust", "out", "python")

    print(f"🔍 Looking for Python bindings at: {bindings_path}")

    if not os.path.exists(bindings_path):
        print("❌ Python bindings not found!")
        print(f"   Expected path: {bindings_path}")
        print(f"   Current working directory: {current_dir}")
        print(f"   Project root: {project_root}")

        # List what's actually there for debugging
        rust_dir = os.path.join(project_root, "rust")
        if os.path.exists(rust_dir):
            print(f"   Contents of rust/: {os.listdir(rust_dir)}")
            out_dir = os.path.join(rust_dir, "out")
            if os.path.exists(out_dir):
                print(f"   Contents of rust/out/: {os.listdir(out_dir)}")

        print("   Please run './build-python-bindings.sh' first")
        return None

    # Add the bindings directory to Python path
    sys.path.insert(0, bindings_path)

    # List the files in the bindings directory for debugging
    print(f"📁 Contents of bindings directory: {os.listdir(bindings_path)}")

    try:
        import isomdl_uniffi

        return isomdl_uniffi
    except ImportError as e:
        print(f"❌ Failed to import isomdl_uniffi: {e}")


def run_all_tests():
    """
    Run all tests in the tests directory.

    Returns:
        bool: True if all tests pass, False otherwise.
    """
    print("=" * 60)
    print("isomdl-uniffi Python Bindings Test Suite")
    print("=" * 60)

    # Import the bindings
    mdl = import_bindings()
    if mdl is None:
        return False

    print("✅ Successfully imported isomdl_uniffi from bindings")

    # Run tests
    test_modules = [
        "test_basic_functionality",
        "test_mdoc_operations",
        "test_presentation_session",
        "test_reader_functionality",
        "test_integration",
        "test_selective_disclosure",
        "test_complete_workflow",
    ]

    failed_tests = []

    for test_module in test_modules:
        print(f"\n🧪 Running {test_module}...")
        try:
            # Import the test module
            test_path = os.path.join(os.path.dirname(__file__), f"{test_module}.py")
            if not os.path.exists(test_path):
                print(f"   ⚠️  Test file not found: {test_path}")
                continue

            spec = importlib.util.spec_from_file_location(test_module, test_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            # Run the test function with mdl module as parameter
            if hasattr(module, "run_tests"):
                test_success = module.run_tests(mdl)
                if not test_success:
                    failed_tests.append(test_module)
            else:
                print(f"   ⚠️  No run_tests() function found in {test_module}")

        except (ImportError, AttributeError, RuntimeError) as e:
            print(f"   ❌ Error running {test_module}: {e}")
            traceback.print_exc()
            failed_tests.append(test_module)

    # Summary
    print("\n" + "=" * 60)
    if failed_tests:
        print(f"❌ Test suite completed with {len(failed_tests)} failed test(s):")
        for test in failed_tests:
            print(f"   - {test}")
        return False
    else:
        print("✅ All tests passed!")
        return True


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
