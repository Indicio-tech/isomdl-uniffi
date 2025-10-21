#!/usr/bin/env python3
"""
Test suite for isomdl-uniffi Python bindings.

This module provides utilities to run the test suite after the Python bindings
have been generated.
"""

import sys
import os
import importlib.util
import traceback


def import_bindings():
    """
    Import the isomdl_uniffi module from the generated bindings.
    
    Returns:
        The imported isomdl_uniffi module, or None if import fails.
    """
    # Try to import from the generated bindings directory
    bindings_path = os.path.join(
        os.path.dirname(__file__), "..", "rust", "out", "python"
    )
    
    if not os.path.exists(bindings_path):
        print("❌ Python bindings not found!")
        print(f"   Expected path: {os.path.abspath(bindings_path)}")
        print("   Please run './build-python-bindings.sh' first")
        return None
    
    # Add the bindings directory to Python path
    sys.path.insert(0, os.path.abspath(bindings_path))
    
    try:
        import isomdl_uniffi
        return isomdl_uniffi
    except ImportError as e:
        print(f"❌ Failed to import isomdl_uniffi: {e}")
        return None


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
    
    print(f"✅ Successfully imported isomdl_uniffi from bindings")
    
    # Run tests
    test_modules = [
        "test_basic_functionality",
        "test_mdoc_operations", 
        "test_presentation_session",
        "test_reader_functionality"
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
            
            # Add mdl to the module's globals so tests can use it
            module.mdl = mdl
            
            spec.loader.exec_module(module)
            
            # Run the test function
            if hasattr(module, 'run_tests'):
                success = module.run_tests()
                if not success:
                    failed_tests.append(test_module)
            else:
                print(f"   ⚠️  No run_tests() function found in {test_module}")
                
        except Exception as e:
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