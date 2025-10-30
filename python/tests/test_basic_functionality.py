#!/usr/bin/env python3
"""
Basic functionality tests for isomdl-uniffi Python bindings.
"""

import sys
import os

# Add the project root to the path to import the generated bindings
sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "..", "rust", "out", "python")
)

try:
    import isomdl_uniffi as mdl
except ImportError:
    # If running via run_tests.py, mdl will be injected as a module global
    mdl = None


def run_tests():
    """
    Run basic functionality tests.

    Returns:
        bool: True if all tests pass, False otherwise.
    """
    global mdl
    if mdl is None:
        raise ImportError("isomdl_uniffi module not available")

    try:
        # Test key pair generation first (required for test MDL)
        print("\n1. Testing key pair generation:")
        key_pair = mdl.P256KeyPair()  # Constructor creates a new key pair
        print("   ✅ Successfully generated P256 key pair")
        print(f"   Key pair type: {type(key_pair)}")

        # Test getting public key as JWK
        public_jwk = key_pair.public_jwk()
        print(f"   ✅ Public key JWK length: {len(public_jwk)} characters")

        # Test signing with key pair
        test_message = b"Hello, isomdl!"
        signature = key_pair.sign(test_message)
        print(f"   ✅ Signature length: {len(signature)} bytes")

        print("\n2. Testing test MDL generation:")
        test_mdl = mdl.generate_test_mdl(key_pair)  # Requires key_pair parameter
        print("   ✅ Successfully generated test MDL")
        print(f"   MDL type: {type(test_mdl)}")

        # Test getting document type
        doc_type = test_mdl.doctype()
        print(f"   ✅ Document type: {doc_type}")

        # Test getting MDL ID
        mdl_id = test_mdl.id()
        print(f"   ✅ MDL ID: {mdl_id}")

        # Test getting key alias
        key_alias = test_mdl.key_alias()
        print(f"   ✅ Key alias: {key_alias}")

        print("\n3. Testing MDL details:")
        details = test_mdl.details()
        print(f"   ✅ Details type: {type(details)}")
        print(f"   ✅ Number of namespaces: {len(details)}")

        for namespace, elements in details.items():
            print(f"   ✅ Namespace '{namespace}': {len(elements)} elements")
            for element in elements[:2]:  # Show first 2 elements
                print(f"     - {element.identifier}: {element.value}")
            if len(elements) > 2:
                print(f"     ... and {len(elements) - 2} more")

        return True

    except Exception as e:
        print(f"   ❌ Error in basic functionality tests: {e}")
        import traceback

        traceback.print_exc()
        return False


if __name__ == "__main__":
    # This allows running the test file directly for debugging
    if mdl is None:
        try:
            import isomdl_uniffi as mdl
        except ImportError as e:
            print(f"❌ Could not import isomdl_uniffi: {e}")
            print("Please run './build-python-bindings.sh' first")
            sys.exit(1)

    success = run_tests()
    sys.exit(0 if success else 1)
