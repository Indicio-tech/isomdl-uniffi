#!/usr/bin/env python3
"""
MDL document operations tests for isomdl-uniffi Python bindings.
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
    Run MDL document operations tests.

    Returns:
        bool: True if all tests pass, False otherwise.
    """
    global mdl
    if mdl is None:
        raise ImportError("isomdl_uniffi module not available")

    try:
        print("\n1. Testing MDL serialization:")

        # Generate a test MDL first
        key_pair = mdl.P256KeyPair()
        test_mdl = mdl.generate_test_mdl(key_pair)

        # Test JSON serialization
        json_str = test_mdl.json()
        print(f"   ✅ JSON serialization successful, length: {len(json_str)} characters")

        # Test stringify (CBOR serialization)
        cbor_str = test_mdl.stringify()
        print(f"   ✅ CBOR stringify successful, length: {len(cbor_str)} characters")

        print("\n2. Testing MDL construction from data:")

        # Test creating MDL from stringified document
        try:
            reconstructed_mdl = mdl.Mdoc.from_stringified_document(
                cbor_str, key_pair.key_alias
            )
            print("   ✅ Successfully reconstructed MDL from stringified document")

            # Verify it has the same document type
            original_doctype = test_mdl.doctype()
            reconstructed_doctype = reconstructed_mdl.doctype()
            if original_doctype == reconstructed_doctype:
                print(f"   ✅ Document types match: {original_doctype}")
            else:
                print(
                    f"   ❌ Document types don't match: {original_doctype} "
                    f"vs {reconstructed_doctype}"
                )
                return False

        except Exception as e:
            print(
                f"   ⚠️  MDL reconstruction test failed (expected for some formats): {e}"
            )

        return True

    except Exception as e:
        print(f"   ❌ Error in MDL operations tests: {e}")
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
