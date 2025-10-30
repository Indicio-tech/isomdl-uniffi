#!/usr/bin/env python3
"""
Test integration between existing tests and new MDL functionality.
"""

import sys
import os


def run_tests(mdl):
    """
    Run integration tests.

    Args:
        mdl: The isomdl_uniffi module

    Returns:
        bool: True if all tests pass, False otherwise.
    """
    print("Running integration tests...")

    test_success = True
    test_success &= test_imports(mdl)
    test_success &= test_mdl_basic(mdl)

    if test_success:
        print("\n✓ All integration tests passed!")
    else:
        print("\n✗ Some tests failed!")

    return test_success


def test_imports(mdl):
    """Test that all required modules can be imported"""
    try:
        # Test that imports work
        _ = mdl.Mdoc, mdl.MdlPresentationSession, mdl.P256KeyPair
        _ = mdl.establish_session, mdl.handle_response, mdl.generate_test_mdl
        _ = mdl.AuthenticationStatus
        print("✓ All imports successful")
        return True
    except (ImportError, AttributeError) as e:
        print(f"✗ Import failed: {e}")
        return False


def test_mdl_basic(mdl):
    """Basic test of MDL functionality"""
    try:
        # Generate a key pair
        holder_key = mdl.P256KeyPair()
        print("✓ Key pair generated")

        # Generate test MDL
        mdoc = mdl.generate_test_mdl(holder_key)
        print("✓ Test MDL generated")

        # Test basic mdoc operations
        doctype = mdoc.doctype()
        print(f"✓ Document type: {doctype}")

        mdoc_id = mdoc.id()
        print(f"✓ MDL ID: {mdoc_id}")

        # Test serialization
        cbor = mdoc.stringify()
        print(f"✓ Serialized to CBOR: {len(cbor)} bytes")

        # Test deserialization
        restored = mdl.Mdoc.from_string(cbor)
        assert (
            restored.doctype() == doctype
        ), "Document type should match after round-trip"
        assert restored.id() == mdoc_id, "Document ID should match after round-trip"
        print("✓ Round-trip serialization successful")

        return True

    except (ValueError, RuntimeError, AttributeError) as e:
        print(f"✗ MDL test failed: {e}")
        return False


if __name__ == "__main__":
    # This allows running the test file directly for debugging
    try:
        # Add the project root to the path to import the generated bindings
        sys.path.insert(
            0, os.path.join(os.path.dirname(__file__), "..", "rust", "out", "python")
        )
        import isomdl_uniffi as mdl_module

        success = run_tests(mdl_module)
        sys.exit(0 if success else 1)
    except ImportError as e:
        print(f"❌ Could not import isomdl_uniffi: {e}")
        print("Please run './build-python-bindings.sh' first")
        sys.exit(1)
