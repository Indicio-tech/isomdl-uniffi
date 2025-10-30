#!/usr/bin/env python3
"""
Test integration between existing tests and new MDL functionality.
"""

import sys
import os

# Add the project root to the path to import the generated bindings
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:
    from isomdl_uniffi import (
        Mdoc,
        MdlPresentationSession,
        P256KeyPair,
        establish_session,
        handle_response,
        generate_test_mdl,
        AuthenticationStatus,
    )
except ImportError:
    # If running via run_tests.py, mdl will be injected as a module global
    pass


def test_imports():
    """Test that all required modules can be imported"""
    try:
        # Test that imports work
        _ = Mdoc, MdlPresentationSession, P256KeyPair
        _ = establish_session, handle_response, generate_test_mdl, AuthenticationStatus
        print("✓ All imports successful")
        return True
    except (ImportError, NameError) as e:
        print(f"✗ Import failed: {e}")
        return False


def test_mdl_basic():
    """Basic test of MDL functionality"""
    try:

        # Generate a key pair
        holder_key = P256KeyPair()
        print("✓ Key pair generated")

        # Generate test MDL
        mdoc = generate_test_mdl(holder_key)
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
        restored = Mdoc.from_string(cbor)
        assert (
            restored.doctype() == doctype
        ), "Document type should match after round-trip"
        assert restored.id() == mdoc_id, "Document ID should match after round-trip"
        print("✓ Round-trip serialization successful")

        return True

    except Exception as e:
        print(f"✗ MDL test failed: {e}")
        return False


if __name__ == "__main__":
    print("Running integration tests...")

    success = True
    success &= test_imports()
    success &= test_mdl_basic()

    if success:
        print("\n✓ All integration tests passed!")
    else:
        print("\n✗ Some tests failed!")
        sys.exit(1)
