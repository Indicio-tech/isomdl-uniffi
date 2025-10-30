#!/usr/bin/env python3
"""
Presentation session tests for isomdl-uniffi Python bindings.
"""

import sys
import os
import uuid

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
    Run presentation session tests.

    Returns:
        bool: True if all tests pass, False otherwise.
    """
    global mdl
    if mdl is None:
        raise ImportError("isomdl_uniffi module not available")

    try:
        print("\n1. Testing presentation session creation:")

        # Generate a test MDL first
        key_pair = mdl.P256KeyPair()
        test_mdl = mdl.generate_test_mdl(key_pair)

        # Create presentation session
        session_uuid = str(uuid.uuid4())
        presentation_session = mdl.MdlPresentationSession(test_mdl, session_uuid)
        print("   ✅ Successfully created presentation session")

        # Test getting QR code URI
        qr_uri = presentation_session.get_qr_code_uri()
        print(f"   ✅ QR Code URI generated, length: {len(qr_uri)} characters")
        print(f"   QR Code URI preview: {qr_uri[:50]}...")

        # Test getting BLE identifier
        ble_ident = presentation_session.get_ble_ident()
        print(f"   ✅ BLE Identifier generated, length: {len(ble_ident)} bytes")

        print("\n2. Testing presentation session operations:")

        # Test generating response (this may fail without a real request)
        try:
            # Mock permitted items structure
            permitted_items = {
                "org.iso.18013.5.1": {
                    "family_name": ["test_value"],
                    "given_name": ["test_value"],
                }
            }

            response = presentation_session.generate_response(permitted_items)
            print(f"   ✅ Generated response, length: {len(response)} bytes")

        except Exception as e:
            print(
                f"   ⚠️  Response generation test failed (expected without real request): {e}"
            )

        return True

    except Exception as e:
        print(f"   ❌ Error in presentation session tests: {e}")
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
