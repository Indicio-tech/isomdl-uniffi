#!/usr/bin/env python3
"""
Reader functionality tests for isomdl-uniffi Python bindings.
"""

import json
import os
import sys
import uuid


def run_tests(mdl):
    """
    Run reader functionality tests.

    Args:
        mdl: The isomdl_uniffi module

    Returns:
        bool: True if all tests pass, False otherwise.
    """

    try:
        print("\n1. Testing reader session establishment:")

        # Define what data elements to request
        requested_items = {
            "org.iso.18013.5.1": {
                "family_name": True,
                "given_name": True,
                "birth_date": True,
                "issue_date": True,
                "expiry_date": True,
                "document_number": True,
            }
        }

        print(f"   Requested items: {json.dumps(requested_items, indent=2)}")

        # Create a real presentation session to get a valid QR code URI
        # (needed for testing reader functionality)
        key_pair = mdl.P256KeyPair()
        test_mdoc = mdl.generate_test_mdl(key_pair)
        session_uuid = str(uuid.uuid4())
        presentation_session = mdl.MdlPresentationSession(test_mdoc, session_uuid)
        test_uri = presentation_session.get_qr_code_uri()

        print("   Attempting to establish reader session with real QR URI...")

        session_data = mdl.establish_session(
            uri=test_uri,
            requested_items=requested_items,
            trust_anchor_registry=[],  # Empty trust anchor list for test
        )

        # ACTUAL VALIDATION - not just printing!
        assert session_data is not None, "Session data should not be None"
        assert hasattr(session_data, "uuid"), "Session data should have uuid"
        assert hasattr(session_data, "request"), "Session data should have request"
        assert hasattr(session_data, "ble_ident"), "Session data should have ble_ident"
        assert hasattr(session_data, "state"), "Session data should have state"

        # Validate session UUID format
        import uuid as uuid_module

        try:
            uuid_obj = uuid_module.UUID(session_data.uuid)
            assert str(uuid_obj) == session_data.uuid, "Invalid UUID format"
        except ValueError:
            raise AssertionError(f"Session UUID is not valid: {session_data.uuid}")

        # Validate request data
        assert isinstance(session_data.request, bytes), "Request should be bytes"
        assert len(session_data.request) > 0, "Request should not be empty"
        assert len(session_data.request) < 10000, (
            f"Request suspiciously large: {len(session_data.request)}"
        )

        # Validate BLE identifier
        assert isinstance(session_data.ble_ident, bytes), "BLE identifier should be bytes"
        assert len(session_data.ble_ident) == 16, (
            f"BLE identifier should be 16 bytes, got {len(session_data.ble_ident)}"
        )

        # Validate session manager
        session_manager = session_data.state
        assert session_manager is not None, "Session manager should not be None"

        print("   ✅ Session established and validated successfully!")
        print(f"   Session UUID: {session_data.uuid}")
        print(f"   Request data length: {len(session_data.request)} bytes")
        print(f"   BLE identifier length: {len(session_data.ble_ident)} bytes")
        print(f"   ✅ Session manager type: {type(session_manager)}")

        # Test complete reader workflow
        print("\n2. Testing complete reader workflow:")

        # Handle the request on the presentation side
        requested_data = presentation_session.handle_request(session_data.request)

        # Validate the requested data structure
        assert isinstance(requested_data, list), "Requested data should be a list"
        assert len(requested_data) > 0, "Should have at least one document request"

        doc_request = requested_data[0]
        assert hasattr(doc_request, "doc_type"), "Document request should have doc_type"
        assert hasattr(doc_request, "namespaces"), "Document request should have namespaces"
        assert doc_request.doc_type == "org.iso.18013.5.1.mDL", (
            f"Wrong doc type: {doc_request.doc_type}"
        )

        # Validate requested attributes match what we requested
        assert "org.iso.18013.5.1" in doc_request.namespaces, "Missing ISO namespace"
        iso_namespace = doc_request.namespaces["org.iso.18013.5.1"]

        # Verify all requested attributes are present
        for attr_name in requested_items["org.iso.18013.5.1"].keys():
            assert attr_name in iso_namespace, f"Missing requested attribute: {attr_name}"
            assert iso_namespace[attr_name] is True, f"Attribute {attr_name} should be required"

        print(f"   ✅ Request validation passed - {len(iso_namespace)} attributes requested")

        # Generate and validate response
        permitted_items = {
            "org.iso.18013.5.1.mDL": {
                "org.iso.18013.5.1": list(requested_items["org.iso.18013.5.1"].keys())
            }
        }

        unsigned_response = presentation_session.generate_response(permitted_items)
        assert isinstance(unsigned_response, bytes), "Unsigned response should be bytes"
        assert len(unsigned_response) > 0, "Unsigned response should not be empty"

        # Sign the response
        signed_response = key_pair.sign(unsigned_response)
        assert isinstance(signed_response, bytes), "Signed response should be bytes"
        assert len(signed_response) > 0, "Signed response should not be empty"
        assert signed_response != unsigned_response, "Signed response should differ from unsigned"

        # Submit the response
        final_response = presentation_session.submit_response(signed_response)
        assert isinstance(final_response, bytes), "Final response should be bytes"
        assert len(final_response) > 0, "Final response should not be empty"

        print(f"   ✅ Response generation validated - {len(final_response)} bytes")

        # Verify the reader can handle the response
        result = mdl.handle_response(session_manager, final_response)
        assert result is not None, "Response handling should not return None"
        assert hasattr(result, "device_authentication"), "Result should have device_authentication"
        assert hasattr(result, "verified_response"), "Result should have verified_response"

        # Validate authentication status
        auth_status = result.device_authentication
        assert auth_status == mdl.AuthenticationStatus.VALID, (
            f"Expected VALID auth, got {auth_status}"
        )

        # Validate response data
        verified_response = result.verified_response
        assert isinstance(verified_response, dict), "Verified response should be a dict"
        assert "org.iso.18013.5.1" in verified_response, "Missing namespace in response"

        response_attrs = verified_response["org.iso.18013.5.1"]
        assert len(response_attrs) > 0, "Response should contain attributes"

        # Verify all permitted attributes are in response
        for attr_name in permitted_items["org.iso.18013.5.1.mDL"]["org.iso.18013.5.1"]:
            assert attr_name in response_attrs, f"Missing attribute in response: {attr_name}"
            # Verify attribute has actual value
            attr_value = response_attrs[attr_name]
            assert attr_value is not None, f"Attribute {attr_name} should have a value"

        print(f"   ✅ Complete workflow validated - {len(response_attrs)} attributes returned")

        return True

    except (ValueError, RuntimeError, AttributeError, ImportError) as e:
        print(f"   ❌ Error in reader functionality tests: {e}")
        import traceback

        traceback.print_exc()
        return False


if __name__ == "__main__":
    # This allows running the test file directly for debugging
    try:
        # Add the project root to the path to import the generated bindings
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "rust", "out", "python"))
        import isomdl_uniffi as mdl_module

        success = run_tests(mdl_module)
        sys.exit(0 if success else 1)
    except ImportError as e:
        print(f"❌ Could not import isomdl_uniffi: {e}")
        print("Please run './build-python-bindings.sh' first")
        sys.exit(1)
