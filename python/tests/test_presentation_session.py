#!/usr/bin/env python3
"""
Presentation session tests for isomdl-uniffi Python bindings.
"""

import os
import sys
import uuid


def run_tests(mdl):
    """
    Run presentation session tests.

    Args:
        mdl: The isomdl_uniffi module

    Returns:
        bool: True if all tests pass, False otherwise.
    """
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

        print("\n2. Testing presentation session operations with validation:")

        # Create a mock reader session and request
        requested_items = {
            "org.iso.18013.5.1": {
                "family_name": True,
                "given_name": True,
            }
        }

        # Establish reader session to generate a proper request
        reader_session = mdl.establish_session(qr_uri, requested_items, None)

        # VALIDATE reader session
        assert reader_session is not None, "Reader session should not be None"
        assert hasattr(reader_session, "request"), "Reader session should have request"
        assert hasattr(reader_session, "state"), "Reader session should have state"
        assert isinstance(reader_session.request, bytes), "Request should be bytes"
        assert len(reader_session.request) > 0, "Request should not be empty"

        # Process the request first (required before generating response)
        requested_data = presentation_session.handle_request(reader_session.request)

        # VALIDATE requested data structure
        assert isinstance(requested_data, list), "Requested data should be a list"
        assert len(requested_data) == 1, (
            f"Should have exactly 1 document, got {len(requested_data)}"
        )

        doc_request = requested_data[0]
        assert hasattr(doc_request, "doc_type"), "Document request should have doc_type"
        assert hasattr(doc_request, "namespaces"), "Document request should have namespaces"
        assert doc_request.doc_type == "org.iso.18013.5.1.mDL", (
            f"Wrong doc type: {doc_request.doc_type}"
        )

        # Validate namespace structure
        assert "org.iso.18013.5.1" in doc_request.namespaces, "Missing ISO namespace"
        iso_namespace = doc_request.namespaces["org.iso.18013.5.1"]

        # Validate requested attributes match what we requested
        expected_attrs = {"family_name", "given_name"}
        actual_attrs = set(iso_namespace.keys())
        assert actual_attrs == expected_attrs, f"Expected {expected_attrs}, got {actual_attrs}"

        # Validate all attributes are marked as required
        for attr in expected_attrs:
            assert iso_namespace[attr] is True, f"Attribute {attr} should be required"

        print(f"   ✅ Request validated - {len(iso_namespace)} attributes requested")

        # Now generate response with permitted items
        permitted_items = {
            "org.iso.18013.5.1.mDL": {"org.iso.18013.5.1": ["family_name", "given_name"]}
        }

        unsigned_response = presentation_session.generate_response(permitted_items)

        # VALIDATE response generation
        assert isinstance(unsigned_response, bytes), "Response should be bytes"
        assert len(unsigned_response) > 0, "Response should not be empty"
        assert len(unsigned_response) > 10, f"Response too short: {len(unsigned_response)}"

        print(f"   ✅ Unsigned response validated, length: {len(unsigned_response)} bytes")

        print("\n3. Testing complete presentation workflow:")

        # Sign the response
        signed_response = key_pair.sign(unsigned_response)

        # VALIDATE signing
        assert isinstance(signed_response, bytes), "Signed response should be bytes"
        assert len(signed_response) > 0, "Signed response should not be empty"
        assert signed_response != unsigned_response, "Signed response should differ from unsigned"

        # Submit the signed response
        final_response = presentation_session.submit_response(signed_response)

        # VALIDATE final response
        assert isinstance(final_response, bytes), "Final response should be bytes"
        assert len(final_response) > 0, "Final response should not be empty"

        print(f"   ✅ Response signing validated, length: {len(final_response)} bytes")

        # Test the reader can handle the response
        result = mdl.handle_response(reader_session.state, final_response)

        # VALIDATE response handling
        assert result is not None, "Response handling result should not be None"
        assert hasattr(result, "device_authentication"), "Result should have device_authentication"
        assert hasattr(result, "verified_response"), "Result should have verified_response"

        # Validate authentication status
        auth_status = result.device_authentication
        assert auth_status == mdl.AuthenticationStatus.VALID, (
            f"Expected VALID auth, got {auth_status}"
        )

        # Validate verified response structure
        verified_response = result.verified_response
        assert isinstance(verified_response, dict), "Verified response should be a dict"
        assert "org.iso.18013.5.1" in verified_response, "Missing namespace in verified response"

        # Validate response contains only permitted attributes
        response_attrs = verified_response["org.iso.18013.5.1"]
        expected_response_attrs = {"family_name", "given_name"}
        actual_response_attrs = set(response_attrs.keys())
        assert actual_response_attrs == expected_response_attrs, (
            f"Expected {expected_response_attrs}, got {actual_response_attrs}"
        )

        # Validate attribute values exist
        for attr in expected_response_attrs:
            attr_value = response_attrs[attr]
            assert attr_value is not None, f"Attribute {attr} should have a value"
            # Extract the actual value (it's wrapped in an MDocItem)
            if hasattr(attr_value, "__len__") and len(attr_value) > 0:
                actual_value = attr_value[0]
                assert actual_value is not None, f"Attribute {attr} inner value should not be None"
                assert len(str(actual_value)) > 0, f"Attribute {attr} should not be empty"

        print(f"   ✅ Complete workflow validated - {len(response_attrs)} attributes verified")

        return True

    except (ValueError, RuntimeError, AttributeError, ImportError) as e:
        print(f"   ❌ Error in presentation session tests: {e}")
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
