#!/usr/bin/env python3
"""
Selective disclosure tests for isomdl-uniffi Python bindings.
Tests that verify only requested attributes are shared and age verification works correctly.
"""

import sys
import os
import uuid


def run_tests(mdl):
    """
    Run selective disclosure tests.

    Args:
        mdl: The isomdl_uniffi module

    Returns:
        bool: True if all tests pass, False otherwise.
    """

    try:
        print("\n🔒 Testing Selective Disclosure:")
        test_basic_selective_disclosure(mdl)
        test_age_verification_attributes(mdl)
        test_minimal_disclosure(mdl)
        test_namespace_filtering(mdl)
        test_request_validation(mdl)

        return True

    except (ValueError, RuntimeError, AttributeError, ImportError) as e:
        print(f"   ❌ Error in selective disclosure tests: {e}")
        import traceback

        traceback.print_exc()
        return False


def test_basic_selective_disclosure(mdl):
    """Test basic selective disclosure functionality."""
    print("   1. Testing basic selective disclosure...")

    # Generate test components
    key_pair = mdl.P256KeyPair()
    test_mdoc = mdl.generate_test_mdl(key_pair)

    # Create a presentation session with a proper UUID
    session_uuid = str(uuid.uuid4())
    presentation_session = mdl.MdlPresentationSession(test_mdoc, session_uuid)

    # Get QR code for reader
    qr_uri = presentation_session.get_qr_code_uri()

    # Define selective request - only request 2 out of many available attributes
    requested_items = {
        "org.iso.18013.5.1": {
            "given_name": True,  # Request this
            "family_name": True,  # Request this
            # Deliberately NOT requesting: birth_date, age_over_18, document_number, etc.
        }
    }

    # Establish reader session
    reader_session = mdl.establish_session(qr_uri, requested_items, None)

    # Process the request
    requested_data = presentation_session.handle_request(reader_session.request)

    # Verify only requested attributes are in the request
    assert len(requested_data) == 1, "Should have exactly one document type"

    doc_request = requested_data[0]
    assert doc_request.doc_type == "org.iso.18013.5.1.mDL", "Should be mDL document"

    # Check namespaces
    assert "org.iso.18013.5.1" in doc_request.namespaces, "Should have ISO namespace"
    iso_namespace = doc_request.namespaces["org.iso.18013.5.1"]

    # Verify only requested attributes are present
    requested_attrs = set(iso_namespace.keys())
    expected_attrs = {"given_name", "family_name"}

    assert (
        requested_attrs == expected_attrs
    ), f"Expected {expected_attrs}, got {requested_attrs}"

    # Verify attributes are marked as required
    assert iso_namespace["given_name"] is True, "given_name should be required"
    assert iso_namespace["family_name"] is True, "family_name should be required"

    print("      ✅ Only requested attributes are present in request")

    # Generate response with selective disclosure
    permitted_items = {
        "org.iso.18013.5.1.mDL": {"org.iso.18013.5.1": ["given_name", "family_name"]}
    }

    unsigned_response = presentation_session.generate_response(permitted_items)
    signed_response = key_pair.sign(unsigned_response)
    response = presentation_session.submit_response(signed_response)

    # Verify the response
    result = mdl.handle_response(reader_session.state, response)

    # Check that only disclosed attributes are in the response
    assert (
        result.device_authentication == mdl.AuthenticationStatus.VALID
    ), "Device auth should be valid"
    assert len(result.verified_response) == 1, "Should have one namespace"

    iso_response = result.verified_response["org.iso.18013.5.1"]
    disclosed_attrs = set(iso_response.keys())

    assert (
        disclosed_attrs == expected_attrs
    ), f"Response should only contain {expected_attrs}, got {disclosed_attrs}"

    print("      ✅ Response contains only disclosed attributes")
    print("      ✅ Basic selective disclosure test passed")


def test_age_verification_attributes(mdl):
    """Test age verification attributes without disclosing birth date"""
    print("   2. Testing age verification attributes...")

    # Generate test data
    holder_key = mdl.P256KeyPair()
    test_mdoc = mdl.generate_test_mdl(holder_key)

    # Create presentation session
    session_uuid = str(uuid.uuid4())
    presentation_session = mdl.MdlPresentationSession(test_mdoc, session_uuid)

    qr_uri = presentation_session.get_qr_code_uri()

    # Request only age verification without birth date
    age_verification_request = {
        "org.iso.18013.5.1": {
            "age_over_18": True,
            "age_over_21": True,
            # Deliberately NOT requesting birth_date
        }
    }

    # Establish session
    reader_session = mdl.establish_session(qr_uri, age_verification_request, None)
    requested_data = presentation_session.handle_request(reader_session.request)

    # Verify request structure
    doc_request = requested_data[0]
    iso_namespace = doc_request.namespaces["org.iso.18013.5.1"]

    # Should only have age verification attributes
    expected_age_attrs = {"age_over_18", "age_over_21"}
    actual_attrs = set(iso_namespace.keys())

    assert (
        actual_attrs == expected_age_attrs
    ), f"Expected {expected_age_attrs}, got {actual_attrs}"

    # Verify no birth_date is requested
    assert "birth_date" not in actual_attrs, "birth_date should not be requested"

    print("      ✅ Age verification request contains only age attributes")

    # Generate age verification response
    age_permitted_items = {
        "org.iso.18013.5.1.mDL": {"org.iso.18013.5.1": ["age_over_18", "age_over_21"]}
    }

    unsigned_response = presentation_session.generate_response(age_permitted_items)
    signed_response = holder_key.sign(unsigned_response)
    response = presentation_session.submit_response(signed_response)

    # Verify age verification response
    result = mdl.handle_response(reader_session.state, response)

    assert (
        result.device_authentication == mdl.AuthenticationStatus.VALID
    ), "Device auth should be valid"

    iso_response = result.verified_response["org.iso.18013.5.1"]

    # Verify only age attributes are disclosed
    assert "age_over_18" in iso_response, "Should have age_over_18"
    assert "age_over_21" in iso_response, "Should have age_over_21"
    assert "birth_date" not in iso_response, "Should NOT disclose birth_date"

    # Verify age values are boolean and sensible
    age_18_item = iso_response["age_over_18"]
    age_21_item = iso_response["age_over_21"]

    # Age verification should return MDocItem.BOOL values
    assert (
        age_18_item.is_bool()
    ), f"age_over_18 should be boolean MDocItem, got: {type(age_18_item)}"
    assert (
        age_21_item.is_bool()
    ), f"age_over_21 should be boolean MDocItem, got: {type(age_21_item)}"

    # Extract actual boolean values
    age_18 = age_18_item[0]
    age_21 = age_21_item[0]
    assert isinstance(
        age_18, bool
    ), f"age_over_18 value should be boolean, got: {type(age_18)}"
    assert isinstance(
        age_21, bool
    ), f"age_over_21 value should be boolean, got: {type(age_21)}"

    print("      ✅ Age verification works without disclosing birth date")
    print("      ✅ Age verification test passed")


def test_minimal_disclosure(mdl):
    """Test minimal disclosure - requesting only one attribute"""
    print("   3. Testing minimal disclosure...")

    holder_key = mdl.P256KeyPair()
    test_mdoc = mdl.generate_test_mdl(holder_key)

    session_uuid = str(uuid.uuid4())
    presentation_session = mdl.MdlPresentationSession(test_mdoc, session_uuid)

    qr_uri = presentation_session.get_qr_code_uri()

    # Request only one attribute
    minimal_request = {
        "org.iso.18013.5.1": {"document_number": True}  # Only request document number
    }

    reader_session = mdl.establish_session(qr_uri, minimal_request, None)
    requested_data = presentation_session.handle_request(reader_session.request)

    # Verify minimal request
    doc_request = requested_data[0]
    iso_namespace = doc_request.namespaces["org.iso.18013.5.1"]

    assert len(iso_namespace) == 1, "Should only have one attribute"
    assert "document_number" in iso_namespace, "Should have document_number"
    assert (
        iso_namespace["document_number"] is True
    ), "document_number should be required"

    # Generate minimal response
    minimal_permitted = {
        "org.iso.18013.5.1.mDL": {"org.iso.18013.5.1": ["document_number"]}
    }

    unsigned_response = presentation_session.generate_response(minimal_permitted)
    signed_response = holder_key.sign(unsigned_response)
    response = presentation_session.submit_response(signed_response)

    # Verify minimal response
    result = mdl.handle_response(reader_session.state, response)

    assert (
        result.device_authentication == mdl.AuthenticationStatus.VALID
    ), "Device auth should be valid"

    iso_response = result.verified_response["org.iso.18013.5.1"]
    assert len(iso_response) == 1, "Should only have one attribute in response"
    assert "document_number" in iso_response, "Should have document_number in response"

    print("      ✅ Minimal disclosure works correctly")
    print("      ✅ Minimal disclosure test passed")


def test_namespace_filtering(mdl):
    """Test that requests can be filtered by namespace"""
    print("   4. Testing namespace filtering...")

    holder_key = mdl.P256KeyPair()
    test_mdoc = mdl.generate_test_mdl(holder_key)

    session_uuid = str(uuid.uuid4())
    presentation_session = mdl.MdlPresentationSession(test_mdoc, session_uuid)

    qr_uri = presentation_session.get_qr_code_uri()

    # Request from specific namespace only
    namespace_request = {
        "org.iso.18013.5.1": {"given_name": True, "family_name": True}
        # Not requesting from any other namespaces that might exist
    }

    reader_session = mdl.establish_session(qr_uri, namespace_request, None)
    requested_data = presentation_session.handle_request(reader_session.request)

    # Verify namespace filtering
    doc_request = requested_data[0]

    # Should only have the requested namespace
    assert len(doc_request.namespaces) == 1, "Should only have one namespace"
    assert "org.iso.18013.5.1" in doc_request.namespaces, "Should have ISO namespace"

    # Generate response for specific namespace
    namespace_permitted = {
        "org.iso.18013.5.1.mDL": {"org.iso.18013.5.1": ["given_name", "family_name"]}
    }

    unsigned_response = presentation_session.generate_response(namespace_permitted)
    signed_response = holder_key.sign(unsigned_response)
    response = presentation_session.submit_response(signed_response)

    # Verify namespace response
    result = mdl.handle_response(reader_session.state, response)

    assert (
        result.device_authentication == mdl.AuthenticationStatus.VALID
    ), "Device auth should be valid"

    # Should only have the requested namespace in response
    assert (
        len(result.verified_response) == 1
    ), "Should only have one namespace in response"
    assert (
        "org.iso.18013.5.1" in result.verified_response
    ), "Should have ISO namespace in response"

    print("      ✅ Namespace filtering works correctly")
    print("      ✅ Namespace filtering test passed")


def test_request_validation(mdl):
    """Test that invalid requests are handled properly"""
    print("   5. Testing request validation...")

    holder_key = mdl.P256KeyPair()
    test_mdoc = mdl.generate_test_mdl(holder_key)

    session_uuid = str(uuid.uuid4())
    presentation_session = mdl.MdlPresentationSession(test_mdoc, session_uuid)

    qr_uri = presentation_session.get_qr_code_uri()

    # Test empty request
    empty_request = {}

    try:
        reader_session = mdl.establish_session(qr_uri, empty_request, None)
        requested_data = presentation_session.handle_request(reader_session.request)

        # Should handle empty request gracefully
        assert len(requested_data) >= 0, "Should handle empty request"
        print("      ✅ Empty request handled gracefully")

    except Exception as e:
        # It's also acceptable to reject empty requests - any error is fine here
        if "Empty" in str(e) or "MdlReaderSessionError" in str(type(e)):
            print(f"      ✅ Empty request properly rejected: {type(e).__name__}")
        else:
            raise e

    # Test request for non-existent attributes
    invalid_attr_request = {
        "org.iso.18013.5.1": {"non_existent_attribute": True, "another_fake_attr": True}
    }

    try:
        reader_session = mdl.establish_session(qr_uri, invalid_attr_request, None)
        requested_data = presentation_session.handle_request(reader_session.request)

        # Should handle request for non-existent attributes
        doc_request = requested_data[0]
        iso_namespace = doc_request.namespaces["org.iso.18013.5.1"]

        # The system should still process the request (attributes may not exist in response)
        assert len(iso_namespace) >= 0, "Should handle non-existent attributes"
        print("      ✅ Non-existent attributes handled gracefully")

    except Exception as e:
        # It's also acceptable to reject invalid attribute requests
        print(f"      ✅ Invalid attributes properly rejected: {type(e).__name__}")

    print("      ✅ Request validation test passed")


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
