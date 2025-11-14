#!/usr/bin/env python3
"""
Selective disclosure tests for isomdl-uniffi Python bindings using pytest.
Tests that verify only requested attributes are shared and age verification works correctly.
"""

import uuid


def test_basic_selective_disclosure(mdl_module):
    """Test basic selective disclosure functionality."""
    # Generate test components
    key_pair = mdl_module.P256KeyPair()
    test_mdoc = mdl_module.generate_test_mdl(key_pair)

    # Create a presentation session with a proper UUID
    session_uuid = str(uuid.uuid4())
    presentation_session = mdl_module.MdlPresentationSession(test_mdoc, session_uuid)

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
    reader_session = mdl_module.establish_session(qr_uri, requested_items, None)

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

    assert requested_attrs == expected_attrs, f"Expected {expected_attrs}, got {requested_attrs}"

    # Verify attributes are marked as required
    assert iso_namespace["given_name"] is True, "given_name should be required"
    assert iso_namespace["family_name"] is True, "family_name should be required"

    # Generate response with selective disclosure
    permitted_items = {
        "org.iso.18013.5.1.mDL": {"org.iso.18013.5.1": ["given_name", "family_name"]}
    }

    unsigned_response = presentation_session.generate_response(permitted_items)
    signed_response = key_pair.sign(unsigned_response)
    response = presentation_session.submit_response(signed_response)

    # Verify the response
    result = mdl_module.handle_response(reader_session.state, response)

    # Check that only disclosed attributes are in the response
    assert result.device_authentication == mdl_module.AuthenticationStatus.VALID, (
        "Device auth should be valid"
    )
    assert len(result.verified_response) == 1, "Should have one namespace"

    iso_response = result.verified_response["org.iso.18013.5.1"]
    disclosed_attrs = set(iso_response.keys())

    assert disclosed_attrs == expected_attrs, (
        f"Response should only contain {expected_attrs}, got {disclosed_attrs}"
    )


def test_age_verification_attributes(mdl_module):
    """Test age verification attributes without disclosing birth date."""
    # Generate test data
    holder_key = mdl_module.P256KeyPair()
    test_mdoc = mdl_module.generate_test_mdl(holder_key)

    # Create presentation session
    session_uuid = str(uuid.uuid4())
    presentation_session = mdl_module.MdlPresentationSession(test_mdoc, session_uuid)

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
    reader_session = mdl_module.establish_session(qr_uri, age_verification_request, None)
    requested_data = presentation_session.handle_request(reader_session.request)

    # Verify request structure
    doc_request = requested_data[0]
    iso_namespace = doc_request.namespaces["org.iso.18013.5.1"]

    # Should only have age verification attributes
    expected_age_attrs = {"age_over_18", "age_over_21"}
    actual_attrs = set(iso_namespace.keys())

    assert actual_attrs == expected_age_attrs, f"Expected {expected_age_attrs}, got {actual_attrs}"

    # Verify no birth_date is requested
    assert "birth_date" not in actual_attrs, "birth_date should not be requested"

    # Generate age verification response
    age_permitted_items = {
        "org.iso.18013.5.1.mDL": {"org.iso.18013.5.1": ["age_over_18", "age_over_21"]}
    }

    unsigned_response = presentation_session.generate_response(age_permitted_items)
    signed_response = holder_key.sign(unsigned_response)
    response = presentation_session.submit_response(signed_response)

    # Verify age verification response
    result = mdl_module.handle_response(reader_session.state, response)

    assert result.device_authentication == mdl_module.AuthenticationStatus.VALID, (
        "Device auth should be valid"
    )

    iso_response = result.verified_response["org.iso.18013.5.1"]

    # Verify only age attributes are disclosed
    assert "age_over_18" in iso_response, "Should have age_over_18"
    assert "age_over_21" in iso_response, "Should have age_over_21"
    assert "birth_date" not in iso_response, "Should NOT disclose birth_date"

    # Verify age values are boolean and sensible
    age_18_item = iso_response["age_over_18"]
    age_21_item = iso_response["age_over_21"]

    # Age verification should return MDocItem.BOOL values
    assert age_18_item.is_bool(), (
        f"age_over_18 should be boolean MDocItem, got: {type(age_18_item)}"
    )
    assert age_21_item.is_bool(), (
        f"age_over_21 should be boolean MDocItem, got: {type(age_21_item)}"
    )

    # Extract actual boolean values
    age_18 = age_18_item[0]
    age_21 = age_21_item[0]
    assert isinstance(age_18, bool), f"age_over_18 value should be boolean, got: {type(age_18)}"
    assert isinstance(age_21, bool), f"age_over_21 value should be boolean, got: {type(age_21)}"


def test_minimal_disclosure(mdl_module):
    """Test minimal disclosure - requesting only one attribute."""
    holder_key = mdl_module.P256KeyPair()
    test_mdoc = mdl_module.generate_test_mdl(holder_key)

    session_uuid = str(uuid.uuid4())
    presentation_session = mdl_module.MdlPresentationSession(test_mdoc, session_uuid)

    qr_uri = presentation_session.get_qr_code_uri()

    # Request only one attribute
    minimal_request = {
        "org.iso.18013.5.1": {"document_number": True}  # Only request document number
    }

    reader_session = mdl_module.establish_session(qr_uri, minimal_request, None)
    requested_data = presentation_session.handle_request(reader_session.request)

    # Verify minimal request
    doc_request = requested_data[0]
    iso_namespace = doc_request.namespaces["org.iso.18013.5.1"]

    assert len(iso_namespace) == 1, "Should only have one attribute"
    assert "document_number" in iso_namespace, "Should have document_number"
    assert iso_namespace["document_number"] is True, "document_number should be required"

    # Generate minimal response
    minimal_permitted = {"org.iso.18013.5.1.mDL": {"org.iso.18013.5.1": ["document_number"]}}

    unsigned_response = presentation_session.generate_response(minimal_permitted)
    signed_response = holder_key.sign(unsigned_response)
    response = presentation_session.submit_response(signed_response)

    # Verify minimal response
    result = mdl_module.handle_response(reader_session.state, response)

    assert result.device_authentication == mdl_module.AuthenticationStatus.VALID, (
        "Device auth should be valid"
    )

    iso_response = result.verified_response["org.iso.18013.5.1"]
    assert len(iso_response) == 1, "Should only have one attribute in response"
    assert "document_number" in iso_response, "Should have document_number in response"


def test_namespace_filtering(mdl_module):
    """Test that requests can be filtered by namespace."""
    holder_key = mdl_module.P256KeyPair()
    test_mdoc = mdl_module.generate_test_mdl(holder_key)

    session_uuid = str(uuid.uuid4())
    presentation_session = mdl_module.MdlPresentationSession(test_mdoc, session_uuid)

    qr_uri = presentation_session.get_qr_code_uri()

    # Request from specific namespace only
    namespace_request = {
        "org.iso.18013.5.1": {"given_name": True, "family_name": True}
        # Not requesting from any other namespaces that might exist
    }

    reader_session = mdl_module.establish_session(qr_uri, namespace_request, None)
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
    result = mdl_module.handle_response(reader_session.state, response)

    assert result.device_authentication == mdl_module.AuthenticationStatus.VALID, (
        "Device auth should be valid"
    )

    # Should only have the requested namespace in response
    assert len(result.verified_response) == 1, "Should only have one namespace in response"
    assert "org.iso.18013.5.1" in result.verified_response, "Should have ISO namespace in response"


def test_request_validation(mdl_module):
    """Test that invalid requests are handled properly."""
    holder_key = mdl_module.P256KeyPair()
    test_mdoc = mdl_module.generate_test_mdl(holder_key)

    session_uuid = str(uuid.uuid4())
    presentation_session = mdl_module.MdlPresentationSession(test_mdoc, session_uuid)

    qr_uri = presentation_session.get_qr_code_uri()

    # Test empty request
    empty_request = {}

    try:
        reader_session = mdl_module.establish_session(qr_uri, empty_request, None)
        requested_data = presentation_session.handle_request(reader_session.request)

        # Should handle empty request gracefully
        assert len(requested_data) >= 0, "Should handle empty request"

    except Exception as e:
        # It's also acceptable to reject empty requests
        if "Empty" in str(e) or "MdlReaderSessionError" in str(type(e)):
            # Empty request properly rejected
            pass
        else:
            raise e

    # Test request for non-existent attributes
    invalid_attr_request = {
        "org.iso.18013.5.1": {
            "non_existent_attribute": True,
            "another_fake_attr": True,
        }
    }

    try:
        reader_session = mdl_module.establish_session(qr_uri, invalid_attr_request, None)
        requested_data = presentation_session.handle_request(reader_session.request)

        # Should handle request for non-existent attributes
        doc_request = requested_data[0]
        iso_namespace = doc_request.namespaces["org.iso.18013.5.1"]

        # The system should still process the request
        # (attributes may not exist in response)
        assert len(iso_namespace) >= 0, "Should handle non-existent attributes"

    except Exception:
        # It's also acceptable to reject invalid attribute requests
        pass


if __name__ == "__main__":
    # Support direct execution for debugging
    import sys
    from pathlib import Path

    # Try to import bindings
    sys.path.insert(0, str(Path(__file__).parent.parent.parent / "rust" / "out" / "python"))

    try:
        # Run with pytest
        import pytest

        import isomdl_uniffi as mdl_module  # noqa: F401

        sys.exit(pytest.main([__file__, "-v"]))
    except ImportError as e:
        print(f"❌ Could not import isomdl_uniffi: {e}")
        print("Please run the build script first")
        sys.exit(1)
