#!/usr/bin/env python3
"""
Reader functionality tests for isomdl-uniffi Python bindings using pytest.
"""

import uuid as uuid_module


def test_reader_session_establishment(mdl_module, test_mdl):
    """Test establishing a reader session with validation."""
    # Create a presentation session to get a valid QR code URI
    session_uuid = str(uuid_module.uuid4())
    presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
    test_uri = presentation_session.get_qr_code_uri()

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

    # Establish reader session
    session_data = mdl_module.establish_session(
        uri=test_uri,
        requested_items=requested_items,
        trust_anchor_registry=[],  # Empty trust anchor list for test
    )

    assert session_data is not None, "Session data should not be None"
    assert hasattr(session_data, "uuid"), "Session data should have uuid"
    assert hasattr(session_data, "request"), "Session data should have request"
    assert hasattr(session_data, "ble_ident"), "Session data should have ble_ident"
    assert hasattr(session_data, "state"), "Session data should have state"


def test_reader_session_uuid_format(mdl_module, test_mdl):
    """Validate session UUID format."""
    session_uuid = str(uuid_module.uuid4())
    presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
    test_uri = presentation_session.get_qr_code_uri()

    requested_items = {"org.iso.18013.5.1": {"family_name": True, "given_name": True}}

    session_data = mdl_module.establish_session(test_uri, requested_items, [])

    # Validate session UUID format
    try:
        uuid_obj = uuid_module.UUID(session_data.uuid)
        assert str(uuid_obj) == session_data.uuid, "Invalid UUID format"
    except ValueError:
        raise AssertionError(f"Session UUID is not valid: {session_data.uuid}")


def test_reader_request_data_structure(mdl_module, test_mdl):
    """Validate reader request data structure."""
    session_uuid = str(uuid_module.uuid4())
    presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
    test_uri = presentation_session.get_qr_code_uri()

    requested_items = {"org.iso.18013.5.1": {"family_name": True, "given_name": True}}

    session_data = mdl_module.establish_session(test_uri, requested_items, [])

    # Validate request data
    assert isinstance(session_data.request, bytes), "Request should be bytes"
    assert len(session_data.request) > 0, "Request should not be empty"
    assert len(session_data.request) < 10000, (
        f"Request suspiciously large: {len(session_data.request)}"
    )


def test_reader_ble_identifier(mdl_module, test_mdl):
    """Validate BLE identifier structure."""
    session_uuid = str(uuid_module.uuid4())
    presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
    test_uri = presentation_session.get_qr_code_uri()

    requested_items = {"org.iso.18013.5.1": {"family_name": True, "given_name": True}}

    session_data = mdl_module.establish_session(test_uri, requested_items, [])

    # Validate BLE identifier
    assert isinstance(session_data.ble_ident, bytes), "BLE identifier should be bytes"
    assert len(session_data.ble_ident) == 16, (
        f"BLE identifier should be 16 bytes, got {len(session_data.ble_ident)}"
    )


def test_reader_session_manager(mdl_module, test_mdl):
    """Validate session manager exists."""
    session_uuid = str(uuid_module.uuid4())
    presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
    test_uri = presentation_session.get_qr_code_uri()

    requested_items = {"org.iso.18013.5.1": {"family_name": True, "given_name": True}}

    session_data = mdl_module.establish_session(test_uri, requested_items, [])

    # Validate session manager
    session_manager = session_data.state
    assert session_manager is not None, "Session manager should not be None"


def test_complete_reader_workflow(mdl_module, key_pair, test_mdl):
    """Test complete reader workflow from session to verified response."""
    # Setup presentation session
    session_uuid = str(uuid_module.uuid4())
    presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
    test_uri = presentation_session.get_qr_code_uri()

    # Define requested items
    requested_items = {
        "org.iso.18013.5.1": {
            "family_name": True,
            "given_name": True,
            "birth_date": True,
            "document_number": True,
        }
    }

    # Establish reader session
    session_data = mdl_module.establish_session(test_uri, requested_items, [])

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
    for attr_name in requested_items["org.iso.18013.5.1"]:
        assert attr_name in iso_namespace, f"Missing requested attribute: {attr_name}"
        assert iso_namespace[attr_name] is True, f"Attribute {attr_name} should be required"

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

    # Verify the reader can handle the response
    result = mdl_module.handle_response(session_data.state, final_response)
    assert result is not None, "Response handling should not return None"
    assert hasattr(result, "device_authentication"), "Result should have device_authentication"
    assert hasattr(result, "verified_response"), "Result should have verified_response"

    # Validate authentication status
    auth_status = result.device_authentication
    assert auth_status == mdl_module.AuthenticationStatus.VALID, (
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
