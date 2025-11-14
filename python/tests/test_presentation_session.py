#!/usr/bin/env python3
# Copyright (c) 2025 Indicio
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# This software may be modified and distributed under the terms
# of either the Apache License, Version 2.0 or the MIT license.
# See the LICENSE-APACHE and LICENSE-MIT files for details.

"""
Presentation session tests for isomdl-uniffi Python bindings using pytest.
"""

import uuid


def test_presentation_session_creation(mdl_module, test_mdl):
    """Test basic presentation session creation."""
    session_uuid = str(uuid.uuid4())
    presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
    assert presentation_session is not None


def test_qr_code_uri_generation(mdl_module, test_mdl):
    """Test QR code URI generation."""
    session_uuid = str(uuid.uuid4())
    presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)

    qr_uri = presentation_session.get_qr_code_uri()
    assert isinstance(qr_uri, str), "QR URI should be a string"
    assert len(qr_uri) > 0, "QR URI should not be empty"


def test_ble_identifier_generation(mdl_module, test_mdl):
    """Test BLE identifier generation."""
    session_uuid = str(uuid.uuid4())
    presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)

    ble_ident = presentation_session.get_ble_ident()
    assert isinstance(ble_ident, bytes), "BLE identifier should be bytes"
    assert len(ble_ident) > 0, "BLE identifier should not be empty"


def test_handle_request_structure(mdl_module, test_mdl):
    """Test handling presentation request and validate structure."""
    session_uuid = str(uuid.uuid4())
    presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
    qr_uri = presentation_session.get_qr_code_uri()

    # Create a reader session to generate a proper request
    requested_items = {
        "org.iso.18013.5.1": {
            "family_name": True,
            "given_name": True,
        }
    }

    reader_session = mdl_module.establish_session(qr_uri, requested_items, None)

    assert reader_session is not None, "Reader session should not be None"
    assert hasattr(reader_session, "request"), "Reader session should have request"
    assert hasattr(reader_session, "state"), "Reader session should have state"
    assert isinstance(reader_session.request, bytes), "Request should be bytes"
    assert len(reader_session.request) > 0, "Request should not be empty"

    # Process the request
    requested_data = presentation_session.handle_request(reader_session.request)

    assert isinstance(requested_data, list), "Requested data should be a list"
    assert len(requested_data) == 1, f"Should have exactly 1 document, got {len(requested_data)}"

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


def test_generate_response(mdl_module, key_pair, test_mdl):
    """Test generating presentation response."""
    session_uuid = str(uuid.uuid4())
    presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
    qr_uri = presentation_session.get_qr_code_uri()

    requested_items = {
        "org.iso.18013.5.1": {
            "family_name": True,
            "given_name": True,
        }
    }

    reader_session = mdl_module.establish_session(qr_uri, requested_items, None)
    presentation_session.handle_request(reader_session.request)

    # Generate response with permitted items
    permitted_items = {
        "org.iso.18013.5.1.mDL": {"org.iso.18013.5.1": ["family_name", "given_name"]}
    }

    unsigned_response = presentation_session.generate_response(permitted_items)

    assert isinstance(unsigned_response, bytes), "Response should be bytes"
    assert len(unsigned_response) > 0, "Response should not be empty"
    assert len(unsigned_response) > 10, f"Response too short: {len(unsigned_response)}"


def test_complete_presentation_workflow(mdl_module, key_pair, test_mdl):
    """Test complete presentation workflow from session to verified response."""
    session_uuid = str(uuid.uuid4())
    presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
    qr_uri = presentation_session.get_qr_code_uri()

    # Create reader session and request
    requested_items = {
        "org.iso.18013.5.1": {
            "family_name": True,
            "given_name": True,
        }
    }

    reader_session = mdl_module.establish_session(qr_uri, requested_items, None)
    presentation_session.handle_request(reader_session.request)

    # Generate and sign response
    permitted_items = {
        "org.iso.18013.5.1.mDL": {"org.iso.18013.5.1": ["family_name", "given_name"]}
    }

    unsigned_response = presentation_session.generate_response(permitted_items)
    signed_response = key_pair.sign(unsigned_response)

    assert isinstance(signed_response, bytes), "Signed response should be bytes"
    assert len(signed_response) > 0, "Signed response should not be empty"
    assert signed_response != unsigned_response, "Signed response should differ from unsigned"

    # Submit the signed response
    final_response = presentation_session.submit_response(signed_response)

    assert isinstance(final_response, bytes), "Final response should be bytes"
    assert len(final_response) > 0, "Final response should not be empty"

    # Test the reader can handle the response
    result = mdl_module.handle_response(reader_session.state, final_response)

    assert result is not None, "Response handling result should not be None"
    assert hasattr(result, "device_authentication"), "Result should have device_authentication"
    assert hasattr(result, "verified_response"), "Result should have verified_response"

    # Validate authentication status
    auth_status = result.device_authentication
    assert auth_status == mdl_module.AuthenticationStatus.VALID, (
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
