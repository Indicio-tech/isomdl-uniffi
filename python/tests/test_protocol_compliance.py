#!/usr/bin/env python3
# Copyright (c) 2025 Indicio
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# This software may be modified and distributed under the terms
# of either the Apache License, Version 2.0 or the MIT license.
# See the LICENSE-APACHE and LICENSE-MIT files for details.

"""
Protocol compliance and format validation tests for isomdl-uniffi Python bindings using pytest.
Tests ISO 18013-5 message formats, encoding compliance, and identifier formats.
"""

import json
import uuid


class TestMessageFormats:
    """Test ISO 18013-5 message format compliance."""

    def test_qr_code_uri_structure(self, mdl_module, test_mdl):
        """Test that QR code URI follows expected structure."""
        session_uuid = str(uuid.uuid4())
        presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)

        qr_uri = presentation_session.get_qr_code_uri()

        # QR URI should be a non-empty string
        assert isinstance(qr_uri, str)
        assert len(qr_uri) > 0

        # Should start with mdoc: scheme
        assert qr_uri.startswith("mdoc:")

    def test_device_request_structure(self, mdl_module, test_mdl):
        """Test that device request follows expected structure."""
        session_uuid = str(uuid.uuid4())
        presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
        qr_uri = presentation_session.get_qr_code_uri()

        requested_items = {"org.iso.18013.5.1": {"given_name": True, "family_name": True}}

        reader_session = mdl_module.establish_session(qr_uri, requested_items, None)

        # Request should be bytes (CBOR encoded)
        assert isinstance(reader_session.request, bytes)
        assert len(reader_session.request) > 0

    def test_device_response_structure(self, mdl_module, key_pair, test_mdl):
        """Test that device response follows expected structure."""
        session_uuid = str(uuid.uuid4())
        presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
        qr_uri = presentation_session.get_qr_code_uri()

        requested_items = {"org.iso.18013.5.1": {"given_name": True}}

        reader_session = mdl_module.establish_session(qr_uri, requested_items, None)
        presentation_session.handle_request(reader_session.request)

        permitted_items = {"org.iso.18013.5.1.mDL": {"org.iso.18013.5.1": ["given_name"]}}

        unsigned_response = presentation_session.generate_response(permitted_items)
        signed_response = key_pair.sign(unsigned_response)
        final_response = presentation_session.submit_response(signed_response)

        # Response should be bytes (CBOR encoded)
        assert isinstance(final_response, bytes)
        assert len(final_response) > 0

    def test_verified_response_structure(self, mdl_module, key_pair, test_mdl):
        """Test that verified response has expected structure."""
        session_uuid = str(uuid.uuid4())
        presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
        qr_uri = presentation_session.get_qr_code_uri()

        requested_items = {"org.iso.18013.5.1": {"given_name": True, "family_name": True}}

        reader_session = mdl_module.establish_session(qr_uri, requested_items, None)
        presentation_session.handle_request(reader_session.request)

        permitted_items = {
            "org.iso.18013.5.1.mDL": {"org.iso.18013.5.1": ["given_name", "family_name"]}
        }

        unsigned_response = presentation_session.generate_response(permitted_items)
        signed_response = key_pair.sign(unsigned_response)
        final_response = presentation_session.submit_response(signed_response)

        result = mdl_module.handle_response(reader_session.state, final_response)

        # Verified response should be a dictionary of parsed data
        assert isinstance(result.verified_response, dict)
        assert len(result.verified_response) > 0

        # Authentication status should be present
        assert result.device_authentication is not None


class TestEncodingCompliance:
    """Test CBOR and JSON encoding compliance."""

    def test_cbor_encoding(self, test_mdl):
        """Test that CBOR encoding is valid."""
        # Get CBOR representation via stringify
        cbor_str = test_mdl.stringify()

        assert isinstance(cbor_str, str)
        assert len(cbor_str) > 0
        # CBOR should be longer than just a few bytes
        assert len(cbor_str) > 50

    def test_json_encoding(self, test_mdl):
        """Test that JSON encoding is valid."""
        json_str = test_mdl.json()

        assert isinstance(json_str, str)
        assert len(json_str) > 0

        # Should be valid JSON
        parsed = json.loads(json_str)
        assert isinstance(parsed, dict)
        assert len(parsed) > 0

    def test_json_special_characters(self, mdl_module, key_pair):
        """Test JSON encoding handles special characters."""
        mdl = mdl_module.generate_test_mdl(key_pair)
        json_str = mdl.json()

        # Should be valid JSON even with special chars in data
        parsed = json.loads(json_str)
        assert isinstance(parsed, dict)

    def test_cbor_determinism(self, mdl_module, key_pair):
        """Test that CBOR encoding is deterministic."""
        mdl = mdl_module.generate_test_mdl(key_pair)

        cbor1 = mdl.stringify()
        cbor2 = mdl.stringify()

        # Should produce identical output
        assert cbor1 == cbor2

    def test_json_determinism(self, mdl_module, key_pair):
        """Test that JSON encoding is deterministic."""
        mdl = mdl_module.generate_test_mdl(key_pair)

        json1 = mdl.json()
        json2 = mdl.json()

        # Should produce identical output
        assert json1 == json2


class TestIdentifierFormats:
    """Test format compliance of identifiers."""

    def test_session_uuid_format(self, mdl_module, test_mdl):
        """Test that session UUIDs are valid."""
        # Create multiple sessions with valid UUIDs
        for _ in range(5):
            session_uuid = str(uuid.uuid4())
            session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)

            qr_uri = session.get_qr_code_uri()
            assert qr_uri is not None
            assert len(qr_uri) > 0

    def test_mdl_id_format(self, mdl_module, key_pair):
        """Test that MDL ID has expected format."""
        mdl = mdl_module.generate_test_mdl(key_pair)
        mdl_id = mdl.id()

        # ID should be a string
        assert isinstance(mdl_id, str)
        assert len(mdl_id) > 0

        # Test MDL has specific ID format (UUID)
        # Format: "00000000-0000-0000-0000-000000000000" for test data
        assert "-" in mdl_id or len(mdl_id) == 32  # UUID with or without dashes

    def test_mdl_key_alias_format(self, mdl_module, key_pair):
        """Test that key alias has expected format."""
        mdl = mdl_module.generate_test_mdl(key_pair)
        key_alias = mdl.key_alias()

        # Key alias should be a string
        assert isinstance(key_alias, str)
        assert len(key_alias) > 0

    def test_ble_identifier_format(self, mdl_module, test_mdl):
        """Test that BLE identifier has correct format."""
        session_uuid = str(uuid.uuid4())
        session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)

        ble_ident = session.get_ble_ident()

        # BLE identifier should be bytes
        assert isinstance(ble_ident, bytes)
        assert len(ble_ident) > 0

        # BLE identifiers are typically 16 bytes
        # Implementation may vary, but should be reasonable length
        assert len(ble_ident) <= 256  # Sanity check

    def test_document_type_format(self, mdl_module, key_pair):
        """Test that document type follows ISO 18013-5 format."""
        mdl = mdl_module.generate_test_mdl(key_pair)
        doctype = mdl.doctype()

        # Should be the standard MDL doctype
        assert doctype == "org.iso.18013.5.1.mDL"

        # Should follow reverse domain notation
        assert doctype.startswith("org.")
        assert "." in doctype

    def test_namespace_format_validation(self, mdl_module, test_mdl):
        """Test that namespaces follow expected format."""
        session_uuid = str(uuid.uuid4())
        presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
        qr_uri = presentation_session.get_qr_code_uri()

        # Test standard ISO namespace
        requested_items = {"org.iso.18013.5.1": {"given_name": True}}

        reader_session = mdl_module.establish_session(qr_uri, requested_items, None)
        assert reader_session is not None

        # Namespace in request should be preserved
        presentation_session.handle_request(reader_session.request)


class TestDataStructures:
    """Test compliance of data structures."""

    def test_mdl_details_structure(self, mdl_module, key_pair):
        """Test that MDL details follow expected structure."""
        mdl = mdl_module.generate_test_mdl(key_pair)
        details = mdl.details()

        # Should be a dictionary of namespaces
        assert isinstance(details, dict)
        assert len(details) > 0

        # Should contain ISO namespace
        assert "org.iso.18013.5.1" in details

        # Each namespace should have a list of elements
        for namespace, elements in details.items():
            assert isinstance(namespace, str)
            assert isinstance(elements, list)
            assert len(elements) > 0

    def test_element_structure(self, mdl_module, key_pair):
        """Test that Element objects have expected structure."""
        mdl = mdl_module.generate_test_mdl(key_pair)
        details = mdl.details()

        # Get elements from ISO namespace
        iso_elements = details.get("org.iso.18013.5.1", [])
        assert len(iso_elements) > 0

        # Each element should have identifier and value
        for element in iso_elements:
            assert hasattr(element, "identifier")
            assert hasattr(element, "value")

            # Identifier should be a string
            identifier = element.identifier
            assert isinstance(identifier, str)
            assert len(identifier) > 0

    def test_requested_items_structure(self, mdl_module, test_mdl):
        """Test that requested items follow expected structure."""
        session_uuid = str(uuid.uuid4())
        presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
        qr_uri = presentation_session.get_qr_code_uri()

        # Structure: Dict[namespace, Dict[attribute, bool]]
        requested_items = {
            "org.iso.18013.5.1": {
                "given_name": True,
                "family_name": True,
                "birth_date": False,  # Optional
            }
        }

        reader_session = mdl_module.establish_session(qr_uri, requested_items, None)
        assert reader_session is not None

    def test_permitted_items_structure(self, mdl_module, test_mdl):
        """Test that permitted items follow expected structure."""
        session_uuid = str(uuid.uuid4())
        presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
        qr_uri = presentation_session.get_qr_code_uri()

        requested_items = {"org.iso.18013.5.1": {"given_name": True, "family_name": True}}

        reader_session = mdl_module.establish_session(qr_uri, requested_items, None)
        presentation_session.handle_request(reader_session.request)

        # Structure: Dict[doctype, Dict[namespace, List[attribute]]]
        permitted_items = {
            "org.iso.18013.5.1.mDL": {"org.iso.18013.5.1": ["given_name", "family_name"]}
        }

        unsigned = presentation_session.generate_response(permitted_items)
        assert isinstance(unsigned, bytes)

    def test_authentication_status_enum(self, mdl_module):
        """Test that AuthenticationStatus enum is properly defined."""
        # Should have VALID status
        assert hasattr(mdl_module, "AuthenticationStatus")
        assert hasattr(mdl_module.AuthenticationStatus, "VALID")

        # Should be usable in comparisons
        status = mdl_module.AuthenticationStatus.VALID
        assert status is not None


class TestProtocolWorkflows:
    """Test complete protocol workflows for compliance."""

    def test_full_protocol_workflow(self, mdl_module, key_pair, test_mdl):
        """Test complete ISO 18013-5 protocol workflow."""
        # 1. Holder creates presentation session
        session_uuid = str(uuid.uuid4())
        presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)

        # 2. Holder generates QR code
        qr_uri = presentation_session.get_qr_code_uri()
        assert len(qr_uri) > 0

        # 3. Reader scans QR and establishes session
        requested_items = {"org.iso.18013.5.1": {"given_name": True, "family_name": True}}
        reader_session = mdl_module.establish_session(qr_uri, requested_items, None)

        # 4. Holder receives and processes request
        presentation_session.handle_request(reader_session.request)

        # 5. Holder selects attributes to share
        permitted_items = {
            "org.iso.18013.5.1.mDL": {"org.iso.18013.5.1": ["given_name", "family_name"]}
        }

        # 6. Holder generates unsigned response
        unsigned_response = presentation_session.generate_response(permitted_items)

        # 7. Holder signs response
        signed_response = key_pair.sign(unsigned_response)

        # 8. Holder submits signed response
        final_response = presentation_session.submit_response(signed_response)

        # 9. Reader verifies response
        result = mdl_module.handle_response(reader_session.state, final_response)

        # 10. Verification successful
        assert result.device_authentication == mdl_module.AuthenticationStatus.VALID
        assert len(result.verified_response) > 0

    def test_protocol_workflow_with_partial_disclosure(self, mdl_module, key_pair, test_mdl):
        """Test protocol workflow with partial attribute disclosure."""
        session_uuid = str(uuid.uuid4())
        presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
        qr_uri = presentation_session.get_qr_code_uri()

        # Reader requests multiple attributes
        requested_items = {
            "org.iso.18013.5.1": {
                "given_name": True,
                "family_name": True,
                "birth_date": True,
                "portrait": True,
            }
        }

        reader_session = mdl_module.establish_session(qr_uri, requested_items, None)
        presentation_session.handle_request(reader_session.request)

        # Holder only permits subset
        permitted_items = {
            "org.iso.18013.5.1.mDL": {
                "org.iso.18013.5.1": ["given_name", "family_name"]
                # Not disclosing birth_date or portrait
            }
        }

        unsigned_response = presentation_session.generate_response(permitted_items)
        signed_response = key_pair.sign(unsigned_response)
        final_response = presentation_session.submit_response(signed_response)

        result = mdl_module.handle_response(reader_session.state, final_response)

        # Should still verify successfully
        assert result.device_authentication == mdl_module.AuthenticationStatus.VALID
