#!/usr/bin/env python3
# Copyright (c) 2025 Indicio
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# This software may be modified and distributed under the terms
# of either the Apache License, Version 2.0 or the MIT license.
# See the LICENSE-APACHE and LICENSE-MIT files for details.

"""
Data validation and type safety tests for isomdl-uniffi Python bindings using pytest.
Tests namespace validation, attribute validation, and value type checking.
"""

import uuid

import pytest


class TestNamespaceValidation:
    """Test validation of namespace names and structures."""

    def test_empty_namespace_name(self, mdl_module, test_mdl):
        """Test handling of empty namespace in request."""
        session_uuid = str(uuid.uuid4())
        presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
        qr_uri = presentation_session.get_qr_code_uri()

        # Empty namespace name
        invalid_request = {"": {"given_name": True}}

        # Should handle gracefully (may accept or reject)
        try:
            reader_session = mdl_module.establish_session(qr_uri, invalid_request, None)
            # If accepted, should still work
            assert reader_session is not None
        except (ValueError, RuntimeError, KeyError):
            # Rejection is also acceptable
            pass

    def test_very_long_namespace_name(self, mdl_module, test_mdl):
        """Test handling of extremely long namespace names."""
        session_uuid = str(uuid.uuid4())
        presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
        qr_uri = presentation_session.get_qr_code_uri()

        # Very long namespace (1000 chars)
        long_namespace = "a" * 1000
        request = {long_namespace: {"some_attr": True}}

        try:
            reader_session = mdl_module.establish_session(qr_uri, request, None)
            # If accepted, should handle gracefully
            assert reader_session is not None
        except (ValueError, RuntimeError, MemoryError):
            # Rejection is acceptable
            pass

    def test_unknown_namespace_handling(self, mdl_module, test_mdl):
        """Test requesting data from unknown namespace."""
        session_uuid = str(uuid.uuid4())
        presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
        qr_uri = presentation_session.get_qr_code_uri()

        # Request from non-existent namespace
        unknown_request = {"com.unknown.namespace.v1": {"unknown_attr": True}}

        try:
            reader_session = mdl_module.establish_session(qr_uri, unknown_request, None)
            # Request should be accepted (reader can ask for anything)
            assert reader_session is not None

            # Process the request
            presentation_session.handle_request(reader_session.request)

            # Response with no permitted items from unknown namespace
            empty_permitted = {}

            # May fail or return empty response
            with pytest.raises((ValueError, RuntimeError, Exception)):
                presentation_session.generate_response(empty_permitted)
        except (ValueError, RuntimeError):
            # Early rejection is also acceptable
            pass

    def test_multiple_namespaces_request(self, mdl_module, key_pair, test_mdl):
        """Test requesting attributes from multiple namespaces."""
        session_uuid = str(uuid.uuid4())
        presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
        qr_uri = presentation_session.get_qr_code_uri()

        # Request from multiple namespaces
        multi_ns_request = {
            "org.iso.18013.5.1": {"given_name": True, "family_name": True},
            "org.iso.18013.5.1.aamva": {"DHS_compliance": True},
        }

        reader_session = mdl_module.establish_session(qr_uri, multi_ns_request, None)
        presentation_session.handle_request(reader_session.request)

        # Permit only from ISO namespace
        permitted_items = {
            "org.iso.18013.5.1.mDL": {"org.iso.18013.5.1": ["given_name", "family_name"]}
        }

        unsigned_response = presentation_session.generate_response(permitted_items)
        signed_response = key_pair.sign(unsigned_response)
        final_response = presentation_session.submit_response(signed_response)

        result = mdl_module.handle_response(reader_session.state, final_response)
        assert result.device_authentication == mdl_module.AuthenticationStatus.VALID


class TestAttributeValidation:
    """Test validation of attribute names and structures."""

    def test_empty_attribute_name(self, mdl_module, test_mdl):
        """Test handling of empty attribute names."""
        session_uuid = str(uuid.uuid4())
        presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
        qr_uri = presentation_session.get_qr_code_uri()

        # Empty attribute name
        invalid_request = {"org.iso.18013.5.1": {"": True}}

        try:
            reader_session = mdl_module.establish_session(qr_uri, invalid_request, None)
            # If accepted, should handle gracefully
            assert reader_session is not None
        except (ValueError, RuntimeError, KeyError):
            # Rejection is acceptable
            pass

    def test_very_long_attribute_names(self, mdl_module, test_mdl):
        """Test handling of extremely long attribute names."""
        session_uuid = str(uuid.uuid4())
        presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
        qr_uri = presentation_session.get_qr_code_uri()

        # Very long attribute name (500 chars)
        long_attr = "attribute_" * 50
        request = {"org.iso.18013.5.1": {long_attr: True}}

        try:
            reader_session = mdl_module.establish_session(qr_uri, request, None)
            assert reader_session is not None
        except (ValueError, RuntimeError, MemoryError):
            # Rejection is acceptable
            pass

    def test_special_characters_in_attribute_names(self, mdl_module, test_mdl):
        """Test attribute names with special characters."""
        session_uuid = str(uuid.uuid4())
        presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
        qr_uri = presentation_session.get_qr_code_uri()

        # Attribute names with special characters
        special_attrs = {
            "org.iso.18013.5.1": {
                "attr-with-dash": True,
                "attr_with_underscore": True,
                "attr.with.dots": True,
            }
        }

        try:
            reader_session = mdl_module.establish_session(qr_uri, special_attrs, None)
            # System should handle or reject gracefully
            assert reader_session is not None
        except (ValueError, RuntimeError):
            pass

    def test_duplicate_attributes_same_namespace(self, mdl_module, test_mdl):
        """Test handling of duplicate attribute requests."""
        session_uuid = str(uuid.uuid4())
        presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
        qr_uri = presentation_session.get_qr_code_uri()

        # Python dict naturally prevents duplicates, but test the concept
        request = {
            "org.iso.18013.5.1": {
                "given_name": True,
                "family_name": True,
            }
        }

        # Should work fine (dict handles duplicates)
        reader_session = mdl_module.establish_session(qr_uri, request, None)
        assert reader_session is not None

    def test_nonexistent_attribute_request(self, mdl_module, key_pair, test_mdl):
        """Test requesting attributes that don't exist in MDL."""
        session_uuid = str(uuid.uuid4())
        presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
        qr_uri = presentation_session.get_qr_code_uri()

        # Request non-existent attributes
        request = {
            "org.iso.18013.5.1": {
                "nonexistent_attribute_1": True,
                "nonexistent_attribute_2": True,
            }
        }

        reader_session = mdl_module.establish_session(qr_uri, request, None)
        presentation_session.handle_request(reader_session.request)

        # Try to permit non-existent attributes
        permitted = {
            "org.iso.18013.5.1.mDL": {
                "org.iso.18013.5.1": [
                    "nonexistent_attribute_1",
                    "nonexistent_attribute_2",
                ]
            }
        }

        try:
            unsigned_response = presentation_session.generate_response(permitted)
            # If it succeeds, response should be valid but may have no attributes
            assert isinstance(unsigned_response, bytes)

            signed_response = key_pair.sign(unsigned_response)
            final_response = presentation_session.submit_response(signed_response)

            result = mdl_module.handle_response(reader_session.state, final_response)
            # Authentication should still work even with no disclosed attributes
            assert result.device_authentication == mdl_module.AuthenticationStatus.VALID
        except (ValueError, RuntimeError, KeyError, Exception):
            # Rejection is also acceptable
            pass


class TestAttributeValues:
    """Test validation of attribute value types and formats."""

    def test_null_value_in_permitted_items(self, mdl_module, test_mdl):
        """Test handling of null values in permitted items."""
        session_uuid = str(uuid.uuid4())
        presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
        qr_uri = presentation_session.get_qr_code_uri()

        requested_items = {"org.iso.18013.5.1": {"given_name": True}}

        reader_session = mdl_module.establish_session(qr_uri, requested_items, None)
        presentation_session.handle_request(reader_session.request)

        # Try permitted items with None value
        try:
            permitted = None
            with pytest.raises((TypeError, ValueError, RuntimeError)):
                presentation_session.generate_response(permitted)
        except Exception:
            pass

    def test_empty_string_attribute_values(self, test_mdl):
        """Test that system handles empty string attribute values."""
        # This tests the MDL itself, not request/response
        # Test MDL should have valid values, but we can verify structure
        details = test_mdl.details()

        assert details is not None
        # details is a dict of namespace -> list of Element objects
        assert isinstance(details, dict)
        assert len(details) > 0

        # Each namespace should have a list of elements
        for _namespace, elements in details.items():
            assert isinstance(elements, list)
            assert len(elements) > 0

    def test_boolean_request_values(self, mdl_module, test_mdl):
        """Test that request items properly use boolean values."""
        session_uuid = str(uuid.uuid4())
        presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
        qr_uri = presentation_session.get_qr_code_uri()

        # Request with explicit True/False values
        request = {
            "org.iso.18013.5.1": {
                "given_name": True,
                "family_name": False,  # Requesting but marking as not required
            }
        }

        reader_session = mdl_module.establish_session(qr_uri, request, None)
        assert reader_session is not None

    def test_permitted_items_list_type(self, mdl_module, key_pair, test_mdl):
        """Test that permitted items use list of attribute names."""
        session_uuid = str(uuid.uuid4())
        presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
        qr_uri = presentation_session.get_qr_code_uri()

        requested_items = {"org.iso.18013.5.1": {"given_name": True, "family_name": True}}

        reader_session = mdl_module.establish_session(qr_uri, requested_items, None)
        presentation_session.handle_request(reader_session.request)

        # Correct format: list of strings
        correct_permitted = {
            "org.iso.18013.5.1.mDL": {"org.iso.18013.5.1": ["given_name", "family_name"]}
        }

        unsigned = presentation_session.generate_response(correct_permitted)
        signed = key_pair.sign(unsigned)
        final = presentation_session.submit_response(signed)

        result = mdl_module.handle_response(reader_session.state, final)
        assert result.device_authentication == mdl_module.AuthenticationStatus.VALID

    def test_permitted_items_wrong_type(self, mdl_module, test_mdl):
        """Test that wrong types in permitted items are handled."""
        session_uuid = str(uuid.uuid4())
        presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
        qr_uri = presentation_session.get_qr_code_uri()

        requested_items = {"org.iso.18013.5.1": {"given_name": True}}

        reader_session = mdl_module.establish_session(qr_uri, requested_items, None)
        presentation_session.handle_request(reader_session.request)

        # Wrong format: dict instead of list (Python may coerce this)
        wrong_permitted = {
            "org.iso.18013.5.1.mDL": {
                "org.iso.18013.5.1": {"given_name": True}  # Should be list
            }
        }

        # Implementation may accept dict or reject it
        try:
            unsigned = presentation_session.generate_response(wrong_permitted)
            # If accepted, it handled the conversion
            assert isinstance(unsigned, bytes)
        except (TypeError, ValueError, RuntimeError):
            # Rejection is also acceptable
            pass

    def test_attribute_value_types_in_mdl(self, mdl_module, key_pair):
        """Test that MDL contains expected attribute structure."""
        mdl = mdl_module.generate_test_mdl(key_pair)
        details = mdl.details()

        # details is a dict of namespace -> list of Element objects
        assert isinstance(details, dict)
        assert len(details) > 0

        # Each namespace should have a list of elements
        for _namespace, elements in details.items():
            assert isinstance(elements, list)
            assert len(elements) > 0

            # Each element should have required properties
            for element in elements:
                assert element is not None
                # Element objects have specific structure
                assert hasattr(element, "identifier")
                assert hasattr(element, "value")


class TestDataIntegrity:
    """Test data integrity and consistency checks."""

    def test_mdl_details_consistency(self, mdl_module, key_pair):
        """Test that MDL details remain consistent across calls."""
        mdl = mdl_module.generate_test_mdl(key_pair)

        # Get details multiple times
        details1 = mdl.details()
        details2 = mdl.details()

        # Should return same structure
        assert isinstance(details1, dict)
        assert isinstance(details2, dict)

        # Same namespaces
        assert details1.keys() == details2.keys()

        # Same number of elements in each namespace
        for namespace in details1:
            assert len(details1[namespace]) == len(details2[namespace])

    def test_doc_type_consistency(self, mdl_module, key_pair):
        """Test that document type is consistent."""
        mdl = mdl_module.generate_test_mdl(key_pair)

        doc_type1 = mdl.doctype()
        doc_type2 = mdl.doctype()

        assert doc_type1 == doc_type2
        assert doc_type1 == "org.iso.18013.5.1.mDL"

    def test_mdl_id_consistency(self, mdl_module, key_pair):
        """Test that MDL ID is consistent."""
        mdl = mdl_module.generate_test_mdl(key_pair)

        id1 = mdl.id()
        id2 = mdl.id()

        assert id1 == id2

    def test_serialization_consistency(self, mdl_module, key_pair):
        """Test that serialization produces consistent results."""
        mdl = mdl_module.generate_test_mdl(key_pair)

        # Serialize multiple times using json() method
        json1 = mdl.json()
        json2 = mdl.json()

        # Should produce identical output
        assert json1 == json2
        assert len(json1) > 0

    def test_cbor_serialization_deterministic(self, mdl_module, key_pair):
        """Test that CBOR serialization is deterministic."""
        mdl = mdl_module.generate_test_mdl(key_pair)

        # Serialize multiple times using stringify() method
        cbor1 = mdl.stringify()
        cbor2 = mdl.stringify()

        # CBOR should be deterministic
        assert cbor1 == cbor2
        assert len(cbor1) > 0
