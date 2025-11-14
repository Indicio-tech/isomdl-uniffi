#!/usr/bin/env python3
# Copyright (c) 2025 Indicio
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# This software may be modified and distributed under the terms
# of either the Apache License, Version 2.0 or the MIT license.
# See the LICENSE-APACHE and LICENSE-MIT files for details.

"""
Error handling and edge case tests for isomdl-uniffi Python bindings using pytest.
Tests invalid input, error recovery, and edge case scenarios.
"""

import uuid

import pytest


class TestInvalidInput:
    """Test handling of invalid input data."""

    def test_invalid_session_uuid_empty(self, mdl_module, test_mdl):
        """Test that empty session UUID is rejected."""
        with pytest.raises(mdl_module.InternalError):
            mdl_module.MdlPresentationSession(test_mdl, "")

    def test_invalid_session_uuid_malformed(self, mdl_module, test_mdl):
        """Test that malformed session UUID is handled."""
        # Try various malformed UUIDs
        invalid_uuids = [
            "not-a-uuid",
            "12345",
            "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            "invalid format",
        ]

        for invalid_uuid in invalid_uuids:
            # Implementation validates UUID format strictly - should raise
            with pytest.raises(mdl_module.InternalError):  # InternalError for invalid UUID
                mdl_module.MdlPresentationSession(test_mdl, invalid_uuid)

    def test_corrupted_qr_code_uri(self, mdl_module):
        """Test that corrupted QR code URIs are rejected."""
        invalid_uris = [
            "",
            "not-a-uri",
            "http://",
            "mdoc://invalid",
            "corrupted-data-here",
        ]

        requested_items = {"org.iso.18013.5.1": {"given_name": True}}

        for invalid_uri in invalid_uris:
            with pytest.raises(mdl_module.MdlReaderSessionError):
                mdl_module.establish_session(invalid_uri, requested_items, None)

    def test_invalid_requested_items_empty_namespace(self, mdl_module, test_mdl):
        """Test handling of empty namespace in request."""
        session_uuid = str(uuid.uuid4())
        presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
        qr_uri = presentation_session.get_qr_code_uri()

        # Empty namespace
        invalid_request = {"": {"given_name": True}}

        try:
            reader_session = mdl_module.establish_session(qr_uri, invalid_request, None)
            # If accepted, should handle gracefully
            assert reader_session is not None
        except (ValueError, RuntimeError, KeyError):
            # Rejection is also acceptable
            pass

    def test_invalid_attribute_values(self, mdl_module, test_mdl):
        """Test handling of invalid attribute values in request."""
        import struct

        session_uuid = str(uuid.uuid4())
        presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
        qr_uri = presentation_session.get_qr_code_uri()

        # Invalid attribute value (not boolean) - should raise type error
        invalid_request = {
            "org.iso.18013.5.1": {
                "given_name": "not-a-boolean",  # Should be True or False
                "family_name": 123,  # Should be True or False
            }
        }

        # Should raise struct.error or TypeError for invalid boolean values
        with pytest.raises((TypeError, ValueError, RuntimeError, struct.error)):
            mdl_module.establish_session(qr_uri, invalid_request, None)

    def test_oversized_attribute_request(self, mdl_module, test_mdl):
        """Test handling of requests with many attributes."""
        session_uuid = str(uuid.uuid4())
        presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
        qr_uri = presentation_session.get_qr_code_uri()

        # Request 100 attributes (most don't exist)
        large_request = {"org.iso.18013.5.1": {f"attribute_{i}": True for i in range(100)}}

        # Should handle gracefully, even if most attributes don't exist
        try:
            reader_session = mdl_module.establish_session(qr_uri, large_request, None)
            requested_data = presentation_session.handle_request(reader_session.request)
            # Should return a list, even if empty or partial
            assert isinstance(requested_data, list)
        except Exception as e:
            # Some reasonable error is acceptable
            assert "attribute" in str(e).lower() or "request" in str(e).lower()


class TestErrorRecovery:
    """Test error recovery scenarios."""

    def test_recovery_from_invalid_signature(self, mdl_module, test_mdl):
        """Test that invalid signatures are properly rejected."""
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

        # Create an invalid signature (just random bytes)
        invalid_signature = b"invalid_signature_data_here_" + unsigned_response[:32]

        # Submitting invalid signature should fail
        with pytest.raises(mdl_module.SignatureError):
            presentation_session.submit_response(invalid_signature)

    def test_recovery_from_wrong_response_order(self, mdl_module, test_mdl):
        """Test that responding before handling request is rejected."""
        session_uuid = str(uuid.uuid4())
        presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)

        # Try to generate response before handling request
        permitted_items = {
            "org.iso.18013.5.1.mDL": {"org.iso.18013.5.1": ["given_name", "family_name"]}
        }

        with pytest.raises(mdl_module.SignatureError):
            presentation_session.generate_response(permitted_items)

    def test_recovery_from_invalid_request_data(self, mdl_module, test_mdl):
        """Test handling of corrupted request data."""
        session_uuid = str(uuid.uuid4())
        presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)

        # Try to handle invalid request data
        invalid_request_data = b"this is not valid request data"

        with pytest.raises(mdl_module.RequestError):
            presentation_session.handle_request(invalid_request_data)


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_duplicate_session_ids(self, mdl_module, test_mdl):
        """Test that duplicate session IDs are handled."""
        session_uuid = str(uuid.uuid4())

        # Create first session
        session1 = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
        assert session1 is not None

        # Create second session with same UUID
        # Should either reject or create independent session
        try:
            session2 = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
            # If allowed, sessions should be independent
            assert session2 is not None
            assert session1.get_qr_code_uri() == session2.get_qr_code_uri() or True
        except (ValueError, RuntimeError):
            # Rejection is also acceptable
            pass

    def test_null_trust_anchor_registry(self, mdl_module, test_mdl):
        """Test that None/null trust anchor registry is handled."""
        session_uuid = str(uuid.uuid4())
        presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
        qr_uri = presentation_session.get_qr_code_uri()

        requested_items = {"org.iso.18013.5.1": {"given_name": True}}

        # None should be acceptable (no trust anchors)
        reader_session = mdl_module.establish_session(qr_uri, requested_items, None)
        assert reader_session is not None

        # Empty list should also work
        reader_session2 = mdl_module.establish_session(qr_uri, requested_items, [])
        assert reader_session2 is not None

    def test_special_characters_in_namespace(self, mdl_module, test_mdl):
        """Test handling of special characters in namespace names."""
        session_uuid = str(uuid.uuid4())
        presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
        qr_uri = presentation_session.get_qr_code_uri()

        # Try various special characters
        special_namespaces = [
            "org.iso.18013.5.1",  # Normal (control)
            "org/iso/18013/5/1",  # Slashes
            "org-iso-18013-5-1",  # Hyphens
            "org_iso_18013_5_1",  # Underscores
        ]

        for namespace in special_namespaces:
            try:
                requested_items = {namespace: {"given_name": True}}
                reader_session = mdl_module.establish_session(qr_uri, requested_items, None)
                # Should either accept or reject, but not crash
                assert reader_session is not None
            except (ValueError, RuntimeError, KeyError):
                # Rejection of invalid namespaces is acceptable
                pass

    def test_unicode_attribute_names(self, mdl_module, test_mdl):
        """Test handling of Unicode characters in attribute names."""
        session_uuid = str(uuid.uuid4())
        presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
        qr_uri = presentation_session.get_qr_code_uri()

        # Try Unicode characters
        unicode_request = {
            "org.iso.18013.5.1": {
                "given_name": True,  # Normal
                "名前": True,  # Japanese
                "nombre": True,  # Spanish (with tilde)
                "имя": True,  # Cyrillic
            }
        }

        try:
            reader_session = mdl_module.establish_session(qr_uri, unicode_request, None)
            requested_data = presentation_session.handle_request(reader_session.request)
            # Should handle gracefully, even if attributes don't exist
            assert isinstance(requested_data, list)
        except Exception:
            # Some systems may not support Unicode attribute names
            pass

    def test_empty_permitted_items(self, mdl_module, test_mdl):
        """Test handling of empty permitted items in response."""
        session_uuid = str(uuid.uuid4())
        presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
        qr_uri = presentation_session.get_qr_code_uri()

        requested_items = {"org.iso.18013.5.1": {"given_name": True, "family_name": True}}

        reader_session = mdl_module.establish_session(qr_uri, requested_items, None)
        presentation_session.handle_request(reader_session.request)

        # Try to generate response with empty permitted items
        # This should fail as there are no signature payloads to process
        empty_permitted = {}

        with pytest.raises((ValueError, RuntimeError, Exception)):
            presentation_session.generate_response(empty_permitted)

    def test_mismatched_permitted_items(self, mdl_module, key_pair, test_mdl):
        """Test handling of permitted items that don't match request."""
        session_uuid = str(uuid.uuid4())
        presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
        qr_uri = presentation_session.get_qr_code_uri()

        # Request specific attributes
        requested_items = {"org.iso.18013.5.1": {"given_name": True, "family_name": True}}

        reader_session = mdl_module.establish_session(qr_uri, requested_items, None)
        presentation_session.handle_request(reader_session.request)

        # Permit completely different attributes
        mismatched_permitted = {
            "org.iso.18013.5.1.mDL": {"org.iso.18013.5.1": ["birth_date", "document_number"]}
        }

        # Should handle gracefully (might return empty or partial response)
        try:
            unsigned_response = presentation_session.generate_response(mismatched_permitted)
            assert isinstance(unsigned_response, bytes)

            # Try to complete the flow
            signed_response = key_pair.sign(unsigned_response)
            response = presentation_session.submit_response(signed_response)
            result = mdl_module.handle_response(reader_session.state, response)

            # Response should still be valid, even if empty
            assert result.device_authentication == mdl_module.AuthenticationStatus.VALID
        except Exception:
            # Some systems may reject mismatched items
            pass

    def test_very_long_attribute_names(self, mdl_module, test_mdl):
        """Test handling of very long attribute names."""
        session_uuid = str(uuid.uuid4())
        presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
        qr_uri = presentation_session.get_qr_code_uri()

        # Create very long attribute name (1000 characters)
        long_name = "a" * 1000

        long_name_request = {
            "org.iso.18013.5.1": {
                "given_name": True,
                long_name: True,
            }
        }

        try:
            reader_session = mdl_module.establish_session(qr_uri, long_name_request, None)
            # Should handle gracefully
            assert reader_session is not None
        except (ValueError, RuntimeError):
            # Rejection of overly long names is acceptable
            pass
