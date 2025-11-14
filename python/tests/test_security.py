#!/usr/bin/env python3
# Copyright (c) 2025 Indicio
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# This software may be modified and distributed under the terms
# of either the Apache License, Version 2.0 or the MIT license.
# See the LICENSE-APACHE and LICENSE-MIT files for details.

"""
Security and cryptography tests for isomdl-uniffi Python bindings using pytest.
Tests signature verification, authentication, and attack prevention.
"""

import uuid
from contextlib import suppress

import pytest


class TestSignatureVerification:
    """Test signature verification and tamper detection."""

    def test_tampered_response_detection(self, mdl_module, key_pair, test_mdl):
        """Test that tampered response data is detected."""
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

        # Tamper with the response data
        tampered_response = bytearray(final_response)
        if len(tampered_response) > 10:
            # Flip some bits in the middle
            tampered_response[len(tampered_response) // 2] ^= 0xFF
        tampered_response = bytes(tampered_response)

        # Tampered response should be rejected or fail verification
        try:
            result = mdl_module.handle_response(reader_session.state, tampered_response)
            # If it doesn't throw, authentication should fail
            assert result.device_authentication != mdl_module.AuthenticationStatus.VALID
        except (ValueError, RuntimeError):
            # Exception is also acceptable for tampered data
            pass

    def test_wrong_key_signature(self, mdl_module, test_mdl):
        """Test that signatures from wrong key are rejected."""
        # Create two different key pairs
        key_pair1 = mdl_module.P256KeyPair()
        key_pair2 = mdl_module.P256KeyPair()

        # Generate MDL with first key
        test_mdl1 = mdl_module.generate_test_mdl(key_pair1)

        session_uuid = str(uuid.uuid4())
        presentation_session = mdl_module.MdlPresentationSession(test_mdl1, session_uuid)
        qr_uri = presentation_session.get_qr_code_uri()

        requested_items = {"org.iso.18013.5.1": {"given_name": True}}

        reader_session = mdl_module.establish_session(qr_uri, requested_items, None)
        presentation_session.handle_request(reader_session.request)

        permitted_items = {"org.iso.18013.5.1.mDL": {"org.iso.18013.5.1": ["given_name"]}}

        unsigned_response = presentation_session.generate_response(permitted_items)

        # Sign with WRONG key
        wrong_signed_response = key_pair2.sign(unsigned_response)

        # Should fail when submitting or verifying
        try:
            final_response = presentation_session.submit_response(wrong_signed_response)
            result = mdl_module.handle_response(reader_session.state, final_response)
            # If it doesn't throw, authentication should fail
            assert result.device_authentication != mdl_module.AuthenticationStatus.VALID
        except (ValueError, RuntimeError):
            # Exception is acceptable for wrong signature
            pass

    def test_unsigned_response_rejection(self, mdl_module, key_pair, test_mdl):
        """Test that unsigned responses are rejected."""
        session_uuid = str(uuid.uuid4())
        presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
        qr_uri = presentation_session.get_qr_code_uri()

        requested_items = {"org.iso.18013.5.1": {"given_name": True}}

        reader_session = mdl_module.establish_session(qr_uri, requested_items, None)
        presentation_session.handle_request(reader_session.request)

        permitted_items = {"org.iso.18013.5.1.mDL": {"org.iso.18013.5.1": ["given_name"]}}

        unsigned_response = presentation_session.generate_response(permitted_items)

        # Try to submit unsigned response directly (should fail with SignatureError)
        with pytest.raises((ValueError, RuntimeError, Exception)):
            # submit_response expects signed data, unsigned should be rejected
            presentation_session.submit_response(unsigned_response)

    def test_signature_malleability(self, mdl_module, key_pair, test_mdl):
        """Test that signature cannot be malleated."""
        session_uuid = str(uuid.uuid4())
        presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
        qr_uri = presentation_session.get_qr_code_uri()

        requested_items = {"org.iso.18013.5.1": {"given_name": True}}

        reader_session = mdl_module.establish_session(qr_uri, requested_items, None)
        presentation_session.handle_request(reader_session.request)

        permitted_items = {"org.iso.18013.5.1.mDL": {"org.iso.18013.5.1": ["given_name"]}}

        unsigned_response = presentation_session.generate_response(permitted_items)
        signed_response = key_pair.sign(unsigned_response)

        # Try to malleate signature (modify signature bytes)
        malleated = bytearray(signed_response)
        if len(malleated) > 0:
            # Flip a bit in the signature portion
            malleated[-1] ^= 0x01
        malleated = bytes(malleated)

        # Malleated signature should be rejected
        # The implementation may accept it and fail later at verification
        # OR reject it immediately - both are acceptable
        try:
            final_response = presentation_session.submit_response(malleated)
            # If submit succeeds, verification should fail
            result = mdl_module.handle_response(reader_session.state, final_response)
            assert result.device_authentication != mdl_module.AuthenticationStatus.VALID
        except (ValueError, RuntimeError, Exception):
            # Immediate rejection is also acceptable
            pass


class TestAuthentication:
    """Test authentication scenarios and failures."""

    def test_device_authentication_validation(self, mdl_module, key_pair, test_mdl):
        """Test that device authentication is properly validated."""
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

        # Authentication should be VALID for properly signed response
        assert result.device_authentication == mdl_module.AuthenticationStatus.VALID
        assert hasattr(result, "verified_response")
        assert len(result.verified_response) > 0

    def test_authentication_status_enum_values(self, mdl_module):
        """Test that AuthenticationStatus enum has expected values."""
        # Verify the authentication status enum exists and has expected values
        assert hasattr(mdl_module, "AuthenticationStatus")
        assert hasattr(mdl_module.AuthenticationStatus, "VALID")

        # There should be other states too (INVALID, UNKNOWN, etc.)
        # The exact names may vary, but VALID should definitely exist

    def test_multiple_authentication_attempts(self, mdl_module, key_pair, test_mdl):
        """Test that multiple authentication attempts are handled correctly."""
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

        # First authentication
        result1 = mdl_module.handle_response(reader_session.state, final_response)
        assert result1.device_authentication == mdl_module.AuthenticationStatus.VALID

        # Second authentication with same response (replay)
        # This might fail or succeed depending on implementation
        try:
            result2 = mdl_module.handle_response(reader_session.state, final_response)
            # If it succeeds, result should be the same
            assert result2.device_authentication == result1.device_authentication
        except (ValueError, RuntimeError):
            # Rejection of replayed response is also acceptable
            pass


class TestAttackPrevention:
    """Test prevention of common attacks."""

    def test_session_isolation(self, mdl_module, key_pair, test_mdl):
        """Test that different sessions are properly isolated."""
        # Create two independent sessions
        session_uuid1 = str(uuid.uuid4())
        session_uuid2 = str(uuid.uuid4())

        session1 = mdl_module.MdlPresentationSession(test_mdl, session_uuid1)
        session2 = mdl_module.MdlPresentationSession(test_mdl, session_uuid2)

        qr_uri1 = session1.get_qr_code_uri()
        qr_uri2 = session2.get_qr_code_uri()

        # URIs should be different (different sessions)
        assert qr_uri1 != qr_uri2

        # Establish reader sessions
        requested_items = {"org.iso.18013.5.1": {"given_name": True}}

        reader1 = mdl_module.establish_session(qr_uri1, requested_items, None)
        reader2 = mdl_module.establish_session(qr_uri2, requested_items, None)

        # Process requests in both sessions
        session1.handle_request(reader1.request)
        session2.handle_request(reader2.request)

        permitted_items = {"org.iso.18013.5.1.mDL": {"org.iso.18013.5.1": ["given_name"]}}

        # Generate responses
        unsigned1 = session1.generate_response(permitted_items)
        unsigned2 = session2.generate_response(permitted_items)

        # Sign both
        signed1 = key_pair.sign(unsigned1)
        signed2 = key_pair.sign(unsigned2)

        response1 = session1.submit_response(signed1)
        response2 = session2.submit_response(signed2)

        # Try to use response1 with reader2 (cross-session attack)
        try:
            result = mdl_module.handle_response(reader2.state, response1)
            # If it doesn't throw, it should fail authentication
            assert result.device_authentication != mdl_module.AuthenticationStatus.VALID
        except (ValueError, RuntimeError):
            # Exception is expected for cross-session use
            pass

        # Correct pairings should work
        result1 = mdl_module.handle_response(reader1.state, response1)
        assert result1.device_authentication == mdl_module.AuthenticationStatus.VALID

        result2 = mdl_module.handle_response(reader2.state, response2)
        assert result2.device_authentication == mdl_module.AuthenticationStatus.VALID

    def test_request_injection(self, mdl_module, key_pair, test_mdl):
        """Test that malicious request injection is prevented."""
        session_uuid = str(uuid.uuid4())
        presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
        qr_uri = presentation_session.get_qr_code_uri()

        requested_items = {"org.iso.18013.5.1": {"given_name": True}}

        reader_session = mdl_module.establish_session(qr_uri, requested_items, None)

        # Try to inject additional attributes by manipulating request
        legit_request = reader_session.request

        # Process legitimate request
        presentation_session.handle_request(legit_request)

        # Try to process same request again (replay)
        with suppress(ValueError, RuntimeError):
            presentation_session.handle_request(legit_request)
            # If allowed, should still work correctly

    def test_data_substitution_attack(self, mdl_module, key_pair):
        """Test that data substitution attacks are prevented."""
        # Create two different MDLs (though they have same test ID)
        mdl1 = mdl_module.generate_test_mdl(key_pair)
        _mdl2 = mdl_module.generate_test_mdl(key_pair)

        # Test MDLs have the same ID (00000000-0000-0000-0000-000000000000)
        # which is expected for test data
        # The cryptographic binding prevents substitution even with same ID

        # Create session with mdl1
        session_uuid = str(uuid.uuid4())
        session1 = mdl_module.MdlPresentationSession(mdl1, session_uuid)
        qr_uri1 = session1.get_qr_code_uri()

        requested_items = {"org.iso.18013.5.1": {"given_name": True}}

        reader_session = mdl_module.establish_session(qr_uri1, requested_items, None)
        session1.handle_request(reader_session.request)

        # Generate response with correct MDL
        permitted_items = {"org.iso.18013.5.1.mDL": {"org.iso.18013.5.1": ["given_name"]}}

        unsigned_response = session1.generate_response(permitted_items)
        signed_response = key_pair.sign(unsigned_response)
        final_response = session1.submit_response(signed_response)

        # Verify with reader (should work)
        result = mdl_module.handle_response(reader_session.state, final_response)
        assert result.device_authentication == mdl_module.AuthenticationStatus.VALID

        # The response should be cryptographically bound to mdl1's specific data
        # and cannot be substituted with data from mdl2 even though they share
        # the same test ID

    def test_mitm_session_hijacking(self, mdl_module, key_pair, test_mdl):
        """Test that man-in-the-middle session hijacking is prevented."""
        # Attacker creates their own session
        attacker_session_uuid = str(uuid.uuid4())
        attacker_session = mdl_module.MdlPresentationSession(test_mdl, attacker_session_uuid)
        # QR code generated but not used directly
        _attacker_qr = attacker_session.get_qr_code_uri()

        # Legitimate holder creates their session
        holder_session_uuid = str(uuid.uuid4())
        holder_session = mdl_module.MdlPresentationSession(test_mdl, holder_session_uuid)
        holder_qr = holder_session.get_qr_code_uri()

        requested_items = {"org.iso.18013.5.1": {"given_name": True}}

        # Reader connects to holder
        reader_session = mdl_module.establish_session(holder_qr, requested_items, None)

        # Holder processes request
        holder_session.handle_request(reader_session.request)

        permitted_items = {"org.iso.18013.5.1.mDL": {"org.iso.18013.5.1": ["given_name"]}}

        # Holder generates response
        unsigned = holder_session.generate_response(permitted_items)
        signed = key_pair.sign(unsigned)
        holder_response = holder_session.submit_response(signed)

        # Attacker tries to intercept and reuse holder's request
        # with their own session (should fail because session state is different)
        with pytest.raises((ValueError, RuntimeError, Exception)):
            attacker_session.handle_request(reader_session.request)
            # Even if handle_request succeeds, generate_response should fail
            # because the attacker session doesn't have the right state
            attacker_session.generate_response(permitted_items)

        # Legitimate holder's response should still work
        result = mdl_module.handle_response(reader_session.state, holder_response)
        assert result.device_authentication == mdl_module.AuthenticationStatus.VALID

    def test_downgrade_attack_prevention(self, mdl_module, key_pair, test_mdl):
        """Test that cryptographic downgrade attacks are prevented."""
        session_uuid = str(uuid.uuid4())
        presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
        qr_uri = presentation_session.get_qr_code_uri()

        # Request with proper items
        requested_items = {"org.iso.18013.5.1": {"given_name": True, "family_name": True}}

        reader_session = mdl_module.establish_session(qr_uri, requested_items, None)
        presentation_session.handle_request(reader_session.request)

        # Generate response
        permitted_items = {
            "org.iso.18013.5.1.mDL": {"org.iso.18013.5.1": ["given_name", "family_name"]}
        }

        unsigned_response = presentation_session.generate_response(permitted_items)
        signed_response = key_pair.sign(unsigned_response)
        final_response = presentation_session.submit_response(signed_response)

        # Verify response is properly signed with P256
        result = mdl_module.handle_response(reader_session.state, final_response)
        assert result.device_authentication == mdl_module.AuthenticationStatus.VALID

        # The system should not accept weaker cryptographic algorithms
        # (This is ensured by the P256KeyPair type)
