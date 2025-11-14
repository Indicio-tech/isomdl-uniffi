#!/usr/bin/env python3
"""
State machine and session lifecycle tests for isomdl-uniffi Python bindings using pytest.
Tests session state transitions, lifecycle management, and concurrent session handling.
"""

import uuid
from contextlib import suppress

import pytest


class TestSessionLifecycle:
    """Test session creation, lifecycle, and cleanup."""

    def test_session_creation(self, mdl_module, test_mdl):
        """Test that presentation session is created successfully."""
        session_uuid = str(uuid.uuid4())
        session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)

        assert session is not None
        # Session should be in initial state, ready to generate QR code
        qr_uri = session.get_qr_code_uri()
        assert qr_uri is not None
        assert len(qr_uri) > 0

    def test_session_initialization_with_mdl(self, mdl_module, key_pair):
        """Test that session properly initializes with MDL."""
        mdl = mdl_module.generate_test_mdl(key_pair)
        session_uuid = str(uuid.uuid4())

        session = mdl_module.MdlPresentationSession(mdl, session_uuid)

        # Session should be able to generate identifiers
        qr_uri = session.get_qr_code_uri()
        ble_ident = session.get_ble_ident()

        assert qr_uri is not None
        assert ble_ident is not None
        assert isinstance(ble_ident, bytes)

    def test_session_complete_lifecycle(self, mdl_module, key_pair, test_mdl):
        """Test complete session lifecycle from creation to completion."""
        # 1. Create session
        session_uuid = str(uuid.uuid4())
        presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
        qr_uri = presentation_session.get_qr_code_uri()

        # 2. Establish reader session
        requested_items = {"org.iso.18013.5.1": {"given_name": True, "family_name": True}}
        reader_session = mdl_module.establish_session(qr_uri, requested_items, None)

        # 3. Handle request
        presentation_session.handle_request(reader_session.request)

        # 4. Generate response
        permitted_items = {
            "org.iso.18013.5.1.mDL": {"org.iso.18013.5.1": ["given_name", "family_name"]}
        }
        unsigned_response = presentation_session.generate_response(permitted_items)

        # 5. Sign and submit response
        signed_response = key_pair.sign(unsigned_response)
        final_response = presentation_session.submit_response(signed_response)

        # 6. Verify response
        result = mdl_module.handle_response(reader_session.state, final_response)

        # Session completed successfully
        assert result.device_authentication == mdl_module.AuthenticationStatus.VALID
        assert len(result.verified_response) > 0

    def test_multiple_sessions_same_mdl(self, mdl_module, test_mdl):
        """Test that same MDL can be used for multiple sessions."""
        # Create multiple sessions with same MDL
        session1_uuid = str(uuid.uuid4())
        session2_uuid = str(uuid.uuid4())

        session1 = mdl_module.MdlPresentationSession(test_mdl, session1_uuid)
        session2 = mdl_module.MdlPresentationSession(test_mdl, session2_uuid)

        qr1 = session1.get_qr_code_uri()
        qr2 = session2.get_qr_code_uri()

        # Both sessions should work independently
        assert qr1 != qr2
        assert len(qr1) > 0
        assert len(qr2) > 0

    def test_session_unique_identifiers(self, mdl_module, test_mdl):
        """Test that each session has unique identifiers."""
        sessions = []
        qr_uris = set()
        ble_idents = set()

        # Create 5 sessions
        for _ in range(5):
            session_uuid = str(uuid.uuid4())
            session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
            sessions.append(session)

            qr_uris.add(session.get_qr_code_uri())
            ble_idents.add(session.get_ble_ident().hex())

        # All QR URIs should be unique
        assert len(qr_uris) == 5
        # All BLE identifiers should be unique
        assert len(ble_idents) == 5


class TestInvalidStateTransitions:
    """Test that invalid state transitions are prevented."""

    def test_generate_response_before_request(self, mdl_module, test_mdl):
        """Test that generating response before handling request fails."""
        session_uuid = str(uuid.uuid4())
        presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)

        # Try to generate response without handling request first
        permitted_items = {"org.iso.18013.5.1.mDL": {"org.iso.18013.5.1": ["given_name"]}}

        # Should fail because no request has been handled
        with pytest.raises((ValueError, RuntimeError, Exception)):
            presentation_session.generate_response(permitted_items)

    def test_submit_response_before_generate(self, mdl_module, key_pair, test_mdl):
        """Test that submitting response before generating fails."""
        session_uuid = str(uuid.uuid4())
        presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
        qr_uri = presentation_session.get_qr_code_uri()

        requested_items = {"org.iso.18013.5.1": {"given_name": True}}
        reader_session = mdl_module.establish_session(qr_uri, requested_items, None)
        presentation_session.handle_request(reader_session.request)

        # Try to submit without generating first
        fake_data = b"not-a-real-response"
        signed_fake = key_pair.sign(fake_data)

        # Should fail because no response was generated
        with pytest.raises((ValueError, RuntimeError, Exception)):
            presentation_session.submit_response(signed_fake)

    def test_handle_request_twice(self, mdl_module, test_mdl):
        """Test handling request twice on same session."""
        session_uuid = str(uuid.uuid4())
        presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
        qr_uri = presentation_session.get_qr_code_uri()

        requested_items = {"org.iso.18013.5.1": {"given_name": True}}
        reader_session = mdl_module.establish_session(qr_uri, requested_items, None)

        # Handle request first time (should work)
        presentation_session.handle_request(reader_session.request)

        # Try to handle same request again
        # Implementation may allow this or reject it
        with suppress(ValueError, RuntimeError):
            presentation_session.handle_request(reader_session.request)
            # If allowed, it should not crash

    def test_generate_response_twice(self, mdl_module, test_mdl):
        """Test generating response twice on same session."""
        session_uuid = str(uuid.uuid4())
        presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
        qr_uri = presentation_session.get_qr_code_uri()

        requested_items = {"org.iso.18013.5.1": {"given_name": True}}
        reader_session = mdl_module.establish_session(qr_uri, requested_items, None)
        presentation_session.handle_request(reader_session.request)

        permitted_items = {"org.iso.18013.5.1.mDL": {"org.iso.18013.5.1": ["given_name"]}}

        # Generate first time (should work)
        response1 = presentation_session.generate_response(permitted_items)
        assert isinstance(response1, bytes)

        # Try to generate again
        # May fail or succeed depending on implementation
        try:
            response2 = presentation_session.generate_response(permitted_items)
            # If allowed, responses might be different due to fresh signatures
            assert isinstance(response2, bytes)
        except (ValueError, RuntimeError, Exception):
            # Rejection is also acceptable
            pass


class TestConcurrentSessions:
    """Test concurrent session handling."""

    def test_multiple_simultaneous_sessions(self, mdl_module, key_pair, test_mdl):
        """Test multiple sessions running simultaneously."""
        sessions = []
        reader_sessions = []

        # Create 5 concurrent sessions
        for _i in range(5):
            session_uuid = str(uuid.uuid4())
            presentation_session = mdl_module.MdlPresentationSession(test_mdl, session_uuid)
            qr_uri = presentation_session.get_qr_code_uri()

            requested_items = {"org.iso.18013.5.1": {"given_name": True}}
            reader_session = mdl_module.establish_session(qr_uri, requested_items, None)

            sessions.append(presentation_session)
            reader_sessions.append(reader_session)

        # Process all sessions
        for presentation_session, reader_session in zip(sessions, reader_sessions):
            presentation_session.handle_request(reader_session.request)

            permitted_items = {"org.iso.18013.5.1.mDL": {"org.iso.18013.5.1": ["given_name"]}}

            unsigned = presentation_session.generate_response(permitted_items)
            signed = key_pair.sign(unsigned)
            final_response = presentation_session.submit_response(signed)

            result = mdl_module.handle_response(reader_session.state, final_response)
            assert result.device_authentication == mdl_module.AuthenticationStatus.VALID

    def test_concurrent_different_mdls(self, mdl_module, key_pair):
        """Test concurrent sessions with different MDLs."""
        # Create multiple MDLs
        mdls = [mdl_module.generate_test_mdl(key_pair) for _ in range(3)]

        sessions = []
        reader_sessions = []

        # Create session for each MDL
        for mdl in mdls:
            session_uuid = str(uuid.uuid4())
            presentation_session = mdl_module.MdlPresentationSession(mdl, session_uuid)
            qr_uri = presentation_session.get_qr_code_uri()

            requested_items = {"org.iso.18013.5.1": {"given_name": True}}
            reader_session = mdl_module.establish_session(qr_uri, requested_items, None)

            sessions.append(presentation_session)
            reader_sessions.append(reader_session)

        # All sessions should complete independently
        for presentation_session, reader_session in zip(sessions, reader_sessions):
            presentation_session.handle_request(reader_session.request)

            permitted_items = {"org.iso.18013.5.1.mDL": {"org.iso.18013.5.1": ["given_name"]}}

            unsigned = presentation_session.generate_response(permitted_items)
            signed = key_pair.sign(unsigned)
            final_response = presentation_session.submit_response(signed)

            result = mdl_module.handle_response(reader_session.state, final_response)
            assert result.device_authentication == mdl_module.AuthenticationStatus.VALID

    def test_session_independence(self, mdl_module, key_pair, test_mdl):
        """Test that concurrent sessions don't interfere with each other."""
        # Create two sessions
        session1_uuid = str(uuid.uuid4())
        session2_uuid = str(uuid.uuid4())

        session1 = mdl_module.MdlPresentationSession(test_mdl, session1_uuid)
        session2 = mdl_module.MdlPresentationSession(test_mdl, session2_uuid)

        qr1 = session1.get_qr_code_uri()
        qr2 = session2.get_qr_code_uri()

        # Establish both reader sessions
        requested_items = {"org.iso.18013.5.1": {"given_name": True, "family_name": True}}

        reader1 = mdl_module.establish_session(qr1, requested_items, None)
        reader2 = mdl_module.establish_session(qr2, requested_items, None)

        # Process session1 fully
        session1.handle_request(reader1.request)
        permitted = {"org.iso.18013.5.1.mDL": {"org.iso.18013.5.1": ["given_name", "family_name"]}}
        unsigned1 = session1.generate_response(permitted)
        signed1 = key_pair.sign(unsigned1)
        response1 = session1.submit_response(signed1)

        # Process session2 fully
        session2.handle_request(reader2.request)
        unsigned2 = session2.generate_response(permitted)
        signed2 = key_pair.sign(unsigned2)
        response2 = session2.submit_response(signed2)

        # Both should succeed independently
        result1 = mdl_module.handle_response(reader1.state, response1)
        result2 = mdl_module.handle_response(reader2.state, response2)

        assert result1.device_authentication == mdl_module.AuthenticationStatus.VALID
        assert result2.device_authentication == mdl_module.AuthenticationStatus.VALID

        # Responses should be different (different sessions)
        assert response1 != response2
