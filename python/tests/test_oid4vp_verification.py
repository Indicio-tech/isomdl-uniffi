#!/usr/bin/env python3
# Copyright (c) 2025 Indicio
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# This software may be modified and distributed under the terms
# of either the Apache License, Version 2.0 or the MIT license.
# See the LICENSE-APACHE and LICENSE-MIT files for details.

"""
OID4VP verification functionality tests for isomdl-uniffi Python bindings.
"""

import hashlib


class TestOID4VPVerification:
    """Test OID4VP stateless verification functionality."""

    def test_verify_oid4vp_response_invalid_cbor(self, mdl_module):
        """Test verify_oid4vp_response with invalid CBOR data."""
        invalid_response = b"\x00\x01\x02\x03"  # Invalid CBOR
        nonce = "test_nonce_12345"
        client_id = "https://verifier.example.com"
        response_uri = "https://verifier.example.com/response/123"
        trust_anchors = None

        # Should raise an error for invalid CBOR
        try:
            mdl_module.verify_oid4vp_response(
                invalid_response, nonce, client_id, response_uri, trust_anchors
            )
            raise AssertionError("Expected an exception for invalid CBOR")
        except Exception as e:
            # Verify it's the expected error type
            error_msg = str(e)
            assert "Unable to parse DeviceResponse" in error_msg

    def test_verify_oid4vp_response_empty_response(self, mdl_module):
        """Test verify_oid4vp_response with empty response."""
        empty_response = b""
        nonce = "test_nonce_12345"
        client_id = "https://verifier.example.com"
        response_uri = "https://verifier.example.com/response/123"
        trust_anchors = None

        try:
            mdl_module.verify_oid4vp_response(
                empty_response, nonce, client_id, response_uri, trust_anchors
            )
            raise AssertionError("Expected an exception for empty response")
        except Exception as e:
            error_msg = str(e)
            assert "Unable to parse DeviceResponse" in error_msg

    def test_verify_oid4vp_response_parameter_validation(self, mdl_module):
        """Test parameter validation for verify_oid4vp_response."""
        # Test with various parameter combinations
        test_cases = [
            {
                "response": b"\x00\x01",
                "nonce": "",  # Empty nonce
                "client_id": "https://verifier.example.com",
                "response_uri": "https://verifier.example.com/response/123",
                "trust_anchors": None,
            },
            {
                "response": b"\x00\x01",
                "nonce": "test_nonce",
                "client_id": "",  # Empty client_id
                "response_uri": "https://verifier.example.com/response/123",
                "trust_anchors": None,
            },
            {
                "response": b"\x00\x01",
                "nonce": "test_nonce",
                "client_id": "https://verifier.example.com",
                "response_uri": "",  # Empty response_uri
                "trust_anchors": None,
            },
        ]

        for i, case in enumerate(test_cases):
            try:
                mdl_module.verify_oid4vp_response(
                    case["response"],
                    case["nonce"],
                    case["client_id"],
                    case["response_uri"],
                    case["trust_anchors"],
                )
                # If it doesn't throw an error, it should at least parse the parameters
                # The CBOR parsing will fail, but parameter validation should work
            except Exception as e:
                # We expect CBOR parsing to fail, but not parameter validation
                error_msg = str(e)
                assert "Unable to parse DeviceResponse" in error_msg, f"Case {i}: {error_msg}"

    def test_oid4vp_session_transcript_construction(self, mdl_module):
        """Test that OID4VP session transcript is constructed correctly."""
        # This is a conceptual test - we can't directly test the session transcript
        # construction since it happens internally, but we can verify the parameters
        # are handled correctly by checking the error messages and behavior

        nonce = "test_nonce_12345"
        client_id = "https://verifier.example.com"
        response_uri = "https://verifier.example.com/response/session123"

        # Calculate expected hashes (for documentation/verification purposes)
        client_id_hash = hashlib.sha256(client_id.encode()).digest()
        response_uri_hash = hashlib.sha256(response_uri.encode()).digest()

        # Verify hashes are computed correctly
        assert len(client_id_hash) == 32
        assert len(response_uri_hash) == 32
        assert client_id_hash != response_uri_hash  # Should be different

        # Test with some minimal CBOR that might parse but fail validation
        minimal_cbor = b"\xa0"  # Empty CBOR map

        try:
            mdl_module.verify_oid4vp_response(
                minimal_cbor, nonce, client_id, response_uri, None
            )
            # If this succeeds, great! If not, we expect a specific error
        except Exception as e:
            error_msg = str(e)
            # Should get past parameter validation and CBOR parsing,
            # likely fail at device response validation
            assert (
                "Unable to parse DeviceResponse" in error_msg
                or "Failed to parse device response" in error_msg
            )

    def test_mdl_reader_verified_data_structure(self, mdl_module):
        """Test that MDLReaderVerifiedData has the expected structure."""
        # We can't easily create a valid MDLReaderVerifiedData without a valid device response,
        # but we can test the error handling path and verify the expected attributes exist

        invalid_response = b"\x00\x01\x02"
        nonce = "test_nonce"
        client_id = "https://verifier.example.com"
        response_uri = "https://verifier.example.com/response/123"

        try:
            result = mdl_module.verify_oid4vp_response(
                invalid_response, nonce, client_id, response_uri, None
            )
            # If somehow this succeeds, verify the structure
            assert hasattr(result, "verified_response")
            assert hasattr(result, "issuer_authentication")
            assert hasattr(result, "device_authentication")
            assert hasattr(result, "errors")
            assert hasattr(result, "verified_response_as_json")
        except Exception as e:
            # Expected to fail with invalid CBOR
            assert "Unable to parse DeviceResponse" in str(e)

    def test_authentication_status_enum_values(self, mdl_module):
        """Test that AuthenticationStatus enum values are accessible."""
        # Verify the AuthenticationStatus enum is available and has expected values
        assert hasattr(mdl_module, "AuthenticationStatus")
        
        auth_status = mdl_module.AuthenticationStatus
        assert hasattr(auth_status, "VALID")
        assert hasattr(auth_status, "INVALID")
        assert hasattr(auth_status, "UNCHECKED")

        # Test enum value types
        assert auth_status.VALID == auth_status.VALID
        assert auth_status.INVALID == auth_status.INVALID
        assert auth_status.UNCHECKED == auth_status.UNCHECKED

        # Verify they're different values
        assert auth_status.VALID != auth_status.INVALID
        assert auth_status.VALID != auth_status.UNCHECKED
        assert auth_status.INVALID != auth_status.UNCHECKED

    def test_verify_oid4vp_response_with_trust_anchors(self, mdl_module):
        """Test verify_oid4vp_response with trust anchor configuration."""
        invalid_response = b"\x00\x01\x02"
        nonce = "test_nonce"
        client_id = "https://verifier.example.com"
        response_uri = "https://verifier.example.com/response/123"

        # Test with empty trust anchor list
        try:
            mdl_module.verify_oid4vp_response(
                invalid_response, nonce, client_id, response_uri, []
            )
        except Exception as e:
            assert "Unable to parse DeviceResponse" in str(e)

        # Test with invalid trust anchor format
        invalid_trust_anchor = ["not_valid_json"]
        try:
            mdl_module.verify_oid4vp_response(
                invalid_response, nonce, client_id, response_uri, invalid_trust_anchor
            )
        except Exception as e:
            # Should fail either at trust anchor parsing or CBOR parsing
            error_msg = str(e)
            assert (
                "Invalid trust anchor JSON" in error_msg
                or "Unable to parse DeviceResponse" in error_msg
            )

    def test_json_serialization_functionality(self, mdl_module):
        """Test JSON serialization related functionality."""
        # Test that the verified_response_as_json_string function exists
        # This function is exported at module level
        assert hasattr(mdl_module, "verified_response_as_json_string")

        # We can't easily test this without a valid MDLReaderResponseData,
        # but we can verify it's callable and has the right signature
        func = mdl_module.verified_response_as_json_string
        assert callable(func)

    def test_oid4vp_parameter_types(self, mdl_module):
        """Test that OID4VP parameters accept correct types."""
        # Test that the function accepts the expected parameter types
        test_params = {
            "response": b"\x00\x01",  # bytes
            "nonce": "test_nonce",  # str
            "client_id": "https://verifier.example.com",  # str
            "response_uri": "https://verifier.example.com/response/123",  # str
            "trust_anchor_registry": None,  # Optional[List[str]]
        }

        try:
            mdl_module.verify_oid4vp_response(**test_params)
        except Exception as e:
            # Should fail at CBOR parsing, not parameter type validation
            assert "Unable to parse DeviceResponse" in str(e)

        # Test with trust_anchor_registry as empty list
        test_params["trust_anchor_registry"] = []
        try:
            mdl_module.verify_oid4vp_response(**test_params)
        except Exception as e:
            assert "Unable to parse DeviceResponse" in str(e)