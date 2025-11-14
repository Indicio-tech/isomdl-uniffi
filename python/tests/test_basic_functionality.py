#!/usr/bin/env python3
# Copyright (c) 2025 Indicio
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# This software may be modified and distributed under the terms
# of either the Apache License, Version 2.0 or the MIT license.
# See the LICENSE-APACHE and LICENSE-MIT files for details.

"""
Basic functionality tests for isomdl-uniffi Python bindings using pytest.
"""

import json
import uuid as uuid_module


class TestKeyPairOperations:
    """Test key pair generation and operations."""

    def test_key_pair_creation(self, mdl_module):
        """Test that we can create a P256KeyPair."""
        key_pair = mdl_module.P256KeyPair()

        assert key_pair is not None
        assert hasattr(key_pair, "public_jwk")
        assert hasattr(key_pair, "sign")

    def test_public_key_jwk_format(self, key_pair):
        """Test that public key JWK is properly formatted."""
        public_jwk = key_pair.public_jwk()

        # Basic format validation
        assert isinstance(public_jwk, str)
        assert 50 < len(public_jwk) < 1000

        # JSON validation
        jwk_obj = json.loads(public_jwk)
        assert isinstance(jwk_obj, dict)
        assert jwk_obj["kty"] == "EC"
        assert jwk_obj["crv"] == "P-256"
        assert "x" in jwk_obj
        assert "y" in jwk_obj

    def test_message_signing(self, key_pair):
        """Test that we can sign messages."""
        test_message = b"Hello, isomdl!"
        signature = key_pair.sign(test_message)

        assert isinstance(signature, bytes)
        assert len(signature) == 64
        assert signature != test_message

        # Test signing different messages produces different signatures
        test_message2 = b"Different message"
        signature2 = key_pair.sign(test_message2)
        assert signature != signature2


class TestMDLGeneration:
    """Test MDL document generation."""

    def test_test_mdl_generation(self, mdl_module, key_pair):
        """Test that we can generate a test MDL."""
        test_mdl = mdl_module.generate_test_mdl(key_pair)

        assert test_mdl is not None
        assert hasattr(test_mdl, "doctype")
        assert hasattr(test_mdl, "id")
        assert hasattr(test_mdl, "key_alias")
        assert hasattr(test_mdl, "details")

    def test_mdl_document_type(self, test_mdl):
        """Test that MDL has correct document type."""
        doc_type = test_mdl.doctype()
        assert isinstance(doc_type, str)
        assert doc_type == "org.iso.18013.5.1.mDL"

    def test_mdl_id_format(self, test_mdl):
        """Test that MDL ID is properly formatted."""
        mdl_id = test_mdl.id()
        assert isinstance(mdl_id, str)
        assert len(mdl_id) > 0

        # Try to validate UUID format (may be custom format)
        try:
            uuid_obj = uuid_module.UUID(mdl_id)
            assert str(uuid_obj) == mdl_id
        except ValueError:
            # Some IDs might not be UUIDs, which is acceptable
            pass

    def test_key_alias_format(self, test_mdl):
        """Test that key alias is UUID formatted."""
        key_alias = test_mdl.key_alias()
        assert isinstance(key_alias, str)
        assert len(key_alias) > 0

        # Key alias should be UUID format
        uuid_obj = uuid_module.UUID(key_alias)
        assert str(uuid_obj) == key_alias


class TestMDLDetails:
    """Test MDL details and attributes."""

    def test_details_structure(self, test_mdl):
        """Test that MDL details have proper structure."""
        details = test_mdl.details()

        assert isinstance(details, dict)
        assert len(details) >= 1

    def test_iso_namespace_exists(self, test_mdl):
        """Test that required ISO namespace exists."""
        details = test_mdl.details()

        required_namespace = "org.iso.18013.5.1"
        assert required_namespace in details

        namespace_elements = details[required_namespace]
        assert isinstance(namespace_elements, list)
        assert len(namespace_elements) > 0

    def test_iso_namespace_attributes(self, test_mdl):
        """Test that ISO namespace has required attributes."""
        details = test_mdl.details()
        iso_elements = details["org.iso.18013.5.1"]

        # Convert to dict for easier validation
        iso_dict = {}
        for element in iso_elements:
            assert hasattr(element, "identifier")
            assert hasattr(element, "value")
            assert isinstance(element.identifier, str)
            assert element.value is not None
            iso_dict[element.identifier] = element.value

        # Validate required attributes exist
        required_attrs = ["given_name", "family_name", "birth_date", "document_number"]
        for attr in required_attrs:
            assert attr in iso_dict
            assert iso_dict[attr] is not None
            assert len(str(iso_dict[attr])) > 0

        # Validate data types
        assert isinstance(iso_dict["given_name"], str)
        assert isinstance(iso_dict["family_name"], str)
        assert isinstance(iso_dict["document_number"], str)

    def test_aamva_namespace_optional(self, test_mdl):
        """Test that AAMVA namespace is properly structured if present."""
        details = test_mdl.details()

        if "org.iso.18013.5.1.aamva" in details:
            aamva_elements = details["org.iso.18013.5.1.aamva"]
            assert isinstance(aamva_elements, list)
            assert len(aamva_elements) > 0

            # Validate structure of first few elements
            for element in aamva_elements[:3]:
                assert hasattr(element, "identifier")
                assert hasattr(element, "value")


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
