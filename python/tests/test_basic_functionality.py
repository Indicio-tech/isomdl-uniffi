#!/usr/bin/env python3
"""
Basic functionality tests for isomdl-uniffi Python bindings.
"""

import sys
import os


def run_tests(mdl):
    """
    Run basic functionality tests.

    Args:
        mdl: The isomdl_uniffi module

    Returns:
        bool: True if all tests pass, False otherwise.
    """

    try:
        # Test key pair generation first (required for test MDL)
        print("\n1. Testing key pair generation with validation:")
        key_pair = mdl.P256KeyPair()  # Constructor creates a new key pair

        # VALIDATE key pair
        assert key_pair is not None, "Key pair should not be None"
        assert hasattr(key_pair, "public_jwk"), "Key pair should have public_jwk method"
        assert hasattr(key_pair, "sign"), "Key pair should have sign method"

        print("   ✅ Key pair object validated")
        print(f"   Key pair type: {type(key_pair)}")

        # Test getting public key as JWK with validation
        public_jwk = key_pair.public_jwk()

        # VALIDATE public key JWK
        assert isinstance(public_jwk, str), "Public JWK should be a string"
        assert len(public_jwk) > 50, f"Public JWK too short: {len(public_jwk)}"
        assert len(public_jwk) < 1000, f"Public JWK too long: {len(public_jwk)}"

        # Validate it's valid JSON
        import json

        try:
            jwk_obj = json.loads(public_jwk)
            assert isinstance(jwk_obj, dict), "JWK should parse to a dict"
            assert "kty" in jwk_obj, "JWK should have key type (kty)"
            assert jwk_obj["kty"] == "EC", f"Expected EC key type, got {jwk_obj['kty']}"
            assert "crv" in jwk_obj, "JWK should have curve (crv)"
            assert (
                jwk_obj["crv"] == "P-256"
            ), f"Expected P-256 curve, got {jwk_obj['crv']}"
            assert "x" in jwk_obj, "JWK should have x coordinate"
            assert "y" in jwk_obj, "JWK should have y coordinate"
        except json.JSONDecodeError as e:
            raise AssertionError(f"Public JWK is not valid JSON: {e}")

        print(f"   ✅ Public key JWK validated, length: {len(public_jwk)} characters")

        # Test signing with key pair with validation
        test_message = b"Hello, isomdl!"
        signature = key_pair.sign(test_message)

        # VALIDATE signature
        assert isinstance(signature, bytes), "Signature should be bytes"
        assert len(signature) == 64, f"Expected 64-byte signature, got {len(signature)}"
        assert signature != test_message, "Signature should differ from message"

        # Test signing different messages produces different signatures
        test_message2 = b"Different message"
        signature2 = key_pair.sign(test_message2)
        assert (
            signature != signature2
        ), "Different messages should produce different signatures"

        print(f"   ✅ Signature generation validated, length: {len(signature)} bytes")

        print("\n2. Testing test MDL generation with validation:")
        test_mdl = mdl.generate_test_mdl(key_pair)  # Requires key_pair parameter

        # VALIDATE MDL object
        assert test_mdl is not None, "Generated MDL should not be None"
        assert hasattr(test_mdl, "doctype"), "MDL should have doctype method"
        assert hasattr(test_mdl, "id"), "MDL should have id method"
        assert hasattr(test_mdl, "key_alias"), "MDL should have key_alias method"
        assert hasattr(test_mdl, "details"), "MDL should have details method"

        print("   ✅ MDL object validated")
        print(f"   MDL type: {type(test_mdl)}")

        # Test getting document type with validation
        doc_type = test_mdl.doctype()
        assert isinstance(doc_type, str), "Document type should be a string"
        assert (
            doc_type == "org.iso.18013.5.1.mDL"
        ), f"Expected mDL doc type, got {doc_type}"

        print(f"   ✅ Document type validated: {doc_type}")

        # Test getting MDL ID with validation
        mdl_id = test_mdl.id()
        assert isinstance(mdl_id, str), "MDL ID should be a string"
        assert len(mdl_id) > 0, "MDL ID should not be empty"

        # Try to validate UUID format
        import uuid as uuid_module

        try:
            uuid_obj = uuid_module.UUID(mdl_id)
            assert str(uuid_obj) == mdl_id, "Invalid MDL ID UUID format"
            print(f"   ✅ MDL ID validated (UUID format): {mdl_id}")
        except ValueError:
            # Some IDs might not be UUIDs
            print(f"   ✅ MDL ID validated (custom format): {mdl_id}")

        # Test getting key alias with validation
        key_alias = test_mdl.key_alias()
        assert isinstance(key_alias, str), "Key alias should be a string"
        assert len(key_alias) > 0, "Key alias should not be empty"

        # Validate it's UUID format
        try:
            uuid_obj = uuid_module.UUID(key_alias)
            assert str(uuid_obj) == key_alias, "Invalid key alias UUID format"
        except ValueError:
            raise AssertionError(f"Key alias should be UUID format: {key_alias}")

        print(f"   ✅ Key alias validated: {key_alias}")

        print("\n3. Testing MDL details with comprehensive validation:")
        details = test_mdl.details()

        # VALIDATE details structure
        assert isinstance(details, dict), "Details should be a dictionary"
        assert len(details) > 0, "Details should not be empty"
        assert len(details) >= 1, "Should have at least one namespace"

        print(f"   ✅ Details structure validated, {len(details)} namespaces")

        # Validate required namespaces
        required_namespaces = ["org.iso.18013.5.1"]
        for namespace in required_namespaces:
            assert namespace in details, f"Missing required namespace: {namespace}"
            namespace_elements = details[namespace]
            assert isinstance(
                namespace_elements, list
            ), f"Namespace {namespace} should be a list"
            assert (
                len(namespace_elements) > 0
            ), f"Namespace {namespace} should not be empty"

        # Validate ISO namespace contents
        iso_elements = details["org.iso.18013.5.1"]

        # Convert to dict for easier validation
        iso_dict = {}
        for element in iso_elements:
            assert hasattr(element, "identifier"), "Element should have identifier"
            assert hasattr(element, "value"), "Element should have value"
            assert isinstance(
                element.identifier, str
            ), "Element identifier should be string"
            assert (
                element.value is not None
            ), f"Element {element.identifier} should have value"
            iso_dict[element.identifier] = element.value

        # Validate required attributes exist
        required_attrs = ["given_name", "family_name", "birth_date", "document_number"]

        for attr in required_attrs:
            assert attr in iso_dict, f"Missing required attribute: {attr}"
            value = iso_dict[attr]
            assert value is not None, f"Attribute {attr} should have a value"
            assert len(str(value)) > 0, f"Attribute {attr} should not be empty"

        # Validate some data types
        assert isinstance(iso_dict["given_name"], str), "given_name should be string"
        assert isinstance(iso_dict["family_name"], str), "family_name should be string"
        assert isinstance(
            iso_dict["document_number"], str
        ), "document_number should be string"

        print(f"   ✅ ISO namespace validated with {len(iso_elements)} attributes")

        # If AAMVA namespace exists, validate it too
        if "org.iso.18013.5.1.aamva" in details:
            aamva_elements = details["org.iso.18013.5.1.aamva"]
            assert isinstance(aamva_elements, list), "AAMVA namespace should be a list"
            assert len(aamva_elements) > 0, "AAMVA namespace should not be empty"

            # Validate structure of AAMVA elements
            for element in aamva_elements[:3]:  # Check first few elements
                assert hasattr(
                    element, "identifier"
                ), "AAMVA element should have identifier"
                assert hasattr(element, "value"), "AAMVA element should have value"

            print(
                f"   ✅ AAMVA namespace validated with {len(aamva_elements)} attributes"
            )

        for namespace, elements in details.items():
            print(f"   📋 Namespace '{namespace}': {len(elements)} elements")
            for element in elements[:2]:  # Show first 2 elements
                print(f"     - {element.identifier}: {element.value}")
            if len(elements) > 2:
                print(f"     ... and {len(elements) - 2} more")

        return True

    except (ValueError, RuntimeError, AttributeError, ImportError) as e:
        print(f"   ❌ Error in basic functionality tests: {e}")
        import traceback

        traceback.print_exc()
        return False


if __name__ == "__main__":
    # This allows running the test file directly for debugging
    try:
        # Add the project root to the path to import the generated bindings
        sys.path.insert(
            0, os.path.join(os.path.dirname(__file__), "..", "rust", "out", "python")
        )
        import isomdl_uniffi as mdl_module

        success = run_tests(mdl_module)
        sys.exit(0 if success else 1)
    except ImportError as e:
        print(f"❌ Could not import isomdl_uniffi: {e}")
        print("Please run './build-python-bindings.sh' first")
        sys.exit(1)
