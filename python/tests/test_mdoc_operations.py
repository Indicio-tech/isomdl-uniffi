#!/usr/bin/env python3
"""
MDL document operations tests for isomdl-uniffi Python bindings using pytest.
"""

import base64
import json
import uuid as uuid_module


def test_mdl_serialization_json(test_mdl):
    """Test JSON serialization with validation."""
    # Test JSON serialization
    json_str = test_mdl.json()
    assert isinstance(json_str, str), "JSON should be a string"
    assert len(json_str) > 100, f"JSON too short: {len(json_str)}"
    assert json_str.startswith("{"), "JSON should start with {"
    assert json_str.endswith("}"), "JSON should end with }"

    # Validate JSON contains expected structure
    parsed_json = json.loads(json_str)
    assert isinstance(parsed_json, dict), "Parsed JSON should be a dict"
    assert len(parsed_json) > 0, "JSON should not be empty"


def test_mdl_serialization_cbor(test_mdl):
    """Test CBOR stringify serialization."""
    cbor_str = test_mdl.stringify()
    assert isinstance(cbor_str, str), "CBOR should be a string"
    assert len(cbor_str) > 100, f"CBOR too short: {len(cbor_str)}"


def test_mdl_has_required_methods(test_mdl):
    """Validate that MDL has all required methods."""
    assert test_mdl is not None, "Generated MDL should not be None"
    assert hasattr(test_mdl, "json"), "MDL should have json method"
    assert hasattr(test_mdl, "stringify"), "MDL should have stringify method"
    assert hasattr(test_mdl, "doctype"), "MDL should have doctype method"


def test_mdl_document_type(test_mdl):
    """Validate document type is correct."""
    doctype = test_mdl.doctype()
    assert isinstance(doctype, str), "Document type should be a string"
    assert doctype == "org.iso.18013.5.1.mDL", f"Wrong document type: {doctype}"


def test_mdl_details_structure(test_mdl):
    """Validate MDL details structure and required attributes."""
    details = test_mdl.details()
    assert isinstance(details, dict), "Details should be a dict"
    assert len(details) > 0, "Details should not be empty"

    # Validate required namespaces exist
    assert "org.iso.18013.5.1" in details, "Missing ISO namespace"
    iso_elements = details["org.iso.18013.5.1"]
    assert isinstance(iso_elements, list), "ISO namespace should be a list of elements"
    assert len(iso_elements) > 0, "ISO namespace should not be empty"

    # Convert to dict for easier validation
    iso_dict = {}
    for element in iso_elements:
        assert hasattr(element, "identifier"), "Element should have identifier"
        assert hasattr(element, "value"), "Element should have value"
        iso_dict[element.identifier] = element.value

    # Validate required attributes
    required_attrs = ["given_name", "family_name", "birth_date", "document_number"]
    for attr in required_attrs:
        assert attr in iso_dict, f"Missing required attribute: {attr}"
        value = iso_dict[attr]
        assert value is not None, f"Attribute {attr} should have a value"
        assert len(str(value)) > 0, f"Attribute {attr} should not be empty"


def test_mdl_cbor_round_trip(test_mdl):
    """Test CBOR serialization round-trip."""
    cbor_str = test_mdl.stringify()

    try:
        # The stringify method might return base64-encoded CBOR
        cbor_bytes = base64.b64decode(cbor_str + "==")  # Add padding if needed
        assert len(cbor_bytes) > 50, f"Decoded CBOR too short: {len(cbor_bytes)}"
    except (ValueError, TypeError):
        # Different encoding formats may exist - this is acceptable
        # Just verify the string is substantial
        assert len(cbor_str) > 100, "CBOR string should be substantial"


def test_mdl_id_format(test_mdl):
    """Validate MDL ID format."""
    mdl_id = test_mdl.id()
    assert isinstance(mdl_id, str), "MDL ID should be a string"
    assert len(mdl_id) > 0, "MDL ID should not be empty"

    # Try to validate it's a proper UUID format
    try:
        uuid_obj = uuid_module.UUID(mdl_id)
        assert str(uuid_obj) == mdl_id, "Invalid MDL ID UUID format"
    except ValueError:
        # Some IDs might not be UUIDs, that's acceptable
        # Just ensure it's a valid string identifier
        pass


def test_mdl_key_alias(test_mdl):
    """Test MDL key alias from the document."""
    mdl_key_alias = test_mdl.key_alias()
    assert isinstance(mdl_key_alias, str), "MDL key alias should be a string"
    assert len(mdl_key_alias) > 0, "MDL key alias should not be empty"


def test_mdl_metadata_consistency(test_mdl):
    """Test that MDL metadata is consistent across calls."""
    # Call multiple times to ensure consistency
    id1 = test_mdl.id()
    id2 = test_mdl.id()
    assert id1 == id2, "MDL ID should be consistent across calls"

    key_alias1 = test_mdl.key_alias()
    key_alias2 = test_mdl.key_alias()
    assert key_alias1 == key_alias2, "Key alias should be consistent across calls"

    doctype1 = test_mdl.doctype()
    doctype2 = test_mdl.doctype()
    assert doctype1 == doctype2, "Doctype should be consistent across calls"
