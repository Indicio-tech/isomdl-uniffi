#!/usr/bin/env python3
# Copyright (c) 2025 Indicio
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# This software may be modified and distributed under the terms
# of either the Apache License, Version 2.0 or the MIT license.
# See the LICENSE-APACHE and LICENSE-MIT files for details.
"""
Tests for PreparedMdoc.new_from_cbor through the Python bindings.

new_from_cbor takes each element value as CBOR bytes, so tagged dates, byte strings and
nested maps keep their CBOR types. The mdoc is signed outside the library, the way an
issuer with an HSM or a wallet-held key would sign it.
"""

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

PHOTO_ID_DOCTYPE = "org.iso.23220.photoid.1"

# Hand-encoded CBOR, so the tests need no CBOR library.
FAMILY_NAME = b"\x65Smith"  # tstr "Smith"
FULL_DATE = b"\xd9\x03\xec\x6a1990-04-01"  # 1004("1990-04-01")
BIRTH_DATE = (  # {"birth_date": 1004("1990-04-01"), "approximate_mask": "00000011"}
    b"\xa2" + b"\x6abirth_date" + FULL_DATE + b"\x70approximate_mask" + b"\x6800000011"
)
PORTRAIT = b"\x44\xff\xd8\xff\xe0"  # bstr, 4 bytes
AGE_OVER_18 = b"\xf5"  # true
PERSON_ID = b"\x6a1234567890"  # tstr "1234567890"

NAMESPACES = {
    "org.iso.23220.1": {
        "family_name": FAMILY_NAME,
        "birth_date": BIRTH_DATE,
        "portrait": PORTRAIT,
        "age_over_18": AGE_OVER_18,
    },
    "org.iso.23220.photoid.1": {"person_id": PERSON_ID},
}

STATUS = {"status_list": {"idx": 5, "uri": "https://example.com/statuslists/1"}}


@pytest.fixture
def document_signer():
    """A P-256 document signer key and its self-signed certificate as PEM."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Issuer")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return key, cert.public_bytes(serialization.Encoding.PEM).decode()


@pytest.fixture
def holder_jwk():
    """The public JWK of a fresh P-256 holder device key."""
    numbers = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()

    def b64url(n: int) -> str:
        return base64.urlsafe_b64encode(n.to_bytes(32, "big")).rstrip(b"=").decode()

    return json.dumps({"kty": "EC", "crv": "P-256", "x": b64url(numbers.x), "y": b64url(numbers.y)})


def raw_es256_signature(key, payload: bytes) -> bytes:
    """ECDSA P-256 with SHA-256 as raw r || s, the form ACA-Py's wallet.sign_message returns."""
    r, s = decode_dss_signature(key.sign(payload, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def rfc3339(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def issuer_signed_bytes(mdoc) -> bytes:
    encoded = mdoc.issuer_signed_b64()
    return base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))


def tstr(text: str) -> bytes:
    """``text`` as a CBOR text string; it must be shorter than 24 bytes."""
    data = text.encode()
    assert len(data) < 24
    return bytes([0x60 + len(data)]) + data


def encoded_element(identifier: str, value: bytes) -> bytes:
    """The end of an encoded IssuerSignedItem: its elementIdentifier, then its elementValue.

    Finding these bytes in IssuerSigned shows the value is carried for that element. The
    test values use preferred CBOR encoding, which re-encoding leaves unchanged.
    """
    return tstr("elementIdentifier") + tstr(identifier) + tstr("elementValue") + value


class TestNewFromCbor:
    """Issue an mdoc from CBOR element values and an external signature."""

    def test_issues_verifiable_mdoc(self, mdl_module, document_signer, holder_jwk):
        key, cert_pem = document_signer
        valid_until = datetime.now(timezone.utc) + timedelta(days=30)

        prepared = mdl_module.PreparedMdoc.new_from_cbor(
            PHOTO_ID_DOCTYPE,
            NAMESPACES,
            holder_jwk,
            "ES256",
            rfc3339(valid_until),
            status_list=json.dumps(STATUS),
        )
        signature = raw_es256_signature(key, prepared.signature_payload())
        mdoc = prepared.complete(cert_pem, signature)

        assert mdoc.doctype() == PHOTO_ID_DOCTYPE
        assert json.loads(mdoc.status_list()) == STATUS

        details = mdoc.details()
        assert set(details) == set(NAMESPACES)
        for namespace, elements in NAMESPACES.items():
            assert {e.identifier for e in details[namespace]} == set(elements)

        # Every element value is carried in IssuerSigned, with its CBOR type, for its element.
        raw = issuer_signed_bytes(mdoc)
        for elements in NAMESPACES.values():
            for identifier, value in elements.items():
                assert encoded_element(identifier, value) in raw, identifier

        result = mdoc.verify_issuer_signature(None, False)
        assert result.verified, result.error

    def test_survives_issuer_signed_round_trip(self, mdl_module, document_signer, holder_jwk):
        key, cert_pem = document_signer
        valid_until = datetime.now(timezone.utc) + timedelta(days=30)
        prepared = mdl_module.PreparedMdoc.new_from_cbor(
            PHOTO_ID_DOCTYPE, NAMESPACES, holder_jwk, "ES256", rfc3339(valid_until)
        )
        mdoc = prepared.complete(cert_pem, raw_es256_signature(key, prepared.signature_payload()))

        reparsed = mdl_module.Mdoc.new_from_base64url_encoded_issuer_signed(
            mdoc.issuer_signed_b64(), "reparsed"
        )
        assert reparsed.doctype() == PHOTO_ID_DOCTYPE
        assert set(reparsed.details()) == set(NAMESPACES)
        assert encoded_element("birth_date", BIRTH_DATE) in issuer_signed_bytes(reparsed)
        assert reparsed.status_list() is None


class TestNewFromCborErrors:
    """new_from_cbor refuses input it cannot turn into a valid MSO."""

    def prepare(self, mdl_module, holder_jwk, namespaces=NAMESPACES, valid_until=None):
        valid_until = valid_until or rfc3339(datetime.now(timezone.utc) + timedelta(days=30))
        return mdl_module.PreparedMdoc.new_from_cbor(
            PHOTO_ID_DOCTYPE, namespaces, holder_jwk, "ES256", valid_until
        )

    def test_rejects_invalid_cbor(self, mdl_module, holder_jwk):
        namespaces = {"org.iso.23220.1": {"family_name": b"\x65Smi"}}  # truncated text string
        with pytest.raises(mdl_module.MdocInitError) as excinfo:
            self.prepare(mdl_module, holder_jwk, namespaces)
        assert "family_name" in str(excinfo.value)
        assert "Smi" not in str(excinfo.value)

    def test_rejects_empty_namespaces(self, mdl_module, holder_jwk):
        with pytest.raises(mdl_module.MdocInitError):
            self.prepare(mdl_module, holder_jwk, {})
        with pytest.raises(mdl_module.MdocInitError):
            self.prepare(mdl_module, holder_jwk, {"org.iso.23220.1": {}})

    def test_rejects_valid_until_in_the_past(self, mdl_module, holder_jwk):
        with pytest.raises(mdl_module.MdocInitError):
            self.prepare(mdl_module, holder_jwk, valid_until="2000-01-01T00:00:00Z")

    def test_rejects_malformed_valid_until(self, mdl_module, holder_jwk):
        with pytest.raises(mdl_module.MdocInitError):
            self.prepare(mdl_module, holder_jwk, valid_until="next month")
