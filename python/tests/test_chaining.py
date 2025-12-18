import base64
import datetime
import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from isomdl_uniffi import Mdoc, MdocVerificationError


def generate_key():
    return ec.generate_private_key(ec.SECP256R1())


def key_to_pem(key):
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


def cert_to_pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def generate_cert(subject_key, issuer_key, subject_name, issuer_name, is_ca=False):
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject_name)
    builder = builder.issuer_name(issuer_name)
    builder = builder.not_valid_before(datetime.datetime.now(datetime.UTC))
    builder = builder.not_valid_after(
        datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=30)
    )
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(subject_key.public_key())

    if is_ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=0), critical=True
        )
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        # Add required extensions for mDL IACA profile
        builder = builder.add_extension(
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier("https://example.com/crl")],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ]
            ),
            critical=False,
        )
        builder = builder.add_extension(
            x509.IssuerAlternativeName([x509.RFC822Name("ca@example.com")]), critical=False
        )

    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()),
        critical=False,
    )
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
        critical=False,
    )

    cert = builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())
    return cert


def generate_jwk(key):
    numbers = key.public_key().public_numbers()
    x = numbers.x.to_bytes(32, byteorder="big")
    y = numbers.y.to_bytes(32, byteorder="big")

    return json.dumps(
        {
            "kty": "EC",
            "crv": "P-256",
            "x": base64.urlsafe_b64encode(x).decode("utf-8").rstrip("="),
            "y": base64.urlsafe_b64encode(y).decode("utf-8").rstrip("="),
        }
    )


def test_verify_issuer_signature_chaining():
    # 1. Generate Root CA
    root_key = generate_key()
    root_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Root CA"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "NY"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SpruceID"),
        ]
    )
    root_cert = generate_cert(root_key, root_key, root_name, root_name, is_ca=True)
    root_cert_pem = cert_to_pem(root_cert)

    # 2. Generate Intermediate CA
    intermediate_key = generate_key()
    intermediate_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Intermediate CA"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "NY"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SpruceID"),
        ]
    )
    intermediate_cert = generate_cert(
        intermediate_key, root_key, intermediate_name, root_name, is_ca=True
    )
    intermediate_cert_pem = cert_to_pem(intermediate_cert)
    intermediate_key_pem = key_to_pem(intermediate_key)

    # 3. Generate Holder Key
    holder_key = generate_key()
    holder_jwk = generate_jwk(holder_key)

    # 4. Sample Data
    mdl_items = json.dumps(
        {
            "family_name": "Doe",
            "given_name": "Jane",
            "birth_date": "1992-01-01",
            "issue_date": "2023-01-01",
            "expiry_date": "2028-01-01",
            "issuing_country": "US",
            "issuing_authority": "DMV",
            "document_number": "987654321",
            "portrait": "SGVsbG8gV29ybGQ=",
            "driving_privileges": [],
            "un_distinguishing_sign": "USA",
        }
    )

    # 5. Create mdoc signed by Intermediate CA
    mdoc = Mdoc.create_and_sign_mdl(
        mdl_items, None, holder_jwk, intermediate_cert_pem, intermediate_key_pem
    )

    # 6. Verify with Root CA as trust anchor

    # Case A: Chaining Disabled (Default) - Should Fail
    try:
        mdoc.verify_issuer_signature([root_cert_pem], False)
        pytest.fail("Verification should fail when chaining is disabled")
    except MdocVerificationError:
        pass  # Expected

    # Case B: Chaining Enabled - Should Succeed
    result = mdoc.verify_issuer_signature([root_cert_pem], True)
    assert result.verified
    assert result.common_name == "SpruceID Test DS"
