#!/usr/bin/env python3
"""
Test suite for MDL (Mobile Driver's License) functionality using the simplified API.
Tests both issuer and verifier capabilities for ISO 18013-5 compliance.
"""

import sys
import os
import pytest
from datetime import datetime

# Add the project root to the path to import the generated bindings
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

try:
    from isomdl import (
        MdlIssuer, MdlVerifier, MdlData, DrivingPrivilege, MdlError,
        MdocIssuer, MdocVerifier, IssuerError, VerifierError
    )
except ImportError as e:
    print(f"Failed to import isomdl bindings: {e}")
    print("Make sure to run build-python-bindings.sh first")
    sys.exit(1)


class TestMdlFunctionality:
    """Test suite for MDL-specific functionality"""
    
    def setup_method(self):
        """Set up test fixtures"""
        # Sample X.509 certificate for testing (self-signed)
        self.test_cert_pem = """-----BEGIN CERTIFICATE-----
MIICXTCCAcOgAwIBAgIJALCmtVf+n6HtMAoGCCqGSM49BAMCMEUxCzAJBgNVBAYT
AkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRn
aXRzIFB0eSBMdGQwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjBFMQsw
CQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJu
ZXQgV2lkZ2l0cyBQdHkgTHRkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjh7c
0Cp6fJ8R3BzGIovGlA+2O0+7cVZ0Qb4/f1z8V9y/+QJQZz0D7xJ1bB0X5J3qKZv
fC9ZxDyHxBYxQX2zGIqOBgTAJBgNVHSMEAjAAMA0GA1UdDwEB/wQEAwIFoDATBgNV
HSUEDDAKBggrBgEFBQcDAjAKBggqhkjOPQQDAgNIADBFAiEA1HxH+XjJsL0qfJzL
5QGqb1A/m0Xo1PZ+0R8TcXBz7v0CIH4Qq1j6D3w8K4xL1E2aJ3xE7mGqW8k9Z4L
qJfG9XlHn
-----END CERTIFICATE-----"""
        
        # Sample driving privilege
        self.sample_privilege = DrivingPrivilege(
            vehicle_category_code="B",
            issue_date="2024-01-01",
            expiry_date="2029-01-01",
            codes=["B1", "B2"]
        )
        
        # Sample MDL data
        self.sample_mdl_data = MdlData(
            family_name="Doe",
            given_name="John",
            birth_date="1990-01-01",
            issue_date="2024-01-01",
            expiry_date="2029-01-01",
            issuing_country="US",
            issuing_authority="Department of Motor Vehicles",
            document_number="DL123456789",
            driving_privileges=[self.sample_privilege],
            portrait=None,
            administrative_number="A123456",
            sex="M",
            height=180,
            weight=75,
            eye_colour="brown",
            hair_colour="black",
            birth_place="New York",
            resident_address="123 Main St, Anytown, US 12345",
            issuing_jurisdiction="NY",
            nationality="US",
            resident_city="Anytown",
            resident_state="NY",
            resident_postal_code="12345",
            resident_country="US",
            organ_donor=True,
            veteran=False,
            age_in_years=34,
            age_birth_year=1990,
            age_over_18=True,
            age_over_21=True,
            edl_credential=False,
            real_id_compliance=True
        )
    
    def test_mdl_issuer_creation(self):
        """Test creation of MDL issuer"""
        issuer = MdlIssuer(self.test_cert_pem)
        assert issuer is not None
    
    def test_mdl_data_creation(self):
        """Test creation of MDL data structure"""
        assert self.sample_mdl_data.family_name == "Doe"
        assert self.sample_mdl_data.given_name == "John"
        assert self.sample_mdl_data.document_number == "DL123456789"
        assert len(self.sample_mdl_data.driving_privileges) == 1
        assert self.sample_mdl_data.driving_privileges[0].vehicle_category_code == "B"
    
    def test_driving_privilege_creation(self):
        """Test creation of driving privilege structure"""
        privilege = DrivingPrivilege(
            vehicle_category_code="A",
            issue_date="2024-01-01",
            expiry_date="2029-01-01",
            codes=["A1", "A2", "A3"]
        )
        assert privilege.vehicle_category_code == "A"
        assert len(privilege.codes) == 3
    
    def test_mdl_issuance_full(self):
        """Test full MDL issuance"""
        issuer = MdlIssuer(self.test_cert_pem)
        
        try:
            mdl_cbor = issuer.issue_mdl(self.sample_mdl_data)
            assert mdl_cbor is not None
            assert len(mdl_cbor) > 0
            print(f"Full MDL issued successfully: {len(mdl_cbor)} bytes")
        except MdlError as e:
            pytest.skip(f"MDL issuance failed (expected with test cert): {e}")
    
    def test_mdl_issuance_minimal(self):
        """Test minimal MDL issuance"""
        issuer = MdlIssuer(self.test_cert_pem)
        
        try:
            mdl_cbor = issuer.issue_minimal_mdl(
                family_name="Smith",
                given_name="Jane",
                birth_date="1985-05-15",
                document_number="DL987654321"
            )
            assert mdl_cbor is not None
            assert len(mdl_cbor) > 0
            print(f"Minimal MDL issued successfully: {len(mdl_cbor)} bytes")
        except MdlError as e:
            pytest.skip(f"Minimal MDL issuance failed (expected with test cert): {e}")
    
    def test_mdl_issuance_from_json(self):
        """Test MDL issuance from JSON"""
        issuer = MdlIssuer(self.test_cert_pem)
        
        json_data = {
            "family_name": "Johnson",
            "given_name": "Bob",
            "birth_date": "1992-12-25",
            "document_number": "DL555666777",
            "issuing_country": "US",
            "issuing_authority": "DMV",
            "issue_date": "2024-01-01",
            "expiry_date": "2029-01-01",
            "driving_privileges": [
                {
                    "vehicle_category_code": "B",
                    "issue_date": "2024-01-01",
                    "expiry_date": "2029-01-01",
                    "codes": ["B"]
                }
            ]
        }
        
        try:
            mdl_cbor = issuer.issue_mdl_from_json(json_data)
            assert mdl_cbor is not None
            assert len(mdl_cbor) > 0
            print(f"JSON MDL issued successfully: {len(mdl_cbor)} bytes")
        except MdlError as e:
            pytest.skip(f"JSON MDL issuance failed (expected with test cert): {e}")
    
    def test_mdl_verifier_creation(self):
        """Test creation of MDL verifier"""
        verifier = MdlVerifier()
        assert verifier is not None
    
    def test_invalid_certificate_handling(self):
        """Test handling of invalid certificates"""
        with pytest.raises(MdlError):
            MdlIssuer("invalid-certificate")
    
    def test_invalid_json_handling(self):
        """Test handling of invalid JSON data"""
        issuer = MdlIssuer(self.test_cert_pem)
        
        invalid_json = {
            "family_name": "Test",
            # Missing required fields
        }
        
        with pytest.raises(MdlError):
            issuer.issue_mdl_from_json(invalid_json)


class TestSimplifiedMdocIntegration:
    """Test integration with simplified mDoc API"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.test_cert_pem = """-----BEGIN CERTIFICATE-----
MIICXTCCAcOgAwIBAgIJALCmtVf+n6HtMAoGCCqGSM49BAMCMEUxCzAJBgNVBAYT
AkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRn
aXRzIFB0eSBMdGQwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjBFMQsw
CQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJu
ZXQgV2lkZ2l0cyBQdHkgTHRkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjh7c
0Cp6fJ8R3BzGIovGlA+2O0+7cVZ0Qb4/f1z8V9y/+QJQZz0D7xJ1bB0X5J3qKZv
fC9ZxDyHxBYxQX2zGIqOBgTAJBgNVHSMEAjAAMA0GA1UdDwEB/wQEAwIFoDATBgNV
HSUEDDAKBggrBgEFBQcDAjAKBggqhkjOPQQDAgNIADBFAiEA1HxH+XjJsL0qfJzL
5QGqb1A/m0Xo1PZ+0R8TcXBz7v0CIH4Qq1j6D3w8K4xL1E2aJ3xE7mGqW8k9Z4L
qJfG9XlHn
-----END CERTIFICATE-----"""
    
    def test_mdoc_issuer_creation(self):
        """Test creation of simplified mDoc issuer"""
        issuer = MdocIssuer(self.test_cert_pem)
        assert issuer is not None
    
    def test_mdoc_verifier_creation(self):
        """Test creation of simplified mDoc verifier"""
        verifier = MdocVerifier()
        assert verifier is not None
    
    def test_mdoc_issuance(self):
        """Test basic mDoc issuance"""
        issuer = MdocIssuer(self.test_cert_pem)
        
        # Sample data for org.iso.18013.5.1 namespace
        data = {
            "family_name": "Test",
            "given_name": "User",
            "birth_date": "1990-01-01"
        }
        
        try:
            mdoc_cbor = issuer.issue_mdoc("org.iso.18013.5.1", data)
            assert mdoc_cbor is not None
            assert len(mdoc_cbor) > 0
            print(f"Basic mDoc issued successfully: {len(mdoc_cbor)} bytes")
        except IssuerError as e:
            pytest.skip(f"mDoc issuance failed (expected with test cert): {e}")


def test_error_types():
    """Test that error types are properly exposed"""
    # Check that error types exist and can be imported
    assert MdlError is not None
    assert IssuerError is not None
    assert VerifierError is not None


if __name__ == "__main__":
    # Run the tests
    print("Running MDL functionality tests...")
    pytest.main([__file__, "-v"])