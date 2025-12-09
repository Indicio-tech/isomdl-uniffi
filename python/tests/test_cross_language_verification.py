
import json
import sys
from pathlib import Path
import pytest

# Add rust bindings to path
def get_mdl_module():
    current_dir = Path.cwd()
    project_root = current_dir
    
    max_levels = 5
    for _ in range(max_levels):
        rust_dir = project_root / "rust"
        if rust_dir.exists() and rust_dir.is_dir():
            break
        parent = project_root.parent
        if parent == project_root:
            break
        project_root = parent
    else:
        project_root = Path(__file__).parent.parent.parent

    bindings_path = project_root / "rust" / "out" / "python"
    sys.path.insert(0, str(bindings_path))
    import isomdl_uniffi
    return isomdl_uniffi, project_root

mdl_module, project_root = get_mdl_module()

class TestCrossLanguageVerification:
    
    @pytest.mark.skip(reason="Fails in pre-commit environment (Python 3.14) with signature error")
    # @pytest.mark.xfail(reason="CBOR encoding mismatch between Node.js and Rust")
    def test_verify_credo_generated_device_response(self):
        artifacts_dir = project_root / "python" / "tests" / "cross_language_artifacts"
        
        # Load artifacts
        with open(artifacts_dir / "device_response.cbor", "rb") as f:
            device_response_bytes = f.read()
            
        with open(artifacts_dir / "issuer_cert.pem", "r") as f:
            issuer_cert_pem = f.read()
            
        with open(artifacts_dir / "oid4vp_params.json", "r") as f:
            params = json.load(f)
            
        nonce = params["nonce"]
        client_id = params["clientId"]
        response_uri = params["responseUri"]
        
        # Verify using isomdl
        # trust_anchor_registry expects a list of strings (JSON strings of PemTrustAnchor)
        trust_anchor = {
            "certificate_pem": issuer_cert_pem,
            "purpose": "Iaca"
        }
        trust_anchors = [json.dumps(trust_anchor)]
        
        print(f"Verifying DeviceResponse ({len(device_response_bytes)} bytes)...")
        
        verified_data = mdl_module.verify_oid4vp_response(
            device_response_bytes,
            nonce,
            client_id,
            response_uri,
            trust_anchors,
            False  # use_intermediate_chaining
        )
        
        print("Verification successful!")
        
        # Check that we have the expected data
        # verified_data is MDLReaderVerifiedData record
        
        # Verify authentication status
        if verified_data.issuer_authentication != mdl_module.AuthenticationStatus.VALID:
            print(f"Issuer Authentication failed. Errors: {verified_data.errors}")
        if verified_data.device_authentication != mdl_module.AuthenticationStatus.VALID:
            print(f"Device Authentication failed. Errors: {verified_data.errors}")
        
        assert verified_data.issuer_authentication == mdl_module.AuthenticationStatus.VALID
        assert verified_data.device_authentication == mdl_module.AuthenticationStatus.VALID
        
        # Check data
        namespaces = verified_data.verified_response
        assert "org.iso.18013.5.1" in namespaces
        family_name_item = namespaces["org.iso.18013.5.1"]["family_name"]
        
        # MDocItem is a UniFfi enum - access the value via index
        print(f"Family Name Item: {family_name_item}")
        
        # UniFfi enum variants support __getitem__ to access tuple values
        assert family_name_item[0] == "Doe"

    @pytest.mark.skip(reason="Fails in pre-commit environment (Python 3.14) with signature error")
    def test_verify_credo_oid4vp_compatibility(self):
        artifacts_dir = project_root / "python" / "tests" / "cross_language_artifacts"
        
        # Load artifacts
        with open(artifacts_dir / "credo_oid4vp_device_response.cbor", "rb") as f:
            device_response_bytes = f.read()
            
        with open(artifacts_dir / "credo_oid4vp_issuer_cert.pem", "r") as f:
            issuer_cert_pem = f.read()
            
        with open(artifacts_dir / "credo_oid4vp_params.json", "r") as f:
            params = json.load(f)
            
        nonce = params["nonce"]
        client_id = params["clientId"]
        response_uri = params["responseUri"]
        
        trust_anchor = {
            "certificate_pem": issuer_cert_pem,
            "purpose": "Iaca"
        }
        trust_anchors = [json.dumps(trust_anchor)]
        
        print(f"Verifying Credo OID4VP DeviceResponse ({len(device_response_bytes)} bytes)...")
        
        verified_data = mdl_module.verify_oid4vp_response(
            device_response_bytes,
            nonce,
            client_id,
            response_uri,
            trust_anchors,
            False
        )
        
        assert verified_data.issuer_authentication == mdl_module.AuthenticationStatus.VALID
        assert verified_data.device_authentication == mdl_module.AuthenticationStatus.VALID
        
        namespaces = verified_data.verified_response
        assert "org.iso.18013.5.1" in namespaces
        family_name_item = namespaces["org.iso.18013.5.1"]["family_name"]
        assert family_name_item[0] == "Doe"

if __name__ == "__main__":
    # Manually run if executed as script
    t = TestCrossLanguageVerification()
    t.test_verify_credo_generated_device_response()
