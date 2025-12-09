import json

import pytest


@pytest.mark.cross_language
class TestCrossLanguageVerification:
    # @pytest.mark.xfail(reason="CBOR encoding mismatch between Node.js and Rust")
    def test_verify_credo_generated_device_response(self, mdl_module, project_root):
        artifacts_dir = project_root / "python" / "tests" / "cross_language_artifacts"

        if not artifacts_dir.exists():
            pytest.skip(f"Artifacts directory not found: {artifacts_dir}")

        required_files = ["device_response.cbor", "issuer_cert.pem", "oid4vp_params.json"]
        missing_files = [f for f in required_files if not (artifacts_dir / f).exists()]
        if missing_files:
            pytest.skip(
                f"Missing artifacts: {missing_files}. Run TypeScript tests to generate them."
            )

        # Load artifacts
        with open(artifacts_dir / "device_response.cbor", "rb") as f:
            device_response_bytes = f.read()

        with open(artifacts_dir / "issuer_cert.pem") as f:
            issuer_cert_pem = f.read()

        with open(artifacts_dir / "oid4vp_params.json") as f:
            params = json.load(f)

        nonce = params["nonce"]
        client_id = params["clientId"]
        response_uri = params["responseUri"]

        # Verify using isomdl
        # trust_anchor_registry expects a list of strings (JSON strings of PemTrustAnchor)
        trust_anchor = {"certificate_pem": issuer_cert_pem, "purpose": "Iaca"}
        trust_anchors = [json.dumps(trust_anchor)]

        print(f"Verifying DeviceResponse ({len(device_response_bytes)} bytes)...")

        verified_data = mdl_module.verify_oid4vp_response(
            device_response_bytes,
            nonce,
            client_id,
            response_uri,
            trust_anchors,
            False,  # use_intermediate_chaining
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

    # @pytest.mark.skip(reason="Fails in pre-commit environment (Python 3.14) with signature error")
    def test_verify_credo_oid4vp_compatibility(self, mdl_module, project_root):
        artifacts_dir = project_root / "python" / "tests" / "cross_language_artifacts"

        if not artifacts_dir.exists():
            pytest.skip(f"Artifacts directory not found: {artifacts_dir}")

        required_files = [
            "credo_oid4vp_device_response.cbor",
            "credo_oid4vp_issuer_cert.pem",
            "credo_oid4vp_params.json",
        ]
        missing_files = [f for f in required_files if not (artifacts_dir / f).exists()]
        if missing_files:
            pytest.skip(
                f"Missing artifacts: {missing_files}. Run TypeScript tests to generate them."
            )

        # Load artifacts
        with open(artifacts_dir / "credo_oid4vp_device_response.cbor", "rb") as f:
            device_response_bytes = f.read()

        with open(artifacts_dir / "credo_oid4vp_issuer_cert.pem") as f:
            issuer_cert_pem = f.read()

        with open(artifacts_dir / "credo_oid4vp_params.json") as f:
            params = json.load(f)

        nonce = params["nonce"]
        client_id = params["clientId"]
        response_uri = params["responseUri"]

        trust_anchor = {"certificate_pem": issuer_cert_pem, "purpose": "Iaca"}
        trust_anchors = [json.dumps(trust_anchor)]

        print(f"Verifying Credo OID4VP DeviceResponse ({len(device_response_bytes)} bytes)...")

        verified_data = mdl_module.verify_oid4vp_response(
            device_response_bytes, nonce, client_id, response_uri, trust_anchors, False
        )

        assert verified_data.issuer_authentication == mdl_module.AuthenticationStatus.VALID
        assert verified_data.device_authentication == mdl_module.AuthenticationStatus.VALID

        namespaces = verified_data.verified_response
        assert "org.iso.18013.5.1" in namespaces
        family_name_item = namespaces["org.iso.18013.5.1"]["family_name"]
        assert family_name_item[0] == "Doe"
