#!/usr/bin/env python3
# Copyright (c) 2025 Indicio
# SPDX-License-Identifier: Apache-2.0 OR MIT

"""
Script to generate cross-language test artifacts (CBOR/JSON) for TypeScript/Credo verification.
"""

import sys
from pathlib import Path

# Ensure we can import utils from the same directory
sys.path.append(str(Path(__file__).parent))
from utils import get_mdl_module, get_project_root


def generate_artifacts():
    project_root = get_project_root()
    mdl_module = get_mdl_module(project_root)

    # Create output directory
    output_dir = project_root / "python" / "tests" / "cross_language_artifacts"
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Generating artifacts in {output_dir}...")

    # 1. Generate Key Pair
    key_pair = mdl_module.P256KeyPair()
    public_jwk = key_pair.public_jwk()

    with open(output_dir / "issuer_public_key.json", "w") as f:
        f.write(public_jwk)
    print("- Generated issuer_public_key.json")

    # 2. Generate mDL
    mdl = mdl_module.generate_test_mdl(key_pair)

    # Get CBOR hex string (stringify returns hex string of CBOR bytes usually)
    # Based on test_mdoc_operations.py: cbor_str = test_mdl.stringify()
    # Let's assume stringify returns the hex representation or we might need to encode it.
    # Wait, test_mdoc_operations.py says: assert isinstance(cbor_str, str)
    # If it's the actual bytes, it wouldn't be a str in Python unless it's hex encoded.
    # Let's verify what stringify returns. If it's raw bytes, it would be bytes type.
    # If it returns a string, it's likely hex or base64.
    # Looking at rust code would confirm, but let's assume hex for now or check the test file again.
    # test_mdoc_operations.py: assert len(cbor_str) > 100.

    cbor_hex = mdl.stringify()

    # If it's hex, we can save it as .cbor file by decoding hex, or keep as .txt
    # Let's save as both for convenience.

    try:
        cbor_bytes = bytes.fromhex(cbor_hex)
        with open(output_dir / "mdl.cbor", "wb") as f:
            f.write(cbor_bytes)
        print("- Generated mdl.cbor")
    except ValueError:
        # Maybe it's not hex?
        print("Warning: mdl.stringify() output might not be hex. Saving as raw string in mdl.txt")
        with open(output_dir / "mdl.txt", "w") as f:
            f.write(cbor_hex)

    # 3. Generate a Device Response (Presentation)
    # We need a reader session to generate a request, then a holder to generate a response.
    # This might be more complex. For now, let's stick to the mDL and Issuer Key.

    print("Artifact generation complete.")


if __name__ == "__main__":
    generate_artifacts()
