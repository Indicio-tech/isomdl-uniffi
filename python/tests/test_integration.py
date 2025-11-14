#!/usr/bin/env python3
# Copyright (c) 2025 Indicio
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# This software may be modified and distributed under the terms
# of either the Apache License, Version 2.0 or the MIT license.
# See the LICENSE-APACHE and LICENSE-MIT files for details.

"""
Integration tests for isomdl-uniffi Python bindings using pytest.
"""


def test_imports(mdl_module):
    """Test that all required modules can be imported"""
    # Test that imports work
    _ = mdl_module.Mdoc, mdl_module.MdlPresentationSession, mdl_module.P256KeyPair
    _ = mdl_module.establish_session, mdl_module.handle_response, mdl_module.generate_test_mdl
    _ = mdl_module.AuthenticationStatus


def test_mdl_basic(mdl_module):
    """Test basic MDL functionality"""
    key_pair = mdl_module.P256KeyPair()
    assert key_pair is not None

    test_mdl = mdl_module.generate_test_mdl(key_pair)
    assert test_mdl is not None

    doc_type = test_mdl.doctype()
    assert doc_type == "org.iso.18013.5.1.mDL"
