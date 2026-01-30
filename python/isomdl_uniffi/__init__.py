# Copyright (c) 2025 Indicio
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# This software may be modified and distributed under the terms
# of either the Apache License, Version 2.0 or the MIT license.
# See the LICENSE-APACHE and LICENSE-MIT files for details.

"""
isomdl-uniffi: ISO 18013-5 mobile Driver License implementation with Python bindings

This package provides Python bindings for the Rust-based isomdl-uniffi library,
implementing the ISO 18013-5 standard for mobile Driver Licenses.
"""

__version__ = "0.1.0"

# Import the main module
try:
    from .isomdl_uniffi import *
except ImportError as e:
    raise ImportError(
        "Failed to import isomdl_uniffi bindings. "
        "This usually means the Rust library hasn't been built yet. "
        f"Please run './python/precommit/build-bindings.sh' first. "
        f"Original error: {e}"
    ) from e
