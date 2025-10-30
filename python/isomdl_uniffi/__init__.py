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