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

import importlib.util
import os
import sys

_imported = False
_import_error = None

# The wheel structure has both:
# - isomdl_uniffi/isomdl_uniffi.py (the Python bindings)
# - isomdl_uniffi/isomdl_uniffi/ (directory containing the .so)
# Python prefers packages over modules, so we must explicitly load the .py file.
# Additionally, the generated bindings look for the .so next to the .py file,
# but it's in the subdirectory. We symlink it before loading.

_module_dir = os.path.dirname(os.path.abspath(__file__))
_bindings_path = os.path.join(_module_dir, "isomdl_uniffi.py")

# Ensure the native library is findable next to isomdl_uniffi.py
# The .so is in isomdl_uniffi/isomdl_uniffi/ but the .py expects it in isomdl_uniffi/
_lib_extensions = {
    "darwin": "libisomdl_uniffi.dylib",
    "win32": "isomdl_uniffi.dll",
}
_lib_name = _lib_extensions.get(sys.platform, "libisomdl_uniffi.so")
_lib_nested = os.path.join(_module_dir, "isomdl_uniffi", _lib_name)
_lib_target = os.path.join(_module_dir, _lib_name)

if os.path.exists(_lib_nested) and not os.path.exists(_lib_target):
    try:
        os.symlink(_lib_nested, _lib_target)
    except OSError:
        # Fallback: copy the file if symlinks are not supported
        import shutil

        shutil.copy2(_lib_nested, _lib_target)

if os.path.exists(_bindings_path):
    try:
        spec = importlib.util.spec_from_file_location(
            "_isomdl_uniffi_bindings", _bindings_path
        )
        if spec and spec.loader:
            _bindings_module = importlib.util.module_from_spec(spec)
            sys.modules["_isomdl_uniffi_bindings"] = _bindings_module
            spec.loader.exec_module(_bindings_module)
            # Export everything from the bindings module
            _all_exports = getattr(_bindings_module, "__all__", [])
            for _name in _all_exports:
                globals()[_name] = getattr(_bindings_module, _name)
            _imported = True
    except Exception as e:
        _import_error = e

if not _imported:
    raise ImportError(
        "Failed to import isomdl_uniffi bindings. "
        "This usually means the Rust library hasn't been built yet. "
        f"Please run './python/precommit/build-bindings.sh' first. "
        f"Original error: {_import_error}"
    )

