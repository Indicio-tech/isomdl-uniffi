# Copyright (c) 2025 Indicio
# SPDX-License-Identifier: Apache-2.0 OR MIT

import sys
from pathlib import Path

def get_project_root() -> Path:
    """
    Find the project root by looking for the rust directory.
    """
    current_dir = Path.cwd()
    project_root = current_dir
    
    # Look for rust directory to identify project root
    max_levels = 5
    for _ in range(max_levels):
        rust_dir = project_root / "rust"
        if rust_dir.exists() and rust_dir.is_dir():
            return project_root
        parent = project_root.parent
        if parent == project_root:
            break
        project_root = parent
    
    # Fallback logic if not found via traversal (e.g. when running from a different location)
    # Assuming this file is in python/tests/utils.py
    return Path(__file__).parent.parent.parent

def get_mdl_module(project_root: Path = None):
    """
    Import and return the isomdl_uniffi module.
    """
    if project_root is None:
        project_root = get_project_root()

    bindings_path = project_root / "rust" / "out" / "python"
    
    # Add to sys.path if not already there
    if str(bindings_path) not in sys.path:
        sys.path.insert(0, str(bindings_path))
    
    try:
        import isomdl_uniffi
        return isomdl_uniffi
    except ImportError as e:
        # If the bindings don't exist or import fails, we might want to raise a clearer error
        # or let the caller handle it.
        raise ImportError(f"Could not import isomdl_uniffi from {bindings_path}. Ensure bindings are generated.") from e
