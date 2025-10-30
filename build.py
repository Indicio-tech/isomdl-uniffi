#!/usr/bin/env python3
"""
Build script for isomdl-uniffi Python package
This handles building the Rust library and generating Python bindings
"""

import os
import subprocess
import sys
from pathlib import Path

def build_rust_and_bindings():
    """Build Rust library and generate Python bindings"""
    project_root = Path(__file__).parent.absolute()
    
    # Build Rust library
    rust_dir = project_root / "rust"
    print("🔧 Building Rust library...")
    subprocess.run([
        "cargo", "build", "--release"
    ], cwd=rust_dir, check=True)
    
    # Generate Python bindings
    print("🐍 Generating Python bindings...")
    build_script = project_root / "python" / "precommit" / "build-bindings.sh"
    subprocess.run([str(build_script)], check=True)
    
    # Copy bindings to package directory
    bindings_dir = project_root / "rust" / "out" / "python"
    package_dir = project_root / "isomdl_uniffi"
    
    if bindings_dir.exists():
        print("📦 Copying bindings to package directory...")
        package_dir.mkdir(exist_ok=True)
        
        for file in bindings_dir.glob("*"):
            if file.is_file():
                import shutil
                shutil.copy2(file, package_dir)
                print(f"   Copied {file.name}")

if __name__ == "__main__":
    build_rust_and_bindings()