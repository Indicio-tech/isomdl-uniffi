#!/usr/bin/env python3
"""
Build script for isomdl-uniffi Python package
This handles building the Rust library and generating Python bindings
"""

import subprocess
import sys
from pathlib import Path


def build_rust_and_bindings():
    """Build Rust library and generate Python bindings"""
    project_root = Path(__file__).parent.parent.absolute()  # Go up from python/ to project root

    print("🚀 Building Rust library and generating Python bindings...")
    # Use the consolidated build script that handles everything
    build_script = (
        Path(__file__).parent / "precommit" / "build-bindings.sh"
    )  # Now in python/precommit/

    try:
        subprocess.run([str(build_script)], check=True)
    except subprocess.CalledProcessError as e:
        print(f"❌ Build failed with exit code {e.returncode}")
        sys.exit(e.returncode)
    except FileNotFoundError:
        print("❌ Build script not found. Make sure you're in the right directory.")
        sys.exit(1)

    # Copy bindings to package directory
    bindings_dir = project_root / "rust" / "out" / "python"
    package_dir = Path(__file__).parent / "isomdl_uniffi"  # Now in python/isomdl_uniffi

    if bindings_dir.exists():
        print("📦 Copying bindings to package directory...")
        package_dir.mkdir(exist_ok=True)

        for file in bindings_dir.glob("*"):
            if file.is_file():
                import shutil

                shutil.copy2(file, package_dir)
                print(f"   Copied {file.name}")
    else:
        print("⚠️  Bindings directory not found, skipping copy step")


if __name__ == "__main__":
    build_rust_and_bindings()
