#!/usr/bin/env python3
# Copyright (c) 2025 Indicio
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# This software may be modified and distributed under the terms
# of either the Apache License, Version 2.0 or the MIT license.
# See the LICENSE-APACHE and LICENSE-MIT files for details.

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

from setuptools import find_packages, setup
from setuptools.command.build_py import build_py
from setuptools.command.egg_info import egg_info


class BuildRust:
    """Mixin for building Rust cdylib and generating UniFFI bindings."""

    def build_rust_library(self):
        """Build the Rust library and generate UniFFI Python bindings."""
        print("🦀 Building Rust library...")

        rust_dir = Path(__file__).parent.parent / "rust"
        output_dir = Path(__file__).parent / "isomdl_uniffi"

        # Detect target architecture from Python
        import platform
        python_arch = platform.machine()
        python_os = platform.system()
        
        # Map Python architecture to Rust target (OS-specific)
        rust_target = None
        if python_os == "Darwin":  # macOS
            if python_arch == "x86_64":
                rust_target = "x86_64-apple-darwin"
            elif python_arch == "arm64" or python_arch == "aarch64":
                rust_target = "aarch64-apple-darwin"
        elif python_os == "Linux":
            # On Linux, just use native compilation
            rust_target = None
        # For other OSes, use default

        # Build the Rust library in release mode for the correct architecture
        build_cmd = ["cargo", "build", "--release"]
        if rust_target:
            print(f"🎯 Cross-compiling for {rust_target}...")
            build_cmd.extend(["--target", rust_target])
            lib_subdir = rust_target
        else:
            lib_subdir = "release"

        subprocess.run(build_cmd, check=True, cwd=rust_dir)

        # Determine library extension
        if platform.system() == "Darwin":
            lib_ext = "dylib"
        elif platform.system() == "Windows":
            lib_ext = "dll"
        else:
            lib_ext = "so"

        # Find the library in the target-specific directory
        if rust_target:
            lib_path = rust_dir / "target" / rust_target / "release" / f"libisomdl_uniffi.{lib_ext}"
        else:
            lib_path = rust_dir / "target" / "release" / f"libisomdl_uniffi.{lib_ext}"

        if not lib_path.exists():
            raise FileNotFoundError(f"Library not found at {lib_path}")

        # Generate Python bindings
        print("🐍 Generating UniFFI Python bindings...")
        subprocess.run(
            [
                "cargo",
                "run",
                "--manifest-path",
                str(rust_dir / "Cargo.toml"),
                "--bin",
                "uniffi-bindgen",
                "--",
                "generate",
                "--library",
                str(lib_path),
                "--language",
                "python",
                "--out-dir",
                str(output_dir),
            ],
            check=True,
            cwd=rust_dir,
        )

        # Copy the library to the Python package
        print(f"📦 Copying library to package...")
        output_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(lib_path, output_dir / lib_path.name)


class BuildPyCommand(build_py, BuildRust):
    """Custom build command that builds Rust and generates UniFFI bindings."""

    def run(self):
        self.build_rust_library()
        super().run()


class EggInfoCommand(egg_info, BuildRust):
    """Custom egg_info command to ensure bindings exist even for editable installs."""

    def run(self):
        # Build Rust for editable installs (needed for development)
        if os.environ.get("SKIP_RUST_BUILD") != "1":
            self.build_rust_library()
        super().run()


if __name__ == "__main__":
    # Read README for long description
    readme_path = Path(__file__).parent.parent / "README.md"
    with open(readme_path, encoding="utf-8") as f:
        long_description = f.read()

    setup(
        name="isomdl-uniffi",
        version="0.1.0",
        author="Indicio",
        author_email="dev@indicio.tech",
        description="ISO 18013-5 mobile Driver License implementation with Python bindings",
        long_description=long_description,
        long_description_content_type="text/markdown",
        url="https://github.com/Indicio-tech/isomdl-uniffi",
        packages=find_packages(),
        package_data={
            "isomdl_uniffi": ["*.dylib", "*.so", "*.dll"],  # Include native libraries
        },
        include_package_data=True,
        zip_safe=False,
        cmdclass={
            "build_py": BuildPyCommand,
            "egg_info": EggInfoCommand,
        },
        classifiers=[
            "Development Status :: 4 - Beta",
            "Intended Audience :: Developers",
            "License :: OSI Approved :: Apache Software License",
            "License :: OSI Approved :: MIT License",
            "Programming Language :: Python :: 3",
            "Programming Language :: Python :: 3.9",
            "Programming Language :: Python :: 3.10",
            "Programming Language :: Python :: 3.11",
            "Programming Language :: Python :: 3.12",
            "Programming Language :: Rust",
            "Topic :: Security :: Cryptography",
            "Topic :: Software Development :: Libraries",
        ],
        python_requires=">=3.9",
    )
