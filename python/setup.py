#!/usr/bin/env python3

import subprocess
import sys
from pathlib import Path

from setuptools import find_packages, setup
from setuptools.command.build_py import build_py


class BuildRustCommand(build_py):
    """Custom build command that builds Rust library and generates bindings"""

    def run(self):
        # Build Rust library and bindings using existing build.py
        self.build_rust_and_bindings()
        # Run the standard build
        super().run()

    def build_rust_and_bindings(self):
        """Build Rust library and generate Python bindings"""
        build_script = Path(__file__).parent / "build.py"
        
        print("🚀 Running build.py to build Rust library and generate bindings...")
        try:
            subprocess.run([sys.executable, str(build_script)], check=True)
        except subprocess.CalledProcessError as e:
            print(f"❌ Build failed with exit code {e.returncode}")
            sys.exit(e.returncode)
        except FileNotFoundError:
            print("❌ build.py not found. Make sure you're in the right directory.")
            sys.exit(1)


if __name__ == "__main__":
    # Read README for long description
    with open("../README.md", encoding="utf-8") as f:
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
            "isomdl_uniffi": ["*.so", "*.dylib", "*.dll", "*.py"],
        },
        include_package_data=True,
        classifiers=[
            "Development Status :: 4 - Beta",
            "Intended Audience :: Developers",
            "License :: OSI Approved :: Apache Software License",
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
        cmdclass={
            "build_py": BuildRustCommand,
        },
    )
