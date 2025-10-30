#!/usr/bin/env python3

import subprocess
import sys
from pathlib import Path
from setuptools import setup, find_packages
from setuptools.command.build_py import build_py


class BuildRustCommand(build_py):
    """Custom build command that builds Rust library and generates bindings"""
    
    def run(self):
        # Build Rust library and bindings
        self.build_rust_and_bindings()
        # Run the standard build
        super().run()
    
    def build_rust_and_bindings(self):
        """Build Rust library and generate Python bindings"""
        project_root = Path(__file__).parent.parent.absolute()  # Go up one level from python/
        
        # Build Rust library
        rust_dir = project_root / "rust"
        print("🔧 Building Rust library...")
        try:
            subprocess.run([
                "cargo", "build", "--release"
            ], cwd=rust_dir, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"❌ Failed to build Rust library: {e}")
            print("Make sure Rust is installed and available in PATH")
            sys.exit(1)
        
        # Generate Python bindings
        print("🐍 Generating Python bindings...")
        build_script = project_root / "python" / "precommit" / "build-bindings.sh"
        try:
            subprocess.run([str(build_script)], check=True)
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"❌ Failed to generate bindings: {e}")
            sys.exit(1)
        
        # Copy bindings to package directory
        bindings_dir = project_root / "rust" / "out" / "python"
        package_dir = Path(__file__).parent / "isomdl_uniffi"  # Now in python/isomdl_uniffi
        
        if bindings_dir.exists():
            print("📦 Copying bindings to package directory...")
            package_dir.mkdir(exist_ok=True)
            
            import shutil
            for file in bindings_dir.glob("*"):
                if file.is_file():
                    shutil.copy2(file, package_dir)
                    print(f"   Copied {file.name}")


if __name__ == "__main__":
    setup(
        name="isomdl-uniffi",
        version="0.1.0",
        author="Indicio",
        author_email="dev@indicio.tech",
        description="ISO 18013-5 mobile Driver License implementation with Python bindings",
        long_description=open("../README.md", encoding="utf-8").read(),
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
            "Programming Language :: Python :: 3.8",
            "Programming Language :: Python :: 3.9",
            "Programming Language :: Python :: 3.10",
            "Programming Language :: Python :: 3.11",
            "Programming Language :: Python :: 3.12",
            "Programming Language :: Rust",
            "Topic :: Security :: Cryptography",
            "Topic :: Software Development :: Libraries",
        ],
        python_requires=">=3.8",
        cmdclass={
            'build_py': BuildRustCommand,
        },
    )