# Installing isomdl-uniffi Python Bindings

## Option 1: Install from Git (Recommended)

```bash
# Install directly from GitHub (requires Rust toolchain)
pip install git+https://github.com/Indicio-tech/isomdl-uniffi.git#subdirectory=python

# Or for development
git clone https://github.com/Indicio-tech/isomdl-uniffi.git
cd isomdl-uniffi/python
pip install -e .
```

**Requirements:**
- Rust toolchain (install from https://rustup.rs/)
- Python 3.8+

## Option 2: Install from PyPI (When published)

```bash
pip install isomdl-uniffi
```

## Option 3: Install from GitHub Releases

Download the appropriate wheel for your platform from the [releases page](https://github.com/Indicio-tech/isomdl-uniffi/releases):

```bash
# Example for Linux
pip install https://github.com/Indicio-tech/isomdl-uniffi/releases/download/v0.1.0/isomdl_uniffi-0.1.0-py3-none-linux_x86_64.whl
```

## Usage

```python
import isomdl_uniffi as mdl

# Use the library
# ... your code here
```

## Building from Source

If you need to build from source:

```bash
git clone https://github.com/Indicio-tech/isomdl-uniffi.git
cd isomdl-uniffi/python

# Build Rust library and generate bindings
python3 build.py

# Or use the shell script
./build-python-bindings.sh

# Or use the precommit script
./precommit/build-bindings.sh

# Install the package
pip install -e .
```

## Build Scripts

The project provides several build scripts:

- `python/build.py` - Python build script that handles everything
- `python/build-python-bindings.sh` - Standalone shell script for building
- `python/precommit/build-bindings.sh` - Pre-commit hook script

All scripts will build the Rust library and generate Python bindings automatically.
