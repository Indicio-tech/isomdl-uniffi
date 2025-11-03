# ISO MDL UniFFI Python Bindings

This repository provides Python bindings for the ISO 18013-5 Mobile Driver's License (mDL) library using UniFFI, allowing interaction with mDL documents from Python applications.

## Overview

The ISO MDL UniFFI library provides a Python interface to the Rust-based `isomdl` library, enabling:

- **Holder functionality**: Create presentation sessions for mDL documents
- **Reader functionality**: Verify and read mDL documents from holders  
- **Document management**: Create, manage, and present mobile driver's licenses
- **Cross-platform support**: Works on macOS, Linux, and Windows

## Architecture

This project uses [UniFFI](https://mozilla.github.io/uniffi-rs/) to generate Python bindings from Rust code:

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Python App   │ ←→ │  UniFFI Bindings │ ←→ │   Rust Library  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                                        │
                                                ┌───────▼───────┐
                                                │  isomdl crate │
                                                └───────────────┘
```

## Prerequisites

- **Rust**: Latest stable version (install via [rustup](https://rustup.rs/))
- **Python**: 3.8 or later
- **UV**: Python package manager (recommended, install via `pip install uv`)
- **Cross-compilation tools** (for building binaries for multiple platforms)

### Platform-specific Requirements

#### macOS
- Xcode command line tools: `xcode-select --install`

#### Linux
- Build essentials: `sudo apt update && sudo apt install build-essential`

#### Windows
- MinGW-w64 toolchain

## Quick Start

### 1. Clone and Setup

```bash
git clone <repository-url>
cd isomdl-uniffi
git checkout python-bindings
```

### 2. (Optional) Setup Pre-commit Hooks

For contributors, set up pre-commit hooks to ensure code quality:

```bash
# Install pre-commit
pip install pre-commit

# Install git hook scripts
pre-commit install

# (Optional) Run against all files
pre-commit run --all-files
```

See [python/precommit/README.md](python/precommit/README.md) for more details.

### 3. CI/CD Pipeline

This project includes comprehensive GitHub Actions workflows:

#### **Pull Request Checks** (`.github/workflows/pr-check.yml`)
- Quick validation for PRs with essential checks
- Runs on every PR to `main` and `develop` branches
- Validates Rust formatting, compilation, and tests
- Builds Python bindings and runs test suite
- Verifies selective disclosure functionality
- Checks Python code quality (black, flake8)

#### **Full CI Pipeline** (`.github/workflows/ci.yml`)
- Comprehensive testing across multiple platforms and Python versions
- Matrix builds: Ubuntu, macOS, Windows × Python 3.9-3.12
- Security auditing with `cargo audit`
- Integration tests including selective disclosure validation

#### **Release Pipeline** (`.github/workflows/release.yml`)
- Automated releases on version tags (`v*`)
- Builds Python wheels for multiple platforms
- Publishes Rust crate to [crates.io](https://crates.io)
- Creates GitHub releases with binaries

#### **Dependency Management** (`.github/dependabot.yml`)
- Automated dependency updates for Rust crates
- Weekly updates for GitHub Actions
- Properly labeled and organized PRs

All workflows ensure that:
- ✅ Rust code compiles and passes tests
- ✅ Python bindings build successfully  
- ✅ Complete test suite passes (including selective disclosure tests)
- ✅ Code meets formatting and quality standards
- ✅ Security vulnerabilities are detected early
- ✅ All commits are properly signed with DCO (Developer Certificate of Origin)

### 4. Build Python Bindings

```bash
# Build the Rust library and generate Python bindings
./build-python-bindings.sh
```

This script will:
- Build the Rust library in release mode
- Generate Python bindings using UniFFI
- Create a complete Python package in `rust/out/python/`

### 3. Test the Bindings

```bash
# Run the comprehensive test suite
./python/test-bindings.py
```

### 4. Install and Use (Optional)

```bash
# Create virtual environment (optional but recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install the generated package
cd rust/out/python
pip install -e .

# Test the installation
python -c "import isomdl_uniffi; print('Success!')"
```

## Usage Examples

### Basic Holder Example

```python
import isomdl_uniffi as mdl
import uuid

# Create an mDL document from CBOR data
mdoc = mdl.Mdoc.from_cbor(cbor_data, "device_key_alias")

# Start a presentation session
session_uuid = uuid.uuid4()
session = mdl.MdlPresentationSession.new(mdoc, session_uuid)

print(f"QR Code URI: {session.qr_code_uri}")
print(f"BLE Identifier: {session.ble_ident.hex()}")
```

### Basic Reader Example

```python
import isomdl_uniffi as mdl

# Define what data elements to request
requested_items = {
    "org.iso.18013.5.1": {
        "family_name": True,
        "given_name": True,
        "birth_date": True
    }
}

# Establish reader session
session_data = mdl.establish_session(
    uri="mdoc://example-uri",
    requested_items=requested_items,
    trust_anchor_registry=["-----BEGIN CERTIFICATE-----\n..."]
)

print(f"Session UUID: {session_data.uuid}")
```

## API Reference

### Core Classes

#### `Mdoc`
Represents an ISO 18013-5 mobile document.

**Methods:**
- `from_cbor(data: bytes, key_alias: str) -> Mdoc`: Create from CBOR data
- `to_cbor() -> bytes`: Export to CBOR format
- `namespaces() -> list[str]`: Get available namespaces
- `elements_for_namespace(namespace: str) -> list[Element]`: Get elements in namespace

#### `MdlPresentationSession`
Manages the holder's presentation session.

**Methods:**
- `new(mdoc: Mdoc, uuid: UUID) -> MdlPresentationSession`: Create new session
- `qr_code_uri: str`: QR code for reader scanning
- `ble_ident: bytes`: Bluetooth Low Energy identifier

#### `MDLSessionManager`
Handles reader-side session management.

**Methods:**
- `establish_session(uri: str, requested_items: dict, trust_anchors: list[str]) -> MDLReaderSessionData`

### Data Structures

#### `Element`
```python
class Element:
    identifier: str        # Element name
    value: Optional[str]   # JSON representation of value
```

## Development

### Project Structure

```
isomdl-uniffi/
├── rust/                    # Rust source code
│   ├── src/
│   │   ├── lib.rs          # Main library entry point
│   │   └── mdl/            # MDL-specific modules
│   │       ├── mod.rs      # Module definitions
│   │       ├── holder.rs   # Holder functionality
│   │       ├── reader.rs   # Reader functionality
│   │       ├── mdoc.rs     # Document management
│   │       └── util.rs     # Utility functions
│   ├── Cargo.toml         # Rust dependencies
│   ├── uniffi-bindgen.rs  # UniFFI binding generator
│   └── out/               # Generated bindings (gitignored)
├── kotlin/                 # Kotlin bindings (separate)
└── out/                   # Generated bindings output
    └── python/            # Python package output
```

### Building for Development

1. **Setup development environment:**
```bash
# Install development dependencies
cargo install uniffi-bindgen
rustup target add x86_64-apple-darwin aarch64-apple-darwin x86_64-unknown-linux-gnu
```

2. **Build and test:**
```bash
# Build library
cargo build --release

# Run Rust tests
cargo test

# Generate Python bindings
cargo run --bin uniffi-bindgen generate --library target/release/libisomdl_uniffi.dylib --language python --out-dir out/python

# Test Python bindings
cd out/python
uv venv test-env
source test-env/bin/activate
uv pip install -e .
python -c "import isomdl_uniffi; print('Import successful!')"
```

### Cross-Platform Building

The `build-python-bindings.sh` script builds binaries for the current platform only. For production deployments requiring multiple platforms, you can:

1. **Use GitHub Actions or CI/CD** to build on different runners
2. **Use cross-compilation tools** like [cross-rs](https://github.com/cross-rs/cross):

```bash
# Install cross-compilation tool
cargo install cross --git https://github.com/cross-rs/cross

# Add target platforms
rustup target add x86_64-apple-darwin aarch64-apple-darwin x86_64-unknown-linux-gnu x86_64-pc-windows-gnu

# Build for specific targets
cross build --release --target x86_64-unknown-linux-gnu --lib
cargo build --release --target x86_64-apple-darwin --lib
# ... etc for other platforms
```

3. **Create universal macOS binaries** using lipo:

```bash
# Build both architectures
cargo build --release --target x86_64-apple-darwin --lib
cargo build --release --target aarch64-apple-darwin --lib

# Merge into universal binary
lipo -create \
    target/x86_64-apple-darwin/release/libisomdl_uniffi.dylib \
    target/aarch64-apple-darwin/release/libisomdl_uniffi.dylib \
    -output out/python/libisomdl_uniffi.dylib
```

## Integration with ACA-Py Plugins

This library is designed to be used within ACA-Py (Aries Cloud Agent Python) plugins. Example integration:

```python
# In your ACA-Py plugin
from aries_cloudagent.core.profile import Profile
import isomdl_uniffi as mdl

class MDLHandler:
    def __init__(self, profile: Profile):
        self.profile = profile
    
    async def create_presentation(self, mdoc_data: bytes):
        # Create mDL document
        mdoc = mdl.Mdoc.from_cbor(mdoc_data, "key_alias")
        
        # Start presentation session
        session = mdl.MdlPresentationSession.new(mdoc, uuid.uuid4())
        
        return {
            "qr_code": session.qr_code_uri,
            "ble_ident": session.ble_ident.hex()
        }
```

## Dependencies

### Rust Dependencies
- `uniffi`: UniFFI framework for generating bindings
- `isomdl`: Core ISO 18013-5 implementation
- `serde`: Serialization framework
- `uuid`: UUID generation and parsing
- `base64`: Base64 encoding/decoding
- `p256`: ECDSA P-256 cryptography
- `anyhow`: Error handling

### Python Dependencies
Generated Python package has minimal dependencies, as most functionality is provided by the compiled Rust library.

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes
4. Run tests: `cargo test`
5. Build Python bindings: `./build-python.sh`
6. Test Python integration
7. **Sign your commits** with DCO (Developer Certificate of Origin):
   ```bash
   git commit -s -m "Your commit message"
   ```
   All commits must include a `Signed-off-by` line to comply with DCO requirements.
   See [.github/DCO.md](.github/DCO.md) for more details.
8. Submit a pull request

### DCO (Developer Certificate of Origin)

This project requires all contributions to be signed with the Developer Certificate of Origin (DCO). 
This certifies that you have the right to contribute the code and agree to the project's license terms.

- **Required**: All commits must include a `Signed-off-by` line
- **How to sign**: Use `git commit -s` for new commits
- **Retroactive signing**: Use `git rebase --signoff` for existing commits
- **Verification**: Our CI pipeline automatically checks DCO compliance

For complete DCO requirements and procedures, see [.github/DCO.md](.github/DCO.md).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### Third-Party Dependencies

This project incorporates code from the following open-source projects:

- **isomdl** by Spruce Systems, Inc. - [https://github.com/spruceid/isomdl](https://github.com/spruceid/isomdl)
- **sprucekit-mobile** by Spruce Systems, Inc. - [https://github.com/spruceid/sprucekit-mobile](https://github.com/spruceid/sprucekit-mobile)

Both projects are dual-licensed under Apache 2.0 and MIT licenses.

See [THIRD_PARTY_LICENSES.md](./THIRD_PARTY_LICENSES.md) for complete license information and attributions.

## Troubleshooting

### Common Issues

1. **Build fails with "target not found"**
   - Ensure all required targets are installed: `rustup target add <target>`

2. **Python import fails**
   - Verify the dynamic library is in the correct location
   - Check that Python can find the generated module

3. **Cross-compilation issues**
   - Install `cross`: `cargo install cross`
   - Use Docker for consistent cross-compilation environment

### Getting Help

- Check the [UniFFI documentation](https://mozilla.github.io/uniffi-rs/)
- Review the [isomdl library documentation](https://github.com/spruceid/isomdl)
- Open an issue in this repository

## Directory Structure

```
isomdl-uniffi/
├── README.md                    # Main documentation
├── build-python-bindings.sh    # Build script for Python bindings
├── rust/                       # Rust source code
│   ├── src/                    # Rust library source
│   ├── Cargo.toml             # Rust dependencies
│   ├── uniffi-bindgen.rs      # UniFFI binding generator
│   └── out/                   # Generated bindings (gitignored)
│       └── python/            # Python bindings output
│           ├── isomdl_uniffi.py        # Generated Python module
│           ├── libisomdl_uniffi.dylib  # Compiled library
│           ├── setup.py               # Package setup
│           └── pyproject.toml         # Package config
└── kotlin/                    # Kotlin bindings (separate)
```

## Roadmap

- [ ] Add comprehensive test suite
- [ ] Improve error handling and error types
- [ ] Add more usage examples
- [ ] Performance optimizations
- [ ] Enhanced documentation
- [ ] CI/CD pipeline for automated builds
- [ ] Cross-platform binary distribution