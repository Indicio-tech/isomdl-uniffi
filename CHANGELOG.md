# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial Python bindings for ISO 18013-5 mDL library using UniFFI
- Holder functionality for creating presentation sessions
- Reader functionality for verifying mDL documents
- Cross-platform support (macOS, Linux, Windows)
- Comprehensive test suite
- CI/CD pipeline with GitHub Actions
- Docker support for development
- Pre-commit hooks for code quality

### Security
- DCO (Developer Certificate of Origin) requirement for contributions
- Security policy documentation
- Third-party license attribution

## [0.1.0] - 2025-11-03

### Added
- Initial release
- UniFFI-based Python bindings for isomdl Rust library
- Basic mDL document operations (create, present, verify)
- Session management for holder and reader interactions
- QR code and BLE support for device engagement
- Selective disclosure functionality
- Integration examples for ACA-Py plugins
- Comprehensive documentation and usage examples

### Dependencies
- isomdl (spruceid/isomdl @ fed574c)
- UniFFI 0.28.3
- Python 3.8+ support
- Rust stable toolchain

---

## Release Types

- **Added** for new features
- **Changed** for changes in existing functionality
- **Deprecated** for soon-to-be removed features
- **Removed** for now removed features
- **Fixed** for any bug fixes
- **Security** for security-related changes