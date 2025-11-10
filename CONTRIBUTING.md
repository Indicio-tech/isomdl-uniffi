# Contributing to ISO MDL UniFFI

Thank you for your interest in contributing to the ISO MDL UniFFI Python Bindings project! This document provides guidelines for contributing to this project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Submitting Changes](#submitting-changes)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)

## Code of Conduct

This project adheres to a code of conduct that we expect all contributors to follow. By participating, you are expected to uphold this code. Please report unacceptable behavior to [support@indicio.tech](mailto:support@indicio.tech).

## Getting Started

### Prerequisites

- Rust (latest stable version)
- Python 3.8+
- Git
- Basic familiarity with ISO 18013-5 mDL concepts

#### For Kotlin/Android Development

- Java Development Kit (JDK) 8 or later
- Android SDK (API level 24+)
- Android NDK (version 28.2.13676358 or compatible)
- Gradle (included via wrapper)

### Repository Structure

```
isomdl-uniffi/
├── rust/           # Rust core library
├── python/         # Python bindings and tests  
├── kotlin/         # Kotlin/Android bindings
└── docs/           # Documentation
```

## Development Setup

1. **Fork and clone the repository:**
   ```bash
   git clone https://github.com/your-username/isomdl-uniffi.git
   cd isomdl-uniffi
   ```

2. **Set up development environment:**
   ```bash
   # Install Rust
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   
   # Install Python dependencies
   cd python
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements-dev.txt
   ```

3. **Install pre-commit hooks:**
   ```bash
   pip install pre-commit
   pre-commit install
   ```

4. **Build and test:**
   ```bash
   # Build Rust library
   cd rust
   cargo build
   
   # Run tests
   cargo test
   
   # Build Python bindings
   cd ../python
   ./build-python-bindings.sh
   
   # Test Python bindings
   ./test-bindings.py
   
   # Build Kotlin/Android bindings
   cd ../kotlin
   ./gradlew build
   
   # Run Kotlin tests
   ./gradlew test
   ```

## Making Changes

### Branch Naming

Use descriptive branch names:
- `feat/add-new-feature` - New features
- `fix/issue-description` - Bug fixes
- `docs/update-readme` - Documentation updates
- `refactor/improve-performance` - Code improvements

### Commit Messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
type(scope): description

[optional body]

[optional footer]
```

Examples:
- `feat(python): add selective disclosure support`
- `fix(rust): resolve memory leak in session management`
- `docs(readme): update installation instructions`

### Developer Certificate of Origin (DCO)

This project requires all contributions to be signed with the Developer Certificate of Origin (DCO). This certifies that you have the right to contribute the code.

**All commits must include a `Signed-off-by` line:**

```bash
git commit -s -m "feat(python): add new functionality"
```

For existing commits, you can add DCO retroactively:
```bash
git rebase --signoff HEAD~N  # where N is the number of commits
```

See [.github/DCO.md](.github/DCO.md) for complete details.

## Submitting Changes

### Pull Request Process

1. **Ensure your fork is up to date:**
   ```bash
   git remote add upstream https://github.com/Indicio-tech/isomdl-uniffi.git
   git fetch upstream
   git checkout main
   git merge upstream/main
   ```

2. **Create a feature branch:**
   ```bash
   git checkout -b feat/your-feature-name
   ```

3. **Make your changes with proper commits:**
   ```bash
   git add .
   git commit -s -m "feat(scope): your change description"
   ```

4. **Push and create a Pull Request:**
   ```bash
   git push origin feat/your-feature-name
   ```

### Review Process

1. Automated checks must pass (CI/CD, tests, linting)
2. At least one maintainer review required
3. Address review feedback promptly
4. Maintain clean commit history

## Coding Standards

### Rust Code

- Follow [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `cargo fmt` for formatting
- Use `cargo clippy` for linting
- Add documentation for public APIs
- Write unit tests for new functionality

```rust
/// Creates a new mDL presentation session.
/// 
/// # Arguments
/// * `mdoc` - The mobile document to present
/// * `session_id` - Unique identifier for the session
/// 
/// # Returns
/// A new `MdlPresentationSession` instance
/// 
/// # Examples
/// ```
/// let session = MdlPresentationSession::new(mdoc, uuid::Uuid::new_v4());
/// ```
pub fn new(mdoc: Mdoc, session_id: Uuid) -> Self {
    // Implementation
}
```

### Python Code

- Follow [PEP 8](https://pep8.org/) style guide
- Use `ruff` for code formatting and linting
- Add type hints where appropriate
- Write docstrings for public functions

```python
def create_presentation_session(
    mdoc: Mdoc, 
    session_id: str,
) -> MdlPresentationSession:
    """Create a new mDL presentation session.
    
    Args:
        mdoc: The mobile document to present
        session_id: Unique identifier for the session
        
    Returns:
        A new MdlPresentationSession instance
        
    Raises:
        ValueError: If mdoc is invalid
    """
    # Implementation
```

### Documentation

- Update README.md for user-facing changes
- Add inline code comments for complex logic
- Update API documentation
- Include usage examples

## Testing

### Rust Tests

```bash
cd rust
cargo test                    # Run all tests
cargo test --release         # Run optimized tests
cargo test test_name         # Run specific test
```

### Python Tests

```bash
cd python
python -m pytest tests/                    # Run all tests
python -m pytest tests/test_specific.py   # Run specific test file
python -m pytest -v                       # Verbose output
```

### Kotlin Tests

```bash
cd kotlin
./gradlew test                            # Run all tests
./gradlew testDebugUnitTest              # Run debug unit tests
./gradlew connectedAndroidTest           # Run Android instrumented tests
./gradlew build                          # Build and run all tests
```

### Integration Tests

```bash
# Full integration test suite
cd python
./tests/run_tests.py
```

### Test Requirements

- **Unit tests** for all new functionality
- **Integration tests** for end-to-end workflows
- **Edge case testing** for error conditions
- **Performance tests** for critical paths
- **All tests must pass** before merging

## Documentation

### API Documentation

- Document all public APIs
- Include usage examples
- Explain parameters and return values
- Note any limitations or requirements

### User Documentation

- Update README.md for user-facing changes
- Add new examples to documentation
- Update installation instructions if needed

## Questions and Support

- **Issues:** Open a GitHub issue for bugs or feature requests
- **Discussions:** Use GitHub Discussions for questions
- **Email:** Contact maintainers at [support@indicio.tech](mailto:support@indicio.tech)

## License

By contributing to this project, you agree that your contributions will be licensed under the project's MIT License. See [LICENSE](LICENSE) for details.

## Recognition

Contributors will be recognized in:
- Repository contributor list
- Release notes for significant contributions
- Annual contributor acknowledgments

Thank you for contributing to ISO MDL UniFFI!
