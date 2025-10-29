# Pre-commit Setup

This repository uses [pre-commit](https://pre-commit.com/) to ensure code quality and that builds succeed before committing.

## Installation

1. Install pre-commit (if not already installed):
   ```bash
   pip install pre-commit
   ```

2. Install the git hook scripts:
   ```bash
   cd /path/to/isomdl-uniffi
   pre-commit install
   ```

3. (Optional) Run against all files to verify setup:
   ```bash
   pre-commit run --all-files
   ```

## What Gets Checked

The pre-commit hooks will automatically run on each commit and check:

### Rust Checks
- **Cargo Check**: Verifies the Rust crate compiles without errors
- **Cargo Test**: Runs all Rust unit tests
- **Cargo Format**: Ensures Rust code follows formatting standards

### Python Bindings
- **Build Python Bindings**: Builds the Rust crate in release mode and generates Python bindings
  - Only runs when Rust source files or Cargo files are modified
  - Ensures bindings can be generated successfully

### Python Tests
- **Run Python Tests**: Executes the full Python test suite
  - Runs when Rust code, Cargo files, or Python test files are modified
  - Ensures all tests pass before committing
  - Automatically builds bindings first if they don't exist

### Python Code Quality (for test files)
- **Black**: Auto-formats Python test files
- **Flake8**: Checks Python code style and potential errors

### General Checks
- Removes trailing whitespace
- Ensures files end with a newline
- Validates YAML and TOML files
- Checks for large files (>1MB)
- Detects merge conflicts

## Skipping Hooks

If you need to skip pre-commit hooks for a specific commit (not recommended):
```bash
git commit --no-verify -m "Your commit message"
```

## Updating Hooks

To update to the latest versions of the pre-commit hooks:
```bash
pre-commit autoupdate
```

## Troubleshooting

If hooks fail:
1. Read the error message carefully - it will tell you what failed
2. Fix the issue in your code
3. Stage the fixes: `git add .`
4. Try committing again

Common issues:
- **Rust build fails**: Fix any Rust compilation errors
- **Python bindings fail**: Ensure Rust builds successfully first
- **Format check fails**: Run `cargo fmt` to auto-format Rust code
- **Black formatting**: Black will auto-format Python files; just stage the changes
