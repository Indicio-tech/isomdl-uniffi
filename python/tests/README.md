# isomdl-uniffi Python Bindings Tests

This directory contains tests for the isomdl-uniffi Python bindings.

## Test Structure

The tests are organized into separate modules:

- `test_basic_functionality.py` - Tests for key pair generation, test MDL creation, and basic operations
- `test_mdoc_operations.py` - Tests for MDL serialization, deserialization, and document operations  
- `test_presentation_session.py` - Tests for presentation session creation and operations
- `test_reader_functionality.py` - Tests for reader session establishment and operations
- `test_integration.py` - Integration tests between existing tests and new MDL functionality
- `test_selective_disclosure.py` - Tests for selective disclosure and age verification scenarios
- `test_complete_workflow.py` - Rigorous end-to-end mdoc workflow test using real test vectors
- `run_tests.py` - Main test runner that imports bindings and runs all test modules

## Running Tests

### Prerequisites

Before running tests, you must build the Python bindings:

```bash
# From repository root
./python/precommit/build-bindings.sh
```

### Run All Tests (Recommended)

**Using pytest (recommended):**
```bash
# From python directory
uv run pytest tests/ -v

# Or with coverage
uv run pytest tests/ --cov=isomdl_uniffi --cov-report=html
```

**Using the test runner:**
```bash
# From python/tests directory - automatically uses pytest if available
python run_tests.py
```

### Run Individual Test Modules

**With pytest:**
```bash
# Run specific test files
uv run pytest tests/test_basic_functionality.py -v
uv run pytest tests/test_mdoc_operations.py -v

# Run specific test classes
uv run pytest tests/test_basic_functionality.py::TestKeyPairOperations -v

# Run specific test methods
uv run pytest tests/test_basic_functionality.py::TestKeyPairOperations::test_key_pair_creation -v
```

**Direct execution (for debugging):**
```bash
# Run a specific test module directly (legacy mode)
python3 test_basic_functionality.py
python3 test_mdoc_operations.py
python3 test_presentation_session.py
python3 test_reader_functionality.py
python3 test_integration.py
python3 test_selective_disclosure.py
python3 test_complete_workflow.py
```

## Test Coverage

The tests cover:

✅ **Key Pair Operations**
- P256 key pair generation
- Public key JWK extraction
- Message signing

✅ **MDL Document Operations** 
- Test MDL generation
- Document type and ID retrieval
- Namespace and element enumeration
- JSON and CBOR serialization

✅ **Presentation Sessions**
- Session creation with UUID
- QR code URI generation
- BLE identifier generation
- Response generation (basic)

✅ **Reader Functionality**
- Session establishment (with mock data)
- Request structure validation
- Error handling for invalid URIs

✅ **Integration Testing**
- Cross-test validation and compatibility
- Module interaction testing

✅ **Selective Disclosure**
- Attribute filtering and privacy protection
- Age verification scenarios
- Partial data sharing validation

✅ **Complete Workflow**
- End-to-end mdoc operations
- Real test vector validation
- Rigorous assertion testing

## Expected Behavior

Some tests are expected to fail gracefully when testing without real mDL devices:

- Reader session establishment with mock URIs will fail (this is expected)
- Response generation without real reader requests may fail (this is expected)

These failures are handled as successful test outcomes since they demonstrate proper error handling.

## Adding New Tests

To add new tests:

1. Create a new test file in this directory following the naming pattern `test_*.py`
2. Implement a `run_tests()` function that returns `True` for success, `False` for failure
3. Add the test module name to the `test_modules` list in `run_tests.py`
4. The test runner will automatically discover and run your new tests

Example test file structure:

```python
#!/usr/bin/env python3
"""
Description of your test module.
"""

def run_tests():
    """
    Run your tests.
    
    Returns:
        bool: True if all tests pass, False otherwise.
    """
    try:
        # Your test code here
        # Access the bindings via the global 'mdl' variable
        
        print("   ✅ Test passed")
        return True
        
    except Exception as e:
        print(f"   ❌ Test failed: {e}")
        return False

# Direct execution support for debugging
if __name__ == "__main__":
    import sys
    import os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "rust", "out", "python"))
    
    try:
        import isomdl_uniffi as mdl
        success = run_tests()
        sys.exit(0 if success else 1)
    except ImportError as e:
        print(f"❌ Could not import isomdl_uniffi: {e}")
        sys.exit(1)
```
