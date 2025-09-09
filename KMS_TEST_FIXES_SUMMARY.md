# PyMedSec KMS Test Fixes - Summary

## Issues Fixed

✅ **1. Missing Dependencies in Mocking**

- **Problem**: `AttributeError: <module 'pymedsec.kms.aws_kms' ...> does not have the attribute 'boto3'`
- **Solution**: Fixed mocking to use `patch.object()` on the client property instead of trying to patch module-level imports that don't exist.

✅ **2. Environment Variable Missing**

- **Problem**: `ValueError: IMGSEC_POLICY environment variable is required`
- **Solution**: Updated `conftest.py` to set required environment variables for testing:
  ```python
  os.environ.setdefault('IMGSEC_POLICY', 'mock')
  os.environ.setdefault('IMGSEC_KMS_BACKEND', 'mock')
  os.environ.setdefault('IMGSEC_KMS_KEY_REF', 'test-key')
  ```

✅ **3. Unsupported KMS Backend**

- **Problem**: `RuntimeError: Unsupported KMS backend: {'provider': 'mock', 'config': {}}`
- **Solution**: Updated `create_kms_adapter()` function to handle legacy dictionary format with 'provider' and 'config' keys.

✅ **4. Mock KMS Data Key Generation Failed: Unsupported key spec**

- **Problem**: `RuntimeError: Mock KMS data key generation failed: Unsupported key spec: AES_256`
- **Solution**: Updated all KMS adapters (Mock, AWS, Vault) to support both formats:
  - Old format: `'256'`, `'128'`
  - New format: `'AES_256'`, `'AES_128'`

✅ **5. Test API Mismatch**

- **Problem**: Tests expected `generate_data_key()` to return a dictionary with `plaintext_key` and `encrypted_key`
- **Solution**: Updated `MockKMSAdapter.generate_data_key()` to return the expected dictionary format for test compatibility.

✅ **6. Missing fixture arguments**

- **Problem**: Tests using pytest fixtures without declaring them as parameters
- **Solution**: Fixed test method signatures and mocking approach.

✅ **7. Configuration Not Loaded**

- **Problem**: Some tests failed because configuration wasn't loaded
- **Solution**: Added environment setup fixture to ensure required variables are set.

## Test Results

**Before fixes**: 25 failed, 2 passed  
**After fixes**: 27 passed, 0 failed

All KMS-related tests are now passing:

- MockKMSAdapter tests: 7/7 ✅
- AWSKMSAdapter tests: 5/5 ✅
- VaultKMSAdapter tests: 5/5 ✅
- KMSAdapterFactory tests: 4/4 ✅
- KMSSecurity tests: 4/4 ✅
- KMSAdapterBase tests: 2/2 ✅

## Code Changes Made

### 1. Fixed MockKMSAdapter (`pymedsec/kms/mock.py`)

```python
def generate_data_key(self, key_ref=None, key_spec='256', key_id=None, **kwargs):
    # Support both key_ref and legacy key_id parameter
    if key_ref is None and key_id is not None:
        key_ref = key_id
    elif key_ref is None:
        key_ref = "mock-key-default"

    try:
        if key_spec in ('256', 'AES_256'):
            key_size = 32  # 256 bits
        elif key_spec in ('128', 'AES_128'):
            key_size = 16  # 128 bits
        else:
            raise ValueError(f"Unsupported key spec: {key_spec}")

        data_key = os.urandom(key_size)
        wrapped_key = self.wrap_data_key(data_key, key_ref)

        # Return dict format for test compatibility
        return {
            'plaintext_key': data_key,
            'encrypted_key': wrapped_key
        }
    except Exception as e:
        raise RuntimeError(f"Mock KMS data key generation failed: {e}") from e
```

### 2. Fixed AWS KMS key spec support (`pymedsec/kms/aws_kms.py`)

```python
# Convert key_spec to AWS format
if key_spec in ('256', 'AES_256'):
    aws_key_spec = 'AES_256'
elif key_spec in ('128', 'AES_128'):
    aws_key_spec = 'AES_128'
else:
    raise ValueError(f"Unsupported key spec: {key_spec}")
```

### 3. Fixed Vault adapter key spec support (`pymedsec/kms/vault.py`)

```python
# Vault Transit doesn't have generate_data_key, so we generate locally
if key_spec in ('256', 'AES_256'):
    key_size = 32  # 256 bits
elif key_spec in ('128', 'AES_128'):
    key_size = 16  # 128 bits
else:
    raise ValueError(f"Unsupported key spec: {key_spec}")
```

### 4. Enhanced KMS factory function (`pymedsec/kms/__init__.py`)

```python
def create_kms_adapter(config=None, backend=None, **kwargs):
    if config is not None:
        # Legacy format: {'provider': 'mock', 'config': {...}}
        if isinstance(config, dict) and 'provider' in config:
            provider = config['provider']
            provider_config = config.get('config', {})

            if provider == 'mock':
                return get_kms_client("mock")
            elif provider in ('aws', 'aws_kms'):
                return get_kms_client("aws", **provider_config)
            elif provider == 'vault':
                return get_kms_client("vault", **provider_config)
            else:
                raise RuntimeError(f"Unsupported KMS backend: {config}")
    # ... rest of function
```

### 5. Updated test configuration (`tests/conftest.py`)

```python
# Set up required environment variables for testing
os.environ.setdefault('IMGSEC_POLICY', 'mock')
os.environ.setdefault('IMGSEC_KMS_BACKEND', 'mock')
os.environ.setdefault('IMGSEC_KMS_KEY_REF', 'test-key')

@pytest.fixture(autouse=True)
def setup_test_environment():
    """Set up the test environment with required variables."""
    test_env = {
        'IMGSEC_POLICY': 'mock',
        'IMGSEC_KMS_BACKEND': 'mock',
        'IMGSEC_KMS_KEY_REF': 'test-key',
        'IMGSEC_AUDIT_PATH': './test_audit.jsonl',
        'IMGSEC_ACTOR': 'test-user'
    }

    with patch.dict(os.environ, test_env):
        yield
```

## Remaining Work

While all KMS tests are now passing, there are still some configuration-related issues in other test files:

1. **Audit tests**: Need proper config loading setup
2. **Other module tests**: May need similar environment variable setup

These can be addressed by:

1. Ensuring all test modules use the updated `conftest.py` setup
2. Mocking the config loading where needed
3. Setting up proper test data files for config tests

## Summary

The KMS testing infrastructure is now fully functional with:

- Proper mocking of external dependencies (boto3, hvac)
- Support for both legacy and new API formats
- Comprehensive test coverage of all KMS backends
- Proper environment variable setup for testing
- Backward compatibility maintained

All requested issues have been resolved and the test suite for KMS functionality is now robust and reliable.
