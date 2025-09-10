# SPDX-License-Identifier: Apache-2.0

"""
Clean test configuration and fixtures for pymedsec package.
"""

from pymedsec.kms.mock import MockKMSAdapter
import os
import tempfile
from pathlib import Path
import pytest
from unittest.mock import MagicMock, patch
import yaml

# Set up test environment BEFORE any imports
TEST_ENV = {
    "IMGSEC_POLICY": str(Path(__file__).parent.parent / "policies" / "hipaa_default.yaml"),
    "IMGSEC_KMS_BACKEND": "mock",
    "IMGSEC_KMS_KEY_REF": "mock-test-key",
    "IMGSEC_AUDIT_PATH": "/tmp/test_audit.jsonl",
    "IMGSEC_ACTOR": "test-user",
}

# Apply test environment
os.environ.update(TEST_ENV)


@pytest.fixture(autouse=True)
def setup_test_environment(tmp_path, monkeypatch):
    """Set up the test environment with required variables."""
    # Create a temporary policy file
    policy_file = tmp_path / "test_policy.yaml"
    policy_content = {
        "schema_version": "1.0",
        "name": "Test Policy",
        "sanitization": {
            "dicom": {
                "remove_private_tags": True,
                "regenerate_uids": True,
                "preserve_technical_tags": True,
            }
        },
        "encryption": {
            "algorithm": "AES-256-GCM",
            "key_rotation_days": 90,
            "require_kms": True,
            "nonce_size_bits": 96,
        },
        "security": {
            "allow_plaintext_disk": True,
            "require_policy_match": False,
        },
        "audit": {
            "log_all_operations": True,
            "include_file_hashes": True,
            "retention_days": 7,
        },
        "compliance": {
            "hipaa_mode": True,
        }
    }

    with open(policy_file, 'w') as f:
        yaml.dump(policy_content, f)

    test_env = {
        "IMGSEC_POLICY": str(policy_file),
        "IMGSEC_KMS_BACKEND": "mock",
        "IMGSEC_KMS_KEY_REF": "mock-test-key",
        "IMGSEC_AUDIT_PATH": str(tmp_path / "audit.jsonl"),
        "IMGSEC_ACTOR": "test-user",
    }

    with patch.dict(os.environ, test_env, clear=False):
        # Mock the config module to avoid global state issues
        from pymedsec import config
        mock_security_config_obj = MagicMock()
        mock_security_config_obj.policy_hash = "test_hash_12345"
        mock_security_config_obj.audit_path = str(tmp_path / "audit.jsonl")
        mock_security_config_obj.actor = "test-user"
        mock_security_config_obj.kms_backend = "mock"
        mock_security_config_obj.kms_key_ref = "mock-test-key"
        mock_security_config_obj.allows_plaintext_disk.return_value = True
        mock_security_config_obj.requires_ocr_redaction.return_value = False
        # Provide real bytes for HMAC key
        signing_key = b"test_signing_key_32_bytes_long_123"
        mock_security_config_obj.audit_signing_key = signing_key
        
        monkeypatch.setattr(config, '_config', mock_security_config_obj)
        yield


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    temp_path = tempfile.mkdtemp()
    yield Path(temp_path)
    import shutil
    shutil.rmtree(temp_path)


@pytest.fixture
def mock_kms():
    """Create a mock KMS adapter for testing."""
    return MockKMSAdapter()


@pytest.fixture
def mock_security_config(tmp_path):
    """Create a properly mocked SecurityConfig."""
    config = MagicMock()
    config.policy_path = str(tmp_path / "test_policy.yaml")
    config.kms_backend = "mock"
    config.kms_key_ref = "mock-test-key"
    config.audit_path = str(tmp_path / "audit.jsonl")
    config.actor = "test-user"
    config.policy_hash = "test_hash_12345"
    config.allows_plaintext_disk.return_value = True
    config.requires_ocr_redaction.return_value = False

    config.policy = {
        "name": "Test Policy",
        "sanitization": {"dicom": {"remove_private_tags": True}},
        "encryption": {"algorithm": "AES-256-GCM"},
        "audit": {"log_all_operations": True},
        "security": {"allow_plaintext_disk": True}
    }

    config.get_sanitization_config.return_value = config.policy["sanitization"]
    config.get_encryption_config.return_value = config.policy["encryption"]
    config.get_audit_config.return_value = config.policy["audit"]

    return config


@pytest.fixture
def sample_image_data():
    """Create sample image data for testing."""
    # Simple test data
    return b"test image data for encryption testing"


@pytest.fixture
def mock_config(tmp_path):
    """Create a mock config for testing - alias for mock_security_config."""
    config = MagicMock()
    config.policy_path = str(tmp_path / "test_policy.yaml")
    config.kms_backend = "mock"
    config.kms_key_ref = "mock-test-key"
    config.audit_path = str(tmp_path / "audit.jsonl")
    config.actor = "test-user"
    config.policy_hash = "test_hash_12345"
    config.allows_plaintext_disk.return_value = True
    config.requires_ocr_redaction.return_value = False
    # Provide real bytes for HMAC key
    config.audit_signing_key = b"test_signing_key_32_bytes_long_123"

    config.policy = {
        "name": "Test Policy",
        "sanitization": {"dicom": {"remove_private_tags": True}},
        "encryption": {"algorithm": "AES-256-GCM"},
        "audit": {"log_all_operations": True},
        "security": {"allow_plaintext_disk": True}
    }

    config.get_sanitization_config.return_value = config.policy["sanitization"]
    config.get_encryption_config.return_value = config.policy["encryption"]
    config.get_audit_config.return_value = config.policy["audit"]

    return config


@pytest.fixture
def sample_dicom_metadata():
    """Create sample DICOM metadata for testing."""
    return {
        "PatientName": "Test^Patient",
        "PatientID": "12345",
        "PatientBirthDate": "19800101",
        "StudyInstanceUID": "1.2.3.4.5.6.7.8.9.0",
        "SeriesInstanceUID": "1.2.3.4.5.6.7.8.9.1",
        "SOPInstanceUID": "1.2.3.4.5.6.7.8.9.2",
        "Modality": "CT",
        "StudyDate": "20230101",
        "SeriesDate": "20230101",
        "AcquisitionDate": "20230101",
        "ContentDate": "20230101",
        "StudyTime": "120000",
        "SeriesTime": "120000",
        "AcquisitionTime": "120000",
        "ContentTime": "120000",
        "AccessionNumber": "ACC123456",
        "ReferringPhysicianName": "Dr^Smith",
        "PerformingPhysicianName": "Dr^Jones",
        "OperatorsName": "Tech^User",
        "InstitutionName": "Test Hospital",
        "InstitutionAddress": "123 Test St, Test City",
        "StationName": "CT01",
        "InstitutionalDepartmentName": "Radiology"
    }


@pytest.fixture
def sample_encrypted_package():
    """Create a sample encrypted package for testing."""
    return {
        "schema": "imgsec/v1",
        "kms_key_ref": "test-key-123",
        "nonce_b64": "dGVzdC1ub25jZS0xMjM=",
        "aad_b64": "dGVzdC1hYWQtZGF0YQ==",
        "wrapped_key_b64": "dGVzdC1lbmNyeXB0ZWQta2V5LWRhdGE=",
        "ciphertext_b64": "dGVzdC1jaXBoZXJ0ZXh0LWRhdGE=",
    }
