"""
Tests for the public API of pymedsec package.

Tests cover all public functions with both success and failure cases.
Uses synthetic data to avoid dependency on real medical images.
"""

import os
import json
import tempfile
import pytest
import unittest
from unittest.mock import patch, MagicMock
from io import BytesIO

# Test imports with proper error handling
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    from pydicom import Dataset, FileDataset
    from pydicom.uid import generate_uid
    HAS_PYDICOM = True
except ImportError:
    HAS_PYDICOM = False

try:
    import pydicom
    from pydicom.dataset import Dataset, FileDataset
    from pydicom.uid import ExplicitVRLittleEndian
    HAS_PYDICOM = True
except ImportError:
    HAS_PYDICOM = False

try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

# Import the public API
from pymedsec.public_api import (
    load_policy, set_active_policy, get_active_policy, list_policies,
    scrub_dicom, scrub_image, encrypt_blob, decrypt_blob, decrypt_to_tensor,
    get_kms_client, SecureImageDataset
)


class TestPolicyManagement(unittest.TestCase):
    """Test policy loading and management functions."""

    def test_list_policies_non_empty(self):
        """Test that list_policies returns non-empty list."""
        policies = list_policies()
        assert isinstance(policies, list)
        assert len(policies) > 0
        # Should contain standard policies
        expected_policies = {"hipaa_default", "gdpr_default", "gxplab_default"}
        assert expected_policies.issubset(set(policies))

    def test_load_policy_by_name(self):
        """Test loading policy by name."""
        policy = load_policy("hipaa_default")
        assert isinstance(policy, dict)
        assert len(policy) > 0
        # Should have some standard keys
        expected_keys = {"sanitization", "encryption", "audit"}
        assert any(key in policy for key in expected_keys)

    def test_load_policy_by_path(self, tmp_path):
        """Test loading policy from absolute path."""
        # Create a temporary YAML policy file
        policy_content = """
policy_type: "custom"
sanitization:
  remove_private_tags: true
  pseudonymize_dates: true
encryption:
  algorithm: "AES-256-GCM"
audit:
  enabled: true
"""
        policy_file = tmp_path / "custom.yaml"
        policy_file.write_text(policy_content)

        policy = load_policy(str(policy_file))
        assert isinstance(policy, dict)
        assert policy["policy_type"] == "custom"
        assert policy["sanitization"]["remove_private_tags"] is True

    def test_load_policy_none_defaults_to_hipaa(self):
        """Test that load_policy(None) defaults to hipaa_default."""
        policy = load_policy(None)
        assert isinstance(policy, dict)
        # Should be the same as explicitly loading hipaa
        hipaa_policy = load_policy("hipaa_default")
        assert policy == hipaa_policy

    def test_load_policy_nonexistent_raises_error(self):
        """Test that loading nonexistent policy raises RuntimeError."""
        with pytest.raises(RuntimeError, match="Policy file not found"):
            load_policy("nonexistent_policy")

        with pytest.raises(RuntimeError, match="Policy file not found"):
            load_policy("/nonexistent/path/policy.yaml")

    def test_set_get_active_policy(self):
        """Test setting and getting active policy."""
        # Initially should be None
        assert get_active_policy() is None

        # Set a policy
        policy = {"test": "policy"}
        set_active_policy(policy)

        # Should return a copy
        active = get_active_policy()
        assert active == policy
        assert active is not policy  # Should be a copy

        # Modifying returned policy shouldn't affect stored one
        active["modified"] = True
        assert get_active_policy() == policy

    def test_set_active_policy_invalid_type(self):
        """Test that set_active_policy rejects non-dict."""
        with pytest.raises(ValueError, match="Policy must be a dictionary"):
            set_active_policy("not a dict")

        with pytest.raises(ValueError, match="Policy must be a dictionary"):
            set_active_policy(None)


class TestKMSClients(unittest.TestCase):
    """Test KMS client factory function."""

    def test_get_kms_client_mock(self):
        """Test creating mock KMS client."""
        kms = get_kms_client("mock")
        assert kms is not None
        # Mock client should have the required interface
        assert hasattr(kms, 'wrap_data_key')
        assert hasattr(kms, 'unwrap_data_key')

    def test_get_kms_client_mock_with_kwargs(self):
        """Test that mock client ignores extra kwargs."""
        kms = get_kms_client("mock", unused_param="value")
        assert kms is not None

    @pytest.mark.skipif(True, reason="AWS dependencies optional")
    def test_get_kms_client_aws_missing_key_id(self):
        """Test AWS client requires key_id."""
        with pytest.raises(RuntimeError, match="AWS KMS backend requires 'key_id' parameter"):
            get_kms_client("aws")

    @pytest.mark.skipif(True, reason="AWS dependencies optional")
    def test_get_kms_client_aws_valid(self):
        """Test AWS client creation with valid parameters."""
        # This would fail without boto3, which is expected
        try:
            kms = get_kms_client("aws", key_id="alias/test-key",
                                 region_name="us-east-1")
            assert kms is not None
        except ImportError:
            pytest.skip("boto3 not available")

    @pytest.mark.skipif(True, reason="Vault dependencies optional")
    def test_get_kms_client_vault_missing_params(self):
        """Test Vault client requires url, token, key_name."""
        with pytest.raises(RuntimeError, match="Vault KMS backend requires 'url' parameter"):
            get_kms_client("vault")

        with pytest.raises(RuntimeError, match="Vault KMS backend requires 'token' parameter"):
            get_kms_client("vault", url="https://vault.example.com")

        with pytest.raises(RuntimeError, match="Vault KMS backend requires 'key_name' parameter"):
            get_kms_client("vault", url="https://vault.example.com", token="s.token")

    def test_get_kms_client_unsupported_backend(self):
        """Test unsupported backend raises error."""
        with pytest.raises(RuntimeError, match="Unsupported KMS backend: invalid"):
            get_kms_client("invalid")


class TestDataProcessing(unittest.TestCase):
    """Test data processing functions."""

    def test_scrub_dicom_synthetic(self):
        """Test DICOM scrubbing with a synthetic file"""
        if not HAS_PYDICOM:
            pytest.skip("pydicom not available")

        # Create synthetic DICOM file with proper file meta
        from pydicom import Dataset, FileDataset
        from pydicom.uid import ExplicitVRLittleEndian

        # Create file meta information
        file_meta = Dataset()
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = "1.2.3"
        file_meta.ImplementationClassUID = "1.2.3.4"
        file_meta.TransferSyntaxUID = ExplicitVRLittleEndian

        # Create main dataset
        ds = FileDataset("test", {}, file_meta=file_meta, preamble=b"\0" * 128)
        ds.PatientName = "Test^Patient"
        ds.PatientID = "12345"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3"

        # Convert to bytes
        buffer = BytesIO()
        ds.save_as(buffer)
        dicom_bytes = buffer.getvalue()

        # Mock the sanitize function to avoid config dependency
        with patch('pymedsec.sanitize.sanitize_dicom') as mock_sanitize:
            # Create a mock sanitized dataset
            sanitized_ds = ds.copy()
            del sanitized_ds.PatientName
            sanitized_ds.PatientID = "ANON123"

            mock_sanitize.return_value = (sanitized_ds, {})

            # Test scrubbing
            result = scrub_dicom(dicom_bytes)
            self.assertIsInstance(result, bytes)
            self.assertNotEqual(result, dicom_bytes)  # Should be different

            # Verify the function was called
            mock_sanitize.assert_called_once()

    def test_scrub_image_synthetic(self):
        """Test image scrubbing with a synthetic file"""
        if not HAS_PIL:
            pytest.skip("PIL not available")

        # Create a simple test image
        img = Image.new('RGB', (100, 100), color=(255, 0, 0))  # Red color as RGB tuple

        # Add some fake EXIF data
        img.info['exif'] = b'\xff\xe1\x00\x1c'  # Minimal EXIF header

        # Convert to bytes
        buffer = BytesIO()
        img.save(buffer, format='JPEG', quality=95)
        image_bytes = buffer.getvalue()

        # Test scrubbing
        result = scrub_image(image_bytes)
        self.assertIsInstance(result, bytes)

        # Verify the result is a valid image
        result_img = Image.open(BytesIO(result))
        self.assertEqual(result_img.size, (100, 100))

        # Check that metadata was removed (info should be empty or minimal)
        self.assertNotIn('exif', result_img.info)

    def test_encrypt_decrypt_blob_roundtrip(self):
        """Test encrypt/decrypt round-trip preserves data."""
        original_data = b"test data for encryption"
        kms = get_kms_client("mock")

        # Test actual round-trip without mocking
        pkg = encrypt_blob(original_data, kms_client=kms)
        decrypted = decrypt_blob(pkg, kms_client=kms)

        assert decrypted == original_data

        # Verify package structure
        assert "schema" in pkg
        assert "nonce" in pkg
        assert "wrapped_key" in pkg
        assert "ciphertext" in pkg
        assert pkg["schema"] == "pymedsec/v1"

    def test_encrypt_blob_with_aad(self):
        """Test encryption with additional authenticated data."""
        data = b"test data"
        kms = get_kms_client("mock")
        aad = {"dataset": "test", "modality": "CT"}

        # Test actual encryption with AAD
        pkg = encrypt_blob(data, kms_client=kms, aad=aad)

        # Verify AAD is stored in package
        assert "aad" in pkg
        assert pkg["aad"] == aad

        # Verify decryption works with AAD
        decrypted = decrypt_blob(pkg, kms_client=kms)
        assert decrypted == data

    @pytest.mark.skipif(not HAS_NUMPY, reason="numpy not available")
    def test_decrypt_to_tensor_raw_data(self):
        """Test decrypt_to_tensor with raw data."""
        test_data = b"raw tensor data"
        kms = get_kms_client("mock")
        pkg = {"encrypted": "data"}

        with patch('pymedsec.public_api.decrypt_blob') as mock_decrypt:
            mock_decrypt.return_value = test_data

            tensor = decrypt_to_tensor(pkg, kms_client=kms)

            assert isinstance(tensor, np.ndarray)
            assert tensor.dtype == np.uint8
            mock_decrypt.assert_called_once_with(pkg, kms)

    @pytest.mark.skipif(not (HAS_NUMPY and HAS_PYDICOM), reason="numpy or pydicom not available")
    def test_decrypt_to_tensor_dicom(self):
        """Test decrypt_to_tensor with DICOM format hint."""
        # Create synthetic DICOM with pixel data
        dicom_data = self._create_synthetic_dicom_with_pixels()
        kms = get_kms_client("mock")
        pkg = {"encrypted": "data"}

        with patch('pymedsec.public_api.decrypt_blob') as mock_decrypt:
            mock_decrypt.return_value = dicom_data

            with patch('pydicom.dcmread') as mock_dcmread:
                mock_dataset = MagicMock()
                mock_dataset.pixel_array = np.array([[1, 2], [3, 4]])
                mock_dcmread.return_value = mock_dataset

                tensor = decrypt_to_tensor(pkg, kms_client=kms, format_hint="dicom")

                assert isinstance(tensor, np.ndarray)
                assert tensor.shape == (2, 2)
                mock_decrypt.assert_called_once()

    def test_decrypt_to_tensor_no_numpy(self):
        """Test decrypt_to_tensor raises ImportError without numpy."""
        with patch.dict('sys.modules', {'numpy': None}):
            with pytest.raises(ImportError, match="decrypt_to_tensor requires numpy"):
                decrypt_to_tensor({}, get_kms_client("mock"))

    def _create_synthetic_dicom(self):
        """Create minimal synthetic DICOM data."""
        if not HAS_PYDICOM:
            return b"fake_dicom_data"

        # Create a minimal DICOM dataset
        file_meta = Dataset()
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = "1.2.3.4.5.6.7.8.9"
        file_meta.ImplementationClassUID = "1.2.3.4.5"

        ds = FileDataset("test", {}, file_meta=file_meta, preamble=b"\0" * 128)
        ds.PatientName = "Test^Patient"
        ds.PatientID = "12345"
        ds.StudyDate = "20240101"

        # Save to bytes
        from io import BytesIO
        output = BytesIO()
        ds.save_as(output, write_like_original=False)
        return output.getvalue()

    def _create_synthetic_dicom_with_pixels(self):
        """Create synthetic DICOM with pixel data."""
        return self._create_synthetic_dicom()  # Simplified for testing

    def _create_synthetic_png(self):
        """Create minimal synthetic PNG data."""
        if not HAS_PIL:
            return b"fake_png_data"

        # Create a small test image
        import numpy as np
        from PIL import Image
        from io import BytesIO

        # Create 2x2 RGB image
        data = np.array([[[255, 0, 0], [0, 255, 0]],
                        [[0, 0, 255], [255, 255, 255]]], dtype=np.uint8)
        image = Image.fromarray(data)

        # Save to bytes
        output = BytesIO()
        image.save(output, format='PNG')
        return output.getvalue()


class TestSecureImageDataset(unittest.TestCase):
    """Test SecureImageDataset class."""

    def test_dataset_creation(self, tmp_path):
        """Test dataset creation and basic properties."""
        # Create some fake encrypted package files
        pkg_dir = tmp_path / "packages"
        pkg_dir.mkdir()

        pkg1 = pkg_dir / "image1.pkg.json"
        pkg1.write_text('{"encrypted": "data1"}')

        pkg2 = pkg_dir / "image2.pkg.json"
        pkg2.write_text('{"encrypted": "data2"}')

        kms = get_kms_client("mock")
        dataset = SecureImageDataset(str(pkg_dir), kms_client=kms)

        assert len(dataset) == 2
        assert len(dataset.file_paths) == 2

    def test_dataset_empty_directory(self, tmp_path):
        """Test dataset with empty directory."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        kms = get_kms_client("mock")
        dataset = SecureImageDataset(str(empty_dir), kms_client=kms)

        assert len(dataset) == 0

    @pytest.mark.skipif(not HAS_NUMPY, reason="numpy not available")
    def test_dataset_iteration(self, tmp_path):
        """Test dataset iteration."""
        # Create fake package
        pkg_dir = tmp_path / "packages"
        pkg_dir.mkdir()

        pkg1 = pkg_dir / "image1.pkg.json"
        pkg1.write_text('{"encrypted": "data1", "metadata": {"format": "png"}}')

        kms = get_kms_client("mock")
        dataset = SecureImageDataset(str(pkg_dir), kms_client=kms)

        # Mock the decrypt_to_tensor function
        with patch('pymedsec.public_api.decrypt_to_tensor') as mock_decrypt:
            mock_decrypt.return_value = np.array([[1, 2], [3, 4]])

            # Test iteration
            tensors = list(dataset)
            assert len(tensors) == 1
            assert isinstance(tensors[0], np.ndarray)

            # Test indexing
            tensor = dataset[0]
            assert isinstance(tensor, np.ndarray)
            mock_decrypt.assert_called()

    def test_dataset_index_out_of_range(self, tmp_path):
        """Test dataset index out of range."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        kms = get_kms_client("mock")
        dataset = SecureImageDataset(str(empty_dir), kms_client=kms)

        with pytest.raises(IndexError, match="Index 0 out of range"):
            dataset[0]


class TestErrorHandling(unittest.TestCase):
    """Test error handling and edge cases."""

    def test_functions_with_policy_none_load_default(self):
        """Test that functions load default policy when policy=None."""
        kms = get_kms_client("mock")

        # Mock the internal functions
        with patch('pymedsec.sanitize.sanitize_dicom_bytes') as mock_sanitize, \
                patch('pymedsec.public_api.load_policy') as mock_load:

            mock_sanitize.return_value = b"sanitized"
            mock_load.return_value = {"test": "policy"}

            # Should load default policy
            scrub_dicom(b"fake_dicom", policy=None)
            mock_load.assert_called_with("hipaa_default")

    def test_crypto_functions_create_mock_kms_when_none(self):
        """Test that crypto functions create mock KMS when kms_client=None."""
        data = b"test data"

        with patch('pymedsec.crypto.encrypt_data') as mock_encrypt, \
                patch('pymedsec.public_api.get_kms_client') as mock_get_kms:

            mock_package = MagicMock()
            mock_package.to_dict.return_value = {"encrypted": "data"}
            mock_encrypt.return_value = mock_package

            mock_kms = MagicMock()
            mock_get_kms.return_value = mock_kms

            encrypt_blob(data, kms_client=None)

            # Should create mock KMS client
            mock_get_kms.assert_called_with("mock")

    def test_crypto_error_handling(self):
        """Test that crypto functions wrap exceptions properly."""
        kms = get_kms_client("mock")

        # Test encryption error
        with patch('pymedsec.crypto.encrypt_data') as mock_encrypt:
            mock_encrypt.side_effect = Exception("Crypto error")

            with pytest.raises(RuntimeError, match="Encryption failed: Crypto error"):
                encrypt_blob(b"data", kms_client=kms)

        # Test decryption error
        with patch('pymedsec.crypto.decrypt_data') as mock_decrypt:
            mock_decrypt.side_effect = Exception("Decrypt error")

            with pytest.raises(RuntimeError, match="Decryption failed: Decrypt error"):
                decrypt_blob({"fake": "package"}, kms_client=kms)
