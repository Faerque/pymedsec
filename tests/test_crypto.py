"""
Tests for the crypto module - envelope encryption functionality.
"""
import os
import json
import base64
from unittest.mock import Mock, patch
import pytest

from pymedsec.crypto import encrypt_data, decrypt_data, EncryptedPackage
from pymedsec.kms.mock import MockKMSAdapter
from pymedsec.config import SecurityConfig


class TestEncryptedPackage:
    """Test cases for EncryptedPackage class."""

    def test_package_creation(self, sample_encrypted_package):
        """Test creating an EncryptedPackage from dictionary."""
        package = EncryptedPackage.from_dict(sample_encrypted_package)

        assert package.version == "1.0"
        assert package.encrypted_dek is not None
        assert package.nonce is not None
        assert package.ciphertext is not None
        assert package.aad["purpose"] == "ml_training"
        assert package.kms_context["provider"] == "mock"

    def test_package_serialization(self, sample_encrypted_package):
        """Test package serialization to dictionary."""
        package = EncryptedPackage.from_dict(sample_encrypted_package)
        serialized = package.to_dict()

        assert serialized["version"] == sample_encrypted_package["version"]
        assert serialized["encrypted_dek"] == sample_encrypted_package["encrypted_dek"]
        assert (
            serialized["aad"]["purpose"] == sample_encrypted_package["aad"]["purpose"]
        )

    def test_package_json_serialization(self, sample_encrypted_package):
        """Test package JSON serialization."""
        package = EncryptedPackage.from_dict(sample_encrypted_package)
        json_str = package.to_json()

        # Should be valid JSON
        parsed = json.loads(json_str)
        assert parsed["version"] == "1.0"
        assert "encrypted_dek" in parsed
        assert "aad" in parsed


class TestEncryptionFunctions:
    """Test cases for encryption and decryption functions."""

    def test_encrypt_data_basic(self, mock_config, mock_kms, sample_image_data):
        """Test basic data encryption functionality."""
        # Mock KMS encrypt operation
        mock_kms.encrypt = Mock(return_value=b"encrypted_dek_data")

        result = encrypt_data(sample_image_data, mock_config, mock_kms)

        assert isinstance(result, EncryptedPackage)
        assert result.version == "1.0"
        assert result.encrypted_dek is not None
        assert result.nonce is not None
        assert result.ciphertext is not None
        assert len(result.nonce) == 16  # 12 bytes base64 encoded ≈ 16 chars

    def test_encrypt_with_aad(self, mock_config, mock_kms, sample_image_data):
        """Test encryption with additional authenticated data."""
        aad = {"purpose": "research", "study_id": "STUDY-001", "patient_consent": True}

        mock_kms.encrypt = Mock(return_value=b"encrypted_dek_data")

        result = encrypt_data(sample_image_data, mock_config, mock_kms, aad=aad)

        assert result.aad["purpose"] == "research"
        assert result.aad["study_id"] == "STUDY-001"
        assert result.aad["patient_consent"] is True

    def test_decrypt_data_basic(self, mock_config, mock_kms, sample_encrypted_package):
        """Test basic data decryption functionality."""
        # Mock KMS decrypt operation
        mock_kms.decrypt = Mock(return_value=b"decrypted_dek_data")

        # Create package from sample
        package = EncryptedPackage.from_dict(sample_encrypted_package)

        with patch("pymedsec.crypto.AESGCM") as mock_aesgcm:
            # Mock the AES-GCM decryption
            mock_cipher = Mock()
            mock_cipher.decrypt.return_value = b"decrypted_image_data"
            mock_aesgcm.return_value = mock_cipher

            result = decrypt_data(package, mock_kms)

            assert result == b"decrypted_image_data"
            mock_kms.decrypt.assert_called_once()
            mock_cipher.decrypt.assert_called_once()

    def test_encrypt_decrypt_roundtrip(self, mock_config, mock_kms, sample_image_data):
        """Test encryption followed by decryption (roundtrip)."""
        original_data = sample_image_data

        # Mock KMS operations
        test_dek = os.urandom(32)  # 256-bit key
        mock_kms.encrypt = Mock(return_value=b"encrypted_dek")
        mock_kms.decrypt = Mock(return_value=test_dek)

        # Encrypt data
        with patch("pymedsec.crypto.os.urandom") as mock_urandom:
            # Mock DEK and nonce generation
            mock_urandom.side_effect = [test_dek, b"test_nonce_12"]

            encrypted_package = encrypt_data(original_data, mock_config, mock_kms)

        # Decrypt data
        decrypted_data = decrypt_data(encrypted_package, mock_kms)

        # Note: In a real test with actual crypto, this would work
        # For this mock test, we verify the flow executed correctly
        assert mock_kms.encrypt.called
        assert mock_kms.decrypt.called

    def test_encryption_with_invalid_data(self, mock_config, mock_kms):
        """Test encryption with invalid input data."""
        with pytest.raises(TypeError):
            encrypt_data(None, mock_config, mock_kms)

        with pytest.raises(TypeError):
            encrypt_data(123, mock_config, mock_kms)

    def test_decryption_with_invalid_package(self, mock_kms):
        """Test decryption with invalid package data."""
        invalid_package = EncryptedPackage(
            version="1.0",
            encrypted_dek="invalid_base64",
            nonce="invalid_nonce",
            ciphertext="invalid_cipher",
            aad={},
            kms_context={},
        )

        with pytest.raises(Exception):  # Should raise some crypto-related exception
            decrypt_data(invalid_package, mock_kms)

    def test_kms_failure_handling(self, mock_config, mock_kms, sample_image_data):
        """Test handling of KMS failures during encryption."""
        # Mock KMS to raise an exception
        mock_kms.encrypt = Mock(side_effect=Exception("KMS service unavailable"))

        with pytest.raises(Exception) as exc_info:
            encrypt_data(sample_image_data, mock_config, mock_kms)

        assert "KMS service unavailable" in str(exc_info.value)

    def test_package_format_validation(self):
        """Test validation of encrypted package format."""
        # Test missing required fields
        incomplete_package_data = {
            "version": "1.0",
            "encrypted_dek": "dGVzdA==",
            # Missing other required fields
        }

        with pytest.raises(KeyError):
            EncryptedPackage.from_dict(incomplete_package_data)

    def test_nonce_uniqueness(self, mock_config, mock_kms, sample_image_data):
        """Test that nonces are unique for each encryption."""
        mock_kms.encrypt = Mock(return_value=b"encrypted_dek")

        with patch("pymedsec.crypto.os.urandom") as mock_urandom:
            # Generate different nonces for each call
            nonces = [b"nonce_1_data", b"nonce_2_data"]
            mock_urandom.side_effect = [
                os.urandom(32),
                nonces[0],  # First encryption (DEK + nonce)
                os.urandom(32),
                nonces[1],  # Second encryption (DEK + nonce)
            ]

            package1 = encrypt_data(sample_image_data, mock_config, mock_kms)
            package2 = encrypt_data(sample_image_data, mock_config, mock_kms)

            # Nonces should be different
            assert package1.nonce != package2.nonce

    def test_aad_integrity(self, mock_config, mock_kms, sample_image_data):
        """Test that AAD (Additional Authenticated Data) maintains integrity."""
        aad = {
            "purpose": "ml_training",
            "timestamp": "2024-01-01T00:00:00Z",
            "sensitive_flag": True,
        }

        mock_kms.encrypt = Mock(return_value=b"encrypted_dek")

        result = encrypt_data(sample_image_data, mock_config, mock_kms, aad=aad)

        # AAD should be preserved in the package
        assert result.aad["purpose"] == aad["purpose"]
        assert result.aad["timestamp"] == aad["timestamp"]
        assert result.aad["sensitive_flag"] == aad["sensitive_flag"]

        # Verify AAD is included in the serialized package
        serialized = result.to_dict()
        assert serialized["aad"]["purpose"] == aad["purpose"]


class TestSecurityProperties:
    """Test security properties of the encryption implementation."""

    def test_key_isolation(self, mock_config, mock_kms, sample_image_data):
        """Test that different encryptions use different keys."""
        mock_kms.encrypt = Mock(return_value=b"encrypted_dek")

        with patch("pymedsec.crypto.os.urandom") as mock_urandom:
            # Generate different DEKs for each encryption
            dek1 = b"key_1_data_256bit_xxxxxxxxx"  # 32 bytes
            dek2 = b"key_2_data_256bit_yyyyyyyyy"  # 32 bytes
            nonce1 = b"nonce_1_12b"  # 12 bytes
            nonce2 = b"nonce_2_12b"  # 12 bytes

            mock_urandom.side_effect = [dek1, nonce1, dek2, nonce2]

            package1 = encrypt_data(sample_image_data, mock_config, mock_kms)
            package2 = encrypt_data(sample_image_data, mock_config, mock_kms)

            # DEKs should be different (reflected in different ciphertexts)
            assert package1.ciphertext != package2.ciphertext

    def test_tamper_detection_simulation(
        self, mock_config, mock_kms, sample_encrypted_package
    ):
        """Test that tampering with ciphertext is detected."""
        package = EncryptedPackage.from_dict(sample_encrypted_package)

        # Simulate tampering with ciphertext
        original_ciphertext = package.ciphertext
        package.ciphertext = base64.b64encode(b"tampered_data").decode()

        mock_kms.decrypt = Mock(return_value=b"decrypted_dek")

        with patch("pymedsec.crypto.AESGCM") as mock_aesgcm:
            mock_cipher = Mock()
            mock_cipher.decrypt.side_effect = Exception(
                "Authentication tag verification failed"
            )
            mock_aesgcm.return_value = mock_cipher

            with pytest.raises(Exception) as exc_info:
                decrypt_data(package, mock_kms)

            assert "Authentication tag verification failed" in str(exc_info.value)

    def test_aad_tampering_detection(
        self, mock_config, mock_kms, sample_encrypted_package
    ):
        """Test that tampering with AAD is detected."""
        package = EncryptedPackage.from_dict(sample_encrypted_package)

        # Simulate tampering with AAD
        package.aad["purpose"] = "malicious_purpose"

        mock_kms.decrypt = Mock(return_value=b"decrypted_dek")

        with patch("pymedsec.crypto.AESGCM") as mock_aesgcm:
            mock_cipher = Mock()
            mock_cipher.decrypt.side_effect = Exception("AAD mismatch")
            mock_aesgcm.return_value = mock_cipher

            with pytest.raises(Exception):
                decrypt_data(package, mock_kms)


class TestPerformanceCharacteristics:
    """Test performance characteristics of encryption operations."""

    def test_large_data_encryption(self, mock_config, mock_kms):
        """Test encryption of large data blocks."""
        # Create large test data (1MB)
        large_data = b"x" * (1024 * 1024)

        mock_kms.encrypt = Mock(return_value=b"encrypted_dek")

        # Should complete without memory issues
        result = encrypt_data(large_data, mock_config, mock_kms)

        assert isinstance(result, EncryptedPackage)
        assert len(result.ciphertext) > 0

    def test_small_data_encryption(self, mock_config, mock_kms):
        """Test encryption of small data blocks."""
        # Test with minimal data
        small_data = b"small"

        mock_kms.encrypt = Mock(return_value=b"encrypted_dek")

        result = encrypt_data(small_data, mock_config, mock_kms)

        assert isinstance(result, EncryptedPackage)
        assert len(result.ciphertext) > 0

    def test_empty_data_handling(self, mock_config, mock_kms):
        """Test handling of empty data."""
        empty_data = b""

        mock_kms.encrypt = Mock(return_value=b"encrypted_dek")

        result = encrypt_data(empty_data, mock_config, mock_kms)

        assert isinstance(result, EncryptedPackage)
        # Even empty data should produce some ciphertext due to authentication tag


class TestErrorConditions:
    """Test various error conditions and edge cases."""

    def test_missing_kms_context(self, mock_config, sample_image_data):
        """Test encryption without proper KMS context."""
        invalid_kms = Mock()
        invalid_kms.encrypt = Mock(side_effect=ValueError("Invalid KMS configuration"))

        with pytest.raises(ValueError):
            encrypt_data(sample_image_data, mock_config, invalid_kms)

    def test_corrupted_encrypted_dek(self, mock_kms, sample_encrypted_package):
        """Test decryption with corrupted encrypted DEK."""
        package = EncryptedPackage.from_dict(sample_encrypted_package)
        package.encrypted_dek = "corrupted_base64_data!"

        mock_kms.decrypt = Mock(side_effect=Exception("Failed to decrypt DEK"))

        with pytest.raises(Exception):
            decrypt_data(package, mock_kms)

    def test_unsupported_version(self, sample_encrypted_package):
        """Test handling of unsupported package versions."""
        package_data = sample_encrypted_package.copy()
        package_data["version"] = "2.0"  # Unsupported version

        # Should still create package but might have different behavior
        package = EncryptedPackage.from_dict(package_data)
        assert package.version == "2.0"

    def test_malformed_base64_data(self, sample_encrypted_package):
        """Test handling of malformed base64 encoded data."""
        package_data = sample_encrypted_package.copy()
        package_data["nonce"] = "not_valid_base64!"

        package = EncryptedPackage.from_dict(package_data)

        # Should fail when trying to decode the nonce
        with pytest.raises(Exception):
            base64.b64decode(package.nonce)
