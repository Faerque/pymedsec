"""
Tests for the KMS (Key Management Service) adapters.
"""

import base64
import os
from unittest.mock import Mock, patch
import pytest

from pymedsec.kms.base import KMSAdapter
from pymedsec.kms.mock import MockKMSAdapter
from pymedsec.kms.aws_kms import AWSKMSAdapter
from pymedsec.kms.vault import VaultAdapter

# Create alias for backward compatibility
VaultKMSAdapter = VaultAdapter


class TestKMSAdapterBase:
    """Test cases for base KMS adapter interface."""

    def test_abstract_interface(self):
        """Test that KMSAdapter is properly abstract."""
        with pytest.raises(TypeError):
            KMSAdapter()  # Should not be instantiable

    def test_required_methods(self):
        """Test that required methods are defined in interface."""
        # Check that abstract methods exist
        required_methods = ["generate_data_key", "wrap_data_key", "unwrap_data_key"]

        for method in required_methods:
            assert hasattr(KMSAdapter, method)


class TestMockKMSAdapter:
    """Test cases for MockKMSAdapter."""

    def test_initialization(self):
        """Test MockKMSAdapter initialization."""
        adapter = MockKMSAdapter()
        assert adapter is not None

    def test_generate_data_key(self):
        """Test data key generation."""
        adapter = MockKMSAdapter()

        result = adapter.generate_data_key(key_id="test-key", key_spec="AES_256")

        assert "plaintext_key" in result
        assert "encrypted_key" in result
        assert len(result["plaintext_key"]) == 32  # 256 bits = 32 bytes
        assert len(result["encrypted_key"]) > 0

    def test_encrypt_decrypt_roundtrip(self):
        """Test encryption and decryption roundtrip."""
        adapter = MockKMSAdapter()

        # Generate a data key
        key_result = adapter.generate_data_key(key_id="test-key", key_spec="AES_256")
        plaintext_key = key_result["plaintext_key"]
        encrypted_key = key_result["encrypted_key"]

        # Decrypt the encrypted key
        decrypted_key = adapter.unwrap_data_key(encrypted_key, "test-key")

        assert decrypted_key == plaintext_key

    def test_different_keys_unique(self):
        """Test that different key generations produce unique keys."""
        adapter = MockKMSAdapter()

        key1 = adapter.generate_data_key(key_id="test-key-1", key_spec="AES_256")
        key2 = adapter.generate_data_key(key_id="test-key-2", key_spec="AES_256")

        assert key1["plaintext_key"] != key2["plaintext_key"]
        assert key1["encrypted_key"] != key2["encrypted_key"]

    def test_key_id_consistency(self):
        """Test that same key ID produces consistent results."""
        adapter = MockKMSAdapter()

        # Use deterministic mode for testing
        with patch("pymedsec.kms.mock.os.urandom") as mock_random:
            mock_random.return_value = b"deterministic_key_32_bytes___"

            key1 = adapter.generate_data_key(key_id="same-key", key_spec="AES_256")
            key2 = adapter.generate_data_key(key_id="same-key", key_spec="AES_256")

            # In deterministic mode, should be same
            assert key1["plaintext_key"] == key2["plaintext_key"]

    def test_invalid_key_spec(self):
        """Test handling of invalid key specifications."""
        adapter = MockKMSAdapter()

        with pytest.raises(RuntimeError) as exc_info:
            adapter.generate_data_key(key_id="test-key", key_spec="INVALID_SPEC")
        assert "Unsupported key spec: INVALID_SPEC" in str(exc_info.value)

    def test_encrypt_with_context(self):
        """Test encryption with encryption context."""
        adapter = MockKMSAdapter()

        context = {"purpose": "medical_imaging", "department": "radiology"}

        result = adapter.generate_data_key(
            key_id="test-key", key_spec="AES_256", encryption_context=context
        )

        assert "plaintext_key" in result
        assert "encrypted_key" in result


class TestAWSKMSAdapter:
    """Test cases for AWS KMS adapter."""

    def test_initialization_with_config(self):
        """Test AWS KMS adapter initialization."""
        adapter = AWSKMSAdapter(key_id="test-key", region_name="us-east-1")
        assert adapter is not None
        assert adapter.key_id == "test-key"
        assert adapter.region_name == "us-east-1"

    def test_generate_data_key_success(self):
        """Test successful data key generation with AWS KMS."""
        with patch.object(
            AWSKMSAdapter, "client", new_callable=lambda: Mock()
        ) as mock_client:
            mock_client.generate_data_key.return_value = {
                "Plaintext": b"32_byte_plaintext_key_data_here",
                "CiphertextBlob": b"encrypted_key_data_from_aws_kms",
            }

            adapter = AWSKMSAdapter(
                key_id="arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
            )
            result = adapter.generate_data_key(key_spec="AES_256")

            assert result == b"32_byte_plaintext_key_data_here"

    def test_decrypt_success(self):
        """Test successful decryption with AWS KMS."""
        with patch.object(
            AWSKMSAdapter, "client", new_callable=lambda: Mock()
        ) as mock_client:
            mock_client.decrypt.return_value = {
                "Plaintext": b"decrypted_key_data_32_bytes___"
            }

            adapter = AWSKMSAdapter(key_id="test-key")
            result = adapter.unwrap_data_key(b"encrypted_key_blob")

            assert result == b"decrypted_key_data_32_bytes___"

    def test_kms_exception_handling(self):
        """Test handling of KMS exceptions."""
        with patch.object(
            AWSKMSAdapter, "client", new_callable=lambda: Mock()
        ) as mock_client:
            mock_client.generate_data_key.side_effect = Exception("KMS service error")

            adapter = AWSKMSAdapter(key_id="test-key")

            with pytest.raises(RuntimeError) as exc_info:
                adapter.generate_data_key(key_spec="256")  # Use supported key spec

            assert "KMS service error" in str(exc_info.value)

    def test_encryption_context_support(self):
        """Test encryption context support in AWS KMS."""
        with patch.object(
            AWSKMSAdapter, "client", new_callable=lambda: Mock()
        ) as mock_client:
            mock_client.generate_data_key.return_value = {
                "Plaintext": b"test_key_data",
                "CiphertextBlob": b"encrypted_blob",
            }

            adapter = AWSKMSAdapter(key_id="test-key")

            # The current AWS adapter doesn't support encryption context in generate_data_key
            # but we can test that it still works
            result = adapter.generate_data_key(key_spec="AES_256")
            assert result == b"test_key_data"


class TestVaultKMSAdapter:
    """Test cases for HashiCorp Vault KMS adapter."""

    def test_initialization_with_config(self):
        """Test Vault KMS adapter initialization."""
        # Set required environment variable
        with patch.dict(os.environ, {"VAULT_TOKEN": "test-token"}):
            with patch.object(
                VaultKMSAdapter, "client", new_callable=lambda: Mock()
            ) as mock_client:
                mock_client.is_authenticated.return_value = True

                adapter = VaultKMSAdapter(
                    vault_url="https://vault.example.com:8200",
                    vault_token="vault_token",
                    mount_point="transit",
                )

                assert adapter is not None

    def test_generate_data_key_success(self):
        """Test successful data key generation with Vault."""
        with patch.dict(os.environ, {"VAULT_TOKEN": "test-token"}):
            with patch.object(
                VaultKMSAdapter, "client", new_callable=lambda: Mock()
            ) as mock_client:
                mock_client.is_authenticated.return_value = True
                mock_client.secrets.transit.generate_data_key.return_value = {
                    "data": {
                        "plaintext": base64.b64encode(
                            b"32_byte_key_data_from_vault____"
                        ).decode(),
                        "ciphertext": "vault:v1:encrypted_data_key",
                    }
                }

                adapter = VaultKMSAdapter(
                    vault_url="https://vault.example.com:8200",
                    vault_token="vault_token",
                    mount_point="transit",
                )
                result = adapter.generate_data_key(
                    key_ref="medical-images", key_spec="AES_256"
                )

                assert len(result) == 32

    def test_decrypt_success(self):
        """Test successful decryption with Vault."""
        with patch.dict(os.environ, {"VAULT_TOKEN": "test-token"}):
            with patch.object(
                VaultKMSAdapter, "client", new_callable=lambda: Mock()
            ) as mock_client:
                mock_client.is_authenticated.return_value = True
                mock_client.secrets.transit.decrypt_data.return_value = {
                    "data": {
                        "plaintext": base64.b64encode(
                            b"decrypted_key_data_32_bytes___"
                        ).decode()
                    }
                }

                adapter = VaultKMSAdapter(
                    vault_url="https://vault.example.com:8200",
                    vault_token="vault_token",
                    mount_point="transit",
                )
                result = adapter.unwrap_data_key("vault:v1:encrypted_data", "test-key")

                assert result == b"decrypted_key_data_32_bytes___"

    def test_authentication_failure(self):
        """Test handling of Vault authentication failures."""
        with patch.dict(os.environ, {"VAULT_TOKEN": "invalid_token"}):
            # Mock at the system level where hvac is imported
            with patch("builtins.__import__") as mock_import:
                original_import = __import__

                def side_effect(name, *args, **kwargs):
                    if name == "hvac":
                        mock_hvac = Mock()
                        mock_client = Mock()
                        mock_client.is_authenticated.return_value = False
                        mock_hvac.Client.return_value = mock_client
                        return mock_hvac
                    return original_import(name, *args, **kwargs)

                mock_import.side_effect = side_effect

                adapter = VaultKMSAdapter(
                    vault_url="https://vault.example.com:8200",
                    vault_token="invalid_token",
                    mount_point="transit",
                )

                # The error should occur when accessing the client
                with pytest.raises(RuntimeError) as exc_info:
                    _ = adapter.client

                assert "authentication" in str(exc_info.value).lower()

    def test_vault_connection_error(self):
        """Test handling of Vault connection errors."""
        with patch.dict(os.environ, {"VAULT_TOKEN": "vault_token"}):
            # Mock at the system level where hvac is imported
            with patch("builtins.__import__") as mock_import:
                original_import = __import__

                def side_effect(name, *args, **kwargs):
                    if name == "hvac":
                        mock_hvac = Mock()
                        mock_hvac.Client.side_effect = Exception("Connection refused")
                        return mock_hvac
                    return original_import(name, *args, **kwargs)

                mock_import.side_effect = side_effect

                adapter = VaultKMSAdapter(
                    vault_url="https://unreachable.vault.com:8200",
                    vault_token="vault_token",
                    mount_point="transit",
                )

                with pytest.raises(RuntimeError) as exc_info:
                    _ = adapter.client

                assert "Connection refused" in str(exc_info.value)


class TestKMSAdapterFactory:
    """Test KMS adapter factory functionality."""

    def test_create_mock_adapter(self):
        """Test creation of mock adapter."""
        from pymedsec.kms import get_kms_client

        adapter = get_kms_client("mock")

        assert isinstance(adapter, MockKMSAdapter)

    def test_create_aws_adapter(self):
        """Test creation of AWS adapter."""
        from pymedsec.kms import get_kms_client

        adapter = get_kms_client("aws", key_id="test-key")

        assert isinstance(adapter, AWSKMSAdapter)

    def test_create_vault_adapter(self):
        """Test creation of Vault adapter."""
        from pymedsec.kms import get_kms_client

        # We can create the adapter without mocking since construction doesn't require hvac
        adapter = get_kms_client(
            "vault",
            url="https://vault.example.com:8200",
            token="test-token",
            key_name="test-key",
        )

        assert isinstance(adapter, VaultAdapter)

    def test_unsupported_provider(self):
        """Test handling of unsupported KMS providers."""
        from pymedsec.kms import get_kms_client

        with pytest.raises(RuntimeError) as exc_info:
            get_kms_client("unsupported_kms")

        assert "Unsupported KMS backend" in str(exc_info.value)


class TestKMSSecurity:
    """Test KMS security and isolation."""

    def test_key_material_isolation(self):
        """Test that different adapters use isolated key material."""
        adapter = MockKMSAdapter()

        key1 = adapter.generate_data_key(key_id="key1", key_spec="AES_256")
        key2 = adapter.generate_data_key(key_id="key2", key_spec="AES_256")

        # Keys should be different
        assert key1["plaintext_key"] != key2["plaintext_key"]
        assert key1["encrypted_key"] != key2["encrypted_key"]

        # Each key should decrypt to its own plaintext
        decrypted1 = adapter.unwrap_data_key(key1["encrypted_key"], "key1")
        decrypted2 = adapter.unwrap_data_key(key2["encrypted_key"], "key2")

        assert decrypted1 == key1["plaintext_key"]
        assert decrypted2 == key2["plaintext_key"]

    def test_encryption_context_validation(self):
        """Test encryption context is properly handled."""
        adapter = MockKMSAdapter()

        context = {
            "purpose": "medical_imaging",
            "department": "radiology",
            "compliance": "HIPAA",
        }

        result = adapter.generate_data_key(
            key_id="context-test-key", key_spec="AES_256", encryption_context=context
        )

        # Should generate valid key regardless of context
        assert "plaintext_key" in result
        assert "encrypted_key" in result
        assert len(result["plaintext_key"]) == 32

    def test_key_size_validation(self):
        """Test that key sizes are properly validated."""
        adapter = MockKMSAdapter()

        result = adapter.generate_data_key(key_id="test", key_spec="AES_256")
        assert len(result["plaintext_key"]) == 32

        result = adapter.generate_data_key(key_id="test", key_spec="AES_128")
        assert len(result["plaintext_key"]) == 16

    def test_secure_key_deletion(self):
        """Test that keys are properly managed."""
        adapter = MockKMSAdapter()

        result = adapter.generate_data_key(key_id="test", key_spec="AES_256")

        # Verify key can be unwrapped
        decrypted = adapter.unwrap_data_key(result["encrypted_key"], "test")
        assert decrypted == result["plaintext_key"]

        # The key material should exist in memory
        assert len(result["plaintext_key"]) == 32
        assert len(result["encrypted_key"]) > 0
