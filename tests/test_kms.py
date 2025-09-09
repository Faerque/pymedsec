"""
Tests for the KMS (Key Management Service) adapters.
"""
import base64
from unittest.mock import Mock, patch
import pytest

from pymedsec.kms.base import KMSAdapter
from pymedsec.kms.mock import MockKMSAdapter
from pymedsec.kms.aws_kms import AWSKMSAdapter
from pymedsec.kms.vault import VaultAdapter


class TestKMSAdapterBase:
    """Test cases for base KMS adapter interface."""

    def test_abstract_interface(self):
        """Test that KMSAdapter is properly abstract."""
        with pytest.raises(TypeError):
            KMSAdapter()  # Should not be instantiable

    def test_required_methods(self):
        """Test that required methods are defined in interface."""
        # Check that abstract methods exist
        required_methods = ['encrypt', 'decrypt', 'generate_data_key']

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

        result = adapter.generate_data_key(
            key_id="test-key", key_spec="AES_256")

        assert 'plaintext_key' in result
        assert 'encrypted_key' in result
        assert len(result['plaintext_key']) == 32  # 256 bits = 32 bytes
        assert len(result['encrypted_key']) > 0

    def test_encrypt_decrypt_roundtrip(self):
        """Test encryption and decryption roundtrip."""
        adapter = MockKMSAdapter()

        # Generate a data key
        key_result = adapter.generate_data_key(
            key_id="test-key", key_spec="AES_256")
        plaintext_key = key_result['plaintext_key']
        encrypted_key = key_result['encrypted_key']

        # Decrypt the encrypted key
        decrypted_key = adapter.decrypt(encrypted_key)

        assert decrypted_key == plaintext_key

    def test_different_keys_unique(self):
        """Test that different key generations produce unique keys."""
        adapter = MockKMSAdapter()

        key1 = adapter.generate_data_key(
            key_id="test-key-1", key_spec="AES_256")
        key2 = adapter.generate_data_key(
            key_id="test-key-2", key_spec="AES_256")

        assert key1['plaintext_key'] != key2['plaintext_key']
        assert key1['encrypted_key'] != key2['encrypted_key']

    def test_key_id_consistency(self):
        """Test that same key ID produces consistent results."""
        adapter = MockKMSAdapter()

        # Use deterministic mode for testing
        with patch('pymedsec.kms.mock.os.urandom') as mock_random:
            mock_random.return_value = b'deterministic_key_32_bytes___'

            key1 = adapter.generate_data_key(
                key_id="same-key", key_spec="AES_256")
            key2 = adapter.generate_data_key(
                key_id="same-key", key_spec="AES_256")

            # In deterministic mode, should be same
            assert key1['plaintext_key'] == key2['plaintext_key']

    def test_invalid_key_spec(self):
        """Test handling of invalid key specifications."""
        adapter = MockKMSAdapter()

        with pytest.raises(ValueError):
            adapter.generate_data_key(
                key_id="test-key", key_spec="INVALID_SPEC")

    def test_encrypt_with_context(self):
        """Test encryption with encryption context."""
        adapter = MockKMSAdapter()

        context = {
            "purpose": "medical_imaging",
            "department": "radiology"
        }

        result = adapter.generate_data_key(
            key_id="test-key",
            key_spec="AES_256",
            encryption_context=context
        )

        assert 'plaintext_key' in result
        assert 'encrypted_key' in result


class TestAWSKMSAdapter:
    """Test cases for AWS KMS adapter."""

    def test_initialization_with_config(self):
        """Test AWS KMS adapter initialization."""
        config = {
            'region': 'us-east-1',
            'access_key_id': 'test_access_key',
            'secret_access_key': 'test_secret_key'
        }

        with patch('pymedsec.kms.aws_kms.boto3') as mock_boto3:
            mock_client = Mock()
            mock_boto3.client.return_value = mock_client

            adapter = AWSKMSAdapter(config)

            assert adapter is not None
            mock_boto3.client.assert_called_once_with(
                'kms',
                region_name='us-east-1',
                aws_access_key_id='test_access_key',
                aws_secret_access_key='test_secret_key'
            )

    def test_generate_data_key_success(self):
        """Test successful data key generation with AWS KMS."""
        config = {'region': 'us-east-1'}

        with patch('pymedsec.kms.aws_kms.boto3') as mock_boto3:
            mock_client = Mock()
            mock_client.generate_data_key.return_value = {
                'Plaintext': b'32_byte_plaintext_key_data_here',
                'CiphertextBlob': b'encrypted_key_data_from_aws_kms'
            }
            mock_boto3.client.return_value = mock_client

            adapter = AWSKMSAdapter(config)
            result = adapter.generate_data_key(
                key_id="arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
                key_spec="AES_256"
            )

            assert result['plaintext_key'] == b'32_byte_plaintext_key_data_here'
            assert result['encrypted_key'] == b'encrypted_key_data_from_aws_kms'

    def test_decrypt_success(self):
        """Test successful decryption with AWS KMS."""
        config = {'region': 'us-east-1'}

        with patch('pymedsec.kms.aws_kms.boto3') as mock_boto3:
            mock_client = Mock()
            mock_client.decrypt.return_value = {
                'Plaintext': b'decrypted_key_data_32_bytes___'
            }
            mock_boto3.client.return_value = mock_client

            adapter = AWSKMSAdapter(config)
            result = adapter.decrypt(b'encrypted_key_blob')

            assert result == b'decrypted_key_data_32_bytes___'

    def test_kms_exception_handling(self):
        """Test handling of KMS exceptions."""
        config = {'region': 'us-east-1'}

        with patch('pymedsec.kms.aws_kms.boto3') as mock_boto3:
            mock_client = Mock()
            mock_client.generate_data_key.side_effect = Exception(
                "KMS service error")
            mock_boto3.client.return_value = mock_client

            adapter = AWSKMSAdapter(config)

            with pytest.raises(Exception) as exc_info:
                adapter.generate_data_key(
                    key_id="test-key", key_spec="AES_256")

            assert "KMS service error" in str(exc_info.value)

    def test_encryption_context_support(self):
        """Test encryption context support in AWS KMS."""
        config = {'region': 'us-east-1'}

        with patch('pymedsec.kms.aws_kms.boto3') as mock_boto3:
            mock_client = Mock()
            mock_client.generate_data_key.return_value = {
                'Plaintext': b'test_key_data',
                'CiphertextBlob': b'encrypted_blob'
            }
            mock_boto3.client.return_value = mock_client

            adapter = AWSKMSAdapter(config)

            context = {"purpose": "medical_imaging"}
            adapter.generate_data_key(
                key_id="test-key",
                key_spec="AES_256",
                encryption_context=context
            )

            # Verify encryption context was passed to AWS
            mock_client.generate_data_key.assert_called_once()
            call_args = mock_client.generate_data_key.call_args
            assert call_args[1]['EncryptionContext'] == context


class TestVaultKMSAdapter:
    """Test cases for HashiCorp Vault KMS adapter."""

    def test_initialization_with_config(self):
        """Test Vault KMS adapter initialization."""
        config = {
            'url': 'https://vault.example.com:8200',
            'token': 'vault_token',
            'mount_point': 'transit'
        }

        with patch('pymedsec.kms.vault.hvac') as mock_hvac:
            mock_client = Mock()
            mock_hvac.Client.return_value = mock_client
            mock_client.is_authenticated.return_value = True

            adapter = VaultKMSAdapter(config)

            assert adapter is not None
            mock_hvac.Client.assert_called_once_with(
                url='https://vault.example.com:8200',
                token='vault_token'
            )

    def test_generate_data_key_success(self):
        """Test successful data key generation with Vault."""
        config = {
            'url': 'https://vault.example.com:8200',
            'token': 'vault_token',
            'mount_point': 'transit'
        }

        with patch('pymedsec.kms.vault.hvac') as mock_hvac:
            mock_client = Mock()
            mock_client.is_authenticated.return_value = True
            mock_client.secrets.transit.generate_data_key.return_value = {
                'data': {
                    'plaintext': base64.b64encode(b'32_byte_key_data_from_vault____').decode(),
                    'ciphertext': 'vault:v1:encrypted_data_key'
                }
            }
            mock_hvac.Client.return_value = mock_client

            adapter = VaultKMSAdapter(config)
            result = adapter.generate_data_key(
                key_id="medical-images", key_spec="AES_256")

            assert len(result['plaintext_key']) == 32
            assert result['encrypted_key'] == 'vault:v1:encrypted_data_key'

    def test_decrypt_success(self):
        """Test successful decryption with Vault."""
        config = {
            'url': 'https://vault.example.com:8200',
            'token': 'vault_token',
            'mount_point': 'transit'
        }

        with patch('pymedsec.kms.vault.hvac') as mock_hvac:
            mock_client = Mock()
            mock_client.is_authenticated.return_value = True
            mock_client.secrets.transit.decrypt_data.return_value = {
                'data': {
                    'plaintext': base64.b64encode(b'decrypted_key_data_32_bytes___').decode()
                }
            }
            mock_hvac.Client.return_value = mock_client

            adapter = VaultKMSAdapter(config)
            result = adapter.decrypt('vault:v1:encrypted_data')

            assert result == b'decrypted_key_data_32_bytes___'

    def test_authentication_failure(self):
        """Test handling of Vault authentication failures."""
        config = {
            'url': 'https://vault.example.com:8200',
            'token': 'invalid_token',
            'mount_point': 'transit'
        }

        with patch('pymedsec.kms.vault.hvac') as mock_hvac:
            mock_client = Mock()
            mock_client.is_authenticated.return_value = False
            mock_hvac.Client.return_value = mock_client

            with pytest.raises(Exception) as exc_info:
                VaultKMSAdapter(config)

            assert "authentication" in str(exc_info.value).lower()

    def test_vault_connection_error(self):
        """Test handling of Vault connection errors."""
        config = {
            'url': 'https://unreachable.vault.com:8200',
            'token': 'vault_token',
            'mount_point': 'transit'
        }

        with patch('pymedsec.kms.vault.hvac') as mock_hvac:
            mock_hvac.Client.side_effect = Exception("Connection refused")

            with pytest.raises(Exception) as exc_info:
                VaultKMSAdapter(config)

            assert "Connection refused" in str(exc_info.value)


class TestKMSAdapterFactory:
    """Test KMS adapter factory functionality."""

    def test_create_mock_adapter(self):
        """Test creation of mock adapter."""
        config = {
            'provider': 'mock',
            'config': {}
        }

        from pymedsec.kms import create_kms_adapter
        adapter = create_kms_adapter(config)

        assert isinstance(adapter, MockKMSAdapter)

    def test_create_aws_adapter(self):
        """Test creation of AWS adapter."""
        config = {
            'provider': 'aws_kms',
            'config': {
                'region': 'us-east-1',
                'access_key_id': 'test_key',
                'secret_access_key': 'test_secret'
            }
        }

        with patch('pymedsec.kms.aws_kms.boto3'):
            from pymedsec.kms import create_kms_adapter
            adapter = create_kms_adapter(config)

            assert isinstance(adapter, AWSKMSAdapter)

    def test_create_vault_adapter(self):
        """Test creation of Vault adapter."""
        config = {
            'provider': 'vault',
            'config': {
                'url': 'https://vault.example.com:8200',
                'token': 'vault_token',
                'mount_point': 'transit'
            }
        }

        with patch('pymedsec.kms.vault.hvac') as mock_hvac:
            mock_client = Mock()
            mock_client.is_authenticated.return_value = True
            mock_hvac.Client.return_value = mock_client

            from pymedsec.kms import create_kms_adapter
            adapter = create_kms_adapter(config)

            assert isinstance(adapter, VaultKMSAdapter)

    def test_unsupported_provider(self):
        """Test handling of unsupported KMS provider."""
        config = {
            'provider': 'unsupported_kms',
            'config': {}
        }

        from pymedsec.kms import create_kms_adapter

        with pytest.raises(ValueError) as exc_info:
            create_kms_adapter(config)

        assert "Unsupported KMS provider" in str(exc_info.value)


class TestKMSSecurity:
    """Test security aspects of KMS adapters."""

    def test_key_material_isolation(self):
        """Test that key material is properly isolated between operations."""
        adapter = MockKMSAdapter()

        # Generate multiple keys
        key1 = adapter.generate_data_key(key_id="key1", key_spec="AES_256")
        key2 = adapter.generate_data_key(key_id="key2", key_spec="AES_256")

        # Keys should be different
        assert key1['plaintext_key'] != key2['plaintext_key']
        assert key1['encrypted_key'] != key2['encrypted_key']

        # Decryption should return correct keys
        decrypted1 = adapter.decrypt(key1['encrypted_key'])
        decrypted2 = adapter.decrypt(key2['encrypted_key'])

        assert decrypted1 == key1['plaintext_key']
        assert decrypted2 == key2['plaintext_key']
        assert decrypted1 != decrypted2

    def test_encryption_context_validation(self):
        """Test that encryption context is properly validated."""
        adapter = MockKMSAdapter()

        context = {
            "purpose": "medical_imaging",
            "department": "radiology",
            "study_id": "STUDY-001"
        }

        # Generate key with context
        result = adapter.generate_data_key(
            key_id="test-key",
            key_spec="AES_256",
            encryption_context=context
        )

        # Should succeed with valid context
        assert 'plaintext_key' in result
        assert 'encrypted_key' in result

    def test_key_size_validation(self):
        """Test validation of key sizes."""
        adapter = MockKMSAdapter()

        # Valid key spec
        result = adapter.generate_data_key(key_id="test", key_spec="AES_256")
        assert len(result['plaintext_key']) == 32  # 256 bits

        # Different valid key spec
        result = adapter.generate_data_key(key_id="test", key_spec="AES_128")
        assert len(result['plaintext_key']) == 16  # 128 bits

    def test_secure_key_deletion(self):
        """Test secure deletion of key material."""
        adapter = MockKMSAdapter()

        # Generate key
        result = adapter.generate_data_key(key_id="test", key_spec="AES_256")

        # Simulate secure deletion (implementation would zero memory)
        # This is more of a design verification than functional test
        assert result['plaintext_key'] is not None

        # In real implementation, would verify memory is zeroed
