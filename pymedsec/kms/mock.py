"""
Mock KMS adapter for development and testing.

Provides a simple in-memory KMS implementation for local development
and testing. NOT FOR PRODUCTION USE.
"""

import logging
import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .base import KMSAdapter

logger = logging.getLogger(__name__)


class MockKMSAdapter(KMSAdapter):
    """Mock KMS adapter for development and testing."""

    def __init__(self, master_key=None):
        # Use a fixed master key for deterministic behavior in tests
        if master_key is None:
            master_key_seed = os.getenv(
                'IMGSEC_MOCK_KEY_SEED', 'development_key_do_not_use_in_production')
            self.master_key = hashlib.sha256(
                master_key_seed.encode('utf-8')).digest()
        else:
            self.master_key = master_key

        # Warn about usage
        logger.warning("=" * 60)
        logger.warning("USING MOCK KMS ADAPTER - NOT FOR PRODUCTION USE")
        logger.warning("This is for development and testing only!")
        logger.warning("=" * 60)

    def generate_data_key(self, key_ref=None, key_spec='256', key_id=None, **kwargs):
        """Generate a random data key.

        Args:
            key_ref: Key reference (preferred parameter)
            key_spec: Key specification ('256', '128', 'AES_256', or 'AES_128')
            key_id: Legacy parameter name for key_ref
            **kwargs: Additional arguments for compatibility

        Returns:
            bytes: Plaintext data key
        """
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

            logger.debug("Generated mock data key for key_ref: %s", key_ref)

            # Return just the bytes as per the interface
            return data_key

        except Exception as e:
            logger.error("Mock data key generation failed: %s", e)
            raise RuntimeError(
                f"Mock KMS data key generation failed: {e}") from e

    def wrap_data_key(self, plaintext_key, key_ref):
        """Wrap data key using AES-GCM with master key."""
        try:
            # Use key_ref as additional authenticated data
            aad = key_ref.encode('utf-8')

            # Generate nonce for wrapping
            nonce = os.urandom(12)

            # Encrypt the data key
            aesgcm = AESGCM(self.master_key)
            ciphertext = aesgcm.encrypt(nonce, plaintext_key, aad)

            # Combine nonce and ciphertext
            wrapped_key = nonce + ciphertext

            logger.debug("Wrapped mock data key for key_ref: %s", key_ref)
            return wrapped_key

        except Exception as e:
            logger.error("Mock key wrapping failed: %s", e)
            raise RuntimeError(f"Mock KMS key wrapping failed: {e}") from e

    def unwrap_data_key(self, wrapped_key, key_ref):
        """Unwrap data key using AES-GCM with master key."""
        try:
            # Split nonce and ciphertext
            if len(wrapped_key) < 12:
                raise ValueError("Wrapped key too short")

            nonce = wrapped_key[:12]
            ciphertext = wrapped_key[12:]

            # Use key_ref as additional authenticated data
            aad = key_ref.encode('utf-8')

            # Decrypt the data key
            aesgcm = AESGCM(self.master_key)
            plaintext_key = aesgcm.decrypt(nonce, ciphertext, aad)

            logger.debug("Unwrapped mock data key for key_ref: %s", key_ref)
            return plaintext_key

        except Exception as e:
            logger.error("Mock key unwrapping failed: %s", e)
            raise RuntimeError(f"Mock KMS key unwrapping failed: {e}") from e

    def decrypt(self, encrypted_data, key_ref=None):
        """Decrypt data - alias for unwrap_data_key for compatibility."""
        if key_ref is None:
            key_ref = "mock-key-default"
        return self.unwrap_data_key(encrypted_data, key_ref)

    def verify_key_access(self, key_ref):
        """Always return True for mock adapter."""
        logger.debug("Mock key access verification (always True): %s", key_ref)
        return True

    def get_key_metadata(self, key_ref):
        """Get mock key metadata."""
        return {
            'key_ref': key_ref,
            'backend': 'Mock KMS (Development Only)',
            'master_key_hash': hashlib.sha256(self.master_key).hexdigest()[:16],
            'warning': 'NOT FOR PRODUCTION USE',
            'algorithm': 'AES-256-GCM',
            'key_size_bits': 256
        }

    def create_key(self, key_name, description=None):
        """Create a mock key (just return metadata)."""
        logger.info("Created mock key: %s", key_name)
        return {
            'key_name': key_name,
            'description': description or f'Mock key: {key_name}',
            'backend': 'Mock KMS',
            'created': True,
            'warning': 'NOT FOR PRODUCTION USE'
        }

    def list_keys(self):
        """List mock keys (return common test keys)."""
        return [
            {'KeyId': 'mock-key-1', 'Description': 'Mock development key 1'},
            {'KeyId': 'mock-key-2', 'Description': 'Mock development key 2'},
            {'KeyId': 'test-key', 'Description': 'Mock test key'},
            {'KeyId': 'dev-key', 'Description': 'Mock development key'}
        ]

    def rotate_master_key(self, new_seed=None):
        """Rotate the mock master key (for testing key rotation)."""
        if new_seed is None:
            new_seed = os.urandom(32).hex()

        old_hash = hashlib.sha256(self.master_key).hexdigest()[:16]
        self.master_key = hashlib.sha256(new_seed.encode('utf-8')).digest()
        new_hash = hashlib.sha256(self.master_key).hexdigest()[:16]

        from datetime import datetime
        logger.warning("Mock master key rotated: %s -> %s", old_hash, new_hash)
        return {
            'old_key_hash': old_hash,
            'new_key_hash': new_hash,
            'rotated_at': datetime.utcnow().isoformat()
        }
