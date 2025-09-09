"""
HashiCorp Vault Transit engine adapter.

Provides Vault Transit engine integration for envelope encryption
using hvac client library.
"""

import logging
import os
import base64

from .base import KMSAdapter

logger = logging.getLogger(__name__)


class VaultAdapter(KMSAdapter):
    """HashiCorp Vault Transit engine adapter."""

    def __init__(self, vault_url=None, vault_token=None, mount_point=None):
        self.vault_url = vault_url or os.getenv(
            'VAULT_ADDR', 'http://localhost:8200')
        self.vault_token = vault_token or os.getenv('VAULT_TOKEN')
        self.mount_point = mount_point or os.getenv('VAULT_MOUNT', 'transit')
        self._client = None

        if not self.vault_token:
            raise ValueError("VAULT_TOKEN environment variable is required")

    @property
    def client(self):
        """Lazy-load hvac Vault client."""
        if self._client is None:
            try:
                import hvac
                self._client = hvac.Client(
                    url=self.vault_url,
                    token=self.vault_token
                )

                # Verify authentication
                if not self._client.is_authenticated():
                    raise RuntimeError("Vault authentication failed")

                logger.debug("Initialized Vault client for: %s",
                             self.vault_url)

            except ImportError as e:
                raise RuntimeError(
                    "hvac library required for Vault adapter") from e
            except Exception as e:
                raise RuntimeError(
                    f"Failed to initialize Vault client: {e}") from e

        return self._client

    def generate_data_key(self, key_ref, key_spec='256'):
        """Generate data key using Vault Transit."""
        try:
            # Vault Transit doesn't have generate_data_key, so we generate locally
            if key_spec == '256':
                key_size = 32  # 256 bits
            elif key_spec == '128':
                key_size = 16  # 128 bits
            else:
                raise ValueError(f"Unsupported key spec: {key_spec}")

            data_key = os.urandom(key_size)
            logger.debug("Generated local data key for Vault key: %s", key_ref)
            return data_key

        except Exception as e:
            logger.error("Failed to generate data key for Vault: %s", e)
            raise RuntimeError(f"Vault data key generation failed: {e}") from e

    def wrap_data_key(self, plaintext_key, key_ref):
        """Wrap data key using Vault Transit encrypt."""
        try:
            # Encode plaintext key to base64 for Vault
            b64_plaintext = base64.b64encode(plaintext_key).decode('utf-8')

            response = self.client.secrets.transit.encrypt_data(
                name=key_ref,
                plaintext=b64_plaintext,
                mount_point=self.mount_point
            )

            # Extract ciphertext (includes vault:v1: prefix)
            ciphertext = response['data']['ciphertext']

            # For storage, we need just the ciphertext bytes
            # Vault returns "vault:v1:base64data"
            wrapped_data = ciphertext.encode('utf-8')

            logger.debug("Wrapped data key using Vault key: %s", key_ref)
            return wrapped_data

        except Exception as e:
            logger.error("Failed to wrap data key with Vault: %s", e)
            raise RuntimeError(f"Vault key wrapping failed: {e}") from e

    def unwrap_data_key(self, wrapped_key, key_ref):
        """Unwrap data key using Vault Transit decrypt."""
        try:
            # Convert wrapped_key back to string format expected by Vault
            if isinstance(wrapped_key, bytes):
                ciphertext = wrapped_key.decode('utf-8')
            else:
                ciphertext = wrapped_key

            response = self.client.secrets.transit.decrypt_data(
                name=key_ref,
                ciphertext=ciphertext,
                mount_point=self.mount_point
            )

            # Decode the base64 plaintext
            b64_plaintext = response['data']['plaintext']
            plaintext_key = base64.b64decode(b64_plaintext)

            logger.debug("Unwrapped data key using Vault key: %s", key_ref)
            return plaintext_key

        except Exception as e:
            logger.error("Failed to unwrap data key with Vault: %s", e)
            raise RuntimeError(f"Vault key unwrapping failed: {e}") from e

    def verify_key_access(self, key_ref):
        """Verify Vault Transit key accessibility."""
        try:
            # Try to read key information
            response = self.client.secrets.transit.read_key(
                name=key_ref,
                mount_point=self.mount_point
            )

            # Check if key exists and is not deleted
            if response and response.get('data'):
                key_data = response['data']
                if key_data.get('deletion_allowed', False) and key_data.get('min_decryption_version', 0) == 0:
                    logger.warning("Vault key may be deleted: %s", key_ref)
                    return False
                return True
            else:
                return False

        except Exception as e:
            logger.error("Vault key access verification failed: %s", e)
            return False

    def get_key_metadata(self, key_ref):
        """Get Vault Transit key metadata."""
        try:
            response = self.client.secrets.transit.read_key(
                name=key_ref,
                mount_point=self.mount_point
            )

            if response and response.get('data'):
                key_data = response['data']

                return {
                    'key_ref': key_ref,
                    'backend': 'HashiCorp Vault Transit',
                    'type': key_data.get('type', 'unknown'),
                    'supports_encryption': key_data.get('supports_encryption', False),
                    'supports_decryption': key_data.get('supports_decryption', False),
                    'supports_signing': key_data.get('supports_signing', False),
                    'supports_derivation': key_data.get('supports_derivation', False),
                    'creation_time': key_data.get('creation_time', ''),
                    'latest_version': key_data.get('latest_version', 0),
                    'min_available_version': key_data.get('min_available_version', 0),
                    'min_decryption_version': key_data.get('min_decryption_version', 0),
                    'min_encryption_version': key_data.get('min_encryption_version', 0),
                    'deletion_allowed': key_data.get('deletion_allowed', False),
                    'derived': key_data.get('derived', False),
                    'exportable': key_data.get('exportable', False),
                    'allow_plaintext_backup': key_data.get('allow_plaintext_backup', False),
                    'mount_point': self.mount_point,
                    'vault_url': self.vault_url
                }
            else:
                raise ValueError(f"Key not found: {key_ref}")

        except Exception as e:
            logger.error("Failed to get Vault key metadata: %s", e)
            return super().get_key_metadata(key_ref)

    def create_key(self, key_name, key_type='aes256-gcm96', derived=False,
                   exportable=False, allow_plaintext_backup=False):
        """Create a new Vault Transit key."""
        try:
            self.client.secrets.transit.create_key(
                name=key_name,
                convergent_encryption=False,
                derived=derived,
                exportable=exportable,
                allow_plaintext_backup=allow_plaintext_backup,
                type=key_type,
                mount_point=self.mount_point
            )

            logger.info("Created new Vault Transit key: %s", key_name)
            return {
                'key_name': key_name,
                'key_type': key_type,
                'mount_point': self.mount_point,
                'created': True
            }

        except Exception as e:
            logger.error("Failed to create Vault key: %s", e)
            raise RuntimeError(f"Vault key creation failed: {e}") from e

    def list_keys(self):
        """List available Vault Transit keys."""
        try:
            response = self.client.secrets.transit.list_keys(
                mount_point=self.mount_point
            )

            if response and response.get('data') and response['data'].get('keys'):
                return response['data']['keys']
            else:
                return []

        except Exception as e:
            logger.error("Failed to list Vault keys: %s", e)
            raise RuntimeError(f"Vault key listing failed: {e}") from e
