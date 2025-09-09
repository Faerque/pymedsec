"""
AWS KMS adapter implementation.

Provides AWS KMS integration for envelope encryption using boto3.
Supports CMK-based data key generation and wrapping/unwrapping.
"""

import logging
import os

from .base import KMSAdapter

logger = logging.getLogger(__name__)


class AWSKMSAdapter(KMSAdapter):
    """AWS KMS adapter using boto3."""

    def __init__(self, region_name=None):
        self.region_name = region_name or os.getenv(
            'AWS_DEFAULT_REGION', 'us-east-1')
        self._client = None

    @property
    def client(self):
        """Lazy-load boto3 KMS client."""
        if self._client is None:
            try:
                import boto3
                self._client = boto3.client(
                    'kms', region_name=self.region_name)
                logger.debug(
                    "Initialized AWS KMS client for region: %s", self.region_name)
            except ImportError as e:
                raise RuntimeError(
                    "boto3 library required for AWS KMS adapter") from e
            except Exception as e:
                raise RuntimeError(
                    f"Failed to initialize AWS KMS client: {e}") from e

        return self._client

    def generate_data_key(self, key_ref, key_spec='256'):
        """Generate data key using AWS KMS."""
        try:
            # Convert key_spec to AWS format
            if key_spec == '256':
                aws_key_spec = 'AES_256'
            elif key_spec == '128':
                aws_key_spec = 'AES_128'
            else:
                raise ValueError(f"Unsupported key spec: {key_spec}")

            response = self.client.generate_data_key(
                KeyId=key_ref,
                KeySpec=aws_key_spec
            )

            logger.debug("Generated data key using AWS KMS key: %s", key_ref)
            return response['Plaintext']

        except Exception as e:
            logger.error("Failed to generate data key with AWS KMS: %s", e)
            raise RuntimeError(
                f"AWS KMS data key generation failed: {e}") from e

    def wrap_data_key(self, plaintext_key, key_ref):
        """Wrap data key using AWS KMS encrypt."""
        try:
            response = self.client.encrypt(
                KeyId=key_ref,
                Plaintext=plaintext_key
            )

            logger.debug("Wrapped data key using AWS KMS key: %s", key_ref)
            return response['CiphertextBlob']

        except Exception as e:
            logger.error("Failed to wrap data key with AWS KMS: %s", e)
            raise RuntimeError(f"AWS KMS key wrapping failed: {e}") from e

    def unwrap_data_key(self, wrapped_key, key_ref):
        """Unwrap data key using AWS KMS decrypt."""
        try:
            response = self.client.decrypt(
                CiphertextBlob=wrapped_key,
                KeyId=key_ref
            )

            logger.debug("Unwrapped data key using AWS KMS key: %s", key_ref)
            return response['Plaintext']

        except Exception as e:
            logger.error("Failed to unwrap data key with AWS KMS: %s", e)
            raise RuntimeError(f"AWS KMS key unwrapping failed: {e}") from e

    def verify_key_access(self, key_ref):
        """Verify AWS KMS key accessibility."""
        try:
            # Use describe_key to check access without generating keys
            response = self.client.describe_key(KeyId=key_ref)

            # Check if key is enabled
            key_metadata = response['KeyMetadata']
            if key_metadata['KeyState'] != 'Enabled':
                logger.warning("AWS KMS key is not enabled: %s", key_ref)
                return False

            return True

        except Exception as e:
            logger.error("AWS KMS key access verification failed: %s", e)
            return False

    def get_key_metadata(self, key_ref):
        """Get AWS KMS key metadata."""
        try:
            response = self.client.describe_key(KeyId=key_ref)
            key_metadata = response['KeyMetadata']

            return {
                'key_ref': key_ref,
                'backend': 'AWS KMS',
                'key_id': key_metadata['KeyId'],
                'arn': key_metadata['Arn'],
                'creation_date': key_metadata['CreationDate'].isoformat(),
                'key_state': key_metadata['KeyState'],
                'key_usage': key_metadata['KeyUsage'],
                'key_spec': key_metadata.get('KeySpec', 'SYMMETRIC_DEFAULT'),
                'origin': key_metadata['Origin'],
                'description': key_metadata.get('Description', ''),
                'region': self.region_name
            }

        except Exception as e:
            logger.error("Failed to get AWS KMS key metadata: %s", e)
            return super().get_key_metadata(key_ref)

    def list_keys(self, limit=100):
        """List available AWS KMS keys."""
        try:
            response = self.client.list_keys(Limit=limit)
            return response['Keys']

        except Exception as e:
            logger.error("Failed to list AWS KMS keys: %s", e)
            raise RuntimeError(f"AWS KMS key listing failed: {e}") from e

    def create_key(self, description=None, key_usage='ENCRYPT_DECRYPT'):
        """Create a new AWS KMS key."""
        try:
            params = {
                'KeyUsage': key_usage,
                'KeySpec': 'SYMMETRIC_DEFAULT'
            }

            if description:
                params['Description'] = description

            response = self.client.create_key(**params)
            key_metadata = response['KeyMetadata']

            logger.info("Created new AWS KMS key: %s", key_metadata['KeyId'])
            return key_metadata

        except Exception as e:
            logger.error("Failed to create AWS KMS key: %s", e)
            raise RuntimeError(f"AWS KMS key creation failed: {e}") from e
