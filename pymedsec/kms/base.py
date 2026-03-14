# SPDX-License-Identifier: Apache-2.0

"""
Base KMS adapter interface.

Defines the common interface that all KMS adapters must implement
for key generation, wrapping, and unwrapping operations.
"""

from abc import ABC, abstractmethod


class KMSAdapter(ABC):
    """Abstract base class for KMS adapters."""

    @abstractmethod
    def generate_data_key(self, key_ref, key_spec="256"):
        """
        Generate a new data encryption key.

        Args:
            key_ref: Reference to the KMS key (ARN, key ID, etc.)
            key_spec: Key specification (e.g., '256' for 256-bit key)

        Returns:
            bytes: Plaintext data key
        """
        raise NotImplementedError("Subclasses must implement generate_data_key")

    @abstractmethod
    def wrap_data_key(self, plaintext_key, key_ref):
        """
        Wrap (encrypt) a data key using KMS.

        Args:
            plaintext_key: Plaintext data key to wrap
            key_ref: Reference to the KMS key

        Returns:
            bytes: Wrapped (encrypted) data key
        """
        raise NotImplementedError("Subclasses must implement wrap_data_key")

    @abstractmethod
    def unwrap_data_key(self, wrapped_key, key_ref):
        """
        Unwrap (decrypt) a data key using KMS.

        Args:
            wrapped_key: Wrapped data key to unwrap
            key_ref: Reference to the KMS key

        Returns:
            bytes: Plaintext data key
        """
        raise NotImplementedError("Subclasses must implement unwrap_data_key")

    def verify_key_access(self, key_ref):
        """
        Verify that the key exists and is accessible.

        Args:
            key_ref: Reference to the KMS key

        Returns:
            bool: True if key is accessible
        """
        try:
            # Default implementation: try to generate a test data key
            test_key = self.generate_data_key(key_ref)
            # Immediately wrap and discard
            self.wrap_data_key(test_key, key_ref)
            return True
        except (ValueError, RuntimeError, OSError):
            return False

    def get_key_metadata(self, key_ref):
        """
        Get metadata about a KMS key.

        Args:
            key_ref: Reference to the KMS key

        Returns:
            dict: Key metadata (implementation-specific)
        """
        return {"key_ref": key_ref, "backend": self.__class__.__name__}
