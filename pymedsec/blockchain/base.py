# SPDX-License-Identifier: Apache-2.0

"""
Abstract base class for blockchain adapters.
"""

from abc import ABC, abstractmethod


class BlockchainAdapter(ABC):
    """Abstract base class for blockchain audit anchoring."""

    def __init__(self, config=None):
        """
        Initialize blockchain adapter.

        Args:
            config: Configuration dict for the adapter
        """
        self.config = config or {}

    def submit_digest(self, digest, metadata=None):
        """Submit a digest to the blockchain.

        Args:
            digest (str): The digest to submit
            metadata (dict, optional): Additional metadata

        Returns:
            dict: Transaction details with 'tx_id' and 'status'
        """
        raise NotImplementedError

    @abstractmethod
    def verify_digest(self, digest_hex, tx_hash):
        """
        Verify a digest exists in the blockchain.

        Args:
            digest_hex: SHA-256 digest as hex string
            tx_hash: Transaction hash to verify

        Returns:
            dict: Verification results
        """
        raise NotImplementedError

    @abstractmethod
    def get_transaction_status(self, tx_hash):
        """
        Get the status of a blockchain transaction.

        Args:
            tx_hash: Transaction hash to check

        Returns:
            dict: Status information
        """
        raise NotImplementedError

    def validate_digest(self, digest_hex):
        """
        Validate digest format.

        Args:
            digest_hex: Digest to validate

        Returns:
            bool: True if valid
        """
        if not isinstance(digest_hex, str):
            return False
        if len(digest_hex) != 64:
            return False
        try:
            int(digest_hex, 16)
            return True
        except ValueError:
            return False
