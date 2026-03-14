# SPDX-License-Identifier: Apache-2.0

"""
Abstract base class for blockchain adapters.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone


class BlockchainAdapter(ABC):
    """Abstract base class for blockchain audit anchoring."""

    def __init__(self, config=None):
        """
        Initialize blockchain adapter.

        Args:
            config: Configuration dict for the adapter
        """
        self.config = config or {}
        self.backend_name = self.config.get("backend", "unknown")

    @staticmethod
    def _utc_now_iso():
        """Return UTC timestamp in ISO-8601 format."""
        return datetime.now(timezone.utc).isoformat()

    def _build_submit_result(
        self,
        tx_hash,
        digest,
        status,
        *,
        block_number=None,
        confirmations=0,
        message=None,
        timestamp=None,
    ):
        """Build a normalized submit response."""
        return {
            "backend": self.backend_name,
            "tx_hash": tx_hash,
            "digest": digest,
            "status": status,
            "block_number": block_number,
            "confirmations": confirmations,
            "message": message,
            "timestamp": timestamp or self._utc_now_iso(),
        }

    def _build_verify_result(
        self,
        *,
        tx_hash,
        digest,
        verified,
        status,
        block_number=None,
        confirmations=0,
        message=None,
        timestamp=None,
    ):
        """Build a normalized verify response."""
        return {
            "backend": self.backend_name,
            "tx_hash": tx_hash,
            "digest": digest,
            "verified": bool(verified),
            "status": status,
            "block_number": block_number,
            "confirmations": confirmations,
            "message": message,
            "timestamp": timestamp,
        }

    def _build_transaction_status(
        self,
        *,
        tx_hash,
        found,
        status,
        block_number=None,
        confirmations=0,
        message=None,
        timestamp=None,
    ):
        """Build a normalized transaction status response."""
        return {
            "backend": self.backend_name,
            "tx_hash": tx_hash,
            "found": bool(found),
            "status": status,
            "block_number": block_number,
            "confirmations": confirmations,
            "message": message,
            "timestamp": timestamp,
        }

    @abstractmethod
    def submit_digest(self, digest, metadata=None):
        """Submit a digest to the blockchain.

        Args:
            digest (str): The digest to submit
            metadata (dict, optional): Additional metadata

        Returns:
            dict: Normalized submit result
        """
        raise NotImplementedError("Subclasses must implement submit_digest")

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
