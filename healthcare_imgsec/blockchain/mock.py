"""
Mock blockchain adapter for testing and development.
"""

import json
import os
import time
import hashlib
from .base import BlockchainAdapter


class MockBlockchainAdapter(BlockchainAdapter):
    """Mock blockchain adapter that simulates blockchain operations."""

    def __init__(self, config=None):
        """Initialize mock blockchain adapter."""
        super().__init__(config)
        self.storage_path = self.config.get(
            'storage_path',
            '/tmp/mock_blockchain.json'
        )
        self._ensure_storage()

    def _ensure_storage(self):
        """Ensure storage file exists."""
        if not os.path.exists(self.storage_path):
            with open(self.storage_path, 'w', encoding='utf-8') as f:
                json.dump({}, f)

    def _load_storage(self):
        """Load blockchain simulation data."""
        try:
            with open(self.storage_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (IOError, json.JSONDecodeError):
            return {}

    def _save_storage(self, data):
        """Save blockchain simulation data."""
        with open(self.storage_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)

    def submit_digest(self, digest_hex, metadata=None):
        """
        Submit digest to mock blockchain.

        Args:
            digest_hex: SHA-256 digest as hex string
            metadata: Additional metadata

        Returns:
            dict: Mock transaction details
        """
        if not self.validate_digest(digest_hex):
            raise ValueError("Invalid digest format")

        # Generate mock transaction hash
        timestamp = str(time.time())
        tx_data = f"{digest_hex}:{timestamp}"
        tx_hash = hashlib.sha256(tx_data.encode()).hexdigest()

        # Store in mock blockchain
        storage = self._load_storage()
        storage[tx_hash] = {
            'digest': digest_hex,
            'timestamp': timestamp,
            'block_number': len(storage) + 1,
            'confirmations': 1,
            'metadata': metadata or {}
        }
        self._save_storage(storage)

        return {
            'tx_hash': tx_hash,
            'block_number': storage[tx_hash]['block_number'],
            'timestamp': timestamp,
            'status': 'confirmed'
        }

    def verify_digest(self, digest_hex, tx_hash):
        """
        Verify digest in mock blockchain.

        Args:
            digest_hex: SHA-256 digest as hex string
            tx_hash: Transaction hash

        Returns:
            dict: Verification results
        """
        storage = self._load_storage()

        if tx_hash not in storage:
            return {
                'verified': False,
                'message': 'Transaction not found'
            }

        tx_data = storage[tx_hash]
        verified = tx_data.get('digest') == digest_hex

        return {
            'verified': verified,
            'block_number': tx_data.get('block_number'),
            'timestamp': tx_data.get('timestamp'),
            'confirmations': tx_data.get('confirmations', 1),
            'message': 'Verified' if verified else 'Digest mismatch'
        }

    def get_transaction_status(self, tx_hash):
        """
        Get mock transaction status.

        Args:
            tx_hash: Transaction hash

        Returns:
            dict: Transaction status
        """
        storage = self._load_storage()

        if tx_hash not in storage:
            return {
                'found': False,
                'status': 'not_found'
            }

        tx_data = storage[tx_hash]
        return {
            'found': True,
            'status': 'confirmed',
            'block_number': tx_data.get('block_number'),
            'confirmations': tx_data.get('confirmations', 1),
            'timestamp': tx_data.get('timestamp')
        }
