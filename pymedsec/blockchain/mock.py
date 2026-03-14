# SPDX-License-Identifier: Apache-2.0

"""
Mock blockchain adapter for testing and development.
"""

import json
import os
import hashlib
import threading
from contextlib import contextmanager
from datetime import datetime, timezone

try:
    import fcntl

    FCNTL_AVAILABLE = True
except ImportError:
    fcntl = None  # type: ignore
    FCNTL_AVAILABLE = False

from .base import BlockchainAdapter


class MockBlockchainAdapter(BlockchainAdapter):
    """Mock blockchain adapter that simulates blockchain operations."""

    def __init__(self, config=None):
        """Initialize mock blockchain adapter."""
        super().__init__(config)
        self.backend_name = "mock"
        self.storage_path = self.config.get(
            "storage_path",
            os.environ.get("IMGSEC_MOCK_BLOCKCHAIN_STORAGE", "/tmp/mock_blockchain.json"),
        )
        self.lock_path = self.config.get("lock_path", f"{self.storage_path}.lock")
        self._fallback_lock = threading.Lock()
        self._ensure_storage()

    @staticmethod
    def _now_iso():
        """Return UTC timestamp in ISO-8601 format."""
        return datetime.now(timezone.utc).isoformat()

    @contextmanager
    def _storage_lock(self):
        """Lock storage to avoid concurrent write corruption."""
        if FCNTL_AVAILABLE:
            os.makedirs(os.path.dirname(self.lock_path) or ".", exist_ok=True)
            with open(self.lock_path, "a", encoding="utf-8") as lock_file:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
            return

        with self._fallback_lock:
            yield

    def _atomic_write_storage(self, data):
        """Write storage atomically to prevent partial/corrupt writes."""
        directory = os.path.dirname(self.storage_path) or "."
        os.makedirs(directory, exist_ok=True)
        temp_path = os.path.join(
            directory, f".{os.path.basename(self.storage_path)}.{os.getpid()}.tmp"
        )
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, self.storage_path)

    def _ensure_storage(self):
        """Ensure storage file exists."""
        with self._storage_lock():
            if not os.path.exists(self.storage_path):
                self._atomic_write_storage({})

    def _load_storage_unlocked(self):
        """Load blockchain simulation data."""
        try:
            with open(self.storage_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (IOError, json.JSONDecodeError):
            return {}

    def _load_storage(self):
        """Load storage with lock protection."""
        with self._storage_lock():
            return self._load_storage_unlocked()

    def _save_storage(self, data):
        """Save blockchain simulation data."""
        with self._storage_lock():
            self._atomic_write_storage(data)

    def submit_digest(self, digest, metadata=None):
        """
        Submit digest to mock blockchain.

        Args:
            digest: SHA-256 digest as hex string
            metadata: Additional metadata

        Returns:
            dict: Mock transaction details
        """
        if not self.validate_digest(digest):
            raise ValueError("Invalid digest format")

        timestamp = self._now_iso()

        with self._storage_lock():
            storage = self._load_storage_unlocked()
            tx_data = f"{digest}:{timestamp}:{len(storage)}"
            tx_hash = hashlib.sha256(tx_data.encode("utf-8")).hexdigest()
            block_number = len(storage) + 1
            storage[tx_hash] = {
                "digest": digest,
                "timestamp": timestamp,
                "block_number": block_number,
                "confirmations": 1,
                "metadata": metadata or {},
            }
            self._atomic_write_storage(storage)

        return self._build_submit_result(
            tx_hash=tx_hash,
            digest=digest,
            status="confirmed",
            block_number=block_number,
            confirmations=1,
            message="Stored in mock ledger",
            timestamp=timestamp,
        )

    def verify_digest(self, digest_hex, tx_hash):
        """
        Verify digest in mock blockchain.

        Args:
            digest_hex: SHA-256 digest as hex string
            tx_hash: Transaction hash

        Returns:
            dict: Verification results
        """
        if not self.validate_digest(digest_hex):
            return self._build_verify_result(
                tx_hash=tx_hash,
                digest=digest_hex,
                verified=False,
                status="invalid_digest",
                message="Invalid digest format",
            )

        storage = self._load_storage()

        if tx_hash not in storage:
            return self._build_verify_result(
                tx_hash=tx_hash,
                digest=digest_hex,
                verified=False,
                status="not_found",
                message="Transaction not found",
            )

        tx_data = storage[tx_hash]
        verified = tx_data.get("digest") == digest_hex
        status = "verified" if verified else "mismatch"

        return self._build_verify_result(
            tx_hash=tx_hash,
            digest=digest_hex,
            verified=verified,
            status=status,
            block_number=tx_data.get("block_number"),
            confirmations=tx_data.get("confirmations", 1),
            timestamp=tx_data.get("timestamp"),
            message="Verified" if verified else "Digest mismatch",
        )

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
            return self._build_transaction_status(
                tx_hash=tx_hash,
                found=False,
                status="not_found",
                message="Transaction not found",
            )

        tx_data = storage[tx_hash]
        return self._build_transaction_status(
            tx_hash=tx_hash,
            found=True,
            status="confirmed",
            block_number=tx_data.get("block_number"),
            confirmations=tx_data.get("confirmations", 1),
            timestamp=tx_data.get("timestamp"),
            message="Transaction confirmed",
        )
