# SPDX-License-Identifier: Apache-2.0

"""Integration tests for mock blockchain backend."""

import os
import tempfile
import threading

from pymedsec.blockchain.mock import MockBlockchainAdapter


def test_mock_blockchain_concurrent_submissions():
    """Concurrent submit/verify should not corrupt mock storage."""
    temp_dir = tempfile.mkdtemp()
    storage_path = os.path.join(temp_dir, "mock_chain.json")

    adapter = MockBlockchainAdapter({"storage_path": storage_path})

    digests = [f"{i:064x}" for i in range(1, 51)]
    tx_hashes_by_digest = {}
    tx_lock = threading.Lock()

    def worker(digest):
        result = adapter.submit_digest(digest, {"thread": digest[-4:]})
        with tx_lock:
            tx_hashes_by_digest[digest] = result["tx_hash"]

    threads = [threading.Thread(target=worker, args=(digest,)) for digest in digests]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(tx_hashes_by_digest) == len(digests)
    assert len(set(tx_hashes_by_digest.values())) == len(digests)

    # Verify all submitted digests are retrievable.
    for digest, tx_hash in tx_hashes_by_digest.items():
        verification = adapter.verify_digest(digest, tx_hash)
        assert verification["verified"] is True
        assert verification["status"] == "verified"
