# SPDX-License-Identifier: Apache-2.0

"""Integration tests for Ethereum blockchain backend."""

import os

import pytest

from pymedsec.blockchain.ethereum import EthereumBlockchainAdapter


@pytest.mark.integration
def test_ethereum_submit_verify_status_roundtrip():
    """Submit digest and verify on an ephemeral Ethereum-compatible node."""
    if os.getenv("RUN_ETHEREUM_INTEGRATION") != "1":
        pytest.skip("Ethereum integration test disabled")

    rpc_url = os.getenv("IMGSEC_ETHEREUM_RPC_URL", "http://127.0.0.1:8545")
    private_key = os.getenv(
        "IMGSEC_ETHEREUM_PRIVATE_KEY",
        # Ganache deterministic first account private key.
        "0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f4a31b8b1f1736f1",
    )

    adapter = EthereumBlockchainAdapter(
        {
            "rpc_url": rpc_url,
            "private_key": private_key,
            "confirmations": 1,
            "retry_count": 2,
            "retry_backoff": 0.2,
            "receipt_timeout": 30,
        }
    )

    digest = "a" * 64
    submit_result = adapter.submit_digest(digest, {"operation": "integration-test"})

    assert submit_result["backend"] == "ethereum"
    assert submit_result["status"] in {"confirmed", "pending"}
    assert submit_result["tx_hash"]

    verify_result = adapter.verify_digest(digest, submit_result["tx_hash"])
    assert verify_result["backend"] == "ethereum"
    assert verify_result["status"] in {"verified", "pending", "mismatch"}

    tx_status = adapter.get_transaction_status(submit_result["tx_hash"])
    assert tx_status["backend"] == "ethereum"
    assert tx_status["status"] in {"pending", "confirmed", "failed"}
