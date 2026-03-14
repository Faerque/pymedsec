# SPDX-License-Identifier: Apache-2.0

"""
Ethereum blockchain adapter using web3.py.
"""

import logging
import os
import time

from .base import BlockchainAdapter

# Try to import web3 at module level
try:
    from web3 import Web3
    from web3.exceptions import TimeExhausted, TransactionNotFound

    WEB3_AVAILABLE = True
except ImportError:
    Web3 = None  # type: ignore
    TimeExhausted = Exception  # type: ignore
    TransactionNotFound = Exception  # type: ignore
    WEB3_AVAILABLE = False

logger = logging.getLogger(__name__)


class EthereumBlockchainAdapter(BlockchainAdapter):
    """Ethereum blockchain adapter for audit anchoring."""

    PAYLOAD_PREFIX = b"IMGSEC_AUDIT_V1:"

    def __init__(self, config=None):
        """Initialize Ethereum blockchain adapter."""
        super().__init__(config)
        self.backend_name = "ethereum"

        # Check if web3 is available
        if not WEB3_AVAILABLE:
            raise ImportError(
                "web3.py is required for Ethereum blockchain support. "
                "Install with: pip install web3"
            )

        # Canonical blockchain environment variables.
        self.rpc_url = self.config.get(
            "rpc_url",
            os.environ.get("IMGSEC_ETHEREUM_RPC_URL", "http://localhost:8545"),
        )
        self.private_key = self.config.get(
            "private_key", os.environ.get("IMGSEC_ETHEREUM_PRIVATE_KEY")
        )
        self.contract_address = self.config.get(
            "contract_address", os.environ.get("IMGSEC_ETHEREUM_CONTRACT_ADDRESS")
        )

        self.retry_count = max(
            0,
            int(
                self.config.get(
                    "retry_count", os.environ.get("IMGSEC_ETHEREUM_RETRY_COUNT", "3")
                )
            ),
        )
        self.retry_backoff = max(
            0.0,
            float(
                self.config.get(
                    "retry_backoff",
                    os.environ.get("IMGSEC_ETHEREUM_RETRY_BACKOFF_SECS", "1.0"),
                )
            ),
        )
        self.receipt_timeout = max(
            1,
            int(
                self.config.get(
                    "receipt_timeout",
                    os.environ.get("IMGSEC_ETHEREUM_RECEIPT_TIMEOUT", "60"),
                )
            ),
        )
        self.required_confirmations = max(
            1,
            int(
                self.config.get(
                    "confirmations",
                    os.environ.get("IMGSEC_ETHEREUM_CONFIRMATIONS", "1"),
                )
            ),
        )

        # Initialize web3
        self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))  # type: ignore

        if not self.w3.is_connected():
            raise ConnectionError(f"Cannot connect to Ethereum node at {self.rpc_url}")

        env_chain_id = self.config.get("chain_id", os.environ.get("IMGSEC_ETHEREUM_CHAIN_ID"))
        if env_chain_id is not None:
            self.chain_id = int(env_chain_id)
        else:
            self.chain_id = int(self._call_with_retry(lambda: self.w3.eth.chain_id))

        # Set up account if private key provided
        if self.private_key:
            if self.private_key.startswith("0x"):
                self.private_key = self.private_key[2:]
            self.account = self.w3.eth.account.from_key(self.private_key)
        else:
            self.account = None
            logger.warning("No Ethereum private key configured - read-only mode")

        if self.contract_address:
            if not self.w3.is_address(self.contract_address):
                raise ValueError("IMGSEC_ETHEREUM_CONTRACT_ADDRESS is not a valid address")
            self.contract_address = self.w3.to_checksum_address(self.contract_address)

    def _call_with_retry(self, func, *args, **kwargs):
        """Execute web3 calls with bounded retry and backoff."""
        for attempt in range(self.retry_count + 1):
            try:
                return func(*args, **kwargs)
            except Exception as exc:
                # Do not retry deterministic/request-shape errors.
                if isinstance(exc, (TransactionNotFound, ValueError)):
                    raise
                if attempt >= self.retry_count:
                    raise
                sleep_secs = self.retry_backoff * (2**attempt)
                if sleep_secs > 0:
                    time.sleep(sleep_secs)

    def _encoded_payload(self, digest_hex):
        """Encode digest into deterministic payload bytes for on-chain verification."""
        return b"0x" + (self.PAYLOAD_PREFIX + bytes.fromhex(digest_hex)).hex().encode("ascii")

    def _normalize_input_hex(self, tx_input):
        """Normalize transaction input to lowercase 0x-prefixed hex string."""
        if tx_input is None:
            return ""

        if isinstance(tx_input, str):
            return tx_input.lower() if tx_input.startswith("0x") else f"0x{tx_input.lower()}"

        if isinstance(tx_input, (bytes, bytearray)):
            return "0x" + bytes(tx_input).hex()

        if hasattr(tx_input, "hex"):
            value = tx_input.hex()
            return value.lower() if value.startswith("0x") else f"0x{value.lower()}"

        return str(tx_input).lower()

    def _confirmation_count(self, block_number):
        """Compute chain confirmation count for a mined tx."""
        if block_number is None:
            return 0
        current_block = self._call_with_retry(lambda: self.w3.eth.block_number)
        return max(0, int(current_block) - int(block_number) + 1)

    def submit_digest(self, digest, metadata=None):
        """Submit digest to Ethereum blockchain."""
        if not self.validate_digest(digest):
            raise ValueError("Invalid digest format")

        if not self.account:
            raise ValueError("No private key configured for Ethereum transactions")

        try:
            to_address = self.contract_address or self.account.address
            tx_input = self._encoded_payload(digest).decode("ascii")

            transaction = {
                "from": self.account.address,
                "to": to_address,
                "value": 0,
                "nonce": self._call_with_retry(
                    self.w3.eth.get_transaction_count, self.account.address, "pending"
                ),
                "data": tx_input,
                "chainId": self.chain_id,
            }

            try:
                gas_estimate = self._call_with_retry(self.w3.eth.estimate_gas, transaction)
            except Exception:
                gas_estimate = 21000 + max(0, (len(tx_input) - 2) // 2) * 16
            transaction["gas"] = max(21000, int(gas_estimate * 1.2))

            latest_block = self._call_with_retry(self.w3.eth.get_block, "latest")
            base_fee = latest_block.get("baseFeePerGas") if isinstance(latest_block, dict) else None
            if base_fee is not None:
                try:
                    priority_fee = self._call_with_retry(lambda: self.w3.eth.max_priority_fee)
                except Exception:
                    priority_fee = self._call_with_retry(lambda: self.w3.eth.gas_price)
                transaction["maxPriorityFeePerGas"] = int(priority_fee)
                transaction["maxFeePerGas"] = int(base_fee) * 2 + int(priority_fee)
            else:
                transaction["gasPrice"] = int(self._call_with_retry(lambda: self.w3.eth.gas_price))

            signed_txn = self.w3.eth.account.sign_transaction(
                transaction, private_key=self.private_key
            )
            tx_hash_bytes = self._call_with_retry(
                self.w3.eth.send_raw_transaction, signed_txn.rawTransaction
            )
            tx_hash = tx_hash_bytes.hex()

            receipt = None
            try:
                receipt = self._call_with_retry(
                    self.w3.eth.wait_for_transaction_receipt,
                    tx_hash_bytes,
                    timeout=self.receipt_timeout,
                )
            except TimeExhausted:
                logger.warning(
                    "Ethereum tx submitted but confirmation timeout reached: %s", tx_hash
                )

            block_number = getattr(receipt, "blockNumber", None) if receipt else None
            confirmations = self._confirmation_count(block_number)

            if receipt and getattr(receipt, "status", 0) == 0:
                tx_status = "failed"
                message = "Transaction reverted"
            elif receipt and confirmations >= self.required_confirmations:
                tx_status = "confirmed"
                message = "Transaction confirmed"
            else:
                tx_status = "pending"
                message = "Transaction pending confirmation"

            return self._build_submit_result(
                tx_hash=tx_hash,
                digest=digest,
                status=tx_status,
                block_number=block_number,
                confirmations=confirmations,
                message=message,
            )

        except Exception as exc:
            logger.error("Failed to submit digest to Ethereum: %s", exc)
            raise

    def verify_digest(self, digest_hex, tx_hash):
        """Verify digest in Ethereum blockchain."""
        if not self.validate_digest(digest_hex):
            return self._build_verify_result(
                tx_hash=tx_hash,
                digest=digest_hex,
                verified=False,
                status="invalid_digest",
                message="Invalid digest format",
            )

        try:
            tx = self._call_with_retry(self.w3.eth.get_transaction, tx_hash)
        except TransactionNotFound:
            return self._build_verify_result(
                tx_hash=tx_hash,
                digest=digest_hex,
                verified=False,
                status="not_found",
                message="Transaction not found",
            )
        except Exception as exc:
            logger.error("Failed to load Ethereum transaction %s: %s", tx_hash, exc)
            return self._build_verify_result(
                tx_hash=tx_hash,
                digest=digest_hex,
                verified=False,
                status="error",
                message=str(exc),
            )

        expected_input = self._encoded_payload(digest_hex).decode("ascii").lower()
        actual_input = self._normalize_input_hex(getattr(tx, "input", ""))
        block_number = getattr(tx, "blockNumber", None)
        confirmations = self._confirmation_count(block_number)

        if actual_input != expected_input:
            return self._build_verify_result(
                tx_hash=tx_hash,
                digest=digest_hex,
                verified=False,
                status="mismatch",
                block_number=block_number,
                confirmations=confirmations,
                message="Digest payload mismatch",
            )

        if block_number is None or confirmations < self.required_confirmations:
            return self._build_verify_result(
                tx_hash=tx_hash,
                digest=digest_hex,
                verified=False,
                status="pending",
                block_number=block_number,
                confirmations=confirmations,
                message="Matching payload found but not sufficiently confirmed",
            )

        return self._build_verify_result(
            tx_hash=tx_hash,
            digest=digest_hex,
            verified=True,
            status="verified",
            block_number=block_number,
            confirmations=confirmations,
            message="Digest verified on chain",
        )

    def get_transaction_status(self, tx_hash):
        """Get Ethereum transaction status."""
        try:
            tx = self._call_with_retry(self.w3.eth.get_transaction, tx_hash)
        except TransactionNotFound:
            return self._build_transaction_status(
                tx_hash=tx_hash,
                found=False,
                status="not_found",
                message="Transaction not found",
            )
        except Exception as exc:
            logger.error("Failed to get Ethereum transaction %s: %s", tx_hash, exc)
            return self._build_transaction_status(
                tx_hash=tx_hash,
                found=False,
                status="error",
                message=str(exc),
            )

        block_number = getattr(tx, "blockNumber", None)
        confirmations = self._confirmation_count(block_number)
        status = "pending"
        message = "Transaction pending confirmation"

        if block_number is not None:
            try:
                receipt = self._call_with_retry(self.w3.eth.get_transaction_receipt, tx_hash)
                if getattr(receipt, "status", 0) == 0:
                    status = "failed"
                    message = "Transaction reverted"
                elif confirmations >= self.required_confirmations:
                    status = "confirmed"
                    message = "Transaction confirmed"
            except Exception:
                if confirmations >= self.required_confirmations:
                    status = "confirmed"
                    message = "Transaction confirmed"

        return self._build_transaction_status(
            tx_hash=tx_hash,
            found=True,
            status=status,
            block_number=block_number,
            confirmations=confirmations,
            message=message,
        )
