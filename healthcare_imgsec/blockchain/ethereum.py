"""
Ethereum blockchain adapter using web3.py.
"""

import os
import logging
from .base import BlockchainAdapter

logger = logging.getLogger(__name__)


class EthereumBlockchainAdapter(BlockchainAdapter):
    """Ethereum blockchain adapter for audit anchoring."""

    def __init__(self, config=None):
        """Initialize Ethereum blockchain adapter."""
        super().__init__(config)

        # Import web3 dynamically for optional dependency
        try:
            from web3 import Web3
            self.Web3 = Web3
        except ImportError:
            raise ImportError(
                "web3.py is required for Ethereum blockchain support. "
                "Install with: pip install web3"
            )

        # Get configuration
        self.rpc_url = self.config.get(
            'rpc_url',
            os.environ.get('ETHEREUM_RPC_URL', 'http://localhost:8545')
        )
        self.private_key = self.config.get(
            'private_key',
            os.environ.get('ETHEREUM_PRIVATE_KEY')
        )
        self.contract_address = self.config.get(
            'contract_address',
            os.environ.get('ETHEREUM_CONTRACT_ADDRESS')
        )

        # Initialize web3
        self.w3 = self.Web3(self.Web3.HTTPProvider(self.rpc_url))

        if not self.w3.is_connected():
            raise ConnectionError(
                f"Cannot connect to Ethereum node at {self.rpc_url}")

        # Set up account if private key provided
        if self.private_key:
            if self.private_key.startswith('0x'):
                self.private_key = self.private_key[2:]
            self.account = self.w3.eth.account.from_key(self.private_key)
        else:
            self.account = None
            logger.warning("No private key configured - read-only mode")

    def submit_digest(self, digest_hex, metadata=None):
        """
        Submit digest to Ethereum blockchain.

        Args:
            digest_hex: SHA-256 digest as hex string
            metadata: Additional metadata

        Returns:
            dict: Transaction details
        """
        if not self.validate_digest(digest_hex):
            raise ValueError("Invalid digest format")

        if not self.account:
            raise ValueError("No private key configured for transactions")

        try:
            # Convert digest to bytes
            digest_bytes = bytes.fromhex(digest_hex)

            # Build transaction data (simple data field approach)
            # Format: "AUDIT:" + digest_hex
            tx_data = f"AUDIT:{digest_hex}".encode('utf-8')

            # Build transaction
            transaction = {
                'to': self.contract_address or self.account.address,
                'value': 0,
                'gas': 21000 + len(tx_data) * 16,  # Base gas + data gas
                'gasPrice': self.w3.eth.gas_price,
                'nonce': self.w3.eth.get_transaction_count(self.account.address),
                'data': tx_data.hex()
            }

            # Sign and send transaction
            signed_txn = self.w3.eth.account.sign_transaction(
                transaction,
                private_key=self.private_key
            )
            tx_hash = self.w3.eth.send_raw_transaction(
                signed_txn.rawTransaction)

            # Wait for confirmation (optional)
            receipt = None
            try:
                receipt = self.w3.eth.wait_for_transaction_receipt(
                    tx_hash,
                    timeout=60
                )
            except Exception as e:
                logger.warning(
                    "Transaction submitted but receipt failed: %s", e)

            return {
                'tx_hash': tx_hash.hex(),
                'block_number': receipt.blockNumber if receipt else None,
                'gas_used': receipt.gasUsed if receipt else None,
                'status': 'confirmed' if receipt and receipt.status == 1 else 'pending'
            }

        except Exception as e:
            logger.error("Failed to submit digest to Ethereum: %s", e)
            raise

    def verify_digest(self, digest_hex, tx_hash):
        """
        Verify digest in Ethereum blockchain.

        Args:
            digest_hex: SHA-256 digest as hex string
            tx_hash: Transaction hash

        Returns:
            dict: Verification results
        """
        try:
            # Get transaction
            tx = self.w3.eth.get_transaction(tx_hash)

            if not tx:
                return {
                    'verified': False,
                    'message': 'Transaction not found'
                }

            # Check transaction data
            expected_data = f"AUDIT:{digest_hex}".encode('utf-8').hex()
            tx_data = tx.input.hex() if hasattr(
                tx.input, 'hex') else tx.input[2:]

            verified = tx_data == expected_data

            # Get block info
            block_number = tx.blockNumber
            current_block = self.w3.eth.block_number
            confirmations = max(0, current_block -
                                block_number + 1) if block_number else 0

            return {
                'verified': verified,
                'block_number': block_number,
                'confirmations': confirmations,
                'message': 'Verified' if verified else 'Digest mismatch'
            }

        except Exception as e:
            logger.error("Failed to verify digest: %s", e)
            return {
                'verified': False,
                'message': f'Verification error: {e}'
            }

    def get_transaction_status(self, tx_hash):
        """
        Get Ethereum transaction status.

        Args:
            tx_hash: Transaction hash

        Returns:
            dict: Transaction status
        """
        try:
            tx = self.w3.eth.get_transaction(tx_hash)

            if not tx:
                return {
                    'found': False,
                    'status': 'not_found'
                }

            # Get receipt if transaction is mined
            receipt = None
            try:
                receipt = self.w3.eth.get_transaction_receipt(tx_hash)
            except Exception:
                pass

            if receipt:
                status = 'confirmed' if receipt.status == 1 else 'failed'
                confirmations = self.w3.eth.block_number - receipt.blockNumber + 1
            else:
                status = 'pending'
                confirmations = 0

            return {
                'found': True,
                'status': status,
                'block_number': tx.blockNumber,
                'confirmations': confirmations,
                'gas_used': receipt.gasUsed if receipt else None
            }

        except Exception as e:
            logger.error("Failed to get transaction status: %s", e)
            return {
                'found': False,
                'status': 'error',
                'message': str(e)
            }
