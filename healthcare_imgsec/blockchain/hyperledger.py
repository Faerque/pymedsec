"""
Hyperledger Fabric blockchain adapter.
"""

import logging
import json
import time
from .base import BlockchainAdapter

# Try to import Hyperledger Fabric SDK
try:
    from hfc.api import Hyperledger_Fabric_Client
    HFC_AVAILABLE = True
except ImportError:
    Hyperledger_Fabric_Client = None  # type: ignore
    HFC_AVAILABLE = False

logger = logging.getLogger(__name__)


class HyperledgerBlockchainAdapter(BlockchainAdapter):
    """Hyperledger Fabric blockchain adapter for audit anchoring."""

    def __init__(self, config=None):
        """Initialize Hyperledger blockchain adapter."""
        super().__init__(config)

        # Check if Hyperledger Fabric SDK is available
        if not HFC_AVAILABLE:
            raise ImportError(
                "Hyperledger Fabric Python SDK is required for Hyperledger support. "
                "Install with: pip install fabric-sdk-py"
            )

        # Initialize Hyperledger Fabric configuration
        self.network_profile = self.config.get('network_profile', 'network.json')
        self.channel_name = self.config.get('channel_name', 'mychannel')
        self.chaincode_name = self.config.get('chaincode_name', 'audit_chaincode')
        self.org_name = self.config.get('org_name', 'Org1MSP')
        self.peer_name = self.config.get('peer_name', 'peer0.org1.example.com')
        self.user_name = self.config.get('user_name', 'Admin')
        self.user_secret = self.config.get('user_secret', 'adminpw')

        # Initialize client
        try:
            self.client = Hyperledger_Fabric_Client(net_profile=self.network_profile)  # type: ignore

            # Get organization and user
            self.org = self.client.get_organization(self.org_name)
            self.user = self.client.get_user(self.org_name, self.user_name)

            # Initialize peer and channel
            self.peer = self.client.get_peer(self.peer_name)
            self.channel = self.client.new_channel(self.channel_name)

            logger.info("Hyperledger Fabric client initialized successfully")

        except Exception as e:
            logger.warning("Failed to initialize Hyperledger Fabric client: %s", e)
            # Set to None for graceful degradation
            self.client = None
            self.org = None
            self.user = None
            self.peer = None
            self.channel = None

    def submit_digest(self, digest, metadata=None):
        """Submit digest to Hyperledger Fabric blockchain."""
        if not self.client:
            raise RuntimeError("Hyperledger Fabric client not initialized")

        if not self.validate_digest(digest):
            raise ValueError("Invalid digest format")

        try:
            # Prepare chaincode arguments
            args = [digest]
            if metadata:
                args.append(json.dumps(metadata))

            # Invoke chaincode to submit digest
            response = self.client.chaincode_invoke(
                requestor=self.user,
                channel_name=self.channel_name,
                peers=[self.peer],
                args=args,
                cc_name=self.chaincode_name,
                fcn='submitDigest'
            )

            # Extract transaction ID
            tx_id = response.get('tx_id')
            if not tx_id:
                raise RuntimeError("Failed to get transaction ID from response")

            return {
                'tx_hash': tx_id,
                'status': 'submitted',
                'timestamp': time.time(),
                'channel': self.channel_name,
                'chaincode': self.chaincode_name
            }

        except Exception as e:
            logger.error("Failed to submit digest to Hyperledger Fabric: %s", e)
            raise

    def verify_digest(self, digest_hex, tx_hash):
        """Verify digest in Hyperledger Fabric blockchain."""
        if not self.client:
            raise RuntimeError("Hyperledger Fabric client not initialized")

        try:
            # Query chaincode to verify digest
            response = self.client.chaincode_query(
                requestor=self.user,
                channel_name=self.channel_name,
                peers=[self.peer],
                args=[digest_hex, tx_hash],
                cc_name=self.chaincode_name,
                fcn='verifyDigest'
            )

            # Parse response
            if response and isinstance(response, str):
                result = json.loads(response)
                return {
                    'verified': result.get('verified', False),
                    'tx_hash': tx_hash,
                    'digest': digest_hex,
                    'timestamp': result.get('timestamp'),
                    'block_number': result.get('block_number'),
                    'message': result.get('message', 'Verification completed')
                }
            else:
                return {
                    'verified': False,
                    'tx_hash': tx_hash,
                    'digest': digest_hex,
                    'message': 'Invalid response from chaincode'
                }

        except Exception as e:
            logger.error("Failed to verify digest: %s", e)
            return {
                'verified': False,
                'tx_hash': tx_hash,
                'digest': digest_hex,
                'message': f'Verification error: {e}'
            }

    def get_transaction_status(self, tx_hash):
        """Get Hyperledger Fabric transaction status."""
        if not self.client:
            raise RuntimeError("Hyperledger Fabric client not initialized")

        try:
            # Query transaction by ID
            transaction = self.client.query_transaction(
                requestor=self.user,
                channel_name=self.channel_name,
                peers=[self.peer],
                tx_id=tx_hash
            )

            if transaction:
                return {
                    'tx_hash': tx_hash,
                    'status': 'confirmed',
                    'valid': transaction.get('valid', False),
                    'timestamp': transaction.get('timestamp'),
                    'block_number': transaction.get('block_number'),
                    'channel': self.channel_name
                }
            else:
                return {
                    'tx_hash': tx_hash,
                    'status': 'not_found',
                    'valid': False,
                    'message': 'Transaction not found'
                }

        except Exception as e:
            logger.error("Failed to get transaction status: %s", e)
            return {
                'tx_hash': tx_hash,
                'status': 'error',
                'valid': False,
                'message': f'Status check error: {e}'
            }

    def validate_digest(self, digest_hex):
        """Validate digest format (SHA-256 hex string)."""
        if not isinstance(digest_hex, str):
            return False
        if len(digest_hex) != 64:
            return False
        try:
            int(digest_hex, 16)
            return True
        except ValueError:
            return False
