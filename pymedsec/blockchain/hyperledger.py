# SPDX-License-Identifier: Apache-2.0

"""
Hyperledger Fabric blockchain adapter.
"""

import json
import logging
import os

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
        self.backend_name = "hyperledger"

        # Check if Hyperledger Fabric SDK is available.
        if not HFC_AVAILABLE:
            raise ImportError(
                "Hyperledger Fabric Python SDK is required for Hyperledger support. "
                "Install with: pip install fabric-sdk-py"
            )

        # Canonical blockchain environment variables.
        self.network_profile = self.config.get(
            "network_profile",
            os.environ.get("IMGSEC_HYPERLEDGER_NETWORK_PROFILE", "network.json"),
        )
        self.channel_name = self.config.get(
            "channel_name", os.environ.get("IMGSEC_HYPERLEDGER_CHANNEL", "mychannel")
        )
        self.chaincode_name = self.config.get(
            "chaincode_name",
            os.environ.get("IMGSEC_HYPERLEDGER_CHAINCODE", "audit_chaincode"),
        )
        self.org_name = self.config.get(
            "org_name", os.environ.get("IMGSEC_HYPERLEDGER_ORG", "Org1MSP")
        )
        self.peer_name = self.config.get(
            "peer_name",
            os.environ.get("IMGSEC_HYPERLEDGER_PEER", "peer0.org1.example.com"),
        )
        self.user_name = self.config.get(
            "user_name", os.environ.get("IMGSEC_HYPERLEDGER_USER", "Admin")
        )
        self.user_secret = self.config.get(
            "user_secret", os.environ.get("IMGSEC_HYPERLEDGER_SECRET", "")
        )

        try:
            self.client = Hyperledger_Fabric_Client(
                net_profile=self.network_profile
            )  # type: ignore
            self.org = self.client.get_organization(self.org_name)
            self.user = self.client.get_user(self.org_name, self.user_name)
            self.peer = self.client.get_peer(self.peer_name)
            self.channel = self.client.new_channel(self.channel_name)

            if not all([self.client, self.org, self.user, self.peer, self.channel]):
                raise RuntimeError("Hyperledger adapter missing required client components")

            logger.info(
                "Hyperledger Fabric client initialized (channel=%s, chaincode=%s)",
                self.channel_name,
                self.chaincode_name,
            )
        except Exception as exc:
            raise RuntimeError(
                f"Failed to initialize Hyperledger client: {exc}"
            ) from exc

    @staticmethod
    def _normalize_response(response):
        """Normalize SDK response payload into a dictionary."""
        if response is None:
            return {}

        if isinstance(response, (list, tuple)):
            if not response:
                return {}
            response = response[0]

        if isinstance(response, bytes):
            response = response.decode("utf-8", errors="replace")

        if isinstance(response, str):
            response = response.strip()
            if not response:
                return {}
            try:
                return json.loads(response)
            except json.JSONDecodeError:
                return {"raw": response}

        if isinstance(response, dict):
            return response

        return {"raw": str(response)}

    @staticmethod
    def _extract_tx_hash(payload):
        """Extract transaction hash from heterogeneous Fabric SDK payloads."""
        for key in ("tx_hash", "tx_id", "transaction_id", "id"):
            value = payload.get(key)
            if value:
                return str(value)
        return None

    def submit_digest(self, digest, metadata=None):
        """Submit digest to Hyperledger Fabric blockchain."""
        if not self.validate_digest(digest):
            raise ValueError("Invalid digest format")

        try:
            args = [digest, json.dumps(metadata or {}, sort_keys=True, separators=(",", ":"))]
            response = self.client.chaincode_invoke(
                requestor=self.user,
                channel_name=self.channel_name,
                peers=[self.peer],
                args=args,
                cc_name=self.chaincode_name,
                fcn="submitDigest",
            )
            payload = self._normalize_response(response)
            tx_hash = self._extract_tx_hash(payload)
            if not tx_hash:
                raise RuntimeError(f"Missing tx identifier in invoke response: {payload}")

            return self._build_submit_result(
                tx_hash=tx_hash,
                digest=digest,
                status="submitted",
                message="Digest submitted to Hyperledger",
            )
        except Exception as exc:
            logger.error("Failed to submit digest to Hyperledger Fabric: %s", exc)
            raise

    def verify_digest(self, digest_hex, tx_hash):
        """Verify digest in Hyperledger Fabric blockchain."""
        if not self.validate_digest(digest_hex):
            return self._build_verify_result(
                tx_hash=tx_hash,
                digest=digest_hex,
                verified=False,
                status="invalid_digest",
                message="Invalid digest format",
            )

        try:
            response = self.client.chaincode_query(
                requestor=self.user,
                channel_name=self.channel_name,
                peers=[self.peer],
                args=[digest_hex, tx_hash],
                cc_name=self.chaincode_name,
                fcn="verifyDigest",
            )
            payload = self._normalize_response(response)
            verified = bool(payload.get("verified", False))
            status = payload.get("status")
            if status not in {"verified", "not_found", "mismatch", "pending", "error"}:
                status = "verified" if verified else "mismatch"

            confirmations = int(payload.get("confirmations", 0) or 0)
            block_number = payload.get("block_number")

            return self._build_verify_result(
                tx_hash=tx_hash,
                digest=digest_hex,
                verified=verified,
                status=status,
                block_number=block_number,
                confirmations=confirmations,
                message=payload.get("message", "Verification completed"),
                timestamp=payload.get("timestamp"),
            )
        except Exception as exc:
            logger.error("Failed to verify Hyperledger digest: %s", exc)
            return self._build_verify_result(
                tx_hash=tx_hash,
                digest=digest_hex,
                verified=False,
                status="error",
                message=str(exc),
            )

    def get_transaction_status(self, tx_hash):
        """Get Hyperledger Fabric transaction status."""
        try:
            response = self.client.query_transaction(
                requestor=self.user,
                channel_name=self.channel_name,
                peers=[self.peer],
                tx_id=tx_hash,
            )
            payload = self._normalize_response(response)
            if not payload:
                return self._build_transaction_status(
                    tx_hash=tx_hash,
                    found=False,
                    status="not_found",
                    message="Transaction not found",
                )

            found = bool(payload.get("found", True))
            status = payload.get("status")
            if not status:
                if payload.get("valid") is False:
                    status = "failed"
                elif payload.get("block_number") is not None:
                    status = "confirmed"
                else:
                    status = "pending"

            return self._build_transaction_status(
                tx_hash=tx_hash,
                found=found,
                status=status,
                block_number=payload.get("block_number"),
                confirmations=int(payload.get("confirmations", 0) or 0),
                message=payload.get("message"),
                timestamp=payload.get("timestamp"),
            )
        except Exception as exc:
            logger.error("Failed to get Hyperledger transaction status: %s", exc)
            return self._build_transaction_status(
                tx_hash=tx_hash,
                found=False,
                status="error",
                message=str(exc),
            )
