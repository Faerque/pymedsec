# SPDX-License-Identifier: Apache-2.0

"""
Blockchain audit anchoring module for pymedsec.

This module provides pluggable blockchain adapters for anchoring audit log
digests to various blockchain networks without exposing PHI.
"""

import os
import logging

logger = logging.getLogger(__name__)


CANONICAL_BACKEND_ENV = "IMGSEC_BLOCKCHAIN_BACKEND"
LEGACY_BACKEND_ENV = "BLOCKCHAIN_BACKEND"


def create_blockchain_adapter(backend=None, config=None):
    """
    Create a blockchain adapter based on configuration.

    Args:
        backend: Blockchain backend type ('ethereum', 'hyperledger', 'mock')
        config: Configuration dict for the adapter

    Returns:
        Blockchain adapter instance or None if disabled
    """
    if backend is None:
        backend = os.environ.get(CANONICAL_BACKEND_ENV, "").strip().lower()
        # Hard switch: legacy env variable is intentionally not supported.
        if not backend and os.environ.get(LEGACY_BACKEND_ENV):
            logger.warning(
                "Ignoring legacy %s. Use %s instead.",
                LEGACY_BACKEND_ENV,
                CANONICAL_BACKEND_ENV,
            )
    else:
        backend = str(backend).strip().lower()

    if not backend or backend == "disabled":
        return None

    if config is None:
        config = {}
    else:
        config = dict(config)
    config.setdefault("backend", backend)

    try:
        if backend == "ethereum":
            from .ethereum import EthereumBlockchainAdapter

            return EthereumBlockchainAdapter(config)

        elif backend == "hyperledger":
            from .hyperledger import HyperledgerBlockchainAdapter

            return HyperledgerBlockchainAdapter(config)

        elif backend == "mock":
            from .mock import MockBlockchainAdapter

            return MockBlockchainAdapter(config)

        else:
            logger.warning("Unknown blockchain backend: %s", backend)
            return None

    except ImportError as e:
        logger.warning("Failed to import blockchain adapter %s: %s", backend, e)
        return None
    except Exception as e:
        logger.error("Failed to create blockchain adapter %s: %s", backend, e)
        return None


__all__ = ["create_blockchain_adapter"]
