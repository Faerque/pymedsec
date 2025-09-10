# SPDX-License-Identifier: Apache-2.0

"""
KMS adapter interfaces and factory.

Provides unified interface for different KMS backends including
AWS KMS, HashiCorp Vault, and mock implementations.
"""

import logging

logger = logging.getLogger(__name__)


def get_kms_client(backend="mock", **kwargs):
    """
    Create a KMS client adapter for the specified backend.

    Args:
        backend: KMS backend type ("aws", "vault", or "mock").
        **kwargs: Backend-specific configuration options.

    For AWS backend:
        - key_id: AWS KMS key ID or alias
        - region_name: AWS region name
        - profile_name: AWS profile name

    For Vault backend:
        - url: Vault server URL
        - token: Vault authentication token
        - mount: Transit secrets engine mount path (default: "transit")
        - key_name: Transit key name

    For mock backend:
        - No additional parameters needed

    Returns:
        KMS adapter instance with wrap_data_key/unwrap_data_key methods.

    Raises:
        RuntimeError: If backend is unsupported or configuration is invalid.
        ImportError: If required dependencies are missing.

    Example:
        >>> # Mock KMS for testing
        >>> kms = get_kms_client("mock")

        >>> # AWS KMS
        >>> kms = get_kms_client("aws", key_id="alias/my-key", region_name="us-east-1")

        >>> # Vault KMS
        >>> kms = get_kms_client("vault", url="https://vault.example.com",
        ...                      token="s.xyz", key_name="my-key")
    """
    if backend == "mock":
        from .mock import MockKMSAdapter

        return MockKMSAdapter()

    elif backend == "aws":
        try:
            from .aws_kms import AWSKMSAdapter
        except ImportError as e:
            raise ImportError(
                f"AWS KMS backend requires boto3: pip install boto3. {e}"
            ) from e

        # Extract AWS-specific parameters
        key_id = kwargs.get("key_id")
        region_name = kwargs.get("region", kwargs.get("region_name"))
        profile_name = kwargs.get("profile_name")
        access_key_id = kwargs.get("access_key_id")
        secret_access_key = kwargs.get("secret_access_key")

        return AWSKMSAdapter(
            key_id=key_id,
            region_name=region_name,
            profile_name=profile_name,
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
        )

    elif backend == "vault":
        try:
            from .vault import VaultAdapter
        except ImportError as e:
            raise ImportError(
                f"Vault KMS backend requires hvac: pip install hvac. {e}"
            ) from e

        # Extract Vault-specific parameters
        url = kwargs.get("url")
        if not url:
            raise RuntimeError("Vault KMS backend requires 'url' parameter")

        token = kwargs.get("token")
        if not token:
            raise RuntimeError("Vault KMS backend requires 'token' parameter")

        mount = kwargs.get("mount", "transit")
        key_name = kwargs.get("key_name")
        if not key_name:
            raise RuntimeError("Vault KMS backend requires 'key_name' parameter")

        return VaultAdapter(
            vault_url=url,
            vault_token=token,
            mount_point=mount,
            key_name=key_name,  # Parameter added to VaultAdapter constructor
        )

    else:
        raise RuntimeError(f"Unsupported KMS backend: {backend}")


def get_kms_adapter():
    """Factory function to get configured KMS adapter (legacy internal API)."""
    from .. import config

    cfg = config.get_config()
    backend = cfg.kms_backend

    if backend == "aws":
        from .aws_kms import AWSKMSAdapter

        return AWSKMSAdapter()
    elif backend == "vault":
        from .vault import VaultAdapter

        return VaultAdapter()
    elif backend == "mock":
        from .mock import MockKMSAdapter

        return MockKMSAdapter()
    else:
        raise ValueError(f"Unsupported KMS backend: {backend}")


def create_kms_adapter(config=None, backend=None, **kwargs):
    """
    Create a KMS adapter instance.

    Args:
        config: Dictionary with 'provider' and 'config' keys (legacy format)
        backend: Backend type string (new format)
        **kwargs: Backend-specific configuration options.
    """
    if config is not None:
        # Legacy format: {'provider': 'mock', 'config': {...}}
        if isinstance(config, dict) and "provider" in config:
            provider = config["provider"]
            provider_config = config.get("config", {})

            if provider == "mock":
                return get_kms_client("mock")
            elif provider in ("aws", "aws_kms"):
                return get_kms_client("aws", **provider_config)
            elif provider == "vault":
                return get_kms_client("vault", **provider_config)
            else:
                raise RuntimeError(f"Unsupported KMS backend: {config}")
        else:
            raise ValueError(
                "Invalid config format. Expected dict with 'provider' key."
            )
    elif backend is not None:
        # New format: create_kms_adapter(backend="mock", **kwargs)
        return get_kms_client(backend, **kwargs)
    else:
        # Use the configured backend from environment
        return get_kms_adapter()


__all__ = ["get_kms_adapter", "get_kms_client", "create_kms_adapter"]
