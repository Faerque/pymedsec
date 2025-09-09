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
        key_id = kwargs.get('key_id')
        if not key_id:
            raise RuntimeError("AWS KMS backend requires 'key_id' parameter")

        region_name = kwargs.get('region_name')
        profile_name = kwargs.get('profile_name')

        return AWSKMSAdapter(
            key_id=key_id,
            region_name=region_name,
            profile_name=profile_name
        )

    elif backend == "vault":
        try:
            from .vault import VaultKMSAdapter
        except ImportError as e:
            raise ImportError(
                f"Vault KMS backend requires hvac: pip install hvac. {e}"
            ) from e

        # Extract Vault-specific parameters
        url = kwargs.get('url')
        if not url:
            raise RuntimeError("Vault KMS backend requires 'url' parameter")

        token = kwargs.get('token')
        if not token:
            raise RuntimeError("Vault KMS backend requires 'token' parameter")

        mount = kwargs.get('mount', 'transit')
        key_name = kwargs.get('key_name')
        if not key_name:
            raise RuntimeError("Vault KMS backend requires 'key_name' parameter")

        return VaultKMSAdapter(
            url=url,
            token=token,
            mount=mount,
            key_name=key_name
        )

    else:
        raise RuntimeError(f"Unsupported KMS backend: {backend}")


def get_kms_adapter():
    """Factory function to get configured KMS adapter (legacy internal API)."""
    from .. import config

    cfg = config.get_config()
    backend = cfg.kms_backend

    if backend == 'aws':
        from .aws_kms import AWSKMSAdapter
        return AWSKMSAdapter()
    elif backend == 'vault':
        from .vault import VaultAdapter
        return VaultAdapter()
    elif backend == 'mock':
        from .mock import MockKMSAdapter
        return MockKMSAdapter()
    else:
        raise ValueError(f"Unsupported KMS backend: {backend}")


__all__ = ['get_kms_adapter']
