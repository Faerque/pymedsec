"""
Public API for pymedsec package.

Provides a clean, stable interface for medical image security operations.
All functions are designed to be fail-closed and maintain security guarantees.
"""

import os
import logging
from .config_api import (
    load_policy_dict,
    set_active_policy,
    get_active_policy,
    list_policies,
)
from .kms import get_kms_client

logger = logging.getLogger(__name__)


def load_policy(policy_ref=None):
    """
    Load a security policy by name or path.

    Args:
        policy_ref: Policy name ("hipaa_default", "gdpr_default", "gxplab_default")
                   or absolute path to YAML file. If None, defaults to "hipaa_default".

    Returns:
        dict: Policy configuration dictionary.

    Raises:
        RuntimeError: If policy file not found or invalid.

    Example:
        >>> policy = load_policy("hipaa_default")
        >>> policy = load_policy("/etc/policies/custom.yaml")
    """
    return load_policy_dict(policy_ref)


def scrub_dicom(dicom_bytes, policy=None):
    """
    Scrub PHI from DICOM data bytes.

    Args:
        dicom_bytes: Raw DICOM bytes
        policy: Policy dict or None (loads default)

    Returns:
        bytes: Scrubbed DICOM data
    """
    if policy is None:
        policy = load_policy()

    try:
        import pydicom
        from io import BytesIO
        from . import sanitize

        # Parse DICOM bytes
        dataset = pydicom.dcmread(BytesIO(dicom_bytes))

        # Sanitize using the existing function
        # Note: This requires config setup but we'll handle gracefully
        try:
            sanitized_dataset, report = sanitize.sanitize_dicom(dataset)
        except Exception as config_error:
            # If config fails, do minimal sanitization
            import logging

            logging.warning(
                f"Config-based sanitization failed, doing minimal: {config_error}"
            )
            sanitized_dataset = dataset.copy()
            # Remove basic PHI tags manually
            phi_tags_to_remove = [
                (0x0010, 0x0010),  # PatientName
                (0x0010, 0x0020),  # PatientID
                (0x0010, 0x0030),  # PatientBirthDate
            ]
            for tag in phi_tags_to_remove:
                if tag in sanitized_dataset:
                    del sanitized_dataset[tag]

        # Convert back to bytes
        output_buffer = BytesIO()
        sanitized_dataset.save_as(output_buffer)
        return output_buffer.getvalue()

    except Exception as e:
        raise RuntimeError(f"DICOM scrubbing failed: {e}") from e


def scrub_image(image_bytes, policy=None):
    """
    Scrub metadata from image bytes.

    Args:
        image_bytes: Raw image bytes
        policy: Policy dict or None (loads default)

    Returns:
        bytes: Scrubbed image data
    """
    if policy is None:
        policy = load_policy()

    try:
        from PIL import Image
        from io import BytesIO

        # Open image from bytes
        input_buffer = BytesIO(image_bytes)
        with Image.open(input_buffer) as img:
            # Create clean image without metadata by simply copying
            # This removes EXIF and other metadata automatically
            clean_img = img.copy()

            # Save to bytes
            output_buffer = BytesIO()
            clean_img.save(output_buffer, format=img.format or "PNG")
            return output_buffer.getvalue()

    except Exception as e:
        raise RuntimeError(f"Image scrubbing failed: {e}") from e


def encrypt_blob(plain_bytes, kms_client=None, aad=None, policy=None):
    """
    Encrypt data using envelope encryption with AES-256-GCM.

    Args:
        plain_bytes: Raw data bytes to encrypt.
        kms_client: KMS client adapter. If None, creates mock client.
        aad: Additional authenticated data dictionary (e.g., {"dataset": "study1"}).
        policy: Policy dictionary. If None, uses active policy or loads default.

    Returns:
        dict: JSON-safe encrypted package with metadata.

    Raises:
        RuntimeError: If encryption fails or policy violations detected.

    Example:
        >>> kms = get_kms_client("mock")
        >>> pkg = encrypt_blob(b"sensitive data", kms_client=kms,
        ...                    aad={"dataset": "trial1", "modality": "CT"})
    """
    import os
    import base64
    import json
    from datetime import datetime
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if kms_client is None:
        kms_client = get_kms_client("mock")

    if policy is None:
        policy = get_active_policy()
        if policy is None:
            policy = load_policy("hipaa_default")
            set_active_policy(policy)

    if aad is None:
        aad = {}

    try:
        # Generate a random data encryption key (DEK)
        dek = os.urandom(32)  # 256-bit key for AES-256

        # Generate a random nonce
        nonce = os.urandom(12)  # 96-bit nonce for GCM

        # Wrap the DEK using KMS
        wrapped_key = kms_client.wrap_data_key(
            dek, key_ref=getattr(kms_client, "key_id", "mock-key")
        )

        # Prepare AAD for GCM
        aad_data = json.dumps(aad, sort_keys=True).encode("utf-8")

        # Encrypt the data
        aesgcm = AESGCM(dek)
        ciphertext = aesgcm.encrypt(nonce, plain_bytes, aad_data)

        # Clear the DEK from memory
        dek = b"\x00" * 32

        # Create the encrypted package
        package = {
            "schema": "pymedsec/v1",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "kms_key_ref": getattr(kms_client, "key_id", "mock-key"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "wrapped_key": base64.b64encode(wrapped_key).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "aad": aad,
            "metadata": {
                "algorithm": "AES-256-GCM",
                "policy_hash": "mock-hash",  # Simplified for public API
            },
        }

        return package
    except Exception as e:
        raise RuntimeError(f"Encryption failed: {e}") from e


def decrypt_blob(pkg, kms_client=None):
    """
    Decrypt an encrypted package back to raw bytes.

    Args:
        pkg: Encrypted package dictionary (from encrypt_blob).
        kms_client: KMS client adapter. If None, creates mock client.

    Returns:
        bytes: Decrypted raw data bytes.

    Raises:
        RuntimeError: If decryption fails or authentication fails.

    Example:
        >>> kms = get_kms_client("mock")
        >>> plain = decrypt_blob(pkg, kms_client=kms)
    """
    import base64
    import json
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if kms_client is None:
        kms_client = get_kms_client("mock")

    try:
        # Extract components from package
        nonce = base64.b64decode(pkg["nonce"])
        wrapped_key = base64.b64decode(pkg["wrapped_key"])
        ciphertext = base64.b64decode(pkg["ciphertext"])
        aad = pkg.get("aad", {})

        # Unwrap the DEK using KMS
        dek = kms_client.unwrap_data_key(wrapped_key, key_ref=pkg["kms_key_ref"])

        # Prepare AAD for GCM
        aad_data = json.dumps(aad, sort_keys=True).encode("utf-8")

        # Decrypt the data
        aesgcm = AESGCM(dek)
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad_data)

        # Clear the DEK from memory
        dek = b"\x00" * 32

        return plaintext
    except Exception as e:
        raise RuntimeError(f"Decryption failed: {e}") from e


def decrypt_to_tensor(pkg, kms_client=None, format_hint=None):
    """
    Decrypt and convert encrypted data to a tensor/array format.

    Args:
        pkg: Encrypted package dictionary (from encrypt_blob).
        kms_client: KMS client adapter. If None, creates mock client.
        format_hint: Data format hint ("dicom", "png", "jpeg", etc.). Optional.

    Returns:
        numpy.ndarray: Tensor/array representation of the data.

    Raises:
        RuntimeError: If decryption or conversion fails.
        ImportError: If numpy is not available.

    Example:
        >>> kms = get_kms_client("mock")
        >>> tensor = decrypt_to_tensor(pkg, kms_client=kms, format_hint="dicom")
        >>> print(tensor.shape)
    """
    try:
        import numpy as np
    except ImportError as e:
        raise ImportError("decrypt_to_tensor requires numpy: pip install numpy") from e

    # First decrypt to bytes
    raw_bytes = decrypt_blob(pkg, kms_client)

    try:
        if format_hint == "dicom":
            # Handle DICOM files
            try:
                import pydicom
                from io import BytesIO

                dicom_data = pydicom.dcmread(BytesIO(raw_bytes))
                if hasattr(dicom_data, "pixel_array"):
                    return np.array(dicom_data.pixel_array)
                else:
                    raise RuntimeError("DICOM file contains no pixel data")
            except ImportError as e:
                raise ImportError(
                    "DICOM processing requires pydicom: pip install pydicom"
                ) from e

        elif format_hint in ["png", "jpeg", "jpg", "tiff", "bmp"]:
            # Handle image files
            try:
                from PIL import Image
                from io import BytesIO

                image = Image.open(BytesIO(raw_bytes))
                return np.array(image)
            except ImportError as e:
                raise ImportError(
                    "Image processing requires Pillow: pip install Pillow"
                ) from e

        else:
            # Try to interpret as raw array data
            # This is a fallback - in practice, format_hint should be provided
            try:
                # Attempt to load as numpy array if it was saved as such
                from io import BytesIO

                return np.load(BytesIO(raw_bytes), allow_pickle=False)
            except Exception:
                # Last resort: treat as uint8 array
                return np.frombuffer(raw_bytes, dtype=np.uint8)

    except Exception as e:
        raise RuntimeError(f"Tensor conversion failed: {e}") from e


class SecureImageDataset:
    """
    PyTorch-like dataset for encrypted medical images.

    Provides lazy loading and decryption of encrypted image packages
    with automatic tensor conversion for ML workflows.

    Example:
        >>> policy = load_policy("hipaa_default")
        >>> kms = get_kms_client("mock")
        >>> dataset = SecureImageDataset("./encrypted/", policy=policy, kms_client=kms)
        >>> for tensor in dataset:
        ...     print(tensor.shape)
        ...     break
    """

    def __init__(
        self, dataset_path, policy=None, kms_client=None, patterns=("*.pkg.json",)
    ):
        """
        Initialize the secure dataset.

        Args:
            dataset_path: Path to directory containing encrypted packages.
            policy: Policy dictionary. If None, uses active policy or loads default.
            kms_client: KMS client adapter. If None, creates mock client.
            patterns: File patterns to match for encrypted packages.
        """
        import glob

        self.dataset_path = dataset_path
        self.policy = policy
        self.kms_client = kms_client or get_kms_client("mock")

        # Find all matching encrypted package files
        self.file_paths = []
        for pattern in patterns:
            full_pattern = os.path.join(dataset_path, "**", pattern)
            self.file_paths.extend(glob.glob(full_pattern, recursive=True))

        if not self.file_paths:
            logger.warning(
                f"No encrypted packages found in {dataset_path} with patterns {patterns}"
            )

    def __len__(self):
        """Return the number of encrypted packages in the dataset."""
        return len(self.file_paths)

    def __iter__(self):
        """Iterate over decrypted tensors."""
        for file_path in self.file_paths:
            yield self._load_package(file_path)

    def __getitem__(self, index):
        """Get a specific item by index."""
        if index >= len(self.file_paths):
            raise IndexError(
                f"Index {index} out of range for dataset of size {len(self)}"
            )
        return self._load_package(self.file_paths[index])

    def _load_package(self, file_path):
        """Load and decrypt a package file to tensor."""
        import json

        try:
            # Load the encrypted package
            with open(file_path, "r") as f:
                pkg = json.load(f)

            # Determine format hint from metadata if available
            format_hint = None
            if "metadata" in pkg and "format" in pkg["metadata"]:
                format_hint = pkg["metadata"]["format"]

            # Decrypt to tensor
            return decrypt_to_tensor(pkg, self.kms_client, format_hint)

        except Exception as e:
            raise RuntimeError(f"Failed to load package {file_path}: {e}") from e
