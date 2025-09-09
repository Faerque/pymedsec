"""
Streaming data loader for ML training.

Provides PyTorch-compatible streaming data loader that decrypts
medical images in memory without writing plaintext to disk.
"""

import logging
from pathlib import Path

from . import config
from . import crypto
from . import intake

logger = logging.getLogger(__name__)


class EncryptedImageLoader:
    """Streaming loader for encrypted medical images."""

    def __init__(self, encrypted_files, batch_size=1, verify_integrity=True):
        """
        Initialize encrypted image loader.

        Args:
            encrypted_files: List of encrypted package file paths or EncryptedPackage objects
            batch_size: Batch size for loading (currently only supports 1)
            verify_integrity: Whether to verify package integrity before decryption
        """
        self.encrypted_files = encrypted_files
        self.batch_size = batch_size
        self.verify_integrity = verify_integrity
        self.current_index = 0

        if batch_size != 1:
            logger.warning("Batch sizes > 1 not yet implemented, using batch_size=1")
            self.batch_size = 1

    def __len__(self):
        """Return number of encrypted files."""
        return len(self.encrypted_files)

    def __iter__(self):
        """Make loader iterable."""
        self.current_index = 0
        return self

    def __next__(self):
        """Get next decrypted tensor."""
        if self.current_index >= len(self.encrypted_files):
            raise StopIteration

        encrypted_file = self.encrypted_files[self.current_index]
        self.current_index += 1

        try:
            # Load encrypted package
            if isinstance(encrypted_file, (str, Path)):
                with open(encrypted_file, "r", encoding="utf-8") as f:
                    package_json = f.read()
                package = crypto.EncryptedPackage.from_json(package_json)
                file_path = str(encrypted_file)
            else:
                package = encrypted_file
                file_path = f"package_{self.current_index - 1}"

            # Verify integrity if requested
            if self.verify_integrity:
                verification_result = crypto.verify_package_integrity(package)
                if not verification_result["is_valid"]:
                    raise RuntimeError(
                        f"Package integrity verification failed: {verification_result['errors']}"
                    )

            # Decrypt in memory
            plaintext_data = crypto.decrypt_data(package, verify_aad=True)

            # Convert to tensor
            # Note: We need to infer format from package metadata
            metadata = crypto.extract_package_metadata(package)
            format_hint = self._infer_format_from_metadata(metadata)

            tensor = intake.to_tensor(plaintext_data, format_hint=format_hint)

            # Zeroize plaintext data
            plaintext_data = b"\x00" * len(plaintext_data)
            del plaintext_data

            logger.debug(
                "Loaded encrypted image: %s, tensor shape: %s", file_path, tensor.shape
            )

            return {"tensor": tensor, "metadata": metadata, "file_path": file_path}

        except Exception as e:
            logger.error("Failed to load encrypted image %s: %s", encrypted_file, e)
            raise

    def _infer_format_from_metadata(self, metadata):
        """Infer image format from package metadata."""
        modality = metadata.get("modality", "OT")

        # Common DICOM modalities
        dicom_modalities = ["CT", "MR", "US", "XA", "DX", "CR", "MG", "PT", "NM"]

        if modality in dicom_modalities:
            return "dicom"
        else:
            # Default to generic image format
            return None

    def get_dataset_info(self):
        """Get information about the encrypted dataset."""
        info = {
            "total_files": len(self.encrypted_files),
            "modalities": {},
            "datasets": {},
            "policies": {},
            "size_stats": {"min_bytes": float("inf"), "max_bytes": 0, "total_bytes": 0},
        }

        for encrypted_file in self.encrypted_files:
            try:
                if isinstance(encrypted_file, (str, Path)):
                    with open(encrypted_file, "r", encoding="utf-8") as f:
                        package_json = f.read()
                    package = crypto.EncryptedPackage.from_json(package_json)
                else:
                    package = encrypted_file
                    package_json = package.to_json()

                metadata = crypto.extract_package_metadata(package)

                # Count modalities
                modality = metadata.get("modality", "Unknown")
                info["modalities"][modality] = info["modalities"].get(modality, 0) + 1

                # Count datasets
                dataset_id = metadata.get("dataset_id", "Unknown")
                info["datasets"][dataset_id] = info["datasets"].get(dataset_id, 0) + 1

                # Count policies
                policy = metadata.get("policy", "Unknown")
                info["policies"][policy] = info["policies"].get(policy, 0) + 1

                # Size statistics
                package_size = len(package_json.encode("utf-8"))
                info["size_stats"]["min_bytes"] = min(
                    info["size_stats"]["min_bytes"], package_size
                )
                info["size_stats"]["max_bytes"] = max(
                    info["size_stats"]["max_bytes"], package_size
                )
                info["size_stats"]["total_bytes"] += package_size

            except Exception as e:
                logger.warning("Failed to analyze encrypted file: %s", e)
                continue

        # Calculate average
        if info["total_files"] > 0:
            info["size_stats"]["avg_bytes"] = (
                info["size_stats"]["total_bytes"] / info["total_files"]
            )
        else:
            info["size_stats"]["avg_bytes"] = 0

        return info


def iter_encrypted(
    encrypted_files,
    reader_fn=None,
    format_hint=None,
    verify_integrity=True,
    batch_size=1,
):
    """
    Iterate over encrypted files with custom reader function.

    Args:
        encrypted_files: List of encrypted package files
        reader_fn: Custom function to process decrypted data
        format_hint: Format hint for tensor conversion
        verify_integrity: Whether to verify package integrity
        batch_size: Batch size (currently only supports 1)

    Yields:
        Processed data from reader_fn or default tensor format
    """
    cfg = config.get_config()

    # Check policy for plaintext disk writes
    if not cfg.allows_plaintext_disk():
        logger.info("Memory-only decryption mode enforced by policy")

    for i, encrypted_file in enumerate(encrypted_files):
        try:
            # Load encrypted package
            if isinstance(encrypted_file, (str, Path)):
                with open(encrypted_file, "r", encoding="utf-8") as f:
                    package_json = f.read()
                package = crypto.EncryptedPackage.from_json(package_json)
            else:
                package = encrypted_file

            # Verify integrity if requested
            if verify_integrity:
                verification_result = crypto.verify_package_integrity(package)
                if not verification_result["is_valid"]:
                    logger.error(
                        "Package integrity failed for %s: %s",
                        encrypted_file,
                        verification_result["errors"],
                    )
                    continue

            # Decrypt in memory
            plaintext_data = crypto.decrypt_data(package, verify_aad=True)

            # Process with custom reader or default conversion
            if reader_fn:
                result = reader_fn(plaintext_data, package, i)
            else:
                # Default: convert to tensor
                metadata = crypto.extract_package_metadata(package)
                inferred_format = format_hint or _infer_format_from_modality(
                    metadata.get("modality")
                )
                tensor = intake.to_tensor(plaintext_data, format_hint=inferred_format)

                result = {"tensor": tensor, "metadata": metadata, "index": i}

            # Zeroize plaintext data
            plaintext_data = b"\x00" * len(plaintext_data)
            del plaintext_data

            yield result

        except Exception as e:
            logger.error("Failed to process encrypted file %s: %s", encrypted_file, e)
            continue


def _infer_format_from_modality(modality):
    """Infer image format from DICOM modality."""
    if not modality:
        return None

    dicom_modalities = ["CT", "MR", "US", "XA", "DX", "CR", "MG", "PT", "NM", "RF"]

    if modality in dicom_modalities:
        return "dicom"
    else:
        return None


def create_pytorch_dataset(encrypted_files, transform=None, verify_integrity=True):
    """
    Create PyTorch-compatible dataset from encrypted files.

    Args:
        encrypted_files: List of encrypted package files
        transform: Optional transform function for tensors
        verify_integrity: Whether to verify package integrity

    Returns:
        PyTorchEncryptedDataset: Dataset compatible with PyTorch DataLoader
    """
    return PyTorchEncryptedDataset(
        encrypted_files=encrypted_files,
        transform=transform,
        verify_integrity=verify_integrity,
    )


class PyTorchEncryptedDataset:
    """PyTorch-compatible dataset for encrypted medical images."""

    def __init__(self, encrypted_files, transform=None, verify_integrity=True):
        self.encrypted_files = encrypted_files
        self.transform = transform
        self.verify_integrity = verify_integrity

    def __len__(self):
        return len(self.encrypted_files)

    def __getitem__(self, idx):
        """Get item by index (required by PyTorch DataLoader)."""
        cfg = config.get_config()

        if idx >= len(self.encrypted_files):
            raise IndexError(
                f"Index {idx} out of range for dataset of size {len(self.encrypted_files)}"
            )

        encrypted_file = self.encrypted_files[idx]

        try:
            # Load and decrypt
            if isinstance(encrypted_file, (str, Path)):
                with open(encrypted_file, "r", encoding="utf-8") as f:
                    package_json = f.read()
                package = crypto.EncryptedPackage.from_json(package_json)
            else:
                package = encrypted_file

            # Verify integrity if requested
            if self.verify_integrity:
                verification_result = crypto.verify_package_integrity(package)
                if not verification_result["is_valid"]:
                    raise RuntimeError(
                        f"Package integrity verification failed: {verification_result['errors']}"
                    )

            # Decrypt in memory
            plaintext_data = crypto.decrypt_data(package, verify_aad=True)

            # Convert to tensor
            metadata = crypto.extract_package_metadata(package)
            format_hint = _infer_format_from_modality(metadata.get("modality"))
            tensor = intake.to_tensor(plaintext_data, format_hint=format_hint)

            # Apply transform if provided
            if self.transform:
                tensor = self.transform(tensor)

            # Zeroize plaintext data
            plaintext_data = b"\x00" * len(plaintext_data)
            del plaintext_data

            return tensor, metadata

        except Exception as e:
            logger.error("Failed to load item %d: %s", idx, e)
            raise

    def get_metadata(self, idx):
        """Get metadata for item without decrypting."""
        encrypted_file = self.encrypted_files[idx]

        if isinstance(encrypted_file, (str, Path)):
            with open(encrypted_file, "r", encoding="utf-8") as f:
                package_json = f.read()
            package = crypto.EncryptedPackage.from_json(package_json)
        else:
            package = encrypted_file

        return crypto.extract_package_metadata(package)


def validate_loader_policy_compliance(loader_config):
    """
    Validate that loader configuration complies with security policy.

    Args:
        loader_config: Dictionary with loader configuration

    Returns:
        dict: Validation results
    """
    cfg = config.get_config()

    results = {"is_compliant": True, "violations": [], "warnings": []}

    # Check memory-only requirement
    if not cfg.allows_plaintext_disk():
        if loader_config.get("cache_plaintext", False):
            results["violations"].append("Plaintext caching not allowed by policy")
            results["is_compliant"] = False

        if loader_config.get("write_temp_files", False):
            results["violations"].append("Temporary file writes not allowed by policy")
            results["is_compliant"] = False

    # Check integrity verification requirement
    if cfg.policy.get("security", {}).get("require_integrity_verification", True):
        if not loader_config.get("verify_integrity", True):
            results["violations"].append("Integrity verification required by policy")
            results["is_compliant"] = False

    # Check batch size limits
    max_batch_size = cfg.policy.get("security", {}).get("max_batch_size", 32)
    if loader_config.get("batch_size", 1) > max_batch_size:
        results["violations"].append(
            f"Batch size exceeds policy limit: {max_batch_size}"
        )
        results["is_compliant"] = False

    return results
