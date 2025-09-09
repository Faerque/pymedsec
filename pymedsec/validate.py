"""
Cryptographic validation and nonce management.

Provides nonce uniqueness tracking, policy validation, and cryptographic
integrity checks to prevent security violations.
"""

import logging
import hashlib
import os
import time
from pathlib import Path
from collections import defaultdict

from . import config

logger = logging.getLogger(__name__)


class NonceTracker:
    """In-memory and file-backed nonce uniqueness tracker."""

    def __init__(self, bloom_file=None, max_memory_nonces=10000):
        self.memory_nonces = set()
        self.max_memory_nonces = max_memory_nonces
        self.bloom_file = bloom_file or self._get_default_bloom_file()
        self.bloom_hash_count = 3  # Number of hash functions for bloom filter
        self.bloom_bit_size = 8192  # Bloom filter size in bits

        # Ensure bloom file directory exists
        self.bloom_file.parent.mkdir(parents=True, exist_ok=True)

    def _get_default_bloom_file(self):
        """Get default bloom filter file path."""
        cfg = config.get_config()
        audit_dir = Path(cfg.audit_path).parent
        return audit_dir / "nonce_bloom.dat"

    def _compute_bloom_hashes(self, nonce):
        """Compute multiple hash values for bloom filter."""
        nonce_bytes = nonce if isinstance(nonce, bytes) else nonce.encode("utf-8")
        hashes = []

        for i in range(self.bloom_hash_count):
            # Use different salts for each hash function
            salt = f"bloom_{i}".encode("utf-8")
            hash_value = hashlib.sha256(salt + nonce_bytes).digest()
            # Convert to bit position
            bit_pos = int.from_bytes(hash_value[:2], "big") % self.bloom_bit_size
            hashes.append(bit_pos)

        return hashes

    def _read_bloom_filter(self):
        """Read bloom filter from file."""
        try:
            if self.bloom_file.exists():
                with open(self.bloom_file, "rb") as f:
                    data = f.read()
                    if len(data) == self.bloom_bit_size // 8:
                        return bytearray(data)
        except Exception as e:
            logger.warning("Failed to read bloom filter: %s", e)

        # Return empty bloom filter
        return bytearray(self.bloom_bit_size // 8)

    def _write_bloom_filter(self, bloom_bits):
        """Write bloom filter to file."""
        try:
            with open(self.bloom_file, "wb") as f:
                f.write(bloom_bits)
                f.flush()
                os.fsync(f.fileno())
        except Exception as e:
            logger.error("Failed to write bloom filter: %s", e)

    def check_nonce_uniqueness(self, nonce):
        """
        Check if nonce is unique (not previously used).

        Returns:
            bool: True if nonce is unique, False if potentially reused
        """
        nonce_hex = nonce.hex() if isinstance(nonce, bytes) else nonce

        # Check in-memory cache first (fast path)
        if nonce_hex in self.memory_nonces:
            logger.error("Nonce reuse detected in memory cache: %s", nonce_hex[:16])
            return False

        # Check bloom filter (probabilistic check)
        bloom_bits = self._read_bloom_filter()
        hash_positions = self._compute_bloom_hashes(nonce)

        # Check if all hash positions are set (potential reuse)
        for pos in hash_positions:
            byte_index = pos // 8
            bit_index = pos % 8
            if not (bloom_bits[byte_index] & (1 << bit_index)):
                # At least one bit is not set, so nonce is definitely unique
                return True

        # All bits are set - potential reuse (bloom filter false positive possible)
        logger.warning(
            "Potential nonce reuse detected by bloom filter: %s", nonce_hex[:16]
        )
        return False

    def record_nonce_usage(self, nonce):
        """Record nonce as used."""
        nonce_hex = nonce.hex() if isinstance(nonce, bytes) else nonce

        # Add to memory cache
        self.memory_nonces.add(nonce_hex)

        # Trim memory cache if too large
        if len(self.memory_nonces) > self.max_memory_nonces:
            # Remove oldest 10% of entries (approximate LRU)
            to_remove = len(self.memory_nonces) // 10
            for _ in range(to_remove):
                self.memory_nonces.pop()

        # Update bloom filter
        bloom_bits = self._read_bloom_filter()
        hash_positions = self._compute_bloom_hashes(nonce)

        for pos in hash_positions:
            byte_index = pos // 8
            bit_index = pos % 8
            bloom_bits[byte_index] |= 1 << bit_index

        self._write_bloom_filter(bloom_bits)

        logger.debug("Recorded nonce usage: %s", nonce_hex[:16])


# Global nonce tracker instance
_nonce_tracker = None


def get_nonce_tracker():
    """Get global nonce tracker instance."""
    global _nonce_tracker
    if _nonce_tracker is None:
        _nonce_tracker = NonceTracker()
    return _nonce_tracker


def check_nonce_uniqueness(nonce):
    """Check if nonce is unique."""
    tracker = get_nonce_tracker()
    return tracker.check_nonce_uniqueness(nonce)


def record_nonce_usage(nonce):
    """Record nonce as used."""
    tracker = get_nonce_tracker()
    tracker.record_nonce_usage(nonce)


def validate_policy_compliance(aad, strict_mode=True):
    """
    Validate AAD compliance with current policy.

    Args:
        aad: Additional Authenticated Data dictionary
        strict_mode: Whether to fail on policy mismatches

    Returns:
        dict: Validation results
    """
    cfg = config.get_config()
    compliance_config = cfg.get_compliance_config()

    results = {
        "is_compliant": True,
        "violations": [],
        "warnings": [],
        "checks_performed": [],
    }

    # Check HIPAA compliance requirements
    if compliance_config.get("hipaa_mode", False):
        results["checks_performed"].append("hipaa_compliance")

        # Verify minimum necessary principle
        if "purpose_limitation" not in aad:
            results["violations"].append(
                "Missing purpose limitation for HIPAA compliance"
            )
            results["is_compliant"] = False

        # Check de-identification requirements
        required_pseudo_fields = ["pseudo_pid"]
        for field in required_pseudo_fields:
            if field not in aad:
                results["violations"].append(f"Missing pseudonymization field: {field}")
                results["is_compliant"] = False

    # Check GDPR compliance requirements
    if compliance_config.get("gdpr_mode", False):
        results["checks_performed"].append("gdpr_compliance")

        # Verify data minimization
        if not compliance_config.get("data_minimization", False):
            results["warnings"].append("Data minimization not enforced")

        # Check purpose limitation
        allowed_purposes = compliance_config.get("allowed_purposes", [])
        if allowed_purposes and aad.get("purpose") not in allowed_purposes:
            results["violations"].append(f"Purpose not allowed: {aad.get('purpose')}")
            results["is_compliant"] = False

    # Check GxP compliance requirements
    if compliance_config.get("gxp_mode", False):
        results["checks_performed"].append("gxp_compliance")

        # Verify traceability requirements
        required_gxp_fields = ["dataset_id", "produced_at", "policy_hash"]
        for field in required_gxp_fields:
            if field not in aad:
                results["violations"].append(f"Missing GxP traceability field: {field}")
                results["is_compliant"] = False

    # Policy hash validation
    current_policy_hash = cfg.policy_hash
    if aad.get("policy_hash") != current_policy_hash:
        message = (
            f"Policy hash mismatch: {aad.get('policy_hash')} != {current_policy_hash}"
        )
        if strict_mode:
            results["violations"].append(message)
            results["is_compliant"] = False
        else:
            results["warnings"].append(message)

    return results


def validate_encryption_parameters(kms_key_ref, nonce, aad):
    """
    Validate encryption parameters before use.

    Args:
        kms_key_ref: KMS key reference
        nonce: Encryption nonce
        aad: Additional Authenticated Data

    Returns:
        dict: Validation results
    """
    results = {"is_valid": True, "errors": [], "warnings": []}

    # Validate nonce
    if not isinstance(nonce, bytes) or len(nonce) != 12:
        results["errors"].append("Invalid nonce: must be 12 bytes")
        results["is_valid"] = False

    # Check nonce uniqueness
    if not check_nonce_uniqueness(nonce):
        results["errors"].append("Nonce reuse detected")
        results["is_valid"] = False

    # Validate KMS key reference format
    if not kms_key_ref or not isinstance(kms_key_ref, str):
        results["errors"].append("Invalid KMS key reference")
        results["is_valid"] = False

    # Validate AAD structure
    if not isinstance(aad, dict):
        results["errors"].append("AAD must be a dictionary")
        results["is_valid"] = False
    else:
        required_aad_fields = [
            "dataset_id",
            "modality",
            "pseudo_pid",
            "pixel_hash",
            "schema_version",
            "policy_hash",
        ]

        for field in required_aad_fields:
            if field not in aad:
                results["errors"].append(f"Missing required AAD field: {field}")
                results["is_valid"] = False

    return results


def validate_dataset_integrity(dataset_id, file_paths, expected_hashes=None):
    """
    Validate integrity of a dataset.

    Args:
        dataset_id: Dataset identifier
        file_paths: List of file paths in dataset
        expected_hashes: Dictionary of expected file hashes

    Returns:
        dict: Integrity validation results
    """
    from . import intake

    results = {
        "dataset_id": dataset_id,
        "total_files": len(file_paths),
        "valid_files": 0,
        "corrupted_files": [],
        "missing_files": [],
        "integrity_valid": True,
    }

    for file_path in file_paths:
        file_path = Path(file_path)

        if not file_path.exists():
            results["missing_files"].append(str(file_path))
            results["integrity_valid"] = False
            continue

        try:
            # Compute current hash
            current_hash = intake.validate_image_integrity(file_path)

            # Check against expected hash if provided
            if expected_hashes and str(file_path) in expected_hashes:
                expected_hash = expected_hashes[str(file_path)]
                if current_hash != expected_hash:
                    results["corrupted_files"].append(
                        {
                            "file": str(file_path),
                            "expected_hash": expected_hash,
                            "actual_hash": current_hash,
                        }
                    )
                    results["integrity_valid"] = False
                    continue

            results["valid_files"] += 1

        except Exception as e:
            results["corrupted_files"].append({"file": str(file_path), "error": str(e)})
            results["integrity_valid"] = False

    return results


def generate_validation_report(dataset_id, validation_results):
    """
    Generate comprehensive validation report.

    Args:
        dataset_id: Dataset identifier
        validation_results: Dictionary of validation results

    Returns:
        dict: Formatted validation report
    """
    from datetime import datetime

    report = {
        "report_id": hashlib.sha256(f"{dataset_id}_{time.time()}".encode()).hexdigest()[
            :16
        ],
        "dataset_id": dataset_id,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "validation_summary": {
            "overall_status": "PASS",
            "total_checks": 0,
            "passed_checks": 0,
            "failed_checks": 0,
        },
        "detailed_results": validation_results,
        "recommendations": [],
    }

    # Analyze results and compute summary
    for check_name, result in validation_results.items():
        report["validation_summary"]["total_checks"] += 1

        if isinstance(result, dict):
            if result.get("is_valid", True) and result.get("is_compliant", True):
                report["validation_summary"]["passed_checks"] += 1
            else:
                report["validation_summary"]["failed_checks"] += 1
                report["validation_summary"]["overall_status"] = "FAIL"
        else:
            # Assume boolean result
            if result:
                report["validation_summary"]["passed_checks"] += 1
            else:
                report["validation_summary"]["failed_checks"] += 1
                report["validation_summary"]["overall_status"] = "FAIL"

    # Generate recommendations
    if report["validation_summary"]["failed_checks"] > 0:
        report["recommendations"].extend(
            [
                "Review failed validation checks and remediate issues",
                "Verify policy compliance configuration",
                "Check data integrity and re-process if necessary",
            ]
        )

    return report


def cleanup_validation_cache():
    """Clean up validation cache files."""
    try:
        tracker = get_nonce_tracker()

        # Clear memory cache
        tracker.memory_nonces.clear()

        # Archive bloom filter with timestamp
        if tracker.bloom_file.exists():
            timestamp = int(time.time())
            archive_path = tracker.bloom_file.with_suffix(f".{timestamp}.archived")
            tracker.bloom_file.rename(archive_path)
            logger.info("Archived bloom filter to %s", archive_path)

        logger.info("Validation cache cleanup completed")

    except Exception as e:
        logger.error("Validation cache cleanup failed: %s", e)
        raise
