"""
Envelope encryption with AES-256-GCM and pluggable KMS backends.

Provides secure encryption/decryption of medical images with tamper detection
and compliance-ready key management integration.
"""

import json
import base64
import logging
import hashlib
import os
from datetime import datetime

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import config
from . import audit
from . import validate
from .kms import get_kms_adapter

logger = logging.getLogger(__name__)


class EncryptedPackage:
    """Represents an encrypted medical image package."""

    def __init__(self, schema="imgsec/v1", kms_key_ref=None, nonce_b64=None,
                 aad_b64=None, wrapped_key_b64=None, ciphertext_b64=None):
        self.schema = schema
        self.kms_key_ref = kms_key_ref
        self.nonce_b64 = nonce_b64
        self.aad_b64 = aad_b64
        self.wrapped_key_b64 = wrapped_key_b64
        self.ciphertext_b64 = ciphertext_b64

    def to_dict(self):
        """Convert to dictionary for serialization."""
        return {
            "schema": self.schema,
            "kms_key_ref": self.kms_key_ref,
            "nonce_b64": self.nonce_b64,
            "aad_b64": self.aad_b64,
            "wrapped_key_b64": self.wrapped_key_b64,
            "ciphertext_b64": self.ciphertext_b64
        }

    def to_json(self):
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), sort_keys=True, separators=(',', ':'))

    @classmethod
    def from_dict(cls, data):
        """Create from dictionary."""
        return cls(**data)

    @classmethod
    def from_json(cls, json_str):
        """Create from JSON string."""
        data = json.loads(json_str)
        return cls.from_dict(data)


def encrypt_data(plaintext_data, kms_key_ref=None, dataset_id=None,
                 modality=None, pseudo_pid=None, pixel_hash=None,
                 policy_hash=None, additional_aad=None):
    """
    Encrypt data using envelope encryption with AES-256-GCM.

    Args:
        plaintext_data: Bytes to encrypt
        kms_key_ref: KMS key reference for wrapping
        dataset_id: Dataset identifier for AAD
        modality: Image modality for AAD
        pseudo_pid: Pseudonymized patient ID for AAD
        pixel_hash: Hash of pixel data for AAD
        policy_hash: Hash of active policy for AAD
        additional_aad: Additional AAD fields

    Returns:
        EncryptedPackage: Encrypted package with all metadata
    """
    cfg = config.get_config()

    # Use configuration defaults if not provided
    kms_key_ref = kms_key_ref or cfg.kms_key_ref
    policy_hash = policy_hash or cfg.policy_hash

    # Validate required AAD fields
    if not all([dataset_id, modality, pseudo_pid, pixel_hash]):
        raise ValueError(
            "Missing required AAD fields: dataset_id, modality, pseudo_pid, pixel_hash")

    # Generate fresh nonce (96-bit for GCM)
    nonce = os.urandom(12)

    # Check for nonce reuse
    if not validate.check_nonce_uniqueness(nonce):
        raise RuntimeError(
            "Nonce reuse detected - cryptographic security violation")

    # Build Additional Authenticated Data (AAD)
    aad = {
        "policy": cfg.policy.get("name", "unknown"),
        "dataset_id": dataset_id,
        "schema_version": "imgsec/v1",
        "modality": modality,
        "pseudo_pid": pseudo_pid,
        "pixel_hash": pixel_hash,
        "produced_at": datetime.utcnow().isoformat() + 'Z',
        "policy_hash": policy_hash
    }

    # Add any additional AAD fields
    if additional_aad:
        aad.update(additional_aad)

    aad_json = json.dumps(aad, sort_keys=True, separators=(',', ':'))
    aad_bytes = aad_json.encode('utf-8')

    try:
        # Get KMS adapter and generate/wrap data key
        kms_adapter = get_kms_adapter()

        # Generate 256-bit data key
        data_key = kms_adapter.generate_data_key(kms_key_ref)
        wrapped_key = kms_adapter.wrap_data_key(data_key, kms_key_ref)

        # Encrypt data with AES-256-GCM
        aesgcm = AESGCM(data_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext_data, aad_bytes)

        # Zeroize the data key
        data_key = b'\x00' * len(data_key)
        del data_key

        # Create encrypted package
        package = EncryptedPackage(
            schema="imgsec/v1",
            kms_key_ref=kms_key_ref,
            nonce_b64=base64.b64encode(nonce).decode('ascii'),
            aad_b64=base64.b64encode(aad_bytes).decode('ascii'),
            wrapped_key_b64=base64.b64encode(wrapped_key).decode('ascii'),
            ciphertext_b64=base64.b64encode(ciphertext).decode('ascii')
        )

        # Record nonce usage
        validate.record_nonce_usage(nonce)

        # Audit log the encryption
        audit.log_operation(
            operation='encrypt_data',
            outcome='success',
            dataset_id=dataset_id,
            kms_key_ref=kms_key_ref,
            modality=modality,
            pseudo_pid=pseudo_pid,
            data_size_bytes=len(plaintext_data),
            package_size_bytes=len(package.to_json())
        )

        logger.info("Data encryption completed for dataset=%s, modality=%s",
                    dataset_id, modality)

        return package

    except Exception as e:
        # Audit log the failure
        audit.log_operation(
            operation='encrypt_data',
            outcome='failure',
            dataset_id=dataset_id,
            kms_key_ref=kms_key_ref,
            error=str(e)
        )

        logger.error(
            "Data encryption failed for dataset=%s: %s", dataset_id, e)
        raise


def decrypt_data(encrypted_package, verify_aad=True):
    """
    Decrypt data from encrypted package.

    Args:
        encrypted_package: EncryptedPackage or JSON string
        verify_aad: Whether to verify AAD policy compliance

    Returns:
        bytes: Decrypted plaintext data
    """
    cfg = config.get_config()

    # Parse package if JSON string
    if isinstance(encrypted_package, str):
        package = EncryptedPackage.from_json(encrypted_package)
    else:
        package = encrypted_package

    # Validate package schema
    if package.schema != "imgsec/v1":
        raise ValueError(f"Unsupported package schema: {package.schema}")

    # Decode base64 components
    try:
        nonce = base64.b64decode(package.nonce_b64)
        aad_bytes = base64.b64decode(package.aad_b64)
        wrapped_key = base64.b64decode(package.wrapped_key_b64)
        ciphertext = base64.b64decode(package.ciphertext_b64)
    except Exception as e:
        raise ValueError(f"Invalid base64 encoding in package: {e}") from e

    # Parse and verify AAD
    try:
        aad = json.loads(aad_bytes.decode('utf-8'))
    except Exception as e:
        raise ValueError(f"Invalid AAD JSON: {e}") from e

    if verify_aad:
        _verify_aad_compliance(aad)

    try:
        # Get KMS adapter and unwrap data key
        kms_adapter = get_kms_adapter()
        data_key = kms_adapter.unwrap_data_key(
            wrapped_key, package.kms_key_ref)

        # Decrypt with AES-256-GCM
        aesgcm = AESGCM(data_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad_bytes)

        # Zeroize the data key
        data_key = b'\x00' * len(data_key)
        del data_key

        # Audit log the decryption
        audit.log_operation(
            operation='decrypt_data',
            outcome='success',
            dataset_id=aad.get('dataset_id'),
            kms_key_ref=package.kms_key_ref,
            modality=aad.get('modality'),
            pseudo_pid=aad.get('pseudo_pid'),
            data_size_bytes=len(plaintext)
        )

        logger.info("Data decryption completed for dataset=%s",
                    aad.get('dataset_id'))

        return plaintext

    except Exception as e:
        # Audit log the failure
        audit.log_operation(
            operation='decrypt_data',
            outcome='failure',
            dataset_id=aad.get('dataset_id'),
            kms_key_ref=package.kms_key_ref,
            error=str(e)
        )

        logger.error("Data decryption failed: %s", e)
        raise


def _verify_aad_compliance(aad):
    """Verify AAD contains required fields and matches current policy."""
    cfg = config.get_config()

    # Required AAD fields
    required_fields = [
        'policy', 'dataset_id', 'schema_version', 'modality',
        'pseudo_pid', 'pixel_hash', 'produced_at', 'policy_hash'
    ]

    missing_fields = []
    for field in required_fields:
        if field not in aad:
            missing_fields.append(field)

    if missing_fields:
        raise ValueError(f"AAD missing required fields: {missing_fields}")

    # Verify schema version compatibility
    if aad['schema_version'] != 'imgsec/v1':
        raise ValueError(
            f"Incompatible schema version: {aad['schema_version']}")

    # Verify policy hash matches current policy (optional check)
    current_policy_hash = cfg.policy_hash
    if aad['policy_hash'] != current_policy_hash:
        logger.warning(
            "Policy hash mismatch - encrypted with different policy")
        logger.warning("Package policy: %s, Current policy: %s",
                       aad['policy_hash'], current_policy_hash)

        # Fail if policy requires strict matching
        if cfg.policy.get('security', {}).get('require_policy_match', False):
            raise ValueError("Policy hash mismatch - decryption not allowed")


def verify_package_integrity(encrypted_package):
    """
    Verify integrity of encrypted package without decryption.

    Args:
        encrypted_package: EncryptedPackage or JSON string

    Returns:
        dict: Verification results
    """
    if isinstance(encrypted_package, str):
        package = EncryptedPackage.from_json(encrypted_package)
    else:
        package = encrypted_package

    results = {
        'is_valid': True,
        'schema_valid': False,
        'aad_valid': False,
        'base64_valid': False,
        'kms_accessible': False,
        'errors': []
    }

    try:
        # Check schema version
        if package.schema == 'imgsec/v1':
            results['schema_valid'] = True
        else:
            results['errors'].append(f"Invalid schema: {package.schema}")
            results['is_valid'] = False

        # Validate base64 encoding
        try:
            base64.b64decode(package.nonce_b64)
            base64.b64decode(package.aad_b64)
            base64.b64decode(package.wrapped_key_b64)
            base64.b64decode(package.ciphertext_b64)
            results['base64_valid'] = True
        except Exception as e:
            results['errors'].append(f"Invalid base64 encoding: {e}")
            results['is_valid'] = False

        # Validate AAD JSON
        try:
            aad_bytes = base64.b64decode(package.aad_b64)
            aad = json.loads(aad_bytes.decode('utf-8'))
            _verify_aad_compliance(aad)
            results['aad_valid'] = True
        except Exception as e:
            results['errors'].append(f"AAD validation failed: {e}")
            results['is_valid'] = False

        # Check KMS accessibility (without unwrapping)
        try:
            kms_adapter = get_kms_adapter()
            # Just verify the adapter can be created and key exists
            if hasattr(kms_adapter, 'verify_key_access'):
                kms_adapter.verify_key_access(package.kms_key_ref)
            results['kms_accessible'] = True
        except Exception as e:
            results['errors'].append(f"KMS accessibility check failed: {e}")
            results['is_valid'] = False

        # Audit the verification
        audit.log_operation(
            operation='verify_package',
            outcome='success' if results['is_valid'] else 'failure',
            kms_key_ref=package.kms_key_ref,
            verification_results=results
        )

        return results

    except Exception as e:
        logger.error("Package verification failed: %s", e)
        results['is_valid'] = False
        results['errors'].append(f"Verification error: {e}")
        return results


def compute_package_hash(encrypted_package):
    """Compute deterministic hash of encrypted package for deduplication."""
    if isinstance(encrypted_package, str):
        package_json = encrypted_package
    else:
        package_json = encrypted_package.to_json()

    return hashlib.sha256(package_json.encode('utf-8')).hexdigest()


def extract_package_metadata(encrypted_package):
    """Extract metadata from encrypted package without decryption."""
    if isinstance(encrypted_package, str):
        package = EncryptedPackage.from_json(encrypted_package)
    else:
        package = encrypted_package

    # Decode and parse AAD
    try:
        aad_bytes = base64.b64decode(package.aad_b64)
        aad = json.loads(aad_bytes.decode('utf-8'))

        metadata = {
            'schema': package.schema,
            'kms_key_ref': package.kms_key_ref,
            'dataset_id': aad.get('dataset_id'),
            'modality': aad.get('modality'),
            'pseudo_pid': aad.get('pseudo_pid'),
            'pixel_hash': aad.get('pixel_hash'),
            'produced_at': aad.get('produced_at'),
            'policy_hash': aad.get('policy_hash'),
            'policy': aad.get('policy'),
            'package_hash': compute_package_hash(package)
        }

        return metadata

    except Exception as e:
        logger.error("Failed to extract package metadata: %s", e)
        raise


def batch_encrypt_files(file_paths, kms_key_ref=None, dataset_id=None,
                        output_dir=None, **common_aad):
    """
    Batch encrypt multiple files with common parameters.

    Args:
        file_paths: List of file paths to encrypt
        kms_key_ref: KMS key reference
        dataset_id: Dataset identifier
        output_dir: Output directory for encrypted files
        **common_aad: Common AAD fields for all files

    Returns:
        list: List of (input_path, output_path, package) tuples
    """
    from pathlib import Path
    from . import intake

    if output_dir:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

    results = []

    for file_path in file_paths:
        try:
            file_path = Path(file_path)

            # Generate output path
            if output_dir:
                output_path = output_dir / f"{file_path.stem}.pkg.json"
            else:
                output_path = file_path.with_suffix('.pkg.json')

            # Get image info for AAD
            image_info = intake.get_image_info(file_path)

            # Read file data
            with open(file_path, 'rb') as f:
                file_data = f.read()

            # Encrypt with image-specific AAD
            package = encrypt_data(
                plaintext_data=file_data,
                kms_key_ref=kms_key_ref,
                dataset_id=dataset_id,
                modality=image_info['modality'],
                pixel_hash=image_info['pixel_hash'],
                **common_aad
            )

            # Save encrypted package
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(package.to_json())

            results.append((str(file_path), str(output_path), package))

            logger.info("Batch encrypted: %s -> %s", file_path, output_path)

        except Exception as e:
            logger.error("Failed to encrypt %s: %s", file_path, e)
            results.append((str(file_path), None, None))

    return results
