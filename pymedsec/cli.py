# Copyright 2025 PyMedSec Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Command-line interface for healthcare image security operations.

Provides CLI commands for sanitize, encrypt, decrypt, and verify operations
with comprehensive error handling and policy compliance.
"""

import sys
import json
import logging
from pathlib import Path

import click

from . import config
from . import intake
from . import sanitize
from . import crypto
from . import audit
from . import validate

logger = logging.getLogger(__name__)


@click.group()
@click.option('--debug', is_flag=True, help='Enable debug logging')
@click.option('--config-check', is_flag=True, help='Validate configuration and exit')
@click.pass_context
def main(ctx, debug, config_check):
    """Healthcare Image Security - Medical image encryption and compliance tools."""
    ctx.ensure_object(dict)

    try:
        # Load configuration
        cfg = config.load_config()
        ctx.obj['config'] = cfg

        if debug:
            logging.getLogger().setLevel(logging.DEBUG)

        if config_check:
            click.echo("Configuration validation:")
            click.echo(f"✓ Policy loaded: {cfg.policy.get('name', 'Unknown')}")
            click.echo(f"✓ KMS backend: {cfg.kms_backend}")
            click.echo(f"✓ Audit path: {cfg.audit_path}")
            click.echo(f"✓ Policy hash: {cfg.policy_hash[:16]}...")

            # Test KMS connectivity
            try:
                from .kms import get_kms_adapter
                kms_adapter = get_kms_adapter()
                kms_accessible = kms_adapter.verify_key_access(cfg.kms_key_ref)
                click.echo(f"✓ KMS accessible: {kms_accessible}")
            except Exception as e:
                click.echo(f"✗ KMS error: {e}")

            sys.exit(0)

    except Exception as e:
        click.echo(f"Configuration error: {e}", err=True)
        if debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@main.command()
@click.option('--in', 'input_path', required=True, help='Input image file path')
@click.option('--out', 'output_path', help='Output sanitized file path')
@click.option('--pseudo', required=True, help='Pseudonymized patient ID')
@click.option('--format', 'format_hint', help='Image format hint (dicom, png, jpeg)')
@click.option('--dataset', help='Dataset identifier for audit logging')
@click.pass_context
def sanitize_cmd(ctx, input_path, output_path, pseudo, format_hint, dataset):
    """Sanitize medical images by removing PHI and metadata."""
    cfg = ctx.obj['config']

    try:
        input_path = Path(input_path)
        if not input_path.exists():
            raise click.FileError(f"Input file not found: {input_path}")

        # Determine output path if not provided
        if not output_path:
            output_path = input_path.with_suffix(
                '.sanitized' + input_path.suffix)
        else:
            output_path = Path(output_path)

        # Check policy compliance for output
        if not cfg.allows_plaintext_disk() and not click.confirm(
            "Policy restricts plaintext disk writes. Continue?", abort=True
        ):
            return

        click.echo(f"Sanitizing: {input_path} -> {output_path}")

        # Perform sanitization based on format
        if format_hint == 'dicom' or input_path.suffix.lower() in ['.dcm', '.dicom']:
            # DICOM sanitization
            with intake.open_image(input_path, 'dicom') as reader:
                sanitized_dataset, report = sanitize.sanitize_dicom(
                    reader.dataset,
                    pseudo_pid=pseudo,
                    dataset_id=dataset
                )

            # Save sanitized DICOM
            sanitized_dataset.save_as(str(output_path))

            click.echo("DICOM sanitization completed:")
            click.echo(f"  - Removed PHI tags: {len(report.removed_tags)}")
            click.echo(
                f"  - Private tags removed: {report.private_tags_removed}")
            click.echo(f"  - UIDs regenerated: {len(report.regenerated_uids)}")
            click.echo(f"  - OCR redaction: {report.ocr_redaction_performed}")

        else:
            # Standard image sanitization
            output_path, report = sanitize.sanitize_image(
                input_path,
                output_path,
                dataset_id=dataset
            )

            click.echo("Image sanitization completed:")
            click.echo(
                f"  - Metadata removed: {len(report['metadata_removed'])}")
            click.echo(
                f"  - OCR redaction: {report['ocr_redaction_performed']}")

        click.echo(f"Sanitized file saved: {output_path}")

    except Exception as e:
        click.echo(f"Sanitization failed: {e}", err=True)
        if cfg.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@main.command()
@click.option('--in', 'input_path', required=True, help='Input file path')
@click.option('--out', 'output_path', help='Output encrypted package path')
@click.option('--kms', 'kms_key_ref', help='KMS key reference (overrides config)')
@click.option('--dataset', required=True, help='Dataset identifier')
@click.option('--modality', required=True, help='Image modality (CT, MR, etc.)')
@click.option('--pseudo', help='Pseudonymized patient ID')
@click.pass_context
def encrypt(ctx, input_path, output_path, kms_key_ref, dataset, modality, pseudo):
    """Encrypt medical images using envelope encryption."""
    cfg = ctx.obj['config']

    try:
        input_path = Path(input_path)
        if not input_path.exists():
            raise click.FileError(f"Input file not found: {input_path}")

        # Determine output path if not provided
        if not output_path:
            output_path = input_path.with_suffix('.pkg.json')
        else:
            output_path = Path(output_path)

        # Use config KMS key if not specified
        kms_key_ref = kms_key_ref or cfg.kms_key_ref

        click.echo(f"Encrypting: {input_path} -> {output_path}")

        # Get image info for AAD
        image_info = intake.get_image_info(input_path)

        # Generate pseudo PID if not provided
        if not pseudo:
            pseudo = sanitize.generate_pseudo_patient_id()
            click.echo(f"Generated pseudo PID: {pseudo}")

        # Read file data
        with open(input_path, 'rb') as f:
            file_data = f.read()

        # Encrypt with envelope encryption
        encrypted_package = crypto.encrypt_data(
            plaintext_data=file_data,
            kms_key_ref=kms_key_ref,
            dataset_id=dataset,
            modality=modality,
            pseudo_pid=pseudo,
            pixel_hash=image_info['pixel_hash']
        )

        # Save encrypted package
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(encrypted_package.to_json())

        click.echo("Encryption completed:")
        click.echo(f"  - KMS key: {kms_key_ref}")
        click.echo(f"  - Dataset: {dataset}")
        click.echo(f"  - Modality: {modality}")
        click.echo(f"  - Pseudo PID: {pseudo}")
        click.echo(
            f"  - Package size: {len(encrypted_package.to_json())} bytes")
        click.echo(f"Encrypted package saved: {output_path}")

    except Exception as e:
        click.echo(f"Encryption failed: {e}", err=True)
        if cfg.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@main.command()
@click.option('--in', 'input_path', required=True, help='Input encrypted package path')
@click.option('--out', 'output_path', help='Output decrypted file path')
@click.option('--force', is_flag=True, help='Force plaintext output despite policy')
@click.pass_context
def decrypt(ctx, input_path, output_path, force):
    """Decrypt encrypted medical image packages."""
    cfg = ctx.obj['config']

    try:
        input_path = Path(input_path)
        if not input_path.exists():
            raise click.FileError(f"Input file not found: {input_path}")

        # Check policy for plaintext disk writes
        if not cfg.allows_plaintext_disk() and output_path and not force:
            click.echo(
                "Policy prohibits plaintext disk writes. Use --force to override or omit --out for memory-only.", err=True)
            sys.exit(1)

        click.echo(f"Decrypting: {input_path}")

        # Load encrypted package
        with open(input_path, 'r', encoding='utf-8') as f:
            package_json = f.read()

        encrypted_package = crypto.EncryptedPackage.from_json(package_json)

        # Extract metadata
        metadata = crypto.extract_package_metadata(encrypted_package)
        click.echo("Package metadata:")
        click.echo(f"  - Dataset: {metadata.get('dataset_id')}")
        click.echo(f"  - Modality: {metadata.get('modality')}")
        click.echo(f"  - Pseudo PID: {metadata.get('pseudo_pid')}")
        click.echo(f"  - Produced: {metadata.get('produced_at')}")

        # Decrypt data
        plaintext_data = crypto.decrypt_data(
            encrypted_package, verify_aad=True)

        if output_path:
            # Write to file
            output_path = Path(output_path)
            with open(output_path, 'wb') as f:
                f.write(plaintext_data)
            click.echo(f"Decrypted file saved: {output_path}")
        else:
            # Memory-only mode
            click.echo(
                f"Decryption completed (memory-only): {len(plaintext_data)} bytes")

        # Zeroize plaintext data
        plaintext_data = b'\x00' * len(plaintext_data)
        del plaintext_data

    except Exception as e:
        click.echo(f"Decryption failed: {e}", err=True)
        if cfg.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@main.command()
@click.option('--in', 'input_path', required=True, help='Input encrypted package path')
@click.option('--verbose', is_flag=True, help='Show detailed verification results')
@click.pass_context
def verify(ctx, input_path, verbose):
    """Verify integrity and compliance of encrypted packages."""
    cfg = ctx.obj['config']

    try:
        input_path = Path(input_path)
        if not input_path.exists():
            raise click.FileError(f"Input file not found: {input_path}")

        click.echo(f"Verifying: {input_path}")

        # Load encrypted package
        with open(input_path, 'r', encoding='utf-8') as f:
            package_json = f.read()

        encrypted_package = crypto.EncryptedPackage.from_json(package_json)

        # Verify package integrity
        verification_result = crypto.verify_package_integrity(
            encrypted_package)

        if verification_result['is_valid']:
            click.echo("✓ Package integrity verification PASSED")
        else:
            click.echo("✗ Package integrity verification FAILED")
            for error in verification_result['errors']:
                click.echo(f"  Error: {error}")

        if verbose:
            click.echo("\nDetailed verification results:")
            click.echo(
                f"  Schema valid: {verification_result['schema_valid']}")
            click.echo(f"  AAD valid: {verification_result['aad_valid']}")
            click.echo(
                f"  Base64 valid: {verification_result['base64_valid']}")
            click.echo(
                f"  KMS accessible: {verification_result['kms_accessible']}")

        # Extract and validate metadata
        metadata = crypto.extract_package_metadata(encrypted_package)
        click.echo("\nPackage metadata:")
        for key, value in metadata.items():
            click.echo(f"  {key}: {value}")

        # Policy compliance check
        import base64
        if encrypted_package.aad_b64:
            aad_bytes = base64.b64decode(encrypted_package.aad_b64)
            aad = json.loads(aad_bytes.decode('utf-8'))
        else:
            raise ValueError("Package missing AAD data")

        compliance_result = validate.validate_policy_compliance(aad)

        if compliance_result['is_compliant']:
            click.echo("✓ Policy compliance verification PASSED")
        else:
            click.echo("✗ Policy compliance verification FAILED")
            for violation in compliance_result['violations']:
                click.echo(f"  Violation: {violation}")

        for warning in compliance_result['warnings']:
            click.echo(f"  Warning: {warning}")

        # Overall result
        overall_valid = verification_result['is_valid'] and compliance_result['is_compliant']

        if overall_valid:
            click.echo("\n✓ Overall verification: PASSED")
            sys.exit(0)
        else:
            click.echo("\n✗ Overall verification: FAILED")
            sys.exit(1)

    except Exception as e:
        click.echo(f"Verification failed: {e}", err=True)
        if cfg.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@main.command()
@click.option('--format', 'output_format', default='table', help='Output format (table, json)')
@click.option('--lines', default=20, help='Number of recent log lines to show')
@click.pass_context
def audit_log(ctx, output_format, lines):
    """View recent audit log entries."""
    try:
        # Get recent audit entries
        audit_stats = audit.get_audit_stats()

        if output_format == 'json':
            click.echo(json.dumps(audit_stats, indent=2))
        else:
            click.echo("Audit Log Summary:")
            click.echo(f"  Total lines: {audit_stats['total_lines']}")
            click.echo(f"  File size: {audit_stats['file_size_bytes']} bytes")
            click.echo(f"  Last modified: {audit_stats['last_modified']}")

            click.echo("\nOperations:")
            for operation, count in audit_stats['operations'].items():
                click.echo(f"  {operation}: {count}")

            click.echo("\nOutcomes:")
            for outcome, count in audit_stats['outcomes'].items():
                click.echo(f"  {outcome}: {count}")

    except Exception as e:
        click.echo(f"Failed to read audit log: {e}", err=True)
        sys.exit(1)


@main.command()
@click.option('--verify', is_flag=True, help='Verify audit log integrity')
@click.pass_context
def audit_verify(ctx, verify):
    """Verify audit log integrity."""
    try:
        if verify:
            click.echo("Verifying audit log integrity...")
            verification_result = audit.verify_audit_integrity()

            if verification_result['is_valid']:
                click.echo("✓ Audit log integrity verification PASSED")
                click.echo(
                    f"  Verified lines: {verification_result['verified_lines']}")
            else:
                click.echo("✗ Audit log integrity verification FAILED")
                click.echo(
                    f"  Failed lines: {len(verification_result['failed_lines'])}")
                for failure in verification_result['failed_lines']:
                    click.echo(
                        f"    Line {failure['line']}: {failure['error']}")

        else:
            click.echo("Use --verify flag to perform integrity verification")

    except Exception as e:
        click.echo(f"Audit verification failed: {e}", err=True)
        sys.exit(1)


@main.command()
@click.option('--audit-file', help='Path to audit log file (optional)')
@click.option('--details', is_flag=True, help='Show detailed anchor information')
@click.pass_context
def verify_blockchain(ctx, audit_file, details):
    """Verify blockchain anchors in audit log."""
    try:
        click.echo("Verifying blockchain anchors in audit log...")

        verification_result = audit.verify_blockchain_anchors(audit_file)

        if not verification_result['blockchain_enabled']:
            click.echo(
                f"⚠ Blockchain anchoring: {verification_result['message']}")
            return

        total = verification_result['total_lines']
        anchored = verification_result['anchored_lines']
        verified = verification_result['verified_anchors']
        failed = verification_result['failed_anchors']
        rate = verification_result['verification_rate']

        click.echo(f"📊 Blockchain Anchor Verification Results:")
        click.echo(f"  Total audit entries: {total}")
        click.echo(f"  Anchored entries: {anchored}")
        click.echo(f"  Verified anchors: {verified}")
        click.echo(f"  Failed anchors: {failed}")
        click.echo(f"  Verification rate: {rate:.1%}")

        if rate >= 0.95:
            click.echo("✓ Blockchain anchor verification PASSED")
        elif rate >= 0.80:
            click.echo("⚠ Blockchain anchor verification PARTIAL")
        else:
            click.echo("✗ Blockchain anchor verification FAILED")

        if details and verification_result['anchor_details']:
            click.echo("\n🔗 Anchor Details:")
            # Show first 10
            for detail in verification_result['anchor_details'][:10]:
                status_icon = "✓" if detail['status'] == 'verified' else "✗"
                click.echo(
                    f"  {status_icon} Line {detail['line']}: {detail['tx_hash'][:16]}...")
                if detail['status'] == 'verified':
                    click.echo(
                        f"    Confirmations: {detail.get('confirmations', 0)}")
                elif detail['status'] == 'error':
                    click.echo(f"    Error: {detail.get('error', 'Unknown')}")

            if len(verification_result['anchor_details']) > 10:
                remaining = len(verification_result['anchor_details']) - 10
                click.echo(f"  ... and {remaining} more anchor(s)")

    except Exception as e:
        click.echo(f"Blockchain verification failed: {e}", err=True)
        if ctx.obj.get('config', {}).get('debug'):
            import traceback
            traceback.print_exc()
        sys.exit(1)


@main.command()
@click.option('--blockchain', is_flag=True, help='Include blockchain anchor verification')
@click.pass_context
def audit_status(ctx, blockchain):
    """Check audit log status and blockchain anchors."""
    try:
        click.echo("Checking audit log integrity...")
        verification_result = audit.verify_audit_integrity()

        if verification_result['is_valid']:
            click.echo("✓ Audit log integrity verification PASSED")
            click.echo(
                f"  Verified lines: {verification_result['verified_lines']}")
        else:
            click.echo("✗ Audit log integrity verification FAILED")
            click.echo(
                f"  Failed lines: {len(verification_result['failed_lines'])}")
            for failure in verification_result['failed_lines']:
                click.echo(
                    f"    Line {failure['line']}: {failure['error']}")

        if blockchain:
            click.echo("\nChecking blockchain anchor status...")
            blockchain_result = audit.verify_blockchain_anchors()

            if blockchain_result['blockchain_enabled']:
                anchored = blockchain_result['anchored_lines']
                total = blockchain_result['total_lines']
                rate = anchored / max(1, total)

                click.echo(f"🔗 Blockchain Anchoring:")
                click.echo(
                    f"  Anchored entries: {anchored}/{total} ({rate:.1%})")

                if blockchain_result['verified_anchors'] > 0:
                    verify_rate = blockchain_result['verification_rate']
                    click.echo(f"  Verification rate: {verify_rate:.1%}")
            else:
                click.echo(f"🔗 Blockchain: {blockchain_result['message']}")

    except Exception as e:
        click.echo(f"Audit status check failed: {e}", err=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
