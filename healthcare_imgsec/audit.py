"""
Tamper-evident audit logging with HMAC line signing and blockchain anchoring.

Provides comprehensive audit trail for all security operations
with integrity protection, SIEM integration, and optional
blockchain digest anchoring for immutable evidence.
"""

import json
import logging
import os
import hashlib
import hmac
from datetime import datetime, timezone
from pathlib import Path

from . import config

logger = logging.getLogger(__name__)


class AuditLogger:
    """Tamper-evident audit logger with HMAC signing and blockchain anchoring."""

    def __init__(self, audit_path=None, audit_secret=None):
        self.audit_path = Path(audit_path or config.get_config().audit_path)
        self.audit_secret = audit_secret or self._get_audit_secret()
        self.line_count = 0
        self.anchor_interval = 1000  # Rolling anchor every N lines
        self.last_anchor_hash = None

        # Initialize blockchain adapter if configured
        self.blockchain_adapter = self._initialize_blockchain()
        self.blockchain_frequency = os.getenv(
            'IMGSEC_BLOCKCHAIN_FREQUENCY', 'every')

        # Ensure audit directory exists
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)

        # Initialize if new file
        if not self.audit_path.exists():
            self._initialize_audit_log()
        else:
            self._load_existing_state()

    def _initialize_blockchain(self):
        """Initialize blockchain adapter if configured."""
        try:
            from .blockchain import create_blockchain_adapter
            adapter = create_blockchain_adapter()
            if adapter:
                logger.info("Blockchain anchoring enabled: %s",
                            os.getenv('IMGSEC_BLOCKCHAIN_BACKEND', 'none'))
            return adapter
        except Exception as e:
            logger.warning("Failed to initialize blockchain adapter: %s", e)
            return None

    def _get_audit_secret(self):
        """Get or generate audit HMAC secret."""
        secret = os.getenv('IMGSEC_AUDIT_SECRET')
        if secret:
            return secret.encode('utf-8')

        # Derive from configuration hash if no explicit secret
        cfg = config.get_config()
        seed = f"audit:{cfg.policy_hash}:{cfg.kms_key_ref}"
        return hashlib.sha256(seed.encode('utf-8')).digest()

    def _initialize_audit_log(self):
        """Initialize new audit log with header."""
        header = {
            'audit_log_version': '1.0',
            'initialized_at': datetime.now(timezone.utc).isoformat(),
            'policy_hash': config.get_config().policy_hash,
            'kms_key_ref': config.get_config().kms_key_ref
        }

        self._write_audit_line('INIT', header)
        logger.info("Initialized new audit log: %s", self.audit_path)

    def _load_existing_state(self):
        """Load state from existing audit log."""
        try:
            with open(self.audit_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                self.line_count = len(lines)

                # Find last anchor hash
                for line in reversed(lines):
                    try:
                        entry = json.loads(line.strip())
                        if entry.get('operation') == 'ANCHOR':
                            self.last_anchor_hash = entry.get(
                                'details', {}).get('anchor_hash')
                            break
                    except Exception:
                        continue

            logger.debug("Loaded existing audit log: %d lines",
                         self.line_count)
        except Exception as e:
            logger.error("Failed to load audit log state: %s", e)
            raise

    def _write_audit_line(self, operation, data):
        """Write a single audit line with HMAC signature and optional blockchain anchoring."""
        timestamp = datetime.now(timezone.utc).isoformat()

        # Build audit entry
        entry = {
            'timestamp': timestamp,
            'line_number': self.line_count + 1,
            'operation': operation,
            'actor': config.get_config().actor,
            **data
        }

        # Serialize and compute HMAC
        entry_json = json.dumps(entry, sort_keys=True, separators=(',', ':'))
        signature = hmac.new(
            self.audit_secret,
            entry_json.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

        # Add signature to entry
        entry['hmac_sha256'] = signature

        # Compute SHA-256 digest for blockchain anchoring
        entry_with_hmac = json.dumps(
            entry, sort_keys=True, separators=(',', ':'))
        line_digest = hashlib.sha256(
            entry_with_hmac.encode('utf-8')).hexdigest()

        # Optional blockchain anchoring
        blockchain_anchor = None
        if self.blockchain_adapter and self._should_anchor_to_blockchain():
            try:
                blockchain_anchor = self._anchor_to_blockchain(
                    line_digest, entry)
            except Exception as e:
                logger.error("Blockchain anchoring failed: %s", e)
                # Continue without blockchain anchoring to avoid blocking audit logging

        # Add blockchain anchor info if successful
        if blockchain_anchor:
            entry['blockchain_anchor'] = blockchain_anchor

        # Final serialization with all components
        final_json = json.dumps(entry, sort_keys=True, separators=(',', ':'))

        # Write to file
        try:
            with open(self.audit_path, 'a', encoding='utf-8') as f:
                f.write(final_json + '\n')
                f.flush()
                os.fsync(f.fileno())  # Force write to disk

            self.line_count += 1

            # Generate anchor hash periodically
            if self.line_count % self.anchor_interval == 0:
                self._generate_anchor_hash()

        except Exception as e:
            logger.error("Failed to write audit line: %s", e)
            raise

    def _should_anchor_to_blockchain(self):
        """Determine if this audit line should be anchored to blockchain."""
        if not self.blockchain_adapter:
            return False

        if self.blockchain_frequency == 'every':
            return True
        elif self.blockchain_frequency == 'batch_hourly':
            # Anchor every hour (approximately every 3600 operations if 1 op/sec)
            return self.line_count % 3600 == 0
        else:
            return False

    def _anchor_to_blockchain(self, line_digest, entry):
        """Anchor audit line digest to blockchain."""
        # Prepare sanitized metadata for blockchain submission
        metadata = {
            'operation': entry.get('operation'),
            'timestamp': entry.get('timestamp'),
            'line_number': entry.get('line_number'),
            'outcome': entry.get('outcome'),
            'actor_hash': hashlib.sha256(entry.get('actor', '').encode()).hexdigest()[:16]
        }

        # Add dataset/modality info if available in details
        details = entry.get('details', {})
        if 'dataset_id' in details:
            metadata['dataset_id'] = str(details['dataset_id'])
        if 'modality' in details:
            metadata['modality'] = str(details['modality'])[
                :20]  # Limit length

        # Submit to blockchain
        tx_info = self.blockchain_adapter.submit_digest(line_digest, metadata)

        # Return anchor information for audit log
        return {
            'tx_hash': tx_info.get('tx_hash'),
            'digest': f"sha256:{line_digest}",
            'chain': os.getenv('IMGSEC_BLOCKCHAIN_BACKEND', 'unknown'),
            'status': tx_info.get('status', 'pending'),
            'block_number': tx_info.get('block_number'),
            'timestamp': tx_info.get('timestamp')
        }

    def _generate_anchor_hash(self):
        """Generate rolling anchor hash for integrity checking."""
        try:
            # Read recent lines for anchor computation
            with open(self.audit_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            # Compute hash of last N lines
            anchor_lines = lines[-self.anchor_interval:]
            combined_content = ''.join(anchor_lines)
            anchor_hash = hashlib.sha256(
                combined_content.encode('utf-8')).hexdigest()

            # Log anchor entry
            anchor_data = {
                'details': {
                    'anchor_hash': anchor_hash,
                    'lines_covered': len(anchor_lines),
                    'previous_anchor': self.last_anchor_hash
                }
            }

            self._write_audit_line('ANCHOR', anchor_data)
            self.last_anchor_hash = anchor_hash

            logger.debug("Generated anchor hash at line %d", self.line_count)

        except Exception as e:
            logger.error("Failed to generate anchor hash: %s", e)

    def log_operation(self, operation, outcome='success', **kwargs):
        """Log a security operation with details."""
        data = {
            'outcome': outcome,
            'details': kwargs
        }

        self._write_audit_line(operation, data)

    def verify_integrity(self, start_line=None, end_line=None):
        """Verify HMAC integrity of audit log lines."""
        try:
            with open(self.audit_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            if start_line is None:
                start_line = 1
            if end_line is None:
                end_line = len(lines)

            verification_results = {
                'total_lines': len(lines),
                'verified_lines': 0,
                'failed_lines': [],
                'is_valid': True
            }

            for i, line in enumerate(lines[start_line - 1:end_line], start_line):
                try:
                    entry = json.loads(line.strip())
                    stored_hmac = entry.pop('hmac_sha256', None)

                    if not stored_hmac:
                        verification_results['failed_lines'].append({
                            'line': i,
                            'error': 'Missing HMAC signature'
                        })
                        verification_results['is_valid'] = False
                        continue

                    # Recompute HMAC
                    entry_json = json.dumps(
                        entry, sort_keys=True, separators=(',', ':'))
                    computed_hmac = hmac.new(
                        self.audit_secret,
                        entry_json.encode('utf-8'),
                        hashlib.sha256
                    ).hexdigest()

                    if not hmac.compare_digest(stored_hmac, computed_hmac):
                        verification_results['failed_lines'].append({
                            'line': i,
                            'error': 'HMAC verification failed'
                        })
                        verification_results['is_valid'] = False
                    else:
                        verification_results['verified_lines'] += 1

                except Exception as e:
                    verification_results['failed_lines'].append({
                        'line': i,
                        'error': f'Parse error: {e}'
                    })
                    verification_results['is_valid'] = False

            return verification_results

        except Exception as e:
            logger.error("Audit integrity verification failed: %s", e)
            raise


# Global audit logger instance
_audit_logger = None


def get_audit_logger():
    """Get global audit logger instance."""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger


def log_operation(operation, outcome='success', **kwargs):
    """Log an operation to the audit trail."""
    audit_logger = get_audit_logger()
    audit_logger.log_operation(operation, outcome, **kwargs)


def verify_audit_integrity(start_line=None, end_line=None):
    """Verify integrity of audit log including blockchain anchors."""
    audit_logger = get_audit_logger()
    return audit_logger.verify_integrity(start_line, end_line)


def verify_blockchain_anchors(audit_file_path=None):
    """
    Verify blockchain anchors in audit log.

    Args:
        audit_file_path: Path to audit log file, defaults to configured path

    Returns:
        dict: Verification results with blockchain anchor status
    """
    if audit_file_path is None:
        audit_logger = get_audit_logger()
        audit_file_path = audit_logger.audit_path

    try:
        from .blockchain import create_blockchain_adapter
        blockchain_adapter = create_blockchain_adapter()

        if not blockchain_adapter:
            return {
                'blockchain_enabled': False,
                'message': 'Blockchain anchoring not configured'
            }

        results = {
            'blockchain_enabled': True,
            'total_lines': 0,
            'anchored_lines': 0,
            'verified_anchors': 0,
            'failed_anchors': 0,
            'anchor_details': []
        }

        with open(audit_file_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                results['total_lines'] += 1

                try:
                    entry = json.loads(line.strip())
                    blockchain_anchor = entry.get('blockchain_anchor')

                    if blockchain_anchor:
                        results['anchored_lines'] += 1

                        # Verify blockchain anchor
                        digest_full = blockchain_anchor.get('digest', '')
                        if digest_full.startswith('sha256:'):
                            digest_hex = digest_full[7:]
                            tx_hash = blockchain_anchor.get('tx_hash')

                            try:
                                verification = blockchain_adapter.verify_digest(
                                    digest_hex, tx_hash)

                                if verification.get('verified'):
                                    results['verified_anchors'] += 1
                                    status = 'verified'
                                else:
                                    results['failed_anchors'] += 1
                                    status = 'not_found'

                                results['anchor_details'].append({
                                    'line': line_num,
                                    'tx_hash': tx_hash,
                                    'digest': digest_hex[:16] + '...',
                                    'status': status,
                                    'confirmations': verification.get('confirmations', 0)
                                })

                            except Exception as e:
                                results['failed_anchors'] += 1
                                results['anchor_details'].append({
                                    'line': line_num,
                                    'tx_hash': tx_hash,
                                    'digest': digest_hex[:16] + '...',
                                    'status': 'error',
                                    'error': str(e)
                                })

                except Exception as e:
                    logger.warning("Error processing line %d: %s", line_num, e)
                    continue

        results['verification_rate'] = (
            results['verified_anchors'] / max(1, results['anchored_lines'])
        )

        return results

    except ImportError:
        return {
            'blockchain_enabled': False,
            'message': 'Blockchain module not available'
        }
    except Exception as e:
        logger.error("Blockchain verification failed: %s", e)
        return {
            'blockchain_enabled': False,
            'message': f'Verification failed: {e}'
        }


def get_audit_stats():
    """Get audit log statistics."""
    audit_logger = get_audit_logger()

    try:
        with open(audit_logger.audit_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        stats = {
            'total_lines': len(lines),
            'file_size_bytes': audit_logger.audit_path.stat().st_size,
            'last_modified': datetime.fromtimestamp(
                audit_logger.audit_path.stat().st_mtime, tz=timezone.utc
            ).isoformat(),
            'operations': {},
            'outcomes': {}
        }

        # Analyze operations and outcomes
        for line in lines:
            try:
                entry = json.loads(line.strip())
                operation = entry.get('operation', 'UNKNOWN')
                outcome = entry.get('outcome', 'unknown')

                stats['operations'][operation] = stats['operations'].get(
                    operation, 0) + 1
                stats['outcomes'][outcome] = stats['outcomes'].get(
                    outcome, 0) + 1

            except Exception:
                continue

        return stats

    except Exception as e:
        logger.error("Failed to get audit stats: %s", e)
        raise


def export_audit_logs(output_path, start_date=None, end_date=None, format='jsonl'):
    """Export audit logs for external analysis."""
    audit_logger = get_audit_logger()
    output_path = Path(output_path)

    try:
        with open(audit_logger.audit_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        # Filter by date range if specified
        filtered_lines = []
        for line in lines:
            try:
                entry = json.loads(line.strip())
                entry_time = datetime.fromisoformat(
                    entry['timestamp'].replace('Z', '+00:00'))

                if start_date and entry_time < start_date:
                    continue
                if end_date and entry_time > end_date:
                    continue

                filtered_lines.append(line)

            except Exception:
                # Include malformed lines for investigation
                filtered_lines.append(line)

        # Export in requested format
        if format == 'jsonl':
            with open(output_path, 'w', encoding='utf-8') as f:
                f.writelines(filtered_lines)
        elif format == 'json':
            entries = []
            for line in filtered_lines:
                try:
                    entries.append(json.loads(line.strip()))
                except Exception:
                    continue

            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(entries, f, indent=2)
        else:
            raise ValueError(f"Unsupported export format: {format}")

        logger.info("Exported %d audit entries to %s",
                    len(filtered_lines), output_path)
        return len(filtered_lines)

    except Exception as e:
        logger.error("Failed to export audit logs: %s", e)
        raise


def search_audit_logs(query_filters):
    """Search audit logs with filters."""
    audit_logger = get_audit_logger()

    try:
        with open(audit_logger.audit_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        results = []

        for line_num, line in enumerate(lines, 1):
            try:
                entry = json.loads(line.strip())

                # Apply filters
                match = True
                for key, value in query_filters.items():
                    if key not in entry:
                        match = False
                        break
                    if entry[key] != value:
                        match = False
                        break

                if match:
                    entry['_line_number'] = line_num
                    results.append(entry)

            except Exception:
                continue

        return results

    except Exception as e:
        logger.error("Failed to search audit logs: %s", e)
        raise
