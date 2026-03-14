# SPDX-License-Identifier: Apache-2.0

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

    def __init__(self, audit_path=None, config_or_secret=None, blockchain_config=None):
        # Handle both config object and audit_secret for backward compatibility
        if config_or_secret and hasattr(config_or_secret, 'audit_path'):
            # It's a config object
            self._injected_config = config_or_secret
            self.audit_path = Path(audit_path or config_or_secret.audit_path)
            audit_secret = getattr(config_or_secret, 'audit_signing_key', None)
            self.audit_secret = audit_secret or self._get_audit_secret()
        else:
            # It's an audit_secret (bytes) or None
            self._injected_config = None
            self.audit_path = Path(audit_path or config.get_config().audit_path)
            self.audit_secret = config_or_secret or self._get_audit_secret()

        self.blockchain_config = blockchain_config
        self.line_count = 0
        self.anchor_interval = 1000  # Rolling anchor every N lines
        self.last_anchor_hash = None
        self.blockchain_backend = os.getenv("IMGSEC_BLOCKCHAIN_BACKEND", "").strip().lower()
        self.blockchain_frequency = self._get_blockchain_frequency()

        # Initialize blockchain adapter if configured.
        self.blockchain_adapter = self._initialize_blockchain()

        # Ensure audit directory exists
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)

        # Initialize if new file
        if not self.audit_path.exists():
            self._initialize_audit_log()
        else:
            self._load_existing_state()

    @staticmethod
    def _now_iso():
        """Return UTC timestamp in ISO-8601 format."""
        return datetime.now(timezone.utc).isoformat()

    def _get_blockchain_frequency(self):
        """Get and validate blockchain anchoring frequency."""
        valid_frequencies = {"every", "batch_hourly"}
        value = os.getenv("IMGSEC_BLOCKCHAIN_FREQUENCY", "every").strip().lower()
        if value in valid_frequencies:
            return value

        logger.warning(
            "Invalid IMGSEC_BLOCKCHAIN_FREQUENCY=%s. Defaulting to 'every'.",
            value,
        )
        return "every"

    def _initialize_blockchain(self):
        """Initialize blockchain adapter if configured."""
        try:
            if not self.blockchain_backend:
                return None

            # Use blockchain_config if provided
            if self.blockchain_config:
                from .blockchain import create_blockchain_adapter

                adapter = create_blockchain_adapter(
                    backend=self.blockchain_backend, config=self.blockchain_config
                )
            else:
                from .blockchain import create_blockchain_adapter

                adapter = create_blockchain_adapter(backend=self.blockchain_backend)

            if adapter:
                logger.info(
                    "Blockchain anchoring enabled: %s",
                    self.blockchain_backend,
                )
            return adapter
        except Exception as e:
            logger.warning("Failed to initialize blockchain adapter: %s", e)
            return None

    def _get_audit_secret(self):
        """Get or generate audit HMAC secret."""
        secret = os.getenv("IMGSEC_AUDIT_SECRET")
        if secret:
            return secret.encode("utf-8")

        # Derive from configuration hash if no explicit secret
        cfg = config.get_config()
        seed = f"audit:{cfg.policy_hash}:{cfg.kms_key_ref}"
        return hashlib.sha256(seed.encode("utf-8")).digest()

    def _initialize_audit_log(self):
        """Initialize new audit log with header."""
        header = {
            "audit_log_version": "1.0",
            "initialized_at": datetime.now(timezone.utc).isoformat(),
            "policy_hash": config.get_config().policy_hash,
            "kms_key_ref": config.get_config().kms_key_ref,
        }

        self._write_audit_line("INIT", header)
        logger.info("Initialized new audit log: %s", self.audit_path)

    def _load_existing_state(self):
        """Load state from existing audit log."""
        try:
            with open(self.audit_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
                self.line_count = len(lines)

                # Find last anchor hash
                for line in reversed(lines):
                    try:
                        entry = json.loads(line.strip())
                        if entry.get("operation") == "ANCHOR":
                            self.last_anchor_hash = entry.get("details", {}).get(
                                "anchor_hash"
                            )
                            break
                    except Exception:
                        continue

            logger.debug("Loaded existing audit log: %d lines", self.line_count)
        except Exception as e:
            logger.error("Failed to load audit log state: %s", e)
            raise

    def _write_audit_line(self, operation, data):
        """Write a single audit line with HMAC signature and optional blockchain anchoring."""
        timestamp = self._now_iso()

        # Build audit entry
        entry = {
            "timestamp": timestamp,
            "line_number": self.line_count + 1,
            "operation": operation,
            "actor": config.get_config().actor,
            **data,
        }

        # Serialize and compute HMAC
        entry_json = json.dumps(entry, sort_keys=True, separators=(",", ":"))
        signature = hmac.new(
            self.audit_secret, entry_json.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        # Add signature to entry
        entry["hmac_sha256"] = signature

        # Compute SHA-256 digest for blockchain anchoring
        entry_with_hmac = json.dumps(entry, sort_keys=True, separators=(",", ":"))
        line_digest = hashlib.sha256(entry_with_hmac.encode("utf-8")).hexdigest()

        # Optional blockchain anchoring
        blockchain_anchor = None
        blockchain_anchor_error = None
        if self.blockchain_adapter and self._should_anchor_to_blockchain():
            try:
                blockchain_anchor = self._anchor_to_blockchain(line_digest, entry)
            except Exception as e:
                logger.error("Blockchain anchoring failed: %s", e)
                # Continue without blockchain anchoring to avoid blocking audit logging
                blockchain_anchor_error = self._build_blockchain_anchor_error(e)

        # Add blockchain anchor info if successful
        if blockchain_anchor:
            entry["blockchain_anchor"] = blockchain_anchor
        elif blockchain_anchor_error:
            entry["blockchain_anchor_error"] = blockchain_anchor_error

        # Final serialization with all components
        final_json = json.dumps(entry, sort_keys=True, separators=(",", ":"))

        # Write to file
        try:
            with open(self.audit_path, "a", encoding="utf-8") as f:
                f.write(final_json + "\n")
                f.flush()
                os.fsync(f.fileno())  # Force write to disk

            self.line_count += 1

            # Generate anchor hash periodically
            if self.line_count % self.anchor_interval == 0:
                self._generate_anchor_hash()

        except Exception as e:
            logger.error("Failed to write audit line: %s", e)
            raise

    def _sanitize_error_message(self, err):
        """Sanitize blockchain error messages for audit safety."""
        message = str(err).replace("\n", " ").replace("\r", " ").strip()
        if len(message) > 240:
            message = message[:240] + "..."
        return message

    def _is_retryable_error(self, err):
        """Best-effort retryability classification for anchor failures."""
        if isinstance(err, (TimeoutError, ConnectionError, OSError)):
            return True

        err_name = err.__class__.__name__.lower()
        message = str(err).lower()
        retryable_tokens = ("timeout", "temporar", "connect", "network", "retry")
        return any(token in err_name or token in message for token in retryable_tokens)

    def _build_blockchain_anchor_error(self, err):
        """Build sanitized fail-open blockchain anchor error for audit logs."""
        return {
            "backend": self.blockchain_backend or "unknown",
            "error_code": err.__class__.__name__.upper(),
            "message": self._sanitize_error_message(err),
            "retryable": self._is_retryable_error(err),
            "timestamp": self._now_iso(),
        }

    def _should_anchor_to_blockchain(self):
        """Determine if this audit line should be anchored to blockchain."""
        if not self.blockchain_adapter:
            return False

        if self.blockchain_frequency == "every":
            return True
        elif self.blockchain_frequency == "batch_hourly":
            # Anchor every hour (approximately every 3600 operations if 1 op/sec)
            return self.line_count % 3600 == 0
        else:
            return False

    def _anchor_to_blockchain(self, line_digest, entry):
        """Anchor audit line digest to blockchain."""
        # Prepare sanitized metadata for blockchain submission
        metadata = {
            "operation": entry.get("operation"),
            "timestamp": entry.get("timestamp"),
            "line_number": entry.get("line_number"),
            "outcome": entry.get("outcome"),
            "actor_hash": hashlib.sha256(entry.get("actor", "").encode()).hexdigest()[
                :16
            ],
        }

        # Add dataset/modality info if available in details
        details = entry.get("details", {})
        if "dataset_id" in details:
            metadata["dataset_id"] = str(details["dataset_id"])
        if "modality" in details:
            metadata["modality"] = str(details["modality"])[:20]  # Limit length

        # Submit to blockchain
        tx_info = self.blockchain_adapter.submit_digest(line_digest, metadata)
        backend_name = tx_info.get("backend") or self.blockchain_backend or "unknown"

        # Return anchor information for audit log
        return {
            "backend": backend_name,
            "tx_hash": tx_info.get("tx_hash"),
            "digest": f"sha256:{line_digest}",
            "chain": backend_name,  # Backward-compatible alias.
            "status": tx_info.get("status", "pending"),
            "block_number": tx_info.get("block_number"),
            "confirmations": tx_info.get("confirmations", 0),
            "timestamp": tx_info.get("timestamp"),
        }

    def _generate_anchor_hash(self):
        """Generate rolling anchor hash for integrity checking."""
        try:
            # Read recent lines for anchor computation
            with open(self.audit_path, "r", encoding="utf-8") as f:
                lines = f.readlines()

            # Compute hash of last N lines
            anchor_lines = lines[-self.anchor_interval :]
            combined_content = "".join(anchor_lines)
            anchor_hash = hashlib.sha256(combined_content.encode("utf-8")).hexdigest()

            # Log anchor entry
            anchor_data = {
                "details": {
                    "anchor_hash": anchor_hash,
                    "lines_covered": len(anchor_lines),
                    "previous_anchor": self.last_anchor_hash,
                }
            }

            self._write_audit_line("ANCHOR", anchor_data)
            self.last_anchor_hash = anchor_hash

            logger.debug("Generated anchor hash at line %d", self.line_count)

        except Exception as e:
            logger.error("Failed to generate anchor hash: %s", e)

    def log_operation(self, operation, outcome="success", **kwargs):
        """Log a security operation with details."""
        data = {"outcome": outcome, "details": kwargs}

        self._write_audit_line(operation, data)

    def log_event(self, event_data):
        """Log an event with custom data. Alias for log_operation."""
        operation = event_data.pop("action", "UNKNOWN_EVENT")
        self.log_operation(operation, **event_data)

    @property
    def log_file(self):
        """Get the audit log file path."""
        return str(self.audit_path)

    @property
    def config(self):
        """Get the configuration object."""
        return self._injected_config or config.get_config()

    def verify_integrity(self, start_line=None, end_line=None):
        """Verify HMAC integrity of audit log lines."""
        try:
            with open(self.audit_path, "r", encoding="utf-8") as f:
                lines = f.readlines()

            if start_line is None:
                start_line = 1
            if end_line is None:
                end_line = len(lines)

            verification_results = {
                "total_lines": len(lines),
                "verified_lines": 0,
                "failed_lines": [],
                "is_valid": True,
            }

            for i, line in enumerate(lines[start_line - 1 : end_line], start_line):
                try:
                    entry = json.loads(line.strip())
                    stored_hmac = entry.pop("hmac_sha256", None)
                    # HMAC is computed before blockchain enrichment, so ignore
                    # post-signature anchor metadata during recomputation.
                    entry.pop("blockchain_anchor", None)
                    entry.pop("blockchain_anchor_error", None)

                    if not stored_hmac:
                        verification_results["failed_lines"].append(
                            {"line": i, "error": "Missing HMAC signature"}
                        )
                        verification_results["is_valid"] = False
                        continue

                    # Recompute HMAC
                    entry_json = json.dumps(
                        entry, sort_keys=True, separators=(",", ":")
                    )
                    computed_hmac = hmac.new(
                        self.audit_secret, entry_json.encode("utf-8"), hashlib.sha256
                    ).hexdigest()

                    if not hmac.compare_digest(stored_hmac, computed_hmac):
                        verification_results["failed_lines"].append(
                            {"line": i, "error": "HMAC verification failed"}
                        )
                        verification_results["is_valid"] = False
                    else:
                        verification_results["verified_lines"] += 1

                except Exception as e:
                    verification_results["failed_lines"].append(
                        {"line": i, "error": f"Parse error: {e}"}
                    )
                    verification_results["is_valid"] = False

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


def log_operation(operation, outcome="success", **kwargs):
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

    backend_name = os.getenv("IMGSEC_BLOCKCHAIN_BACKEND", "").strip().lower()
    results = {
        "blockchain_enabled": False,
        "backend": backend_name or None,
        "status": "disabled",
        "message": "Blockchain anchoring not configured",
        "total_lines": 0,
        "anchored_lines": 0,
        "verified_anchors": 0,
        "failed_anchors": 0,
        "anchor_error_lines": 0,
        "verification_rate": 0.0,
        "anchor_details": [],
    }

    try:
        from .blockchain import create_blockchain_adapter

        blockchain_adapter = create_blockchain_adapter()
        if not blockchain_adapter:
            return results

        results["blockchain_enabled"] = True
        results["backend"] = blockchain_adapter.backend_name
        results["status"] = "failed"
        results["message"] = "Blockchain anchor verification completed"

        with open(audit_file_path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                results["total_lines"] += 1

                try:
                    entry = json.loads(line.strip())
                except Exception as e:
                    logger.warning("Error parsing line %d: %s", line_num, e)
                    continue

                anchor_error = entry.get("blockchain_anchor_error")
                if anchor_error:
                    results["anchor_error_lines"] += 1
                    results["anchor_details"].append(
                        {
                            "line": line_num,
                            "backend": anchor_error.get("backend", "unknown"),
                            "tx_hash": None,
                            "digest": None,
                            "status": "anchor_error",
                            "confirmations": 0,
                            "block_number": None,
                            "message": anchor_error.get("message", ""),
                            "error_code": anchor_error.get("error_code"),
                        }
                    )

                blockchain_anchor = entry.get("blockchain_anchor")
                if not blockchain_anchor:
                    continue

                results["anchored_lines"] += 1
                digest_full = blockchain_anchor.get("digest", "")
                tx_hash = blockchain_anchor.get("tx_hash")
                anchor_backend = blockchain_anchor.get("backend") or blockchain_anchor.get("chain") or results["backend"]

                if not digest_full.startswith("sha256:") or not tx_hash:
                    results["failed_anchors"] += 1
                    results["anchor_details"].append(
                        {
                            "line": line_num,
                            "backend": anchor_backend,
                            "tx_hash": tx_hash,
                            "digest": digest_full,
                            "status": "invalid_anchor",
                            "confirmations": 0,
                            "block_number": None,
                            "message": "Invalid anchor format",
                        }
                    )
                    continue

                digest_hex = digest_full[7:]
                try:
                    verification = blockchain_adapter.verify_digest(digest_hex, tx_hash)
                except Exception as e:
                    verification = {
                        "verified": False,
                        "status": "error",
                        "confirmations": 0,
                        "block_number": None,
                        "message": str(e),
                    }

                verified = bool(verification.get("verified"))
                detail_status = verification.get("status") or ("verified" if verified else "mismatch")
                if verified and detail_status == "verified":
                    results["verified_anchors"] += 1
                else:
                    results["failed_anchors"] += 1

                results["anchor_details"].append(
                    {
                        "line": line_num,
                        "backend": verification.get("backend", anchor_backend),
                        "tx_hash": tx_hash,
                        "digest": digest_hex[:16] + "...",
                        "status": detail_status,
                        "confirmations": verification.get("confirmations", 0),
                        "block_number": verification.get("block_number"),
                        "message": verification.get("message"),
                    }
                )

        if results["anchored_lines"] > 0:
            results["verification_rate"] = results["verified_anchors"] / results["anchored_lines"]
        else:
            results["verification_rate"] = 0.0

        if results["anchored_lines"] == 0:
            results["status"] = "failed"
            results["message"] = "No blockchain anchors found in audit log"
        elif results["failed_anchors"] == 0:
            results["status"] = "passed"
            results["message"] = "All blockchain anchors verified"
        elif results["verified_anchors"] > 0:
            results["status"] = "partial"
            results["message"] = "Some blockchain anchors failed verification"
        else:
            results["status"] = "failed"
            results["message"] = "Blockchain anchor verification failed"

        return results

    except ImportError:
        results["status"] = "error"
        results["message"] = "Blockchain module not available"
        return results
    except Exception as e:
        logger.error("Blockchain verification failed: %s", e)
        results["status"] = "error"
        results["message"] = f"Verification failed: {e}"
        return results


def get_audit_stats():
    """Get audit log statistics."""
    audit_logger = get_audit_logger()

    try:
        with open(audit_logger.audit_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        stats = {
            "total_lines": len(lines),
            "file_size_bytes": audit_logger.audit_path.stat().st_size,
            "last_modified": datetime.fromtimestamp(
                audit_logger.audit_path.stat().st_mtime, tz=timezone.utc
            ).isoformat(),
            "operations": {},
            "outcomes": {},
        }

        # Analyze operations and outcomes
        for line in lines:
            try:
                entry = json.loads(line.strip())
                operation = entry.get("operation", "UNKNOWN")
                outcome = entry.get("outcome", "unknown")

                stats["operations"][operation] = (
                    stats["operations"].get(operation, 0) + 1
                )
                stats["outcomes"][outcome] = stats["outcomes"].get(outcome, 0) + 1

            except Exception:
                continue

        return stats

    except Exception as e:
        logger.error("Failed to get audit stats: %s", e)
        raise


def export_audit_logs(output_path, start_date=None, end_date=None, format="jsonl"):
    """Export audit logs for external analysis."""
    audit_logger = get_audit_logger()
    output_path = Path(output_path)

    try:
        with open(audit_logger.audit_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        # Filter by date range if specified
        filtered_lines = []
        for line in lines:
            try:
                entry = json.loads(line.strip())
                entry_time = datetime.fromisoformat(
                    entry["timestamp"].replace("Z", "+00:00")
                )

                if start_date and entry_time < start_date:
                    continue
                if end_date and entry_time > end_date:
                    continue

                filtered_lines.append(line)

            except Exception:
                # Include malformed lines for investigation
                filtered_lines.append(line)

        # Export in requested format
        if format == "jsonl":
            with open(output_path, "w", encoding="utf-8") as f:
                f.writelines(filtered_lines)
        elif format == "json":
            entries = []
            for line in filtered_lines:
                try:
                    entries.append(json.loads(line.strip()))
                except Exception:
                    continue

            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(entries, f, indent=2)
        else:
            raise ValueError(f"Unsupported export format: {format}")

        logger.info("Exported %d audit entries to %s", len(filtered_lines), output_path)
        return len(filtered_lines)

    except Exception as e:
        logger.error("Failed to export audit logs: %s", e)
        raise


def search_audit_logs(query_filters):
    """Search audit logs with filters."""
    audit_logger = get_audit_logger()

    try:
        with open(audit_logger.audit_path, "r", encoding="utf-8") as f:
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
                    entry["_line_number"] = line_num
                    results.append(entry)

            except Exception:
                continue

        return results

    except Exception as e:
        logger.error("Failed to search audit logs: %s", e)
        raise


def generate_audit_signature(entry_data, config_obj):
    """Generate HMAC signature for audit entry data.

    Args:
        entry_data (dict): Audit entry data
        config_obj: Configuration object with audit settings

    Returns:
        str: HMAC-SHA256 signature
    """
    # Get signing key from config
    audit_config = getattr(config_obj, "get_audit_config", lambda: {})()
    signing_key = audit_config.get("signing_key", "default_key")

    # Serialize entry data
    entry_json = json.dumps(entry_data, sort_keys=True, separators=(",", ":"))

    # Generate HMAC signature
    signature = hmac.new(
        signing_key.encode("utf-8"), entry_json.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    return signature


def verify_audit_chain(audit_file_path, config_obj):
    """Verify the integrity of an audit log chain.

    Args:
        audit_file_path (str): Path to audit log file
        config_obj: Configuration object with audit settings

    Returns:
        bool: True if chain is valid, False otherwise
    """
    try:
        audit_config = getattr(config_obj, "get_audit_config", lambda: {})()
        signing_key = audit_config.get("signing_key", "default_key")

        with open(audit_file_path, "r") as f:
            for line_num, line in enumerate(f, 1):
                try:
                    entry = json.loads(line.strip())

                    # Extract signature
                    stored_signature = entry.pop("hmac_sha256", None)
                    entry.pop("blockchain_anchor", None)
                    entry.pop("blockchain_anchor_error", None)
                    if not stored_signature:
                        return False

                    # Recompute signature
                    entry_json = json.dumps(
                        entry, sort_keys=True, separators=(",", ":")
                    )
                    computed_signature = hmac.new(
                        signing_key.encode("utf-8"),
                        entry_json.encode("utf-8"),
                        hashlib.sha256,
                    ).hexdigest()

                    if stored_signature != computed_signature:
                        return False

                except (json.JSONDecodeError, KeyError):
                    return False

        return True

    except Exception:
        return False
