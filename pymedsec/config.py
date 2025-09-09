"""
Configuration management for healthcare image security.

Loads configuration from environment variables and YAML policy files.
Provides centralized access to all security and compliance settings.
"""

import os
import sys
import logging
import hashlib
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)


class SecurityConfig:
    """Centralized security configuration with fail-closed validation."""

    def __init__(self):
        # Required environment variables
        self.policy_path = os.getenv("IMGSEC_POLICY")
        if not self.policy_path:
            raise ValueError("IMGSEC_POLICY environment variable is required")

        self.kms_backend = os.getenv("IMGSEC_KMS_BACKEND", "mock")
        self.kms_key_ref = os.getenv("IMGSEC_KMS_KEY_REF")

        if not self.kms_key_ref:
            raise ValueError(
                "IMGSEC_KMS_KEY_REF environment variable is required")

        # Optional settings with secure defaults
        self.audit_path = os.getenv("IMGSEC_AUDIT_PATH", "./audit.jsonl")
        self.no_plaintext_disk = os.getenv(
            "IMGSEC_NO_PLAINTEXT_DISK", "false").lower() == "true"
        self.ocr_redaction = os.getenv(
            "IMGSEC_OCR_REDACTION", "false").lower() == "true"
        self.require_tee = os.getenv(
            "IMGSEC_REQUIRE_TEE", "false").lower() == "true"
        self.actor = os.getenv("IMGSEC_ACTOR", self._get_default_actor())
        self.debug = os.getenv("IMGSEC_DEBUG", "false").lower() == "true"

        # AWS KMS specific settings
        self.aws_region = os.getenv("AWS_DEFAULT_REGION", "us-east-1")

        # Vault specific settings
        self.vault_url = os.getenv("VAULT_ADDR", "http://localhost:8200")
        self.vault_token = os.getenv("VAULT_TOKEN")
        self.vault_mount = os.getenv("VAULT_MOUNT", "transit")

        # Load and validate policy
        self.policy = self._load_policy()
        self.policy_hash = self._compute_policy_hash()

        # Validate configuration
        self._validate_config()

        # Setup logging
        self._setup_logging()

    def _get_default_actor(self):
        """Get default actor name from system."""
        try:
            import getpass
            return getpass.getuser()
        except (ImportError, OSError):
            return "unknown"

    def _load_policy(self):
        """Load and parse YAML policy file."""
        try:
            policy_path = Path(self.policy_path)
            if not policy_path.exists():
                raise FileNotFoundError(
                    f"Policy file not found: {self.policy_path}")

            with open(policy_path, 'r', encoding='utf-8') as f:
                policy = yaml.safe_load(f)

            if not policy:
                raise ValueError("Policy file is empty or invalid")

            return policy
        except Exception as e:
            logger.error("Failed to load policy from %s: %s",
                         self.policy_path, e)
            raise

    def _load_from_file(self, file_path):
        """Load configuration from a file (for testing purposes).

        Args:
            file_path (str): Path to the configuration file

        Returns:
            dict: Loaded configuration data
        """
        try:
            path = Path(file_path)
            if not path.exists():
                raise FileNotFoundError(f"Configuration file not found: {file_path}")

            with open(path, 'r', encoding='utf-8') as f:
                if path.suffix.lower() in ['.yaml', '.yml']:
                    config_data = yaml.safe_load(f)
                elif path.suffix.lower() == '.json':
                    import json
                    config_data = json.load(f)
                else:
                    # Assume YAML by default
                    config_data = yaml.safe_load(f)

            if not config_data:
                raise ValueError("Configuration file is empty or invalid")

            return config_data

        except Exception as e:
            logger.error("Failed to load configuration from %s: %s", file_path, e)
            raise

    def _compute_policy_hash(self):
        """Compute SHA-256 hash of policy for tamper detection."""
        policy_str = yaml.dump(
            self.policy, sort_keys=True, default_flow_style=False)
        return hashlib.sha256(policy_str.encode('utf-8')).hexdigest()

    def _validate_config(self):
        """Validate configuration for security and compliance."""
        # Validate KMS backend
        valid_backends = ["aws", "vault", "mock"]
        if self.kms_backend not in valid_backends:
            raise ValueError(
                f"Invalid KMS backend: {self.kms_backend}. Must be one of {valid_backends}")

        # Warn about mock backend in production
        if self.kms_backend == "mock":
            logger.warning(
                "WARNING: Using mock KMS backend - NOT FOR PRODUCTION USE")

        # Validate policy schema
        required_policy_fields = ["schema_version",
                                  "name", "sanitization", "encryption", "audit"]
        for field in required_policy_fields:
            if field not in self.policy:
                raise ValueError(f"Policy missing required field: {field}")

        # Validate OCR requirements
        if self.ocr_redaction:
            try:
                import pytesseract  # noqa: F401
            except ImportError as exc:
                if self.policy.get("sanitization", {}).get("require_ocr", False):
                    raise RuntimeError(
                        "OCR redaction enabled but pytesseract not available") from exc
                else:
                    logger.warning(
                        "OCR redaction requested but pytesseract not available - disabling")
                    self.ocr_redaction = False

        # Validate TEE requirements
        if self.require_tee:
            logger.info(
                "TEE validation enabled - add your TEE detection logic here")
            # NOTE: Add actual TEE validation logic based on your environment

    def _setup_logging(self):
        """Configure logging based on debug settings."""
        level = logging.DEBUG if self.debug else logging.INFO

        # Configure root logger
        logging.basicConfig(
            level=level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout)
            ]
        )

        # Suppress noisy third-party loggers unless in debug mode
        if not self.debug:
            logging.getLogger('boto3').setLevel(logging.WARNING)
            logging.getLogger('botocore').setLevel(logging.WARNING)
            logging.getLogger('urllib3').setLevel(logging.WARNING)

    def get_sanitization_config(self):
        """Get sanitization configuration from policy."""
        return self.policy.get("sanitization", {})

    def get_encryption_config(self):
        """Get encryption configuration from policy."""
        return self.policy.get("encryption", {})

    def get_audit_config(self):
        """Get audit configuration from policy."""
        return self.policy.get("audit", {})

    def get_compliance_config(self):
        """Get compliance configuration from policy."""
        return self.policy.get("compliance", {})

    def allows_plaintext_disk(self):
        """Check if policy allows plaintext disk writes."""
        if self.no_plaintext_disk:
            return False
        return self.policy.get("security", {}).get("allow_plaintext_disk", True)

    def requires_ocr_redaction(self):
        """Check if policy requires OCR redaction."""
        return self.policy.get("sanitization", {}).get("require_ocr", False)


# Global configuration instance
_config = None


def load_config():
    """Load global configuration instance."""
    global _config
    if _config is None:
        _config = SecurityConfig()
    return _config


def get_config():
    """Get current configuration instance."""
    if _config is None:
        raise RuntimeError(
            "Configuration not loaded. Call load_config() first.")
    return _config


def reload_config():
    """Reload configuration from environment and policy file."""
    global _config
    _config = None
    return load_config()


# Environment validation helper
def validate_environment():
    """Validate that all required environment variables are set."""
    required_vars = [
        "IMGSEC_POLICY",
        "IMGSEC_KMS_KEY_REF"
    ]

    missing_vars = []
    for var in required_vars:
        if not os.getenv(var):
            missing_vars.append(var)

    if missing_vars:
        raise ValueError(
            f"Missing required environment variables: {missing_vars}")

    return True
