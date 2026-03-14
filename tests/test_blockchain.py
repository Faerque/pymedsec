# SPDX-License-Identifier: Apache-2.0

"""Tests for blockchain audit anchoring hardening."""

import json
import os
import tempfile

import pytest

from pymedsec.audit import AuditLogger, verify_blockchain_anchors
from pymedsec.blockchain import create_blockchain_adapter
from pymedsec.blockchain.mock import MockBlockchainAdapter


EXPECTED_SUBMIT_KEYS = {
    "backend",
    "tx_hash",
    "digest",
    "status",
    "block_number",
    "confirmations",
    "message",
    "timestamp",
}
EXPECTED_VERIFY_KEYS = {
    "backend",
    "tx_hash",
    "digest",
    "verified",
    "status",
    "block_number",
    "confirmations",
    "message",
    "timestamp",
}
EXPECTED_TX_STATUS_KEYS = {
    "backend",
    "tx_hash",
    "found",
    "status",
    "block_number",
    "confirmations",
    "message",
    "timestamp",
}


def assert_contract_keys(result, required_keys):
    """Assert normalized adapter contract keys are present."""
    assert required_keys.issubset(set(result.keys()))


class TestBlockchainAdapterBase:
    """Test blockchain adapter base functionality."""

    def test_validate_digest_valid(self):
        adapter = MockBlockchainAdapter()
        assert adapter.validate_digest("a" * 64)

    def test_validate_digest_invalid_length(self):
        adapter = MockBlockchainAdapter()
        assert not adapter.validate_digest("a" * 63)
        assert not adapter.validate_digest("a" * 65)

    def test_validate_digest_invalid_chars(self):
        adapter = MockBlockchainAdapter()
        assert not adapter.validate_digest("g" * 64)

    def test_validate_digest_non_string(self):
        adapter = MockBlockchainAdapter()
        assert not adapter.validate_digest(123)
        assert not adapter.validate_digest(None)
        assert not adapter.validate_digest(b"bytes")


class TestMockBlockchainAdapter:
    """Test mock blockchain adapter."""

    @pytest.fixture(autouse=True)
    def setup_adapter(self):
        self.temp_dir = tempfile.mkdtemp()
        self.storage_path = os.path.join(self.temp_dir, "mock_blockchain.json")
        os.environ["IMGSEC_MOCK_BLOCKCHAIN_STORAGE"] = self.storage_path
        self.adapter = MockBlockchainAdapter({"storage_path": self.storage_path})
        yield
        os.environ.pop("IMGSEC_MOCK_BLOCKCHAIN_STORAGE", None)

    def test_submit_digest_success(self):
        digest = "a1b2c3d4e5f6" + "0" * 52
        result = self.adapter.submit_digest(digest, {"operation": "encrypt"})

        assert_contract_keys(result, EXPECTED_SUBMIT_KEYS)
        assert result["backend"] == "mock"
        assert result["status"] == "confirmed"
        assert result["digest"] == digest
        assert len(result["tx_hash"]) == 64

    def test_submit_digest_invalid(self):
        with pytest.raises(ValueError, match="Invalid digest format"):
            self.adapter.submit_digest("invalid")

    def test_submit_digest_with_metadata(self):
        digest = "b1c2d3e4f5a6" + "0" * 52
        metadata = {"operation": "encrypt", "dataset": "test"}

        result = self.adapter.submit_digest(digest, metadata)
        assert result["status"] == "confirmed"

        storage = self.adapter._load_storage()  # pylint: disable=protected-access
        tx_data = storage[result["tx_hash"]]
        assert tx_data["metadata"] == metadata

    def test_verify_digest_success(self):
        digest = "c1d2e3f4a5b6" + "0" * 52
        submit_result = self.adapter.submit_digest(digest)

        verify_result = self.adapter.verify_digest(digest, submit_result["tx_hash"])

        assert_contract_keys(verify_result, EXPECTED_VERIFY_KEYS)
        assert verify_result["verified"] is True
        assert verify_result["status"] == "verified"

    def test_verify_digest_not_found(self):
        digest = "d1e2f3a4b5c6" + "0" * 52
        verify_result = self.adapter.verify_digest(digest, "f" * 64)

        assert verify_result["verified"] is False
        assert verify_result["status"] == "not_found"

    def test_verify_digest_mismatch(self):
        digest1 = "e1f2a3b4c5d6" + "0" * 52
        digest2 = "f1a2b3c4d5e6" + "0" * 52
        submit_result = self.adapter.submit_digest(digest1)

        verify_result = self.adapter.verify_digest(digest2, submit_result["tx_hash"])

        assert verify_result["verified"] is False
        assert verify_result["status"] == "mismatch"

    def test_get_transaction_status_found(self):
        digest = "a1b2c3d4e5f6" + "1" * 52
        submit_result = self.adapter.submit_digest(digest)
        status_result = self.adapter.get_transaction_status(submit_result["tx_hash"])

        assert_contract_keys(status_result, EXPECTED_TX_STATUS_KEYS)
        assert status_result["found"] is True
        assert status_result["status"] == "confirmed"

    def test_get_transaction_status_not_found(self):
        status_result = self.adapter.get_transaction_status("a" * 64)
        assert status_result["found"] is False
        assert status_result["status"] == "not_found"


class TestBlockchainAdapterFactory:
    """Test blockchain adapter factory function."""

    def test_create_mock_adapter(self):
        adapter = create_blockchain_adapter("mock")
        assert isinstance(adapter, MockBlockchainAdapter)

    def test_create_disabled_adapter(self):
        assert create_blockchain_adapter("disabled") is None

    def test_create_unknown_adapter(self):
        assert create_blockchain_adapter("unknown_backend") is None

    def test_create_from_canonical_environment(self, monkeypatch):
        monkeypatch.setenv("IMGSEC_BLOCKCHAIN_BACKEND", "mock")
        monkeypatch.delenv("BLOCKCHAIN_BACKEND", raising=False)
        adapter = create_blockchain_adapter()
        assert isinstance(adapter, MockBlockchainAdapter)

    def test_legacy_environment_is_ignored(self, monkeypatch):
        monkeypatch.delenv("IMGSEC_BLOCKCHAIN_BACKEND", raising=False)
        monkeypatch.setenv("BLOCKCHAIN_BACKEND", "mock")
        adapter = create_blockchain_adapter()
        assert adapter is None


class TestAuditBlockchainIntegration:
    """Test audit logger blockchain integration."""

    @pytest.fixture(autouse=True)
    def setup_audit_logger(self, mock_config, monkeypatch):
        self.temp_dir = tempfile.mkdtemp()
        self.audit_path = os.path.join(self.temp_dir, "audit.log")
        self.blockchain_storage = os.path.join(self.temp_dir, "blockchain.json")

        monkeypatch.setenv("IMGSEC_BLOCKCHAIN_BACKEND", "mock")
        monkeypatch.setenv("IMGSEC_BLOCKCHAIN_FREQUENCY", "every")
        monkeypatch.setenv("IMGSEC_MOCK_BLOCKCHAIN_STORAGE", self.blockchain_storage)
        monkeypatch.delenv("BLOCKCHAIN_BACKEND", raising=False)

        self.audit_logger = AuditLogger(
            self.audit_path,
            config_or_secret=mock_config,
            blockchain_config={"storage_path": self.blockchain_storage},
        )

        yield

    def _last_entry(self):
        with open(self.audit_path, "r", encoding="utf-8") as f:
            entries = [json.loads(line.strip()) for line in f if line.strip()]
        return entries[-1]

    def test_audit_with_blockchain_anchoring(self):
        self.audit_logger.log_operation(
            operation="encrypt",
            dataset_id="test_dataset",
            modality="CT",
            outcome="success",
        )

        entry = self._last_entry()
        assert "blockchain_anchor" in entry
        anchor = entry["blockchain_anchor"]
        assert anchor["backend"] == "mock"
        assert anchor["status"] == "confirmed"
        assert anchor["digest"].startswith("sha256:")
        assert len(anchor["tx_hash"]) == 64
        assert "confirmations" in anchor
        assert "blockchain_anchor_error" not in entry

    def test_audit_without_blockchain(self, mock_config, monkeypatch):
        monkeypatch.delenv("IMGSEC_BLOCKCHAIN_BACKEND", raising=False)

        audit_path_no_bc = os.path.join(self.temp_dir, "audit_no_blockchain.log")
        audit_logger = AuditLogger(audit_path_no_bc, config_or_secret=mock_config)
        audit_logger.log_operation(
            operation="encrypt",
            dataset_id="test_dataset",
            modality="CT",
            outcome="success",
        )

        with open(audit_path_no_bc, "r", encoding="utf-8") as f:
            entries = [json.loads(line.strip()) for line in f if line.strip()]
        entry = entries[-1]

        assert "blockchain_anchor" not in entry
        assert "blockchain_anchor_error" not in entry

    def test_fail_open_records_sanitized_anchor_error(self):
        class FailingAdapter:
            backend_name = "mock"

            def submit_digest(self, digest, metadata=None):
                raise ConnectionError("network timeout while submitting digest")

        self.audit_logger.blockchain_adapter = FailingAdapter()

        self.audit_logger.log_operation(
            operation="encrypt",
            outcome="success",
            patient_id="12345",
            file_path="/sensitive/path/image.dcm",
        )

        entry = self._last_entry()
        assert "blockchain_anchor" not in entry
        assert "blockchain_anchor_error" in entry

        anchor_error = entry["blockchain_anchor_error"]
        assert set(anchor_error.keys()) == {
            "backend",
            "error_code",
            "message",
            "retryable",
            "timestamp",
        }
        assert anchor_error["backend"] == "mock"
        assert anchor_error["retryable"] is True
        # Error message should not include payload fields.
        assert "12345" not in anchor_error["message"]
        assert "image.dcm" not in anchor_error["message"]

    def test_invalid_frequency_defaults_to_every(self, mock_config, monkeypatch):
        monkeypatch.setenv("IMGSEC_BLOCKCHAIN_BACKEND", "mock")
        monkeypatch.setenv("IMGSEC_BLOCKCHAIN_FREQUENCY", "invalid-value")

        audit_logger = AuditLogger(
            os.path.join(self.temp_dir, "invalid_frequency.log"),
            config_or_secret=mock_config,
            blockchain_config={
                "storage_path": os.path.join(self.temp_dir, "invalid_frequency_chain.json")
            },
        )
        assert audit_logger.blockchain_frequency == "every"


class TestBlockchainVerification:
    """Test blockchain verification functions."""

    @pytest.fixture(autouse=True)
    def setup_verification_test(self, mock_config, monkeypatch):
        self.temp_dir = tempfile.mkdtemp()
        self.audit_path = os.path.join(self.temp_dir, "audit.log")
        self.blockchain_storage = os.path.join(self.temp_dir, "blockchain.json")

        monkeypatch.setenv("IMGSEC_BLOCKCHAIN_BACKEND", "mock")
        monkeypatch.setenv("IMGSEC_MOCK_BLOCKCHAIN_STORAGE", self.blockchain_storage)
        monkeypatch.delenv("BLOCKCHAIN_BACKEND", raising=False)

        audit_logger = AuditLogger(
            self.audit_path,
            config_or_secret=mock_config,
            blockchain_config={"storage_path": self.blockchain_storage},
        )

        for i in range(5):
            audit_logger.log_operation(
                operation="encrypt",
                dataset_id=f"dataset_{i}",
                modality="CT",
                outcome="success",
            )

        self.audit_logger = audit_logger
        yield

    def test_verify_blockchain_anchors_success(self):
        result = verify_blockchain_anchors(self.audit_path)

        assert result["blockchain_enabled"] is True
        assert result["backend"] == "mock"
        assert result["status"] in {"passed", "partial"}
        assert result["total_lines"] >= 5
        assert result["anchored_lines"] >= 5
        assert len(result["anchor_details"]) >= 5

    def test_verify_blockchain_anchors_disabled(self, monkeypatch):
        monkeypatch.delenv("IMGSEC_BLOCKCHAIN_BACKEND", raising=False)
        result = verify_blockchain_anchors(self.audit_path)

        assert result["blockchain_enabled"] is False
        assert result["status"] == "disabled"

    def test_verify_blockchain_anchors_partial_failure(self):
        with open(self.blockchain_storage, "w", encoding="utf-8") as f:
            json.dump({}, f)

        result = verify_blockchain_anchors(self.audit_path)

        assert result["blockchain_enabled"] is True
        assert result["status"] in {"partial", "failed"}
        assert result["failed_anchors"] >= 1

    def test_verify_reports_anchor_error_lines(self):
        class FailingAdapter:
            backend_name = "mock"

            def submit_digest(self, digest, metadata=None):
                raise RuntimeError("simulated blockchain outage")

        self.audit_logger.blockchain_adapter = FailingAdapter()
        self.audit_logger.log_operation(operation="decrypt", outcome="success")

        result = verify_blockchain_anchors(self.audit_path)
        assert result["anchor_error_lines"] >= 1


class TestEthereumAdapter:
    """Test Ethereum adapter behavior without forcing network dependencies."""

    def test_ethereum_import_or_connection_error(self):
        try:
            from pymedsec.blockchain.ethereum import EthereumBlockchainAdapter

            with pytest.raises((ImportError, ConnectionError, RuntimeError)):
                EthereumBlockchainAdapter(
                    {
                        "rpc_url": "http://localhost:9999",
                        "private_key": "0x" + "1" * 64,
                    }
                )
        except ImportError:
            pass


class TestHyperledgerAdapter:
    """Test Hyperledger adapter dependency handling."""

    def test_hyperledger_requires_dependency(self):
        from pymedsec.blockchain.hyperledger import HyperledgerBlockchainAdapter

        with pytest.raises(
            ImportError, match="Hyperledger Fabric Python SDK is required"
        ):
            HyperledgerBlockchainAdapter()
