"""
Tests for blockchain audit anchoring functionality.
"""

import os
import json
import tempfile
import hashlib
from pathlib import Path

import pytest

from pymedsec.blockchain import create_blockchain_adapter
from pymedsec.blockchain.base import BlockchainAdapter
from pymedsec.blockchain.mock import MockBlockchainAdapter
from pymedsec.audit import AuditLogger, verify_blockchain_anchors


class TestBlockchainAdapterBase:
    """Test blockchain adapter base functionality."""

    def test_validate_digest_valid(self):
        """Test digest validation with valid digest."""
        adapter = MockBlockchainAdapter()

        valid_digest = "a" * 64  # 64 hex chars
        assert adapter.validate_digest(valid_digest)

    def test_validate_digest_invalid_length(self):
        """Test digest validation with invalid length."""
        adapter = MockBlockchainAdapter()

        # Too short
        assert not adapter.validate_digest("a" * 63)

        # Too long
        assert not adapter.validate_digest("a" * 65)

    def test_validate_digest_invalid_chars(self):
        """Test digest validation with invalid characters."""
        adapter = MockBlockchainAdapter()

        # Non-hex characters
        invalid_digest = "g" * 64
        assert not adapter.validate_digest(invalid_digest)

    def test_validate_digest_non_string(self):
        """Test digest validation with non-string input."""
        adapter = MockBlockchainAdapter()

        assert not adapter.validate_digest(123)
        assert not adapter.validate_digest(None)
        assert not adapter.validate_digest(b"bytes")


class TestMockBlockchainAdapter:
    """Test mock blockchain adapter."""

    def setup_method(self):
        """Set up test with temporary storage."""
        self.temp_dir = tempfile.mkdtemp()
        self.storage_path = os.path.join(self.temp_dir, "mock_blockchain.json")

        config = {'storage_path': self.storage_path}
        self.adapter = MockBlockchainAdapter(config)

    def test_submit_digest_success(self):
        """Test successful digest submission."""
        digest = "a1b2c3d4e5f6" + "0" * 52  # Valid 64-char hex

        result = self.adapter.submit_digest(digest)

        assert 'tx_hash' in result
        assert 'block_number' in result
        assert result['status'] == 'confirmed'
        assert len(result['tx_hash']) == 64  # SHA-256 hex

    def test_submit_digest_invalid(self):
        """Test digest submission with invalid digest."""
        invalid_digest = "invalid"

        with pytest.raises(ValueError, match="Invalid digest format"):
            self.adapter.submit_digest(invalid_digest)

    def test_submit_digest_with_metadata(self):
        """Test digest submission with metadata."""
        digest = "b1c2d3e4f5a6" + "0" * 52
        metadata = {"operation": "encrypt", "dataset": "test"}

        result = self.adapter.submit_digest(digest, metadata)

        assert result['status'] == 'confirmed'

        # Verify metadata stored
        storage = self.adapter._load_storage()
        tx_data = storage[result['tx_hash']]
        assert tx_data['metadata'] == metadata

    def test_verify_digest_success(self):
        """Test successful digest verification."""
        digest = "c1d2e3f4a5b6" + "0" * 52

        # Submit digest
        submit_result = self.adapter.submit_digest(digest)
        tx_hash = submit_result['tx_hash']

        # Verify digest
        verify_result = self.adapter.verify_digest(digest, tx_hash)

        assert verify_result['verified'] is True
        assert verify_result['message'] == 'Verified'
        assert 'block_number' in verify_result
        assert 'confirmations' in verify_result

    def test_verify_digest_not_found(self):
        """Test digest verification with non-existent transaction."""
        digest = "d1e2f3a4b5c6" + "0" * 52
        fake_tx_hash = "f" * 64

        verify_result = self.adapter.verify_digest(digest, fake_tx_hash)

        assert verify_result['verified'] is False
        assert verify_result['message'] == 'Transaction not found'

    def test_verify_digest_mismatch(self):
        """Test digest verification with digest mismatch."""
        digest1 = "e1f2a3b4c5d6" + "0" * 52
        digest2 = "f1a2b3c4d5e6" + "0" * 52

        # Submit one digest
        submit_result = self.adapter.submit_digest(digest1)
        tx_hash = submit_result['tx_hash']

        # Try to verify different digest
        verify_result = self.adapter.verify_digest(digest2, tx_hash)

        assert verify_result['verified'] is False
        assert verify_result['message'] == 'Digest mismatch'

    def test_get_transaction_status_found(self):
        """Test transaction status for existing transaction."""
        digest = "a1b2c3d4e5f6" + "1" * 52

        submit_result = self.adapter.submit_digest(digest)
        tx_hash = submit_result['tx_hash']

        status_result = self.adapter.get_transaction_status(tx_hash)

        assert status_result['found'] is True
        assert status_result['status'] == 'confirmed'
        assert 'block_number' in status_result
        assert 'confirmations' in status_result

    def test_get_transaction_status_not_found(self):
        """Test transaction status for non-existent transaction."""
        fake_tx_hash = "a" * 64

        status_result = self.adapter.get_transaction_status(fake_tx_hash)

        assert status_result['found'] is False
        assert status_result['status'] == 'not_found'


class TestBlockchainAdapterFactory:
    """Test blockchain adapter factory function."""

    def test_create_mock_adapter(self):
        """Test creating mock blockchain adapter."""
        adapter = create_blockchain_adapter('mock')

        assert isinstance(adapter, MockBlockchainAdapter)

    def test_create_disabled_adapter(self):
        """Test creating disabled adapter."""
        adapter = create_blockchain_adapter('disabled')

        assert adapter is None

    def test_create_unknown_adapter(self):
        """Test creating unknown adapter type."""
        adapter = create_blockchain_adapter('unknown_backend')

        assert adapter is None

    def test_create_from_environment(self):
        """Test creating adapter from environment variable."""
        # Set environment variable
        os.environ['BLOCKCHAIN_BACKEND'] = 'mock'

        try:
            adapter = create_blockchain_adapter()
            assert isinstance(adapter, MockBlockchainAdapter)
        finally:
            # Clean up
            del os.environ['BLOCKCHAIN_BACKEND']

    def test_create_default_disabled(self):
        """Test default behavior when no backend specified."""
        # Ensure no environment variable
        if 'BLOCKCHAIN_BACKEND' in os.environ:
            del os.environ['BLOCKCHAIN_BACKEND']

        adapter = create_blockchain_adapter()

        assert adapter is None


class TestAuditBlockchainIntegration:
    """Test audit logger blockchain integration."""

    def setup_method(self):
        """Set up test with temporary files."""
        self.temp_dir = tempfile.mkdtemp()
        self.audit_path = os.path.join(self.temp_dir, "audit.log")
        self.blockchain_storage = os.path.join(
            self.temp_dir, "blockchain.json")

        # Configure mock blockchain
        os.environ['BLOCKCHAIN_BACKEND'] = 'mock'

        # Create audit logger
        self.audit_logger = AuditLogger(
            self.audit_path,
            blockchain_config={'storage_path': self.blockchain_storage}
        )

    def teardown_method(self):
        """Clean up environment."""
        if 'BLOCKCHAIN_BACKEND' in os.environ:
            del os.environ['BLOCKCHAIN_BACKEND']

    def test_audit_with_blockchain_anchoring(self):
        """Test audit logging with blockchain anchoring."""
        # Log an audit entry
        self.audit_logger.log_operation(
            operation="encrypt",
            dataset_id="test_dataset",
            modality="CT",
            outcome="success"
        )

        # Read audit log
        with open(self.audit_path, 'r', encoding='utf-8') as f:
            line = f.readline().strip()
            entry = json.loads(line)

        # Check blockchain anchor
        assert 'blockchain_anchor' in entry
        anchor = entry['blockchain_anchor']
        assert anchor['backend'] == 'mock'
        assert anchor['digest'].startswith('sha256:')
        assert len(anchor['tx_hash']) == 64
        assert 'timestamp' in anchor

    def test_audit_without_blockchain(self):
        """Test audit logging without blockchain backend."""
        # Disable blockchain
        del os.environ['BLOCKCHAIN_BACKEND']

        # Create new audit logger
        audit_logger = AuditLogger(self.audit_path)

        # Log an audit entry
        audit_logger.log_operation(
            operation="encrypt",
            dataset_id="test_dataset",
            modality="CT",
            outcome="success"
        )

        # Read audit log
        with open(self.audit_path, 'r', encoding='utf-8') as f:
            line = f.readline().strip()
            entry = json.loads(line)

        # Check no blockchain anchor
        assert 'blockchain_anchor' not in entry

    def test_blockchain_digest_calculation(self):
        """Test blockchain digest calculation excludes PHI."""
        # Log entry with PHI-like data
        self.audit_logger.log_operation(
            operation="encrypt",
            dataset_id="test_dataset",
            modality="CT",
            outcome="success",
            patient_id="12345",
            file_path="/sensitive/path/image.dcm",
            operator="dr_smith"
        )

        # Read audit log
        with open(self.audit_path, 'r', encoding='utf-8') as f:
            line = f.readline().strip()
            entry = json.loads(line)

        # Get stored digest
        # Remove 'sha256:'
        stored_digest = entry['blockchain_anchor']['digest'][7:]

        # Calculate expected digest (without PHI fields)
        sanitized_entry = entry.copy()
        phi_fields = ['patient_id', 'pseudo_patient_id',
                      'file_path', 'operator', 'timestamp']
        for field in phi_fields:
            sanitized_entry.pop(field, None)

        # Remove blockchain_anchor for digest calculation
        sanitized_entry.pop('blockchain_anchor', None)

        expected_digest = hashlib.sha256(
            json.dumps(sanitized_entry, sort_keys=True).encode('utf-8')
        ).hexdigest()

        assert stored_digest == expected_digest


class TestBlockchainVerification:
    """Test blockchain verification functions."""

    def setup_method(self):
        """Set up test with audit log and blockchain anchors."""
        self.temp_dir = tempfile.mkdtemp()
        self.audit_path = os.path.join(self.temp_dir, "audit.log")
        self.blockchain_storage = os.path.join(
            self.temp_dir, "blockchain.json")

        # Configure mock blockchain
        os.environ['BLOCKCHAIN_BACKEND'] = 'mock'

        # Create audit logger and log some entries
        audit_logger = AuditLogger(
            self.audit_path,
            blockchain_config={'storage_path': self.blockchain_storage}
        )

        # Log multiple entries
        for i in range(5):
            audit_logger.log_operation(
                operation="encrypt",
                dataset_id=f"dataset_{i}",
                modality="CT",
                outcome="success"
            )

    def teardown_method(self):
        """Clean up environment."""
        if 'BLOCKCHAIN_BACKEND' in os.environ:
            del os.environ['BLOCKCHAIN_BACKEND']

    def test_verify_blockchain_anchors_success(self):
        """Test blockchain anchor verification with all valid anchors."""
        result = verify_blockchain_anchors(self.audit_path)

        assert result['blockchain_enabled'] is True
        assert result['total_lines'] == 5
        assert result['anchored_lines'] == 5
        assert result['verified_anchors'] == 5
        assert result['failed_anchors'] == 0
        assert result['verification_rate'] == 1.0
        assert len(result['anchor_details']) == 5

    def test_verify_blockchain_anchors_disabled(self):
        """Test blockchain verification when blockchain is disabled."""
        # Disable blockchain
        del os.environ['BLOCKCHAIN_BACKEND']

        result = verify_blockchain_anchors(self.audit_path)

        assert result['blockchain_enabled'] is False
        assert 'not configured' in result['message']

    def test_verify_blockchain_anchors_partial_failure(self):
        """Test blockchain verification with some failures."""
        # Corrupt blockchain storage to simulate failures
        with open(self.blockchain_storage, 'w', encoding='utf-8') as f:
            json.dump({}, f)  # Empty blockchain storage

        result = verify_blockchain_anchors(self.audit_path)

        assert result['blockchain_enabled'] is True
        assert result['total_lines'] == 5
        assert result['anchored_lines'] == 5
        assert result['verified_anchors'] == 0
        assert result['failed_anchors'] == 5
        assert result['verification_rate'] == 0.0


class TestEthereumAdapter:
    """Test Ethereum adapter (if web3 available)."""

    def test_ethereum_import_error(self):
        """Test Ethereum adapter handles missing web3 dependency."""
        # This test will pass even without web3 installed
        try:
            from pymedsec.blockchain.ethereum import EthereumBlockchainAdapter

            # If web3 is available, test initialization without connection
            with pytest.raises((ImportError, ConnectionError)):
                EthereumBlockchainAdapter({'rpc_url': 'http://localhost:9999'})

        except ImportError:
            # Expected when web3 is not installed
            pass


class TestHyperledgerAdapter:
    """Test Hyperledger adapter placeholder."""

    def test_hyperledger_not_implemented(self):
        """Test Hyperledger adapter raises NotImplementedError."""
        from pymedsec.blockchain.hyperledger import HyperledgerBlockchainAdapter

        with pytest.raises(NotImplementedError):
            HyperledgerBlockchainAdapter()


# Integration test fixtures
@pytest.fixture
def temp_audit_environment():
    """Create temporary audit environment with blockchain."""
    temp_dir = tempfile.mkdtemp()
    audit_path = os.path.join(temp_dir, "audit.log")
    blockchain_storage = os.path.join(temp_dir, "blockchain.json")

    # Set up environment
    os.environ['BLOCKCHAIN_BACKEND'] = 'mock'

    yield {
        'audit_path': audit_path,
        'blockchain_storage': blockchain_storage,
        'temp_dir': temp_dir
    }

    # Clean up
    if 'BLOCKCHAIN_BACKEND' in os.environ:
        del os.environ['BLOCKCHAIN_BACKEND']


def test_end_to_end_blockchain_audit(temp_audit_environment):
    """End-to-end test of blockchain audit functionality."""
    env = temp_audit_environment

    # Create audit logger with blockchain
    audit_logger = AuditLogger(
        env['audit_path'],
        blockchain_config={'storage_path': env['blockchain_storage']}
    )

    # Log several operations
    operations = [
        {'operation': 'sanitize', 'dataset_id': 'ds1', 'modality': 'CT'},
        {'operation': 'encrypt', 'dataset_id': 'ds1', 'modality': 'CT'},
        {'operation': 'decrypt', 'dataset_id': 'ds1', 'modality': 'CT'},
    ]

    for op in operations:
        audit_logger.log_operation(outcome='success', **op)

    # Verify blockchain anchors
    verification = verify_blockchain_anchors(env['audit_path'])

    assert verification['blockchain_enabled'] is True
    assert verification['total_lines'] == 3
    assert verification['anchored_lines'] == 3
    assert verification['verified_anchors'] == 3
    assert verification['verification_rate'] == 1.0

    # Verify each anchor has required fields
    for detail in verification['anchor_details']:
        assert 'line' in detail
        assert 'tx_hash' in detail
        assert 'digest' in detail
        assert detail['status'] == 'verified'
        assert 'confirmations' in detail
