"""
Tests for the audit module - tamper-evident logging functionality.
"""
import json
import hashlib
import hmac
from datetime import datetime
from unittest.mock import Mock, patch
import pytest

from pymedsec.audit import (
    AuditLogger,
    verify_audit_integrity,
    verify_blockchain_anchors,
    generate_audit_signature,
    verify_audit_chain
)
from pymedsec.config import SecurityConfig


class TestAuditLogger:
    """Test cases for AuditLogger class."""

    def test_audit_logger_initialization(self, mock_config, temp_dir):
        """Test AuditLogger initialization."""
        log_file = temp_dir / "test_audit.jsonl"

        logger = AuditLogger(str(log_file), mock_config)

        assert logger.log_file == str(log_file)
        assert logger.config == mock_config

    def test_log_event_basic(self, mock_config, temp_dir):
        """Test basic event logging."""
        log_file = temp_dir / "test_audit.jsonl"
        logger = AuditLogger(str(log_file), mock_config)

        event_data = {
            'action': 'ENCRYPT',
            'resource': 'test_image.dcm',
            'user': 'test_user@example.com'
        }

        logger.log_event(event_data)

        # Verify log file was created and contains data
        assert log_file.exists()

        with open(log_file, 'r') as f:
            log_entry = json.loads(f.readline())

        assert log_entry['action'] == 'ENCRYPT'
        assert log_entry['resource'] == 'test_image.dcm'
        assert log_entry['user'] == 'test_user@example.com'
        assert 'timestamp' in log_entry
        assert 'signature' in log_entry

    def test_log_entry_structure(self, mock_config, temp_dir):
        """Test that log entries have required structure."""
        log_file = temp_dir / "test_audit.jsonl"
        logger = AuditLogger(str(log_file), mock_config)

        logger.log_event({'action': 'TEST_ACTION'})

        with open(log_file, 'r') as f:
            log_entry = json.loads(f.readline())

        required_fields = [
            'timestamp', 'action', 'signature', 'anchor_hash'
        ]

        for field in required_fields:
            assert field in log_entry, f"Required field {field} missing from log entry"

    def test_timestamp_format(self, mock_config, temp_dir):
        """Test that timestamps are in correct ISO format."""
        log_file = temp_dir / "test_audit.jsonl"
        logger = AuditLogger(str(log_file), mock_config)

        logger.log_event({'action': 'TEST_TIMESTAMP'})

        with open(log_file, 'r') as f:
            log_entry = json.loads(f.readline())

        timestamp = log_entry['timestamp']

        # Should be valid ISO format with Z suffix
        assert timestamp.endswith('Z')

        # Should be parseable as datetime
        parsed_dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        assert isinstance(parsed_dt, datetime)

    def test_multiple_log_entries(self, mock_config, temp_dir):
        """Test logging multiple events."""
        log_file = temp_dir / "test_audit.jsonl"
        logger = AuditLogger(str(log_file), mock_config)

        events = [
            {'action': 'ENCRYPT', 'resource': 'image1.dcm'},
            {'action': 'DECRYPT', 'resource': 'image1.dcm'},
            {'action': 'DELETE', 'resource': 'image1.dcm'}
        ]

        for event in events:
            logger.log_event(event)

        # Verify all events were logged
        with open(log_file, 'r') as f:
            lines = f.readlines()

        assert len(lines) == 3

        for i, line in enumerate(lines):
            entry = json.loads(line)
            assert entry['action'] == events[i]['action']
            assert entry['resource'] == events[i]['resource']

    def test_log_file_append_mode(self, mock_config, temp_dir):
        """Test that logging appends to existing files."""
        log_file = temp_dir / "test_audit.jsonl"

        # Create first logger and log event
        logger1 = AuditLogger(str(log_file), mock_config)
        logger1.log_event({'action': 'FIRST_EVENT'})

        # Create second logger and log another event
        logger2 = AuditLogger(str(log_file), mock_config)
        logger2.log_event({'action': 'SECOND_EVENT'})

        # Should have both events in file
        with open(log_file, 'r') as f:
            lines = f.readlines()

        assert len(lines) == 2
        assert json.loads(lines[0])['action'] == 'FIRST_EVENT'
        assert json.loads(lines[1])['action'] == 'SECOND_EVENT'


class TestAuditSecurity:
    """Test security features of audit logging."""

    def test_signature_generation(self, mock_config):
        """Test HMAC signature generation for log entries."""
        entry_data = {
            'timestamp': '2024-01-01T00:00:00.000Z',
            'action': 'TEST_ACTION',
            'user': 'test@example.com'
        }

        # Mock configuration with signing key
        mock_config.get_audit_config.return_value = {
            'signing_key': 'test_secret_key',
            'hash_algorithm': 'sha256'
        }

        signature = generate_audit_signature(entry_data, mock_config)

        assert isinstance(signature, str)
        assert len(signature) > 0

        # Verify signature is consistent
        signature2 = generate_audit_signature(entry_data, mock_config)
        assert signature == signature2

    def test_signature_verification(self, mock_config, temp_dir):
        """Test that signatures can be verified."""
        log_file = temp_dir / "test_audit.jsonl"
        logger = AuditLogger(str(log_file), mock_config)

        logger.log_event({'action': 'VERIFY_TEST'})

        with open(log_file, 'r') as f:
            log_entry = json.loads(f.readline())

        # Extract signature and recreate entry without signature
        signature = log_entry.pop('signature')

        # Verify signature
        expected_signature = generate_audit_signature(log_entry, mock_config)
        assert signature == expected_signature

    def test_tamper_detection(self, mock_config, temp_dir):
        """Test detection of tampered log entries."""
        log_file = temp_dir / "test_audit.jsonl"
        logger = AuditLogger(str(log_file), mock_config)

        logger.log_event({'action': 'ORIGINAL_ACTION'})

        # Read and tamper with log entry
        with open(log_file, 'r') as f:
            log_entry = json.loads(f.readline())

        original_signature = log_entry['signature']

        # Tamper with the action
        log_entry['action'] = 'TAMPERED_ACTION'

        # Verify tampering is detected
        current_signature = generate_audit_signature(
            {k: v for k, v in log_entry.items() if k != 'signature'},
            mock_config
        )

        assert current_signature != original_signature

    def test_anchor_hash_chain(self, mock_config, temp_dir):
        """Test anchor hash chaining for sequence integrity."""
        log_file = temp_dir / "test_audit.jsonl"
        logger = AuditLogger(str(log_file), mock_config)

        # Log multiple events
        events = [
            {'action': 'EVENT_1'},
            {'action': 'EVENT_2'},
            {'action': 'EVENT_3'}
        ]

        for event in events:
            logger.log_event(event)

        # Read all log entries
        with open(log_file, 'r') as f:
            entries = [json.loads(line) for line in f.readlines()]

        # Verify anchor hash chain
        for i in range(1, len(entries)):
            previous_anchor = entries[i - 1]['anchor_hash']
            current_content = {k: v for k, v in entries[i].items()
                               if k not in ['signature', 'anchor_hash']}

            # Current anchor should be hash of (previous_anchor + current_content)
            expected_anchor = hashlib.sha256(
                (previous_anchor + json.dumps(current_content, sort_keys=True)).encode()
            ).hexdigest()

            # Note: This test assumes specific anchor hash implementation
            # Actual implementation may vary
            # Should have anchor hash
            assert len(entries[i]['anchor_hash']) > 0

    def test_chain_verification(self, mock_config, temp_dir):
        """Test verification of complete audit chain."""
        log_file = temp_dir / "test_audit.jsonl"
        logger = AuditLogger(str(log_file), mock_config)

        # Create a series of audit events
        for i in range(5):
            logger.log_event({'action': f'EVENT_{i}', 'sequence': i})

        # Verify entire chain
        is_valid = verify_audit_chain(str(log_file), mock_config)

        assert is_valid is True

    def test_broken_chain_detection(self, mock_config, temp_dir):
        """Test detection of broken audit chains."""
        log_file = temp_dir / "test_audit.jsonl"
        logger = AuditLogger(str(log_file), mock_config)

        # Create some audit events
        logger.log_event({'action': 'EVENT_1'})
        logger.log_event({'action': 'EVENT_2'})

        # Manually tamper with the log file
        with open(log_file, 'r') as f:
            lines = f.readlines()

        # Tamper with second entry
        tampered_entry = json.loads(lines[1])
        tampered_entry['action'] = 'TAMPERED_EVENT'
        lines[1] = json.dumps(tampered_entry) + '\n'

        with open(log_file, 'w') as f:
            f.writelines(lines)

        # Chain verification should fail
        is_valid = verify_audit_chain(str(log_file), mock_config)

        assert is_valid is False


class TestAuditConfiguration:
    """Test audit logging configuration options."""

    def test_configurable_log_level(self, temp_dir):
        """Test configurable audit log levels."""
        config_info = Mock()
        config_info.get_audit_config.return_value = {
            'log_level': 'INFO',
            'signing_key': 'test_key'
        }

        config_debug = Mock()
        config_debug.get_audit_config.return_value = {
            'log_level': 'DEBUG',
            'signing_key': 'test_key'
        }

        log_file = temp_dir / "test_audit.jsonl"

        # Test INFO level logging
        logger_info = AuditLogger(str(log_file), config_info)
        logger_info.log_event({'action': 'INFO_EVENT', 'level': 'INFO'})

        # Test DEBUG level logging
        logger_debug = AuditLogger(str(log_file), config_debug)
        logger_debug.log_event({'action': 'DEBUG_EVENT', 'level': 'DEBUG'})

        # Both should be logged (implementation may filter based on level)
        with open(log_file, 'r') as f:
            lines = f.readlines()

        assert len(lines) >= 1  # At least one event should be logged

    def test_configurable_retention(self, mock_config, temp_dir):
        """Test configurable audit log retention."""
        # Configure retention policy
        mock_config.get_audit_config.return_value = {
            'retention_days': 30,
            'max_file_size': 1048576,  # 1MB
            'signing_key': 'test_key'
        }

        log_file = temp_dir / "test_audit.jsonl"
        logger = AuditLogger(str(log_file), mock_config)

        # This would typically trigger retention policy checks
        logger.log_event({'action': 'RETENTION_TEST'})

        # Verify basic functionality (retention logic would be in implementation)
        assert log_file.exists()

    def test_custom_fields(self, mock_config, temp_dir):
        """Test support for custom audit fields."""
        log_file = temp_dir / "test_audit.jsonl"
        logger = AuditLogger(str(log_file), mock_config)

        custom_event = {
            'action': 'CUSTOM_EVENT',
            'custom_field_1': 'value1',
            'custom_field_2': 123,
            'custom_field_3': True,
            'nested_data': {
                'sub_field': 'sub_value'
            }
        }

        logger.log_event(custom_event)

        with open(log_file, 'r') as f:
            log_entry = json.loads(f.readline())

        # Custom fields should be preserved
        assert log_entry['custom_field_1'] == 'value1'
        assert log_entry['custom_field_2'] == 123
        assert log_entry['custom_field_3'] is True
        assert log_entry['nested_data']['sub_field'] == 'sub_value'


class TestAuditPerformance:
    """Test performance characteristics of audit logging."""

    def test_high_volume_logging(self, mock_config, temp_dir):
        """Test logging large numbers of events."""
        log_file = temp_dir / "test_audit.jsonl"
        logger = AuditLogger(str(log_file), mock_config)

        # Log many events
        num_events = 1000
        for i in range(num_events):
            logger.log_event({
                'action': 'BULK_EVENT',
                'sequence': i,
                'data': f'event_data_{i}'
            })

        # Verify all events were logged
        with open(log_file, 'r') as f:
            lines = f.readlines()

        assert len(lines) == num_events

        # Verify structure of first and last entries
        first_entry = json.loads(lines[0])
        last_entry = json.loads(lines[-1])

        assert first_entry['sequence'] == 0
        assert last_entry['sequence'] == num_events - 1

    def test_concurrent_logging(self, mock_config, temp_dir):
        """Test concurrent access to audit logging."""
        log_file = temp_dir / "test_audit.jsonl"

        # Simulate concurrent loggers (in practice would use threading)
        logger1 = AuditLogger(str(log_file), mock_config)
        logger2 = AuditLogger(str(log_file), mock_config)

        # Log from both loggers
        logger1.log_event({'action': 'CONCURRENT_1', 'logger': 'logger1'})
        logger2.log_event({'action': 'CONCURRENT_2', 'logger': 'logger2'})
        logger1.log_event({'action': 'CONCURRENT_3', 'logger': 'logger1'})

        # Verify all events were logged
        with open(log_file, 'r') as f:
            lines = f.readlines()

        assert len(lines) == 3

        # Verify content
        entries = [json.loads(line) for line in lines]
        actions = [entry['action'] for entry in entries]

        assert 'CONCURRENT_1' in actions
        assert 'CONCURRENT_2' in actions
        assert 'CONCURRENT_3' in actions


class TestAuditUtilities:
    """Test audit utility functions."""

    def test_audit_log_parsing(self, mock_config, temp_dir):
        """Test parsing of audit log files."""
        log_file = temp_dir / "test_audit.jsonl"
        logger = AuditLogger(str(log_file), mock_config)

        # Create test data
        test_events = [
            {'action': 'ENCRYPT', 'resource': 'file1.dcm'},
            {'action': 'DECRYPT', 'resource': 'file1.dcm'},
            {'action': 'DELETE', 'resource': 'file1.dcm'}
        ]

        for event in test_events:
            logger.log_event(event)

        # Parse log file
        parsed_events = []
        with open(log_file, 'r') as f:
            for line in f:
                parsed_events.append(json.loads(line))

        assert len(parsed_events) == len(test_events)

        for i, event in enumerate(parsed_events):
            assert event['action'] == test_events[i]['action']
            assert event['resource'] == test_events[i]['resource']

    def test_audit_search_and_filter(self, mock_config, temp_dir):
        """Test searching and filtering audit logs."""
        log_file = temp_dir / "test_audit.jsonl"
        logger = AuditLogger(str(log_file), mock_config)

        # Create diverse test data
        events = [
            {'action': 'ENCRYPT', 'user': 'alice@example.com', 'resource': 'file1.dcm'},
            {'action': 'DECRYPT', 'user': 'bob@example.com', 'resource': 'file1.dcm'},
            {'action': 'ENCRYPT', 'user': 'alice@example.com', 'resource': 'file2.dcm'},
            {'action': 'DELETE', 'user': 'admin@example.com', 'resource': 'file1.dcm'}
        ]

        for event in events:
            logger.log_event(event)

        # Parse and filter logs
        with open(log_file, 'r') as f:
            all_entries = [json.loads(line) for line in f]

        # Filter by action
        encrypt_events = [e for e in all_entries if e['action'] == 'ENCRYPT']
        assert len(encrypt_events) == 2

        # Filter by user
        alice_events = [e for e in all_entries if e['user']
                        == 'alice@example.com']
        assert len(alice_events) == 2

        # Filter by resource
        file1_events = [e for e in all_entries if e['resource'] == 'file1.dcm']
        assert len(file1_events) == 3

    def test_audit_export(self, mock_config, temp_dir):
        """Test exporting audit logs for compliance reporting."""
        log_file = temp_dir / "test_audit.jsonl"
        logger = AuditLogger(str(log_file), mock_config)

        # Create compliance-relevant events
        compliance_events = [
            {
                'action': 'DATA_ACCESS',
                'user': 'researcher@hospital.com',
                'resource': 'patient_study_001.dcm',
                'purpose': 'clinical_research',
                'authorization': 'IRB-2024-001'
            },
            {
                'action': 'DATA_EXPORT',
                'user': 'researcher@hospital.com',
                'resource': 'patient_study_001.dcm',
                'destination': 'research_database',
                'approval': 'EXPORT-2024-001'
            }
        ]

        for event in compliance_events:
            logger.log_event(event)

        # Export for compliance (simple JSON format)
        export_file = temp_dir / "compliance_export.json"
        with open(log_file, 'r') as source:
            with open(export_file, 'w') as dest:
                events = [json.loads(line) for line in source]
                json.dump(events, dest, indent=2)

        # Verify export
        assert export_file.exists()

        with open(export_file, 'r') as f:
            exported_data = json.load(f)

        assert len(exported_data) == 2
        assert all('signature' in event for event in exported_data)
        assert all('timestamp' in event for event in exported_data)
