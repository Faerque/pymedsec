# SPDX-License-Identifier: Apache-2.0

"""
Clean KMS tests for pymedsec package.

This file contains only the essential tests for the KMS adapters,
focusing on the MockKMSAdapter which is the primary adapter used.
"""

import os
import pytest

from pymedsec.kms.base import KMSAdapter
from pymedsec.kms.mock import MockKMSAdapter


class TestKMSAdapterBase:
    """Test cases for base KMS adapter interface."""

    def test_abstract_interface(self):
        """Test that KMSAdapter is properly abstract."""
        # Check that the class has abstract methods without instantiating
        assert KMSAdapter.__abstractmethods__
        assert "generate_data_key" in KMSAdapter.__abstractmethods__
        assert "wrap_data_key" in KMSAdapter.__abstractmethods__
        assert "unwrap_data_key" in KMSAdapter.__abstractmethods__

    def test_required_methods(self):
        """Test that required methods are defined in interface."""
        # Check that abstract methods exist
        required_methods = ["generate_data_key", "wrap_data_key", "unwrap_data_key"]

        for method in required_methods:
            assert hasattr(KMSAdapter, method)


class TestMockKMSAdapter:
    """Test cases for MockKMSAdapter with correct interface."""

    def test_initialization(self):
        """Test MockKMSAdapter initialization."""
        adapter = MockKMSAdapter()
        assert adapter is not None
        assert adapter.master_key is not None

    def test_generate_data_key_256(self):
        """Test 256-bit data key generation."""
        adapter = MockKMSAdapter()

        # generate_data_key should return bytes directly
        result = adapter.generate_data_key(key_ref="test-key", key_spec="256")

        assert isinstance(result, bytes)
        assert len(result) == 32  # 256 bits = 32 bytes

    def test_generate_data_key_128(self):
        """Test 128-bit data key generation."""
        adapter = MockKMSAdapter()

        result = adapter.generate_data_key(key_ref="test-key", key_spec="128")

        assert isinstance(result, bytes)
        assert len(result) == 16  # 128 bits = 16 bytes

    def test_generate_data_key_aes_specs(self):
        """Test data key generation with AES specifications."""
        adapter = MockKMSAdapter()

        result_256 = adapter.generate_data_key(key_ref="test-key", key_spec="AES_256")
        assert isinstance(result_256, bytes)
        assert len(result_256) == 32

        result_128 = adapter.generate_data_key(key_ref="test-key", key_spec="AES_128")
        assert isinstance(result_128, bytes)
        assert len(result_128) == 16

    def test_generate_data_key_legacy_param(self):
        """Test data key generation with legacy key_id parameter."""
        adapter = MockKMSAdapter()

        result = adapter.generate_data_key(key_id="test-key", key_spec="AES_256")

        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_wrap_unwrap_roundtrip(self):
        """Test key wrapping and unwrapping roundtrip."""
        adapter = MockKMSAdapter()

        # Generate a test key
        test_key = os.urandom(32)

        # Wrap the key
        wrapped = adapter.wrap_data_key(test_key, "test-key-ref")
        assert isinstance(wrapped, bytes)
        assert len(wrapped) > 32  # Should be larger due to nonce + tag

        # Unwrap the key
        unwrapped = adapter.unwrap_data_key(wrapped, "test-key-ref")
        assert unwrapped == test_key

    def test_wrap_different_keys(self):
        """Test wrapping different keys produces different results."""
        adapter = MockKMSAdapter()

        key1 = os.urandom(32)
        key2 = os.urandom(32)

        wrapped1 = adapter.wrap_data_key(key1, "key-ref-1")
        wrapped2 = adapter.wrap_data_key(key2, "key-ref-2")

        # Different keys should produce different wrapped results
        assert wrapped1 != wrapped2

    def test_wrap_same_key_different_refs(self):
        """Test wrapping same key with different refs produces different results."""
        adapter = MockKMSAdapter()

        test_key = os.urandom(32)

        wrapped1 = adapter.wrap_data_key(test_key, "ref-1")
        wrapped2 = adapter.wrap_data_key(test_key, "ref-2")

        # Same key with different refs should produce different wrapped results
        # due to AAD (additional authenticated data) being different
        assert wrapped1 != wrapped2

    def test_invalid_key_spec(self):
        """Test handling of invalid key specifications."""
        adapter = MockKMSAdapter()

        with pytest.raises(RuntimeError) as exc_info:
            adapter.generate_data_key(key_ref="test-key", key_spec="INVALID_SPEC")
        assert "Unsupported key spec: INVALID_SPEC" in str(exc_info.value)

    def test_verify_key_access(self):
        """Test key access verification."""
        adapter = MockKMSAdapter()

        # Mock adapter should always return True
        assert adapter.verify_key_access("any-key") is True

    def test_get_key_metadata(self):
        """Test key metadata retrieval."""
        adapter = MockKMSAdapter()

        metadata = adapter.get_key_metadata("test-key")

        assert isinstance(metadata, dict)
        assert metadata["key_ref"] == "test-key"
        assert metadata["backend"] == "Mock KMS (Development Only)"
        assert "NOT FOR PRODUCTION USE" in metadata["warning"]

    def test_create_key(self):
        """Test key creation."""
        adapter = MockKMSAdapter()

        result = adapter.create_key("new-test-key", "Test key description")

        assert isinstance(result, dict)
        assert result["key_name"] == "new-test-key"
        assert result["description"] == "Test key description"
        assert result["created"] is True

    def test_list_keys(self):
        """Test key listing."""
        adapter = MockKMSAdapter()

        keys = adapter.list_keys()

        assert isinstance(keys, list)
        assert len(keys) > 0
        # Should contain some default mock keys
        key_ids = [key["KeyId"] for key in keys]
        assert "test-key" in key_ids

    def test_unwrap_invalid_data(self):
        """Test unwrapping invalid wrapped data."""
        adapter = MockKMSAdapter()

        with pytest.raises(RuntimeError):
            adapter.unwrap_data_key(b"invalid_wrapped_data", "test-key")

    def test_unwrap_wrong_key_ref(self):
        """Test unwrapping with wrong key reference."""
        adapter = MockKMSAdapter()

        test_key = os.urandom(32)
        wrapped = adapter.wrap_data_key(test_key, "correct-ref")

        # Trying to unwrap with wrong ref should fail
        with pytest.raises(RuntimeError):
            adapter.unwrap_data_key(wrapped, "wrong-ref")

    def test_different_key_generation(self):
        """Test that key generation is properly random."""
        adapter = MockKMSAdapter()

        key1 = adapter.generate_data_key(key_ref="test-key-1")
        key2 = adapter.generate_data_key(key_ref="test-key-2")

        # Different calls should produce different keys
        assert key1 != key2

    def test_encryption_context_handling(self):
        """Test that encryption context is properly handled."""
        adapter = MockKMSAdapter()

        # Should not raise an error even with encryption context
        result = adapter.generate_data_key(
            key_ref="test-key",
            key_spec="256",
            encryption_context={"purpose": "test"}
        )

        assert isinstance(result, bytes)
        assert len(result) == 32


if __name__ == "__main__":
    # Run this test file directly
    pytest.main([__file__, "-v"])
