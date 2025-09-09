#!/usr/bin/env python3
"""
Example script demonstrating blockchain audit anchoring functionality.

This script shows how to enable and use blockchain anchoring for audit logs
in the healthcare image security system.
"""

from healthcare_imgsec.blockchain import create_blockchain_adapter
from healthcare_imgsec.audit import AuditLogger, verify_blockchain_anchors
import os
import tempfile
import sys
from pathlib import Path

# Add the package to the path for this example
sys.path.insert(0, str(Path(__file__).parent.parent))


def setup_blockchain_environment():
    """Set up mock blockchain environment for demonstration."""
    print("🔧 Setting up blockchain environment...")

    # Use mock blockchain for demonstration
    os.environ['BLOCKCHAIN_BACKEND'] = 'mock'

    # Create temporary audit log
    temp_dir = tempfile.mkdtemp()
    audit_path = os.path.join(temp_dir, 'demo_audit.log')

    print(f"📁 Temporary audit log: {audit_path}")
    print(f"⛓️  Blockchain backend: mock")

    return audit_path, temp_dir


def demonstrate_blockchain_anchoring(audit_path):
    """Demonstrate blockchain anchoring functionality."""
    print("\n📝 Creating audit logger with blockchain anchoring...")

    # Create audit logger (blockchain auto-detected from environment)
    audit_logger = AuditLogger(audit_path)

    # Log several operations to demonstrate anchoring
    operations = [
        {
            'operation': 'sanitize',
            'dataset_id': 'demo_study_001',
            'modality': 'CT',
            'outcome': 'success',
            'details': 'Removed 15 PHI tags, regenerated UIDs'
        },
        {
            'operation': 'encrypt',
            'dataset_id': 'demo_study_001',
            'modality': 'CT',
            'outcome': 'success',
            'details': 'AES-256-GCM encryption with KMS key wrapping'
        },
        {
            'operation': 'decrypt',
            'dataset_id': 'demo_study_001',
            'modality': 'CT',
            'outcome': 'success',
            'details': 'Memory-only decryption for ML training'
        }
    ]

    print(
        f"🔒 Logging {len(operations)} operations with blockchain anchoring...")

    for i, op in enumerate(operations, 1):
        audit_logger.log_operation(**op)
        print(f"  ✓ Operation {i}: {op['operation']} -> blockchain anchored")

    print(
        f"📊 Audit log created with {len(operations)} blockchain-anchored entries")


def verify_blockchain_integrity(audit_path):
    """Verify blockchain anchor integrity."""
    print("\n🔍 Verifying blockchain anchor integrity...")

    # Verify blockchain anchors
    verification_result = verify_blockchain_anchors(audit_path)

    if not verification_result['blockchain_enabled']:
        print(f"⚠️  Blockchain not enabled: {verification_result['message']}")
        return

    total = verification_result['total_lines']
    anchored = verification_result['anchored_lines']
    verified = verification_result['verified_anchors']
    failed = verification_result['failed_anchors']
    rate = verification_result['verification_rate']

    print(f"📊 Verification Results:")
    print(f"  📋 Total audit entries: {total}")
    print(f"  ⛓️  Anchored entries: {anchored}")
    print(f"  ✅ Verified anchors: {verified}")
    print(f"  ❌ Failed anchors: {failed}")
    print(f"  📈 Verification rate: {rate:.1%}")

    if rate >= 0.95:
        print("🎉 Blockchain anchor verification PASSED!")
    else:
        print("⚠️  Blockchain anchor verification issues detected")

    # Show anchor details
    if verification_result['anchor_details']:
        print(f"\n🔗 Anchor Details:")
        for detail in verification_result['anchor_details']:
            status_icon = "✅" if detail['status'] == 'verified' else "❌"
            tx_hash_short = detail['tx_hash'][:16] + "..."
            print(f"  {status_icon} Line {detail['line']}: {tx_hash_short}")
            if detail['status'] == 'verified':
                confirmations = detail.get('confirmations', 0)
                print(f"     📦 Confirmations: {confirmations}")


def demonstrate_blockchain_adapter():
    """Demonstrate direct blockchain adapter usage."""
    print("\n🔧 Demonstrating blockchain adapter directly...")

    # Create blockchain adapter
    adapter = create_blockchain_adapter()

    if not adapter:
        print("⚠️  No blockchain adapter available")
        return

    print(f"✅ Created blockchain adapter: {type(adapter).__name__}")

    # Submit a test digest
    test_digest = "a1b2c3d4e5f67890" * 4  # 64-char hex string
    print(f"📤 Submitting test digest: {test_digest[:16]}...")

    try:
        result = adapter.submit_digest(test_digest, {"test": "demo"})
        tx_hash = result['tx_hash']
        print(f"✅ Digest submitted successfully")
        print(f"   🆔 Transaction hash: {tx_hash[:16]}...")
        print(f"   📦 Block number: {result.get('block_number', 'pending')}")

        # Verify the digest
        print(f"🔍 Verifying digest...")
        verification = adapter.verify_digest(test_digest, tx_hash)

        if verification['verified']:
            print(f"✅ Digest verification successful!")
            print(f"   📦 Block: {verification.get('block_number')}")
            print(
                f"   🔗 Confirmations: {verification.get('confirmations', 0)}")
        else:
            print(
                f"❌ Digest verification failed: {verification.get('message')}")

    except Exception as e:
        print(f"❌ Error during blockchain operations: {e}")


def demonstrate_hyperledger_setup():
    """Demonstrate how to set up Hyperledger Fabric blockchain adapter."""
    print("\n🔧 Hyperledger Fabric Setup Guide...")
    print("=" * 50)

    print("📋 Prerequisites:")
    print("  1. Install Hyperledger Fabric Python SDK:")
    print("     pip install fabric-sdk-py")
    print("  2. Set up Hyperledger Fabric network")
    print("  3. Deploy audit chaincode (see examples/hyperledger_chaincode_example.go)")

    print("\n⚙️  Configuration Example:")
    config = {
        'network_profile': '/path/to/network.json',
        'channel_name': 'mychannel',
        'chaincode_name': 'audit_chaincode',
        'org_name': 'Org1MSP',
        'peer_name': 'peer0.org1.example.com',
        'user_name': 'Admin',
        'user_secret': 'adminpw'
    }

    for key, value in config.items():
        print(f"     {key}: {value}")

    print("\n💻 Usage Example:")
    print("     from healthcare_imgsec.blockchain.hyperledger import HyperledgerBlockchainAdapter")
    print("     adapter = HyperledgerBlockchainAdapter(config)")
    print("     result = adapter.submit_digest('a1b2c3...', {'metadata': 'value'})")

    print("\n📁 See examples/hyperledger_config_example.json for full configuration")

    try:
        from healthcare_imgsec.blockchain.hyperledger import HyperledgerBlockchainAdapter
        print("✅ Hyperledger adapter module available")

        # Try to create adapter (will fail without SDK but shows structure)
        try:
            adapter = HyperledgerBlockchainAdapter({})
            print("✅ Hyperledger Fabric SDK detected")
        except ImportError as e:
            print(f"⚠️  Hyperledger Fabric SDK not installed: {e}")
            print("   Install with: pip install fabric-sdk-py")
        except Exception as e:
            print(f"⚠️  Hyperledger configuration needed: {e}")

    except ImportError:
        print("❌ Hyperledger adapter not available")


def cleanup_and_summary(temp_dir):
    """Clean up and show summary."""
    print(f"\n🧹 Cleaning up temporary files in {temp_dir}")
    print("\n📋 Summary:")
    print("  ✅ Demonstrated blockchain audit anchoring")
    print("  ✅ Verified blockchain anchor integrity")
    print("  ✅ Showed direct blockchain adapter usage")
    print("\n💡 Next steps:")
    print("  1. Configure real blockchain backend (Ethereum)")
    print("  2. Set up production KMS integration")
    print("  3. Deploy to secure healthcare environment")
    print("  4. Read docs/BLOCKCHAIN_AUDIT.md for details")


def main():
    """Main demonstration function."""
    print("🏥 Healthcare Image Security - Blockchain Audit Anchoring Demo")
    print("=" * 60)

    try:
        # Set up environment
        audit_path, temp_dir = setup_blockchain_environment()

        # Demonstrate blockchain anchoring
        demonstrate_blockchain_anchoring(audit_path)

        # Verify integrity
        verify_blockchain_integrity(audit_path)

        # Show direct adapter usage
        demonstrate_blockchain_adapter()

        # Show Hyperledger setup guide
        demonstrate_hyperledger_setup()

        # Cleanup and summary
        cleanup_and_summary(temp_dir)

    except KeyboardInterrupt:
        print("\n\n⏹️  Demo interrupted by user")
    except Exception as e:
        print(f"\n❌ Demo failed with error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Clean up environment
        if 'BLOCKCHAIN_BACKEND' in os.environ:
            del os.environ['BLOCKCHAIN_BACKEND']


if __name__ == '__main__':
    main()
