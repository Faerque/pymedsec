#!/usr/bin/env python3
"""Quick test to verify all imports work correctly with renamed package."""

print("Testing pymedsec imports...")

try:
    # Test main package import
    import pymedsec
    print("✓ pymedsec package imported successfully")

    # Test core modules
    from pymedsec import audit, config, crypto, sanitize, validate
    print("✓ Core modules imported successfully")

    # Test CLI module
    from pymedsec import cli
    print("✓ CLI module imported successfully")

    # Test blockchain adapters
    from pymedsec.blockchain import base, ethereum, mock, hyperledger
    print("✓ Blockchain adapters imported successfully")

    # Test KMS adapters
    from pymedsec.kms import base as kms_base, aws_kms, mock as kms_mock, vault
    print("✓ KMS adapters imported successfully")

    # Test instantiation of key classes
    from pymedsec.audit import AuditLogger
    from pymedsec.config import SecurityConfig
    from pymedsec.kms.mock import MockKMSAdapter
    
    # Test creating instances
    config_instance = SecurityConfig()
    print("✓ SecurityConfig instantiated successfully")
    
    kms_instance = MockKMSAdapter()
    print("✓ MockKMSAdapter instantiated successfully")

    print("\n🎉 All imports successful! Package rename completed successfully.")

except ImportError as e:
    print(f"❌ Import error: {e}")
except Exception as e:
    print(f"❌ Other error: {e}")
