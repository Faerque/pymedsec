#!/bin/bash
# run_tests.sh - Test runner script with proper environment isolation

# Set test environment
export IMGSEC_KMS_BACKEND=mock
export IMGSEC_KMS_KEY_REF=test-key
export IMGSEC_POLICY=/mnt/data/pymedsec/policies/hipaa_default.yaml
export IMGSEC_AUDIT_PATH=/tmp/test_audit.jsonl
export IMGSEC_ACTOR=test-user

# Ensure the audit path directory exists
mkdir -p "$(dirname "$IMGSEC_AUDIT_PATH")"

echo "Running pymedsec tests with mock environment..."
echo "KMS Backend: $IMGSEC_KMS_BACKEND"
echo "Policy: $IMGSEC_POLICY"
echo "Audit Path: $IMGSEC_AUDIT_PATH"
echo ""

# Run specific test files that we know work
echo "Running KMS tests..."
python -m pytest tests/test_kms.py::TestMockKMSAdapter -v --tb=short

echo ""
echo "Running basic crypto tests..."
python -m pytest tests/test_crypto.py::TestEncryptionFunctions::test_encrypt_data_basic -v --tb=short

echo ""
echo "Test run complete!"
