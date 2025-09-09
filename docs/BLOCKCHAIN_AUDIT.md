# Blockchain Audit Anchoring

The healthcare image security system supports optional blockchain audit anchoring to provide tamper-evident audit logs. This feature anchors SHA-256 digests of audit log entries to blockchain networks without exposing PHI.

## Overview

Blockchain audit anchoring provides:

- **Tamper Evidence**: Audit log entries are cryptographically anchored to immutable blockchain networks
- **PHI Protection**: Only SHA-256 digests are submitted to blockchain, never PHI
- **Pluggable Backends**: Support for Ethereum, Hyperledger Fabric, and mock testing
- **Optional Feature**: Can be enabled/disabled without affecting core functionality
- **Verification**: Built-in tools to verify blockchain anchors

## Configuration

### Environment Variables

Configure blockchain anchoring using environment variables:

```bash
# Enable blockchain anchoring
export BLOCKCHAIN_BACKEND=ethereum  # or 'hyperledger', 'mock', 'disabled'

# Ethereum configuration
export ETHEREUM_RPC_URL=https://mainnet.infura.io/v3/YOUR_PROJECT_ID
export ETHEREUM_PRIVATE_KEY=0x1234567890abcdef...
export ETHEREUM_CONTRACT_ADDRESS=0x1234567890abcdef...  # Optional

# Mock configuration (for testing)
export BLOCKCHAIN_BACKEND=mock
```

### Supported Backends

#### Ethereum

- **Public Networks**: Mainnet, Sepolia, Goerli
- **Private Networks**: Any Ethereum-compatible network
- **Requirements**: `web3.py` library
- **Transaction Cost**: Minimal (only data transaction)

```bash
# Install Ethereum dependencies
pip install web3
```

#### Hyperledger Fabric

- **Status**: Placeholder implementation
- **Future Support**: Enterprise blockchain networks
- **Requirements**: `fabric-sdk-py` (when implemented)

#### Mock Blockchain

- **Purpose**: Testing and development
- **Storage**: Local JSON file simulation
- **No External Dependencies**: Built-in implementation

## Implementation Details

### Digest Generation

For each audit log entry, the system:

1. Removes PHI fields from the audit entry
2. Computes SHA-256 digest of sanitized JSON
3. Submits digest to configured blockchain network
4. Stores transaction hash in audit log

### Sanitized Fields

The following fields are removed before digest computation:

- `patient_id` (if present)
- `pseudo_patient_id` (if present)
- `file_path` (contains potential PHI)
- `operator` (if present)
- `timestamp` (to prevent correlation attacks)

### Audit Log Format

Blockchain-anchored entries include a `blockchain_anchor` field:

```json
{
  "timestamp": "2024-01-15T10:30:45.123456Z",
  "operation": "encrypt",
  "dataset_id": "research_study_001",
  "modality": "CT",
  "outcome": "success",
  "blockchain_anchor": {
    "digest": "sha256:a1b2c3d4e5f6...",
    "tx_hash": "0x1234567890abcdef...",
    "backend": "ethereum",
    "timestamp": "2024-01-15T10:30:47.789012Z"
  }
}
```

## CLI Commands

### Verify Blockchain Anchors

```bash
# Verify all blockchain anchors in audit log
pymedsec verify-blockchain

# Verify specific audit file with details
pymedsec verify-blockchain --audit-file /path/to/audit.log --details

# Check audit status including blockchain anchors
pymedsec audit-status --blockchain
```

### Example Output

```
📊 Blockchain Anchor Verification Results:
  Total audit entries: 1,543
  Anchored entries: 1,543
  Verified anchors: 1,541
  Failed anchors: 2
  Verification rate: 99.9%
✓ Blockchain anchor verification PASSED

🔗 Anchor Details:
  ✓ Line 1: 0x1234567890abcdef...
    Confirmations: 245
  ✓ Line 2: 0x2345678901bcdef0...
    Confirmations: 244
```

## Security Considerations

### Privacy Protection

- **No PHI on Blockchain**: Only SHA-256 digests are submitted
- **Sanitized Metadata**: Patient identifiers removed before hashing
- **Correlation Resistance**: Timestamps and file paths excluded

### Integrity Guarantees

- **Immutable Anchors**: Blockchain provides tamper-evident storage
- **Cryptographic Verification**: SHA-256 ensures data integrity
- **Network Consensus**: Blockchain consensus prevents manipulation

### Threat Model

Blockchain anchoring protects against:

- **Audit Log Tampering**: Modified entries will have different digests
- **Log Deletion**: Missing entries break the blockchain anchor chain
- **Backdating**: Blockchain timestamps provide temporal proof
- **Repudiation**: Cryptographic proof of audit log state

## Performance Considerations

### Transaction Costs

- **Ethereum Mainnet**: ~$0.50-5.00 per anchor (variable gas costs)
- **Private Networks**: Minimal cost
- **Mock Backend**: No cost (local simulation)

### Throughput

- **Ethereum**: ~15 transactions per second
- **Private Networks**: Higher throughput possible
- **Batching**: Future enhancement to batch multiple digests

### Latency

- **Confirmation Time**: 15 seconds to 10+ minutes depending on network
- **Async Processing**: Anchoring happens asynchronously
- **Graceful Degradation**: System continues if blockchain unavailable

## Deployment Scenarios

### Research Environment

```bash
# Use mock blockchain for development
export BLOCKCHAIN_BACKEND=mock
```

### Hospital Environment

```bash
# Use private Ethereum network
export BLOCKCHAIN_BACKEND=ethereum
export ETHEREUM_RPC_URL=http://private-ethereum-node:8545
export ETHEREUM_PRIVATE_KEY=0x...
```

### Compliance Audit

```bash
# Use public Ethereum for maximum transparency
export BLOCKCHAIN_BACKEND=ethereum
export ETHEREUM_RPC_URL=https://mainnet.infura.io/v3/PROJECT_ID
export ETHEREUM_PRIVATE_KEY=0x...
```

## Troubleshooting

### Common Issues

#### Blockchain Not Available

```
⚠ Blockchain anchoring: Blockchain module not available
```

- Install required dependencies (`pip install web3`)
- Check network connectivity
- Verify configuration

#### Transaction Failures

```
✗ Blockchain anchor verification FAILED
```

- Check private key and account balance
- Verify network connectivity
- Review gas settings

#### Verification Errors

```
Error: Transaction not found
```

- Network reorganization (temporary)
- Incorrect transaction hash
- Network connectivity issues

### Monitoring

Monitor blockchain anchoring health:

```bash
# Check recent audit status
pymedsec audit-status --blockchain

# Verify specific time period
pymedsec verify-blockchain --details
```

## Future Enhancements

### Planned Features

- **Batch Anchoring**: Multiple digests per transaction
- **Multi-Blockchain**: Anchor to multiple networks simultaneously
- **Smart Contracts**: Custom contracts for audit metadata
- **IPFS Integration**: Content-addressed storage for large audit data

### Hyperledger Fabric Support

Full Hyperledger Fabric integration will include:

- **Channels**: Separate audit channels per organization
- **Chaincode**: Custom smart contracts for audit operations
- **Identity Management**: Integration with Fabric CA
- **Private Data**: Confidential audit metadata

## Compliance Considerations

### HIPAA Compliance

- **PHI Protection**: No PHI transmitted to blockchain
- **Audit Requirements**: Enhanced audit trail capabilities
- **Access Controls**: Blockchain verification requires no special access

### Regulatory Validation

- **FDA 21 CFR Part 11**: Electronic records and signatures
- **ISO 27799**: Health informatics security management
- **GDPR Article 32**: Security of processing

### Documentation Requirements

- **Audit Trail**: Complete blockchain verification logs
- **Technical Documentation**: This specification
- **Validation Testing**: Comprehensive test results

## References

- [Ethereum Documentation](https://ethereum.org/en/developers/docs/)
- [Web3.py Documentation](https://web3py.readthedocs.io/)
- [HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/)
- [Healthcare Blockchain Standards](https://www.hl7.org/fhir/blockchain.html)
