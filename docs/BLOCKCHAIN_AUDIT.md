# Blockchain Audit Anchoring

PyMedSec supports optional blockchain anchoring for audit log entries. Anchoring stores only a SHA-256 digest of each signed audit line and never writes PHI to blockchain payloads.

## Overview

Blockchain anchoring provides:

- Tamper evidence for signed audit records
- Independent timestamped anchor proofs
- Pluggable backends: `mock`, `ethereum`, `hyperledger`
- Fail-open behavior: audit logging continues even if blockchain is unavailable

## Canonical Environment Variables

Use only `IMGSEC_*` names.

```bash
# Backend selection
export IMGSEC_BLOCKCHAIN_BACKEND=ethereum   # ethereum | hyperledger | mock | disabled
export IMGSEC_BLOCKCHAIN_FREQUENCY=every    # every | batch_hourly

# Ethereum backend
export IMGSEC_ETHEREUM_RPC_URL=https://mainnet.infura.io/v3/YOUR_PROJECT_ID
export IMGSEC_ETHEREUM_PRIVATE_KEY=0x...
export IMGSEC_ETHEREUM_CONTRACT_ADDRESS=0x...   # optional
export IMGSEC_ETHEREUM_CHAIN_ID=1               # optional
export IMGSEC_ETHEREUM_CONFIRMATIONS=1          # optional

# Hyperledger backend
export IMGSEC_HYPERLEDGER_NETWORK_PROFILE=/etc/pymedsec/fabric/network.json
export IMGSEC_HYPERLEDGER_CHANNEL=mychannel
export IMGSEC_HYPERLEDGER_CHAINCODE=audit_chaincode
export IMGSEC_HYPERLEDGER_ORG=Org1MSP
export IMGSEC_HYPERLEDGER_PEER=peer0.org1.example.com
export IMGSEC_HYPERLEDGER_USER=Admin
export IMGSEC_HYPERLEDGER_SECRET=...
```

Legacy names such as `BLOCKCHAIN_BACKEND` and `ETHEREUM_*` are no longer used.

## Dependency Extras

```bash
pip install pymedsec[ethereum]       # Ethereum backend only
pip install pymedsec[hyperledger]    # Hyperledger backend only
pip install pymedsec[blockchain-all] # both backends
```

## Backend Notes

### Mock

- Local JSON ledger for development/testing
- Uses file locking + atomic writes for concurrency safety

### Ethereum

- Uses `web3.py` and an HTTP RPC endpoint
- Includes retry/backoff and confirmation-aware verification
- Transaction payload is deterministic and digest-verifiable

### Hyperledger

- Uses Fabric SDK if installed
- Initialization fails clearly when required client pieces are missing
- Normalized status/verification contracts match other backends

## Audit Behavior and Fail-Open Mode

When anchoring succeeds, audit entries include:

- `blockchain_anchor.backend`
- `blockchain_anchor.tx_hash`
- `blockchain_anchor.digest`
- `blockchain_anchor.status`
- `blockchain_anchor.confirmations`

When anchoring fails, audit writes continue and include:

- `blockchain_anchor_error.backend`
- `blockchain_anchor_error.error_code`
- `blockchain_anchor_error.message`
- `blockchain_anchor_error.retryable`
- `blockchain_anchor_error.timestamp`

## CLI Verification

```bash
# Verify anchors for configured backend
pymedsec verify-blockchain

# Verify a specific audit file and show details
pymedsec verify-blockchain --audit-file /path/to/audit.log --details

# Combined local integrity + blockchain status
pymedsec audit-status --blockchain
```

`verify-blockchain` exit codes:

- `0`: all anchors verified (`status=passed`)
- `2`: partial or failed anchor verification (`status=partial|failed`)
- `1`: runtime/configuration error or blockchain disabled (`status=error|disabled`)

## Troubleshooting

### Blockchain Disabled

- Ensure `IMGSEC_BLOCKCHAIN_BACKEND` is set to `mock`, `ethereum`, or `hyperledger`
- Confirm old env names are not being used

### Ethereum Connectivity Errors

- Check `IMGSEC_ETHEREUM_RPC_URL`
- Verify account key and funds
- Confirm chain ID and confirmations policy

### Hyperledger Initialization Errors

- Validate Fabric network profile path
- Confirm channel/peer/org/user configuration
- Ensure SDK dependencies are available in the active environment
