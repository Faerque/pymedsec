# Architecture Documentation

This document provides a comprehensive overview of the pymedsec package architecture, design decisions, and implementation details.

## System Overview

The pymedsec package implements a secure, compliant pipeline for medical image processing with envelope encryption, sanitization, and audit logging capabilities.

### High-Level Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Image Input   │───▶│  Sanitization   │───▶│   Encryption    │
│   (DICOM/PNG/   │    │   (PHI Removal) │    │  (AES-256-GCM)  │
│    JPEG/TIFF)   │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                        │
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Audit Logging  │◀───│  Policy Engine  │◀───│   KMS Provider  │
│ (Tamper-Evident)│    │  (Validation)   │    │ (Key Management)│
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │
                        ┌─────────────────┐
                        │  Secure Storage │
                        │ (Encrypted Pkg) │
                        └─────────────────┘
```

## Core Components

### 1. Configuration Management (`config.py`)

**Purpose**: Centralized configuration management with policy-driven security controls.

**Key Classes**:

- `SecurityConfig`: Main configuration class with environment integration

**Design Patterns**:

- Singleton pattern for global configuration
- Factory pattern for policy loading
- Builder pattern for configuration assembly

```python
# Configuration flow
Environment Variables → YAML Policy → SecurityConfig Instance
```

**Security Features**:

- Policy integrity verification (SHA-256 hashing)
- Environment variable validation
- Secure defaults with explicit overrides

### 2. Image Intake System (`intake.py`)

**Purpose**: Secure ingestion and validation of medical images with metadata preservation.

**Architecture**:

```
Input Validation → Format Detection → Metadata Extraction → Security Checks
```

**Supported Formats**:

- DICOM: Full metadata extraction and validation
- PNG: EXIF and technical metadata
- JPEG: EXIF, IPTC, and XMP metadata
- TIFF: EXIF and technical metadata

**Security Controls**:

- File type validation
- Size limit enforcement
- Malware scanning hooks
- Content verification

### 3. Sanitization Engine (`sanitize.py`)

**Purpose**: PHI removal and metadata sanitization while preserving clinical utility.

**DICOM Sanitization**:

```python
# Three-tier sanitization approach
Basic Identifiers → Extended PHI → Technical Metadata Preservation
```

**Sanitization Levels**:

1. **Basic**: Remove obvious identifiers (names, IDs, dates)
2. **Standard**: Remove extended PHI per HIPAA guidelines
3. **Aggressive**: Remove all non-essential metadata

**Preservation Strategy**:

- Clinical data elements preserved
- Technical imaging parameters maintained
- Study relationships anonymized but preserved

### 4. Cryptographic System (`crypto.py`)

**Purpose**: Envelope encryption with AES-256-GCM and KMS integration.

**Encryption Flow**:

```
Plaintext → AES-256-GCM Encryption → DEK Generation → KEK Wrapping → Package Assembly
```

**Package Structure**:

```json
{
  "version": "1.0",
  "encrypted_dek": "<base64-encoded>",
  "nonce": "<96-bit-base64>",
  "ciphertext": "<base64-encoded>",
  "aad": {
    "purpose": "ml_training",
    "timestamp": "2024-01-01T00:00:00Z",
    "policy_hash": "<sha256>",
    "metadata": {}
  },
  "kms_context": {
    "provider": "aws_kms",
    "key_id": "alias/medical-images",
    "region": "us-east-1"
  }
}
```

**Security Properties**:

- Forward secrecy through unique DEKs
- Authenticated encryption (AES-256-GCM)
- Cryptographic binding to purpose and policy
- Tamper detection through AAD integrity

### 5. Key Management System (`kms/`)

**Purpose**: Pluggable key management with support for multiple providers.

**Architecture**:

```
KMSAdapter (Abstract) → [AWS KMS | HashiCorp Vault | Mock] → Key Operations
```

**Provider Implementations**:

#### AWS KMS (`aws_kms.py`)

- IAM-based access control
- CloudTrail audit integration
- Multi-region key replication
- Hardware security module backing

#### HashiCorp Vault (`vault.py`)

- Token-based authentication
- Policy-driven access control
- Secret versioning and rotation
- Comprehensive audit logging

#### Mock Provider (`mock.py`)

- Development and testing
- Deterministic key generation
- Local key storage simulation
- Audit trail emulation

### 6. Validation Framework (`validate.py`)

**Purpose**: Comprehensive validation of encrypted packages and system state.

**Validation Categories**:

1. **Package Integrity**: Cryptographic verification
2. **Policy Compliance**: Configuration adherence
3. **Content Validation**: Data format verification
4. **Security Posture**: System security checks

**Validation Pipeline**:

```
Input Validation → Cryptographic Checks → Policy Verification → Content Analysis
```

### 7. Audit System (`audit.py`)

**Purpose**: Tamper-evident audit logging with cryptographic integrity.

**Log Structure**:

```json
{
  "timestamp": "2024-01-01T00:00:00.000Z",
  "action": "ENCRYPT",
  "user": "user@example.com",
  "resource": "image_001.dcm",
  "outcome": "SUCCESS",
  "details": {},
  "signature": "<hmac-sha256>",
  "anchor_hash": "<rolling-hash>"
}
```

**Integrity Mechanisms**:

- HMAC-SHA256 signatures for individual entries
- Rolling anchor hashes for sequence integrity
- Separate signing keys for audit isolation
- Configurable retention and archival

### 8. Secure Loader (`loader.py`)

**Purpose**: Memory-only decryption for ML training workflows.

**Security Design**:

- No plaintext persistence to disk
- Memory-mapped file operations
- Automatic memory cleanup
- Exception-safe resource management

**Integration Points**:

```python
# Direct integration with ML frameworks
for encrypted_path in dataset:
    with SecureImageLoader(encrypted_path, kms) as image:
        model.train_on_batch(image.data, labels)
    # Image automatically cleared from memory
```

### 9. Command-Line Interface (`cli.py`)

**Purpose**: Production-ready CLI for all package operations.

**Command Structure**:

```
pymedsec
├── sanitize    # Remove PHI from images
├── encrypt     # Encrypt sanitized images
├── decrypt     # Decrypt for authorized use
└── verify      # Validate package integrity
```

**Features**:

- Progress reporting for batch operations
- Detailed error reporting with actionable guidance
- Configuration validation and troubleshooting
- Audit logging for all operations

## Data Flow Architecture

### Ingestion Pipeline

```
Raw Image → Validation → Sanitization → Encryption → Audit → Storage
    ↓           ↓            ↓            ↓         ↓        ↓
Metadata   Format Check  PHI Removal   DEK Gen   Logging  Package
Extract    Size Limit   Policy Apply  KEK Wrap  HMAC     Archive
```

### Decryption Pipeline

```
Package → Validation → KMS Request → Decryption → Memory Load → Usage
   ↓          ↓           ↓            ↓           ↓          ↓
Integrity  Policy     Key Unwrap   AES-GCM    Secure     ML Train
Verify     Check      Authorize    Decrypt    Loader     Clean Exit
```

## Security Architecture

### Defense in Depth

1. **Input Validation**: Comprehensive file format and content validation
2. **Access Controls**: KMS-based authorization with fine-grained permissions
3. **Encryption**: Strong encryption with authenticated encryption modes
4. **Audit Logging**: Comprehensive tamper-evident audit trails
5. **Policy Enforcement**: Configurable security policies with validation
6. **Secure Defaults**: Most restrictive settings by default

### Threat Model

**Protected Assets**:

- Medical images and associated metadata
- Patient identifiers and PHI
- Encryption keys and key material
- Audit logs and compliance records

**Threat Actors**:

- External attackers (network-based)
- Malicious insiders (authorized users)
- Accidental disclosure (human error)
- System compromise (malware, APT)

**Attack Vectors**:

- Network interception
- Unauthorized access to storage
- Key material extraction
- Audit log tampering
- Policy circumvention

### Security Controls

| Control Category  | Implementation                  | Standards Alignment |
| ----------------- | ------------------------------- | ------------------- |
| Access Control    | KMS-based authorization         | NIST AC-2, AC-3     |
| Encryption        | AES-256-GCM envelope encryption | NIST SC-13, SC-28   |
| Audit Logging     | HMAC-signed tamper-evident logs | NIST AU-2, AU-6     |
| Data Integrity    | Cryptographic checksums         | NIST SI-7           |
| Data Sanitization | Configurable PHI removal        | NIST MP-6           |

## Performance Architecture

### Scalability Design

**Horizontal Scaling**:

- Stateless operation design
- Parallel processing capability
- Distributed KMS support
- Load balancer compatibility

**Vertical Scaling**:

- Memory-efficient processing
- Streaming encryption for large files
- Configurable buffer sizes
- Resource usage monitoring

### Performance Characteristics

| Operation    | Typical Performance | Scaling Factors    |
| ------------ | ------------------- | ------------------ |
| Encryption   | 50-100 MB/s         | CPU, I/O bandwidth |
| Decryption   | 75-150 MB/s         | CPU, KMS latency   |
| Sanitization | 10-50 images/s      | Image complexity   |
| Validation   | 100-500 MB/s        | Network, storage   |

### Optimization Strategies

1. **Batching**: Group operations for efficiency
2. **Caching**: KMS key caching for repeated operations
3. **Streaming**: Process large files without full memory load
4. **Compression**: Optional compression before encryption
5. **Parallelization**: Multi-threaded processing for batches

## Deployment Architecture

### Environment Support

**Development**:

- Mock KMS provider for testing
- Local configuration files
- Simplified audit logging
- Debug-level error reporting

**Staging**:

- Production-like KMS integration
- Full audit logging enabled
- Performance testing environment
- Compliance validation

**Production**:

- Enterprise KMS providers
- High-availability configuration
- Comprehensive monitoring
- Disaster recovery procedures

### Integration Patterns

**Batch Processing**:

```python
# ETL pipeline integration
for image_batch in data_pipeline:
    sanitized = sanitize_batch(image_batch)
    encrypted = encrypt_batch(sanitized)
    store_batch(encrypted)
```

**Real-time Processing**:

```python
# Streaming integration
async def process_image_stream():
    async for image in image_stream:
        result = await process_secure(image)
        await result_queue.put(result)
```

**ML Training Integration**:

```python
# PyTorch DataLoader
class SecureImageDataset(Dataset):
    def __getitem__(self, idx):
        with SecureImageLoader(self.paths[idx]) as image:
            return self.transform(image.data)
```

## Configuration Architecture

### Policy Hierarchy

```
Default Policy → Environment Policy → User Policy → Runtime Overrides
```

**Policy Types**:

1. **Security Policies**: Encryption, access control, audit requirements
2. **Compliance Policies**: HIPAA, GDPR, GxP-specific configurations
3. **Operational Policies**: Performance, monitoring, error handling
4. **Integration Policies**: KMS, storage, networking configurations

### Configuration Management

**Static Configuration**:

- YAML policy files with schema validation
- Environment variable injection
- Compile-time security settings

**Dynamic Configuration**:

- Runtime policy updates
- Feature flag support
- A/B testing capabilities
- Emergency configuration changes

## Monitoring and Observability

### Metrics Collection

**System Metrics**:

- Processing throughput and latency
- Error rates and failure modes
- Resource utilization and capacity
- Security event frequencies

**Business Metrics**:

- Compliance posture indicators
- Data processing volumes
- User activity patterns
- Policy violation rates

### Alerting Framework

**Security Alerts**:

- Unauthorized access attempts
- Policy violations
- Audit log anomalies
- Encryption failures

**Operational Alerts**:

- Performance degradation
- Capacity thresholds
- Integration failures
- Configuration drift

## Extension Points

### Plugin Architecture

**KMS Providers**:

- Custom KMS adapter implementation
- Provider-specific configuration
- Failover and redundancy support

**Sanitization Policies**:

- Custom PHI detection rules
- Domain-specific sanitization
- Regulatory compliance modules

**Audit Destinations**:

- Custom audit log handlers
- External SIEM integration
- Real-time monitoring hooks

### API Integration

**REST API**:

```python
# Future API endpoint structure
POST /api/v1/images/sanitize
POST /api/v1/images/encrypt
GET  /api/v1/images/{id}/decrypt
GET  /api/v1/audit/logs
```

**gRPC Interface**:

```protobuf
service ImageSecurityService {
  rpc SanitizeImage(SanitizeRequest) returns (SanitizeResponse);
  rpc EncryptImage(EncryptRequest) returns (EncryptResponse);
  rpc DecryptImage(DecryptRequest) returns (DecryptResponse);
}
```

## Quality Attributes

### Reliability

- Error handling and recovery mechanisms
- Graceful degradation under failure
- Comprehensive testing and validation
- Monitoring and alerting systems

### Security

- Defense-in-depth architecture
- Principle of least privilege
- Secure coding practices
- Regular security assessments

### Performance

- Efficient algorithms and data structures
- Resource optimization
- Scalability planning
- Performance monitoring

### Maintainability

- Modular design with clear interfaces
- Comprehensive documentation
- Automated testing and deployment
- Code quality standards

### Compliance

- Regulatory requirement mapping
- Audit trail completeness
- Policy enforcement mechanisms
- Validation and verification procedures

---

This architecture supports the core requirements of secure, compliant medical image processing while maintaining flexibility for future enhancements and integrations.
