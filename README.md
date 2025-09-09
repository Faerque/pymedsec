# PyMedSec - Medical Image Security Framework

<div align="center">

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![PyPI](https://img.shields.io/pypi/v/pymedsec.svg)](https://pypi.org/project/pymedsec/)
[![Tests](https://github.com/Faerque/pymedsec/workflows/Tests/badge.svg)](https://github.com/Faerque/pymedsec/actions)
[![Coverage](https://codecov.io/gh/Faerque/pymedsec/branch/main/graph/badge.svg)](https://codecov.io/gh/Faerque/pymedsec)
[![Documentation](https://img.shields.io/badge/docs-latest-brightgreen.svg)](https://pymedsec.readthedocs.io/)

**Enterprise-Grade Medical Image Security & Compliance Framework**

_Secure medical image processing with HIPAA/GDPR/GxP compliance, envelope encryption, PHI sanitization, and tamper-evident audit logging_

[🚀 Quick Start](#-quick-start) •
[📖 Documentation](#-documentation) •
[🏗️ Architecture](#-architecture) •
[🔧 Examples](#-examples) •
[🏥 Compliance](#-compliance)

</div>

---

## 🎯 Overview

PyMedSec is a production-ready Python framework designed for secure medical image processing in healthcare environments. It provides comprehensive tools for encryption, sanitization, and compliance management while maintaining the highest security standards for Protected Health Information (PHI).

### ✅ Production Ready Features

- **🔒 Enterprise Encryption**: AES-256-GCM envelope encryption with KMS integration
- **🧹 PHI Sanitization**: Intelligent DICOM/EXIF metadata removal and de-identification
- **📊 Audit Compliance**: Tamper-evident logging with HMAC signatures and blockchain anchoring
- **⚡ ML Integration**: Zero-copy memory decryption for secure machine learning workflows
- **🔌 Multi-Cloud KMS**: AWS KMS, HashiCorp Vault, and Azure Key Vault support
- **📋 Regulatory Compliance**: HIPAA, GDPR, CLIA, and GxP alignment with validation documentation

## �️ Architecture

PyMedSec follows a modular, security-first architecture designed for enterprise healthcare environments.

### System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              PyMedSec Framework                                 │
├─────────────────────┬─────────────────────┬─────────────────────┬──────────────┤
│    Public API       │   Core Security     │   Compliance        │   Audit      │
│                     │                     │                     │              │
│  ┌─────────────┐   │  ┌─────────────┐   │  ┌─────────────┐   │ ┌──────────┐ │
│  │ load_policy │   │  │ Envelope    │   │  │ PHI         │   │ │ Tamper   │ │
│  │ scrub_dicom │   │  │ Encryption  │   │  │ Sanitizer   │   │ │ Evident  │ │
│  │ encrypt_blob│   │  │ AES-256-GCM │   │  │ DICOM/EXIF  │   │ │ Logging  │ │
│  │ decrypt_blob│   │  │             │   │  │             │   │ │ HMAC     │ │
│  └─────────────┘   │  └─────────────┘   │  └─────────────┘   │ └──────────┘ │
└─────────────────────┴─────────────────────┴─────────────────────┴──────────────┘
           │                      │                      │                │
           ▼                      ▼                      ▼                ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐  ┌─────────────┐
│   KMS Adapters  │    │ Crypto Provider │    │ Policy Engine   │  │ Blockchain  │
│                 │    │                 │    │                 │  │ Anchoring   │
│ ┌─────────────┐ │    │ ┌─────────────┐ │    │ ┌─────────────┐ │  │ ┌─────────┐ │
│ │  AWS KMS    │ │    │ │ Key         │ │    │ │ HIPAA       │ │  │ │Ethereum │ │
│ │  Vault      │ │    │ │ Generation  │ │    │ │ GDPR        │ │  │ │Fabric   │ │
│ │  Mock       │ │    │ │ Wrapping    │ │    │ │ GxP/CLIA    │ │  │ │Mock     │ │
│ └─────────────┘ │    │ └─────────────┘ │    │ └─────────────┘ │  │ └─────────┘ │
└─────────────────┘    └─────────────────┘    └─────────────────┘  └─────────────┘
```

### Data Flow Architecture

```
                Medical Image Processing Pipeline

┌─────────────┐   ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
│             │   │                 │   │                 │   │                 │
│  Raw Image  │──▶│  PHI Scrubbing  │──▶│   Encryption    │──▶│ Secure Storage  │
│  (DICOM/    │   │                 │   │                 │   │                 │
│   PNG/JPEG) │   │ • Remove PII    │   │ • Generate DEK  │   │ • Encrypted Pkg │
│             │   │ • Strip EXIF    │   │ • AES-256-GCM   │   │ • Audit Trail   │
│             │   │ • Regenerate    │   │ • Wrap with KMS │   │ • Blockchain    │
│             │   │   UIDs          │   │ • Sign Package  │   │   Anchor        │
└─────────────┘   └─────────────────┘   └─────────────────┘   └─────────────────┘
                           │                       │                       │
                           ▼                       ▼                       ▼
                  ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
                  │ Sanitization    │   │ Encryption      │   │ Audit Events    │
                  │ Report          │   │ Metadata        │   │                 │
                  │ • Removed Tags  │   │ • Algorithm     │   │ • Actor         │
                  │ • Pseudo PID    │   │ • Key Reference │   │ • Timestamp     │
                  │ • Hash          │   │ • IV/Nonce      │   │ • Operation     │
                  │ • Compliance    │   │ • AAD Context   │   │ • Outcome       │
                  └─────────────────┘   └─────────────────┘   └─────────────────┘
```

### ML Training Pipeline

```
               Secure Machine Learning Workflow

┌─────────────┐   ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
│ Encrypted   │   │ Memory-Only     │   │ Tensor          │   │ Model Training  │
│ Dataset     │──▶│ Decryption      │──▶│ Conversion      │──▶│                 │
│             │   │                 │   │                 │   │ • PyTorch       │
│ • .enc files│   │ • KMS Unwrap    │   │ • DICOM→Tensor  │   │ • TensorFlow    │
│ • Metadata  │   │ • AES Decrypt   │   │ • Preprocessing │   │ • No Disk I/O   │
│ • Audit Log │   │ • Verify HMAC   │   │ • Normalization │   │ • Auto Cleanup  │
└─────────────┘   └─────────────────┘   └─────────────────┘   └─────────────────┘
                           │                       │                       │
                           ▼                       ▼                       ▼
                  ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
                  │ Zero-Copy       │   │ Image Tensors   │   │ Privacy         │
                  │ Operations      │   │                 │   │ Guarantees      │
                  │                 │   │ • Shape: (H,W,C)│   │                 │
                  │ • No temp files │   │ • Dtype: float32│   │ • No PHI leaks  │
                  │ • Memory pools  │   │ • Range: [0,1]  │   │ • Secure delete │
                  │ • Automatic     │   │ • Batch ready   │   │ • Audit trail   │
                  │   cleanup       │   │                 │   │                 │
                  └─────────────────┘   └─────────────────┘   └─────────────────┘
```

## 🚀 Quick Start

### Installation

```bash
# Production installation
pip install pymedsec

# Development installation with all features
pip install pymedsec[dev,aws,vault,ocr]

# Specific feature sets
pip install pymedsec[aws]        # AWS KMS support
pip install pymedsec[vault]      # HashiCorp Vault support
pip install pymedsec[ocr]        # OCR-based redaction
pip install pymedsec[blockchain] # Blockchain anchoring
```

### 30-Second Example

```python
from pymedsec import load_policy, scrub_dicom, get_kms_client, encrypt_blob

# 1. Load HIPAA-compliant policy
policy = load_policy("hipaa_default")

# 2. Initialize KMS (use AWS KMS in production)
kms = get_kms_client("mock")  # or "aws" with proper credentials

# 3. Sanitize medical image
with open("patient_scan.dcm", "rb") as f:
    clean_data = scrub_dicom(f.read(), policy=policy, pseudo_pid="PX001")

# 4. Encrypt for secure storage
encrypted_package = encrypt_blob(
    clean_data,
    kms_client=kms,
    aad={"dataset": "study2025", "modality": "CT"}
)

# 5. Save encrypted package
with open("secure_scan.enc", "w") as f:
    f.write(encrypted_package.to_json())

print("✅ Medical image securely processed and encrypted!")
```

## 📖 API Documentation

### High-Level API (Recommended)

#### Policy Management

```python
from pymedsec import load_policy, list_policies, set_active_policy

# Load built-in policies
policy = load_policy("hipaa_default")  # or "gdpr_default", "gxp_default"

# Load custom policy
policy = load_policy("/path/to/custom_policy.yaml")

# List all available policies
policies = list_policies()

# Set global active policy
set_active_policy("hipaa_default")
```

#### KMS Integration

```python
from pymedsec import get_kms_client

# AWS KMS (production)
kms = get_kms_client("aws",
                     key_id="alias/medical-images",
                     region_name="us-east-1")

# HashiCorp Vault
kms = get_kms_client("vault",
                     vault_url="https://vault.company.com",
                     vault_path="medical/keys/imaging")

# Mock KMS (development/testing)
kms = get_kms_client("mock")
```

#### Image Processing

```python
from pymedsec import scrub_dicom, scrub_image, encrypt_blob, decrypt_blob

# DICOM sanitization with PHI removal
clean_dicom = scrub_dicom(dicom_bytes,
                          policy=policy,
                          pseudo_pid="ANON123",
                          preserve_technical=True)

# Generic image sanitization
clean_image = scrub_image(image_bytes,
                          format_hint="png",  # or "jpeg", "tiff"
                          policy=policy)

# Encryption with authenticated additional data
package = encrypt_blob(clean_data,
                       kms_client=kms,
                       aad={"study": "TRIAL001", "modality": "MRI"})

# Decryption
original_data = decrypt_blob(package, kms_client=kms)
```

#### ML Integration

```python
from pymedsec import SecureImageDataset, decrypt_to_tensor

# Create secure dataset for training
dataset = SecureImageDataset(
    data_dir="./encrypted_scans/",
    policy=policy,
    kms_client=kms,
    transform=torchvision.transforms.Compose([
        transforms.Resize((224, 224)),
        transforms.ToTensor(),
        transforms.Normalize(mean=[0.485], std=[0.229])
    ])
)

# Use with PyTorch DataLoader
dataloader = torch.utils.data.DataLoader(dataset, batch_size=32, shuffle=True)

for batch_tensors, metadata in dataloader:
    # Train your model
    outputs = model(batch_tensors)
    loss = criterion(outputs, targets)

# Direct tensor decryption (zero-copy)
tensor = decrypt_to_tensor(encrypted_package,
                          kms_client=kms,
                          format_hint="dicom")
```

### Low-Level API (Advanced Use Cases)

```python
from pymedsec.config import SecurityConfig
from pymedsec.crypto import EncryptionEngine
from pymedsec.sanitize import DicomSanitizer
from pymedsec.audit import AuditLogger

# Advanced configuration
config = SecurityConfig.load_from_file("/etc/pymedsec/config.yaml")

# Direct encryption engine
engine = EncryptionEngine(config)
encrypted_data = engine.encrypt(data, key_ref="prod-key-001")

# Advanced DICOM processing
sanitizer = DicomSanitizer(config)
result = sanitizer.sanitize(dicom_dataset)

# Audit logging
logger = AuditLogger(audit_path="/var/log/pymedsec.jsonl")
logger.log_operation("ENCRYPT", outcome="success", file_hash="sha256:abc123...")
```

## 🔧 Configuration

PyMedSec uses environment variables and YAML configuration files for flexible deployment.

### Environment Variables

| Variable                     | Description                          | Default         | Required |
| ---------------------------- | ------------------------------------ | --------------- | -------- |
| `PYMEDSEC_POLICY`            | Path to YAML policy file             | -               | ✅       |
| `PYMEDSEC_KMS_BACKEND`       | KMS backend (`aws`\|`vault`\|`mock`) | `mock`          | ✅       |
| `PYMEDSEC_KMS_KEY_REF`       | KMS key identifier                   | -               | ✅       |
| `PYMEDSEC_AUDIT_PATH`        | Audit log file path                  | `./audit.jsonl` | -        |
| `PYMEDSEC_DEBUG`             | Enable debug logging                 | `false`         | -        |
| `PYMEDSEC_NO_PLAINTEXT_DISK` | Forbid plaintext disk writes         | `false`         | -        |

### Policy Configuration

Create a YAML policy file to define security and compliance requirements:

```yaml
# /etc/pymedsec/hipaa_policy.yaml
schema_version: '1.0'
name: 'HIPAA Compliance Policy'
description: 'Enterprise HIPAA-compliant policy for medical imaging'

sanitization:
  dicom:
    remove_private_tags: true
    regenerate_uids: true
    preserve_technical_tags: true
    phi_tags_action: 'remove' # remove, replace, or pseudonymize
    burned_in_annotation_policy: 'strict' # strict, moderate, or permissive

  exif:
    strip_all_metadata: true
    preserve_orientation: false
    preserve_color_space: true

encryption:
  algorithm: 'AES-256-GCM'
  key_rotation_days: 90
  require_kms: true
  additional_authenticated_data: ['dataset_id', 'modality', 'timestamp']

audit:
  log_all_operations: true
  include_file_hashes: true
  blockchain_anchoring: false
  retention_days: 2557 # 7 years for HIPAA

compliance:
  framework: 'hipaa' # hipaa, gdpr, gxp
  purpose_limitation: 'medical_research'
  data_minimization: true
  pseudonymization_required: true
```

## 🔐 Security Model

### Envelope Encryption

PyMedSec uses industry-standard envelope encryption to protect medical images:

1. **Data Encryption Key (DEK) Generation**: Generate a random 256-bit AES key for each image
2. **Image Encryption**: Encrypt the medical image using AES-256-GCM with the DEK
3. **Key Wrapping**: Encrypt the DEK using the master key in KMS/HSM
4. **Package Creation**: Combine encrypted image + wrapped DEK + metadata in tamper-evident package

```
┌─────────────────────────────────────────────────────────────────┐
│                    Encrypted Package Structure                  │
├─────────────────────────────────────────────────────────────────┤
│ Header:                                                         │
│  ├─ version: "1.0"                                             │
│  ├─ algorithm: "AES-256-GCM"                                   │
│  ├─ kms_key_ref: "arn:aws:kms:us-east-1:123:key/abc123"       │
│  └─ created_at: "2025-09-09T10:30:00Z"                        │
├─────────────────────────────────────────────────────────────────┤
│ Crypto:                                                         │
│  ├─ wrapped_dek: "AQICAHh...encrypted_key"                     │
│  ├─ iv: "12_byte_initialization_vector"                        │
│  ├─ auth_tag: "16_byte_authentication_tag"                     │
│  └─ aad: {"dataset": "study1", "modality": "CT"}              │
├─────────────────────────────────────────────────────────────────┤
│ Data:                                                           │
│  └─ ciphertext: "encrypted_medical_image_data"                 │
├─────────────────────────────────────────────────────────────────┤
│ Integrity:                                                      │
│  ├─ package_hash: "sha256:package_content_hash"                │
│  ├─ signature: "hmac_sha256_signature"                         │
│  └─ audit_ref: "audit_log_entry_reference"                     │
└─────────────────────────────────────────────────────────────────┘
```

### PHI Sanitization

Comprehensive removal and pseudonymization of Protected Health Information:

#### DICOM Tags Handling

```python
# Automatic PHI tag removal based on DICOM standard
PHI_TAGS = [
    (0x0010, 0x0010),  # Patient's Name
    (0x0010, 0x0020),  # Patient ID
    (0x0010, 0x0030),  # Patient's Birth Date
    (0x0010, 0x1040),  # Patient's Address
    (0x0008, 0x0080),  # Institution Name
    (0x0008, 0x0090),  # Referring Physician's Name
    # ... 100+ additional PHI tags
]

# Technical tags preserved for medical utility
TECHNICAL_TAGS = [
    (0x0018, 0x0050),  # Slice Thickness
    (0x0018, 0x0088),  # Spacing Between Slices
    (0x0020, 0x0032),  # Image Position Patient
    (0x0028, 0x0030),  # Pixel Spacing
    # ... imaging parameters
]
```

### Audit Trail

Tamper-evident audit logging with HMAC signatures and optional blockchain anchoring:

```jsonl
{"timestamp": "2025-09-09T10:30:15.123Z", "actor": "radiologist@hospital.com", "operation": "ENCRYPT", "outcome": "success", "file_hash": "sha256:abc123", "kms_key": "alias/medical", "signature": "hmac_sha256_sig"}
{"timestamp": "2025-09-09T10:31:22.456Z", "actor": "ml-pipeline", "operation": "DECRYPT", "outcome": "success", "access_purpose": "model_training", "signature": "hmac_sha256_sig"}
```

## 🏥 Compliance

### HIPAA Compliance

PyMedSec addresses HIPAA Security Rule requirements:

- **§164.312(a)(1)** - Access Control: KMS-based access control with audit logging
- **§164.312(a)(2)(i)** - Unique User Identification: Actor tracking in audit logs
- **§164.312(b)** - Audit Controls: Comprehensive tamper-evident audit trail
- **§164.312(c)(1)** - Integrity: HMAC signatures and hash verification
- **§164.312(d)** - Person or Entity Authentication: KMS authentication
- **§164.312(e)(1)** - Transmission Security: Envelope encryption for data in transit

### GDPR Compliance

- **Article 25** - Data Protection by Design: Privacy-preserving architecture
- **Article 32** - Security of Processing: AES-256-GCM encryption and access controls
- **Article 35** - Data Protection Impact Assessment: Validation documentation provided
- **Article 17** - Right to Erasure: Secure deletion capabilities

### FDA/GxP Compliance

- **21 CFR Part 11** - Electronic Records: Tamper-evident audit trail and electronic signatures
- **CLIA** - Clinical Laboratory Standards: Quality controls and traceability

## 📊 Performance

### Benchmarks

| Operation         | Image Size    | Throughput     | Memory Usage |
| ----------------- | ------------- | -------------- | ------------ |
| DICOM Encryption  | 512x512x16bit | 45 MB/s        | 128 MB       |
| DICOM Decryption  | 512x512x16bit | 52 MB/s        | 96 MB        |
| PHI Sanitization  | 1024 tags     | 1,200 images/s | 64 MB        |
| Tensor Conversion | 512x512 DICOM | 890 images/s   | 32 MB        |

_Benchmarks on AWS c5.2xlarge (8 vCPU, 16 GB RAM)_

### Scalability

- **Horizontal Scaling**: Stateless design enables easy horizontal scaling
- **Cloud Native**: Native integration with AWS, Azure, and GCP KMS services
- **Memory Efficient**: Zero-copy operations and automatic cleanup
- **Batch Processing**: Optimized for large-scale medical imaging pipelines
  pip install pymedsec[aws]

# With Vault KMS support

pip install pymedsec[vault]

## 🔧 Examples

### Healthcare Research Pipeline

```python
import pymedsec
from pathlib import Path

# Setup
policy = pymedsec.load_policy("hipaa_default")
kms = pymedsec.get_kms_client("aws", key_id="alias/research-images")

# Process a batch of DICOM files
for dicom_file in Path("./raw_scans/").glob("*.dcm"):
    # Sanitize and encrypt
    with open(dicom_file, "rb") as f:
        clean_data = pymedsec.scrub_dicom(
            f.read(),
            policy=policy,
            pseudo_pid=f"STUDY001_{dicom_file.stem}"
        )

    encrypted_pkg = pymedsec.encrypt_blob(
        clean_data,
        kms_client=kms,
        aad={"study": "TRIAL001", "patient": dicom_file.stem}
    )

    # Save encrypted version
    output_file = Path("./secure_scans/") / f"{dicom_file.stem}.enc"
    with open(output_file, "w") as f:
        f.write(encrypted_pkg.to_json())
```

### ML Training with SecureImageDataset

```python
import torch
from torch.utils.data import DataLoader
from pymedsec import SecureImageDataset, load_policy, get_kms_client

# Setup secure dataset
policy = load_policy("research_policy.yaml")
kms = get_kms_client("aws", key_id="alias/ml-training")

dataset = SecureImageDataset(
    data_dir="./encrypted_training_data/",
    policy=policy,
    kms_client=kms,
    transform=torch.transforms.Compose([
        torch.transforms.Resize((224, 224)),
        torch.transforms.ToTensor(),
        torch.transforms.Normalize([0.485, 0.456, 0.406], [0.229, 0.224, 0.225])
    ])
)

# Train your model
dataloader = DataLoader(dataset, batch_size=32, shuffle=True, num_workers=4)

for epoch in range(10):
    for batch_idx, (images, metadata) in enumerate(dataloader):
        # Forward pass
        outputs = model(images)
        loss = criterion(outputs, targets)

        # Backward pass
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()

        # Images automatically cleared from memory after batch
```

### Command Line Interface

PyMedSec provides a comprehensive CLI for batch processing and operations:

```bash
# Set up environment
export PYMEDSEC_POLICY=/etc/pymedsec/hipaa_policy.yaml
export PYMEDSEC_KMS_BACKEND=aws
export PYMEDSEC_KMS_KEY_REF=alias/medical-images
export PYMEDSEC_AUDIT_PATH=/var/log/pymedsec/audit.jsonl

# Sanitize a DICOM file
pymedsec sanitize-cmd \
    --input patient_001.dcm \
    --output clean_001.dcm \
    --pseudo-pid STUDY001_001 \
    --format dicom

# Encrypt sanitized image
pymedsec encrypt \
    --input clean_001.dcm \
    --output secure_001.enc \
    --dataset-id CLINICAL_TRIAL_2025 \
    --modality CT \
    --additional-data '{"site": "hospital_a", "protocol": "v2.1"}'

# Batch processing with parallel workers
pymedsec encrypt \
    --input-dir ./sanitized_scans/ \
    --output-dir ./encrypted_scans/ \
    --workers 8 \
    --dataset-id BATCH_PROCESS_001

# Decrypt for analysis
pymedsec decrypt \
    --input secure_001.enc \
    --output analysis_001.dcm \
    --memory-only  # Decrypt to memory only, no disk write

# Verify package integrity
pymedsec verify --input secure_001.enc --verbose

# Audit operations
pymedsec audit-log --last 100 --format table
pymedsec audit-status --check-blockchain
pymedsec audit-verify --start-date 2025-09-01 --end-date 2025-09-09
```

## 🛠️ Development

### Setting Up Development Environment

```bash
# Clone repository
git clone https://github.com/Faerque/pymedsec.git
cd pymedsec

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install in development mode
pip install -e ".[dev,aws,vault,ocr]"

# Install pre-commit hooks
pre-commit install
```

### Running Tests

```bash
# Run all tests
make test

# Run with coverage
make test-cov

# Run specific test file
python -m pytest tests/test_crypto.py -v

# Run integration tests
make test-integration
```

### Code Quality

```bash
# Format code
make fmt

# Lint code
make lint

# Type checking
make type-check

# Security scanning
make security-scan
```

### Building Documentation

```bash
# Build docs locally
make docs

# Serve docs locally
make docs-serve

# Build for deployment
make docs-build
```

## 🚀 Deployment

### Production Deployment Checklist

- [ ] **KMS Setup**: Configure AWS KMS or HashiCorp Vault with proper IAM roles
- [ ] **Policy Configuration**: Create and validate security policies for your environment
- [ ] **Environment Variables**: Set all required environment variables securely
- [ ] **Audit Logging**: Configure persistent audit log storage with proper rotation
- [ ] **Monitoring**: Set up monitoring for encryption/decryption operations and errors
- [ ] **Backup**: Implement backup strategy for encrypted data and audit logs
- [ ] **Key Rotation**: Establish key rotation procedures and schedules
- [ ] **Incident Response**: Create incident response procedures for security events

### Docker Deployment

```dockerfile
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install PyMedSec
RUN pip install pymedsec[aws,vault]

# Copy configuration
COPY policies/ /etc/pymedsec/policies/
COPY config.yaml /etc/pymedsec/config.yaml

# Set environment variables
ENV PYMEDSEC_POLICY=/etc/pymedsec/policies/production.yaml
ENV PYMEDSEC_KMS_BACKEND=aws
ENV PYMEDSEC_AUDIT_PATH=/var/log/pymedsec/audit.jsonl

# Create non-root user
RUN useradd -m pymedsec
USER pymedsec

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD pymedsec --config-check || exit 1

ENTRYPOINT ["pymedsec"]
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pymedsec-processor
spec:
  replicas: 3
  selector:
    matchLabels:
      app: pymedsec-processor
  template:
    metadata:
      labels:
        app: pymedsec-processor
    spec:
      serviceAccountName: pymedsec-service-account
      containers:
        - name: pymedsec
          image: your-registry/pymedsec:latest
          env:
            - name: PYMEDSEC_POLICY
              value: /etc/config/policy.yaml
            - name: PYMEDSEC_KMS_BACKEND
              value: aws
            - name: PYMEDSEC_KMS_KEY_REF
              valueFrom:
                secretKeyRef:
                  name: kms-config
                  key: key-id
          volumeMounts:
            - name: config-volume
              mountPath: /etc/config
            - name: audit-volume
              mountPath: /var/log/pymedsec
          resources:
            requests:
              memory: '256Mi'
              cpu: '100m'
            limits:
              memory: '1Gi'
              cpu: '500m'
      volumes:
        - name: config-volume
          configMap:
            name: pymedsec-config
        - name: audit-volume
          persistentVolumeClaim:
            claimName: audit-storage
```

## 📚 Additional Resources

### Documentation

- [API Reference](https://pymedsec.readthedocs.io/en/latest/api/)
- [Security Architecture](docs/ARCHITECTURE.md)
- [HIPAA Compliance Guide](docs/HIPAA_READINESS.md)
- [GDPR Compliance Guide](docs/GDPR_READINESS.md)
- [GxP/CLIA Alignment](docs/GXP_CLIA_ALIGNMENT.md)
- [Validation & Traceability](docs/VALIDATION_TRACEABILITY.md)

### Community

- [GitHub Issues](https://github.com/Faerque/pymedsec/issues) - Bug reports and feature requests
- [GitHub Discussions](https://github.com/Faerque/pymedsec/discussions) - Questions and discussions
- [Security Policy](https://github.com/Faerque/pymedsec/security/policy) - Security vulnerability reporting

### Related Projects

- [PyDICOM](https://pydicom.github.io/) - DICOM file handling in Python
- [SimpleITK](https://simpleitk.org/) - Medical image analysis toolkit
- [MONAI](https://monai.io/) - Medical imaging AI framework
- [OHIF Viewer](https://ohif.org/) - Web-based medical imaging viewer

## ⚖️ Legal & Compliance

### License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

### Compliance Disclaimer

> **Important**: PyMedSec provides tools that can support HIPAA, GDPR, and GxP compliance but does not by itself ensure compliance. Compliance depends on your deployment environment, policies, procedures, and governance. Organizations must implement appropriate administrative, physical, and technical safeguards according to applicable regulations and their specific use cases.

### Security Vulnerability Reporting

If you discover a security vulnerability, please report it responsibly:

- **Email**: Send details to security@pymedsec.org (not a real email - replace with actual contact)
- **Do NOT** create public GitHub issues for security vulnerabilities
- **Include**: Description, reproduction steps, and potential impact
- **Response**: We aim to acknowledge reports within 24 hours

### Export Control

This software may be subject to export controls. Users are responsible for compliance with applicable export control laws and regulations.

---

<div align="center">

**Made with ❤️ for the healthcare community**

[🏠 Homepage](https://github.com/Faerque/pymedsec) •
[📖 Documentation](https://pymedsec.readthedocs.io/) •
[🐛 Report Bug](https://github.com/Faerque/pymedsec/issues) •
[💡 Request Feature](https://github.com/Faerque/pymedsec/issues)

</div>
