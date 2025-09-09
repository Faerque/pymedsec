# PyMedSec Documentation

Welcome to PyMedSec, a HIPAA/GDPR-ready medical image sanitization and encryption library with blockchain audit anchoring.

## Overview

PyMedSec provides a comprehensive solution for securely handling medical imaging data in compliance with healthcare regulations. The library offers:

- **Medical Image Sanitization**: Remove sensitive metadata from DICOM and other medical image formats
- **End-to-End Encryption**: Industry-standard encryption with secure key management
- **Compliance Ready**: Built-in HIPAA and GDPR compliance features
- **Blockchain Auditing**: Immutable audit trails using blockchain technology
- **Multi-Backend Support**: AWS KMS, HashiCorp Vault, and mock implementations

## Quick Start

```python
from pymedsec import PyMedSec

# Initialize with default configuration
pymedsec = PyMedSec()

# Sanitize and encrypt a DICOM file
result = pymedsec.secure_process(
    input_path="patient_scan.dcm",
    output_path="secure_scan.encrypted",
    policy="hipaa_default"
)
```

## Table of Contents

```{toctree}
:maxdepth: 2
:caption: Contents:

installation
quickstart
api/index
architecture
compliance/index
blockchain
examples
contributing
changelog
```

## Architecture Documents

```{toctree}
:maxdepth: 1
:caption: Architecture:

ARCHITECTURE
HIPAA_READINESS
GDPR_READINESS
GXP_CLIA_ALIGNMENT
BLOCKCHAIN_AUDIT
VALIDATION_TRACEABILITY
```

## Indices and tables

* {ref}`genindex`
* {ref}`modindex`
* {ref}`search`
