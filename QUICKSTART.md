# pymedsec Quick Start Guide

## Overview

pymedsec is a medical image security library that provides HIPAA, GDPR, and GXP-compliant encryption for healthcare data using AWS KMS.

## Quick Setup

### 1. Install Dependencies

```bash
pip install boto3 python-dotenv
cd pymedsec
pip install -e .
```

### 2. Configure AWS KMS

Create a KMS key in AWS Console:

- Go to AWS Console → KMS → Create key
- Choose Symmetric, Encrypt/decrypt
- Set alias: `pymedsec`
- Add your user as key administrator and user

### 3. Configure Environment

Create `.env` file:

```env
PYMEDSEC_KMS_BACKEND=aws
AWS_PROFILE=your_aws_profile
AWS_REGION=your_region
PYMEDSEC_KMS_KEY_REF=alias/pymedsec
PYMEDSEC_NO_PLAINTEXT_DISK=true
PYMEDSEC_POLICY=hipaa_default
```

Configure AWS profile:

```bash
aws configure --profile your_aws_profile
```

### 4. Test Installation

```bash
export AWS_PROFILE=your_aws_profile
cd test_pymedsec
source .venv/bin/activate

# Test single file with all policies
python test_all_policies.py --file Test_jpg.jpg --kms aws

# Test specific policy
python test_encryption.py --kms aws --policy hipaa_default
```

## Basic Usage

### Python API

```python
import pymedsec.public_api as pymedsec
from pymedsec.kms import get_kms_client
import os

# Set AWS profile
os.environ['AWS_PROFILE'] = 'your_aws_profile'

# Create KMS client
kms_client = get_kms_client(
    backend='aws',
    key_id='alias/pymedsec',
    region_name='your_region'
)

# Encrypt medical image
with open('medical_image.dcm', 'rb') as f:
    data = f.read()

policy = pymedsec.load_policy('hipaa_default')
aad = {'dataset_id': 'study_001', 'modality': 'CT'}

encrypted_package = pymedsec.encrypt_blob(
    data, kms_client=kms_client, aad=aad, policy=policy
)

# Decrypt
decrypted_data = pymedsec.decrypt_blob(encrypted_package, kms_client=kms_client)
```

### Command Line

```bash
# Test with different policies
python test_encryption.py --kms aws --policy hipaa_default --files image.dcm
python test_encryption.py --kms aws --policy gdpr_default --files image.jpg
python test_encryption.py --kms aws --policy gxplab_default --files image.tif
```

## Compliance Policies

- **HIPAA Default**: US healthcare compliance
- **GDPR Default**: EU privacy regulation compliance
- **GXP Lab Default**: Pharmaceutical/clinical trial compliance

## Features

✅ **AWS KMS Integration**: Production-grade key management  
✅ **Multiple Compliance Policies**: HIPAA, GDPR, GXP Lab support  
✅ **Medical Image Formats**: DICOM, JPEG, PNG, TIFF support  
✅ **Blockchain Audit Trails**: Immutable operation logging  
✅ **Memory-Only Operations**: No plaintext disk writes  
✅ **Envelope Encryption**: AES-256-GCM with KMS key wrapping

## Testing Results

All tests passed successfully:

- ✅ **AWS KMS Tests**: 4/4 files encrypted/decrypted with HIPAA, GDPR, GXP policies
- ✅ **Blockchain Tests**: 100% verification rate for audit anchors
- ✅ **Data Integrity**: Perfect integrity verification for all test files
- ✅ **File Formats**: DICOM (27MB), JPEG (107KB), PNG (137KB), TIFF (310KB)

## Documentation

For detailed setup instructions, see: [AWS_KMS_SETUP_GUIDE.md](AWS_KMS_SETUP_GUIDE.md)

## Troubleshooting

### Common Issues

1. **Credentials Not Found**: Configure AWS profile with `aws configure --profile your_profile`
2. **KMS Key Not Found**: Create KMS key with alias `pymedsec` in AWS Console
3. **Access Denied**: Add KMS permissions to your IAM user
4. **Policy Not Found**: Ensure policy files exist in `pymedsec/policies/`

### Test Environment

```bash
# Verify AWS setup
aws sts get-caller-identity --profile your_aws_profile
aws kms describe-key --key-id alias/pymedsec --profile your_aws_profile

# Test with mock KMS (development)
python test_all_policies.py --file Test_jpg.jpg --kms mock
```

## Support

- Check [AWS_KMS_SETUP_GUIDE.md](AWS_KMS_SETUP_GUIDE.md) for comprehensive documentation
- Review test scripts for working examples
- Ensure AWS KMS permissions are properly configured
