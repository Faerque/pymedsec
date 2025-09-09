# pymedsec AWS KMS Setup and Usage Guide

## Overview

This guide explains how to set up AWS Key Management Service (KMS) with pymedsec and how to encrypt/decrypt medical images using different compliance policies.

## Table of Contents

1. [AWS KMS Setup](#aws-kms-setup)
2. [pymedsec Installation](#pymedsec-installation)
3. [Environment Configuration](#environment-configuration)
4. [Encryption and Decryption](#encryption-and-decryption)
5. [Compliance Policies](#compliance-policies)
6. [Code Examples](#code-examples)
7. [Testing](#testing)
8. [Troubleshooting](#troubleshooting)

## AWS KMS Setup

### Step 1: Create KMS Key in AWS Console

1. **Log in to AWS Console** and navigate to **Key Management Service (KMS)**

2. **Create Customer Managed Key**:

   - Go to KMS → Customer managed keys → Create key
   - Choose **Symmetric** key type
   - Select **Encrypt and decrypt** usage
   - Click **Next**

3. **Configure Key**:

   - **Alias**: Enter `pymedsec` (this will create `alias/pymedsec`)
   - **Description**: `Medical image encryption key for pymedsec`
   - Click **Next**

4. **Define Key Administrative Permissions**:

   - Add your IAM user as **Key administrator**
   - This allows you to manage the key
   - Click **Next**

5. **Define Key Usage Permissions**:

   - Add your IAM user as **Key user**
   - This allows encryption/decryption operations
   - Click **Next**

6. **Review and Create**:
   - Review the key policy
   - Click **Finish**

### Step 2: Configure IAM Permissions

Ensure your IAM user has the following permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:CreateGrant",
        "kms:DescribeKey"
      ],
      "Resource": "arn:aws:kms:YOUR_REGION:YOUR_ACCOUNT:key/*"
    },
    {
      "Effect": "Allow",
      "Action": ["kms:ListKeys", "kms:ListAliases"],
      "Resource": "*"
    }
  ]
}
```

### Step 3: Configure AWS CLI

```bash
# Install AWS CLI if not already installed
pip install awscli

# Configure AWS credentials
aws configure --profile pymedseca
# Enter your Access Key ID, Secret Access Key, region (e.g., ap-south-1), and output format (json)

# Test AWS access
aws sts get-caller-identity --profile pymedseca
```

## pymedsec Installation

### Option 1: Install from Source (Development)

```bash
# Clone the repository
git clone https://github.com/Faerque/pymedsec.git
cd pymedsec

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -e .
pip install boto3 python-dotenv
```

### Option 2: Install from PyPI (Production)

```bash
pip install pymedsec boto3 python-dotenv
```

## Environment Configuration

### Create .env File

Create a `.env` file in your project directory:

```bash
# AWS KMS Configuration
PYMEDSEC_KMS_BACKEND=aws
AWS_PROFILE=pymedseca
AWS_REGION=ap-south-1
PYMEDSEC_KMS_KEY_REF=alias/pymedsec

# Security Settings
PYMEDSEC_NO_PLAINTEXT_DISK=true

# Compliance Policy
PYMEDSEC_POLICY=hipaa_default

# Optional: Blockchain Audit
BLOCKCHAIN_BACKEND=mock
```

### Environment Variables Explanation

- **PYMEDSEC_KMS_BACKEND**: KMS backend (`aws`, `mock`, `vault`)
- **AWS_PROFILE**: AWS CLI profile name
- **AWS_REGION**: AWS region where your KMS key exists
- **PYMEDSEC_KMS_KEY_REF**: KMS key alias or ARN
- **PYMEDSEC_NO_PLAINTEXT_DISK**: Prevents writing decrypted data to disk
- **PYMEDSEC_POLICY**: Default compliance policy to use
- **BLOCKCHAIN_BACKEND**: Blockchain backend for audit trails

## Encryption and Decryption

### Basic Python API Usage

```python
import pymedsec.public_api as pymedsec
from pymedsec.kms import get_kms_client
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Set AWS profile
os.environ['AWS_PROFILE'] = 'pymedseca'

def encrypt_medical_image(file_path, policy_name='hipaa_default'):
    """Encrypt a medical image file."""

    # Create KMS client
    kms_client = get_kms_client(
        backend='aws',
        key_id='alias/pymedsec',
        region_name='ap-south-1'
    )

    # Read file
    with open(file_path, 'rb') as f:
        original_data = f.read()

    # Load policy
    policy = pymedsec.load_policy(policy_name)

    # Create Additional Authenticated Data (AAD)
    aad = {
        'dataset_id': 'medical_study_001',
        'modality': 'CT',  # CT, MRI, XR, GEN
        'filename': os.path.basename(file_path)
    }

    # Encrypt
    encrypted_package = pymedsec.encrypt_blob(
        original_data,
        kms_client=kms_client,
        aad=aad,
        policy=policy
    )

    # Save encrypted package
    output_file = file_path + '.encrypted.pkg.json'
    import json
    with open(output_file, 'w') as f:
        json.dump(encrypted_package, f, indent=2)

    print(f"✅ File encrypted: {output_file}")
    return encrypted_package

def decrypt_medical_image(encrypted_package_file):
    """Decrypt a medical image file."""

    # Create KMS client
    kms_client = get_kms_client(
        backend='aws',
        key_id='alias/pymedsec',
        region_name='ap-south-1'
    )

    # Load encrypted package
    import json
    with open(encrypted_package_file, 'r') as f:
        encrypted_package = json.load(f)

    # Decrypt
    decrypted_data = pymedsec.decrypt_blob(
        encrypted_package,
        kms_client=kms_client
    )

    # Save decrypted file (optional - check PYMEDSEC_NO_PLAINTEXT_DISK)
    if os.getenv('PYMEDSEC_NO_PLAINTEXT_DISK', 'false').lower() != 'true':
        output_file = encrypted_package_file.replace('.encrypted.pkg.json', '.decrypted')
        with open(output_file, 'wb') as f:
            f.write(decrypted_data)
        print(f"✅ File decrypted: {output_file}")
    else:
        print("✅ File decrypted (memory only - no disk write)")

    return decrypted_data

# Example usage
if __name__ == "__main__":
    # Encrypt a DICOM file
    encrypted_pkg = encrypt_medical_image('patient_scan.dcm', 'hipaa_default')

    # Decrypt the file
    decrypted_data = decrypt_medical_image('patient_scan.dcm.encrypted.pkg.json')

    print(f"Encryption/decryption cycle completed successfully!")
```

### Command Line Usage

```bash
# Set AWS profile
export AWS_PROFILE=pymedseca

# Activate virtual environment
source .venv/bin/activate

# Encrypt with different policies
python test_encryption.py --kms aws --policy hipaa_default --files Test_scan.dcm
python test_encryption.py --kms aws --policy gdpr_default --files Test_image.jpg
python test_encryption.py --kms aws --policy gxplab_default --files Test_data.tif

# Test all policies on a single file
python test_all_policies.py --file Test_scan.dcm --kms aws
```

## Compliance Policies

### Available Policies

1. **HIPAA Default** (`hipaa_default`):

   - Healthcare Insurance Portability and Accountability Act
   - Strongest encryption requirements
   - Comprehensive audit logging
   - Best for US healthcare data

2. **GDPR Default** (`gdpr_default`):

   - General Data Protection Regulation
   - EU privacy protection compliance
   - Data subject rights support
   - Best for EU healthcare data

3. **GXP Lab Default** (`gxplab_default`):
   - Good Practice (GxP) Laboratory compliance
   - FDA/EMA regulatory compliance
   - Clinical trial data protection
   - Best for pharmaceutical research

### Policy Configuration Files

Policies are located in `pymedsec/policies/`:

- `hipaa_default.yaml`
- `gdpr_default.yaml`
- `gxplab_default.yaml`

You can also create custom policies by providing a path to your own YAML file:

```python
policy = pymedsec.load_policy('/path/to/custom_policy.yaml')
```

## Code Examples

### Example 1: Batch Processing Medical Images

```python
import os
import glob
import pymedsec.public_api as pymedsec
from pymedsec.kms import get_kms_client

def batch_encrypt_medical_images(directory, policy_name='hipaa_default'):
    """Encrypt all medical images in a directory."""

    # Set up KMS client
    os.environ['AWS_PROFILE'] = 'pymedseca'
    kms_client = get_kms_client(
        backend='aws',
        key_id='alias/pymedsec',
        region_name='ap-south-1'
    )

    # Load policy
    policy = pymedsec.load_policy(policy_name)

    # Supported medical image formats
    patterns = ['*.dcm', '*.jpg', '*.jpeg', '*.png', '*.tif', '*.tiff']

    encrypted_files = []

    for pattern in patterns:
        files = glob.glob(os.path.join(directory, pattern))

        for file_path in files:
            try:
                print(f"🔐 Encrypting: {os.path.basename(file_path)}")

                # Read file
                with open(file_path, 'rb') as f:
                    data = f.read()

                # Create AAD
                aad = {
                    'dataset_id': f'batch_process_{policy_name}',
                    'modality': 'GEN',
                    'filename': os.path.basename(file_path),
                    'original_size': len(data)
                }

                # Encrypt
                encrypted_package = pymedsec.encrypt_blob(
                    data,
                    kms_client=kms_client,
                    aad=aad,
                    policy=policy
                )

                # Save encrypted package
                output_file = file_path + '.encrypted.pkg.json'
                import json
                with open(output_file, 'w') as f:
                    json.dump(encrypted_package, f, indent=2)

                encrypted_files.append(output_file)
                print(f"✅ Encrypted: {output_file}")

            except Exception as e:
                print(f"❌ Failed to encrypt {file_path}: {e}")

    print(f"\n📊 Batch encryption complete: {len(encrypted_files)} files encrypted")
    return encrypted_files

# Usage
encrypted_files = batch_encrypt_medical_images('/path/to/medical/images', 'hipaa_default')
```

### Example 2: Secure Medical Image Analysis Pipeline

```python
import pymedsec.public_api as pymedsec
from pymedsec.kms import get_kms_client
import numpy as np
from PIL import Image
import io

def secure_image_analysis(encrypted_package_file):
    """Analyze medical image without writing to disk."""

    # Set up KMS client
    kms_client = get_kms_client(
        backend='aws',
        key_id='alias/pymedsec',
        region_name='ap-south-1'
    )

    # Load and decrypt in memory
    import json
    with open(encrypted_package_file, 'r') as f:
        encrypted_package = json.load(f)

    # Decrypt to memory only
    decrypted_data = pymedsec.decrypt_blob(
        encrypted_package,
        kms_client=kms_client
    )

    # Convert to PIL Image for analysis
    image = Image.open(io.BytesIO(decrypted_data))

    # Convert to numpy for analysis
    img_array = np.array(image)

    # Perform analysis (example: basic statistics)
    analysis_results = {
        'dimensions': img_array.shape,
        'data_type': str(img_array.dtype),
        'min_value': int(img_array.min()),
        'max_value': int(img_array.max()),
        'mean_value': float(img_array.mean()),
        'std_value': float(img_array.std())
    }

    # Clear sensitive data from memory
    del decrypted_data
    del img_array
    del image

    return analysis_results

# Usage
results = secure_image_analysis('patient_scan.dcm.encrypted.pkg.json')
print(f"Analysis results: {results}")
```

## Testing

### Test AWS KMS Connection

```bash
# Test AWS credentials
aws sts get-caller-identity --profile pymedseca

# Test KMS key access
aws kms describe-key --key-id alias/pymedsec --profile pymedseca --region ap-south-1
```

### Run pymedsec Tests

```bash
# Test single file with all policies
python test_all_policies.py --file Test_image.jpg --kms aws

# Test blockchain functionality
python simple_blockchain_test.py

# Test specific policy
python test_encryption.py --kms aws --policy hipaa_default --files Test_scan.dcm
```

### Verify Encryption Output

```bash
# Check encrypted package structure
python -c "
import json
with open('Test_image.jpg.encrypted.pkg.json', 'r') as f:
    pkg = json.load(f)
print('Package keys:', list(pkg.keys()))
print('AAD:', pkg.get('aad'))
print('Policy applied:', pkg.get('policy_name'))
"
```

## Troubleshooting

### Common Issues and Solutions

#### 1. AWS Credentials Not Found

```
Error: Unable to locate credentials
```

**Solution**:

```bash
# Configure AWS profile
aws configure --profile pymedseca

# Or set environment variables
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_DEFAULT_REGION=ap-south-1
```

#### 2. KMS Key Not Found

```
Error: Alias arn:aws:kms:region:account:alias/pymedsec is not found
```

**Solution**:

- Create the KMS key in AWS Console with alias `pymedsec`
- Verify the key exists: `aws kms list-aliases --profile pymedseca`

#### 3. Access Denied to KMS

```
Error: AccessDeniedException: User is not authorized to perform kms:Encrypt
```

**Solution**:

- Add KMS permissions to your IAM user
- Ensure you're added as both key administrator and key user

#### 4. Policy File Not Found

```
Error: Policy file not found: hipaa_default
```

**Solution**:

```python
# Use full path to policy
import os
from pathlib import Path

policy_path = Path(__file__).parent / "pymedsec" / "policies" / "hipaa_default.yaml"
policy = pymedsec.load_policy(str(policy_path))
```

#### 5. Mock KMS for Development

If you need to test without AWS KMS:

```python
# Use mock KMS for development
os.environ['PYMEDSEC_KMS_BACKEND'] = 'mock'
kms_client = get_kms_client(backend='mock')
```

### Debug Mode

Enable verbose logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Environment Verification Script

```python
#!/usr/bin/env python3
"""Verify pymedsec environment setup."""

import os
import boto3
from pathlib import Path

def verify_environment():
    """Verify all environment components."""

    checks = []

    # 1. Check AWS profile
    try:
        profile = os.environ.get('AWS_PROFILE', 'pymedseca')
        session = boto3.Session(profile_name=profile)
        sts = session.client('sts')
        identity = sts.get_caller_identity()
        checks.append(("✅ AWS Profile", f"Connected as {identity['Arn']}"))
    except Exception as e:
        checks.append(("❌ AWS Profile", str(e)))

    # 2. Check KMS key
    try:
        session = boto3.Session(profile_name=profile)
        kms = session.client('kms', region_name='ap-south-1')
        key = kms.describe_key(KeyId='alias/pymedsec')
        checks.append(("✅ KMS Key", f"Found key {key['KeyMetadata']['KeyId']}"))
    except Exception as e:
        checks.append(("❌ KMS Key", str(e)))

    # 3. Check pymedsec policies
    policy_dir = Path(__file__).parent / "pymedsec" / "policies"
    if policy_dir.exists():
        policies = list(policy_dir.glob("*.yaml"))
        checks.append(("✅ Policies", f"Found {len(policies)} policy files"))
    else:
        checks.append(("❌ Policies", "Policy directory not found"))

    # Print results
    print("🔍 Environment Verification Results")
    print("=" * 50)
    for check, result in checks:
        print(f"{check}: {result}")

    return all("✅" in check for check, _ in checks)

if __name__ == "__main__":
    success = verify_environment()
    if success:
        print("\n🎉 Environment setup is complete!")
    else:
        print("\n⚠️  Environment setup needs attention.")
```

## Security Best Practices

1. **Never store AWS credentials in code**
2. **Use IAM roles in production environments**
3. **Enable CloudTrail for KMS key usage auditing**
4. **Rotate KMS keys regularly**
5. **Use `PYMEDSEC_NO_PLAINTEXT_DISK=true` in production**
6. **Implement proper access controls for encrypted packages**
7. **Enable blockchain audit trails for compliance**

## Support

For issues and questions:

- Check the troubleshooting section above
- Review the test scripts for working examples
- Ensure your AWS KMS setup follows the documented steps
- Verify all environment variables are correctly configured

## License

This project is licensed under the terms specified in the LICENSE file.
