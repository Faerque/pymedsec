# Public API Quickstart

The pymedsec package provides a clean public API for secure medical image processing with HIPAA/GDPR compliance features.

## Basic HIPAA Workflow

```python
from pymedsec import load_policy, scrub_dicom, get_kms_client, encrypt_blob, decrypt_to_tensor

# Load default HIPAA policy
policy = load_policy("hipaa_default")

# Create a mock KMS client for testing
kms = get_kms_client("mock")

# Process a DICOM file
raw = open("scan.dcm", "rb").read()
clean = scrub_dicom(raw, policy=policy, pseudo_pid="PX001")

# Encrypt with additional authenticated data
pkg = encrypt_blob(clean, kms_client=kms, aad={"dataset": "ds1", "modality": "CT"})

# Later: decrypt directly to tensor for ML processing
tensor = decrypt_to_tensor(pkg, kms_client=kms, format_hint="dicom")
print(f"Image shape: {tensor.shape}")
```

## Custom Policy with AWS KMS

```python
from pymedsec import load_policy, scrub_image, get_kms_client, encrypt_blob, decrypt_blob

# Load custom policy from file
policy = load_policy("/etc/policies/gxp_lab.yaml")

# Create AWS KMS client
kms = get_kms_client("aws", key_id="alias/prod-medimg", region_name="us-east-1")

# Process and encrypt an image
raw_image = open("scan.png", "rb").read()
clean_image = scrub_image(raw_image, format_hint="png", policy=policy)
pkg = encrypt_blob(clean_image, kms_client=kms, aad={"dataset": "trial42", "modality": "MRI"})

# Later: decrypt back to raw bytes
decrypted = decrypt_blob(pkg, kms_client=kms)
with open("decrypted_scan.png", "wb") as f:
    f.write(decrypted)
```

## ML Dataset Integration

```python
from pymedsec import SecureImageDataset, load_policy, get_kms_client

# Set up policy and KMS
policy = load_policy("hipaa_default")
kms = get_kms_client("mock")

# Create a dataset that decrypts on-the-fly
dataset = SecureImageDataset("./encrypted/", policy=policy, kms_client=kms, patterns=["*.pkg.json"])

# Iterate like a PyTorch dataset
for i, tensor in enumerate(dataset):
    print(f"Sample {i}: shape={tensor.shape}, dtype={tensor.dtype}")
    if i >= 2:  # Just show first 3 samples
        break

# Random access
first_sample = dataset[0]
print(f"First sample shape: {first_sample.shape}")
```

## Policy Management

```python
from pymedsec import list_policies, load_policy, set_active_policy, get_active_policy

# List available bundled policies
policies = list_policies()
print(f"Available policies: {policies}")

# Load and set a global active policy
policy = load_policy("gdpr_default")
set_active_policy(policy)

# Now other functions will use this policy by default
current = get_active_policy()
print(f"Active policy type: {current.get('policy_type', 'unknown')}")
```

## Error Handling

```python
from pymedsec import load_policy, get_kms_client

try:
    # This will raise RuntimeError if policy not found
    policy = load_policy("nonexistent_policy")
except RuntimeError as e:
    print(f"Policy error: {e}")

try:
    # This will raise ImportError if boto3 not installed
    kms = get_kms_client("aws", key_id="alias/my-key")
except ImportError as e:
    print(f"Dependency error: {e}")

try:
    # This will raise RuntimeError if key_id missing
    kms = get_kms_client("aws")
except RuntimeError as e:
    print(f"Configuration error: {e}")
```
