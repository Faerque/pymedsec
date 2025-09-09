# Copyright 2025 PyMedSec Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Healthcare Image Security Package

A production-grade Python package for secure medical image processing 
with HIPAA/GDPR/GxP compliance features.

Public API:
    Policy Management:
        - load_policy: Load policy by name or path
        - set_active_policy: Set the active policy
        - get_active_policy: Get current active policy
        - list_policies: List available bundled policies

    Data Processing:
        - scrub_dicom: Remove PHI from DICOM files
        - scrub_image: Remove metadata from images
        - encrypt_blob: Encrypt data with envelope encryption
        - decrypt_blob: Decrypt encrypted packages
        - decrypt_to_tensor: Decrypt and convert to tensor/array

    KMS Integration:
        - get_kms_client: Create KMS adapter instances

    ML Integration:
        - SecureImageDataset: PyTorch-like dataset for encrypted images

Example:
    Basic HIPAA workflow:
    
    >>> from pymedsec import load_policy, scrub_dicom, get_kms_client, encrypt_blob
    >>> policy = load_policy("hipaa_default")
    >>> kms = get_kms_client("mock")
    >>> raw = open("scan.dcm", "rb").read()
    >>> clean = scrub_dicom(raw, policy=policy, pseudo_pid="PX001")
    >>> pkg = encrypt_blob(clean, kms_client=kms, aad={"dataset": "ds1"})
"""

from .config import load_config
from .intake import to_tensor
from .sanitize import sanitize_dicom, sanitize_image
from .crypto import encrypt_data, decrypt_data
from . import loader
from . import validate
from . import audit
from . import crypto
from . import sanitize
from . import intake
from . import config
__version__ = "0.1.0"
__author__ = "Healthcare Security Team"
__email__ = "security@example.com"
__license__ = "Apache-2.0"

# Lazy imports for the public API


def __getattr__(name):
    """Lazy loading of public API functions to avoid heavy imports at startup."""
    if name in [
        "load_policy", "set_active_policy", "get_active_policy", "list_policies",
        "scrub_dicom", "scrub_image", "encrypt_blob", "decrypt_blob",
        "decrypt_to_tensor", "get_kms_client", "SecureImageDataset"
    ]:
        from .public_api import (
            load_policy, set_active_policy, get_active_policy, list_policies,
            scrub_dicom, scrub_image, encrypt_blob, decrypt_blob,
            decrypt_to_tensor, get_kms_client, SecureImageDataset
        )
        # Cache the imported functions in globals
        globals().update({
            'load_policy': load_policy,
            'set_active_policy': set_active_policy,
            'get_active_policy': get_active_policy,
            'list_policies': list_policies,
            'scrub_dicom': scrub_dicom,
            'scrub_image': scrub_image,
            'encrypt_blob': encrypt_blob,
            'decrypt_blob': decrypt_blob,
            'decrypt_to_tensor': decrypt_to_tensor,
            'get_kms_client': get_kms_client,
            'SecureImageDataset': SecureImageDataset
        })
        return globals()[name]
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


# For static analysis and IDE support
__all__ = [
    "load_policy", "set_active_policy", "get_active_policy", "list_policies",
    "scrub_dicom", "scrub_image", "encrypt_blob", "decrypt_blob",
    "decrypt_to_tensor", "get_kms_client", "SecureImageDataset"
]

# Package-level imports for internal use

# Main functions for common workflows

__all__ = [
    "__version__",
    "__author__",
    "__email__",
    "__license__",
    "config",
    "intake",
    "sanitize",
    "crypto",
    "audit",
    "validate",
    "loader",
    "encrypt_data",
    "decrypt_data",
    "sanitize_dicom",
    "sanitize_image",
    "to_tensor",
    "load_config",
]
