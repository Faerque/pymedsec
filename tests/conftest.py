"""
Test configuration and fixtures for pymedsec package.
"""
from pymedsec.kms.mock import MockKMSAdapter
import os
import tempfile
import shutil
from pathlib import Path
import pytest
from unittest.mock import Mock, patch

# Import the package modules
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Set up required environment variables for testing
os.environ.setdefault("IMGSEC_POLICY", "mock")
os.environ.setdefault("IMGSEC_KMS_BACKEND", "mock")
os.environ.setdefault("IMGSEC_KMS_KEY_REF", "test-key")


@pytest.fixture(autouse=True)
def setup_test_environment():
    """Set up the test environment with required variables."""
    test_env = {
        "IMGSEC_POLICY": "mock",
        "IMGSEC_KMS_BACKEND": "mock",
        "IMGSEC_KMS_KEY_REF": "test-key",
        "IMGSEC_AUDIT_PATH": "./test_audit.jsonl",
        "IMGSEC_ACTOR": "test-user",
    }

    with patch.dict(os.environ, test_env):
        yield


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    temp_path = tempfile.mkdtemp()
    yield Path(temp_path)
    shutil.rmtree(temp_path)


@pytest.fixture
def mock_config():
    """Create a mock security configuration for testing."""
    config_data = {
        "encryption": {"algorithm": "AES-256-GCM", "key_size": 32, "nonce_size": 12},
        "kms": {"provider": "mock", "config": {"mock_key_id": "test-key-123"}},
        "sanitization": {
            "dicom": {
                "remove_private_tags": True,
                "remove_patient_info": True,
                "preserve_study_info": False,
            },
            "exif": {"remove_gps": True, "remove_personal": True},
        },
        "audit": {"enabled": True, "log_level": "INFO", "retention_days": 90},
        "validation": {
            "strict_mode": True,
            "max_file_size": 1073741824,  # 1GB
            "allowed_formats": ["DICOM", "PNG", "JPEG", "TIFF"],
        },
    }
    return config_data


@pytest.fixture
def mock_kms():
    """Create a mock KMS adapter for testing."""
    return MockKMSAdapter()


@pytest.fixture
def sample_dicom_metadata():
    """Sample DICOM metadata for testing sanitization."""
    return {
        # Patient Information (should be removed)
        (0x0010, 0x0010): "Smith^John^A",  # Patient Name
        (0x0010, 0x0020): "12345678",  # Patient ID
        (0x0010, 0x0030): "19850601",  # Patient Birth Date
        (0x0010, 0x0040): "M",  # Patient Sex
        # Study Information (configurable)
        (0x0020, 0x000D): "1.2.3.4.5.6.7.8.9",  # Study Instance UID
        (0x0020, 0x0010): "STU001",  # Study ID
        (0x0008, 0x0020): "20240101",  # Study Date
        (0x0008, 0x0030): "120000",  # Study Time
        # Technical Information (should be preserved)
        (0x0028, 0x0010): 512,  # Rows
        (0x0028, 0x0011): 512,  # Columns
        (0x0028, 0x0100): 16,  # Bits Allocated
        (0x0028, 0x0101): 12,  # Bits Stored
        (0x0028, 0x0102): 11,  # High Bit
        (0x0028, 0x0103): 0,  # Pixel Representation
        # Device Information (should be preserved)
        (0x0008, 0x0070): "ACME Medical",  # Manufacturer
        (0x0008, 0x1090): "MRI Scanner 3000",  # Model Name
        (0x0018, 0x0050): "5.0",  # Slice Thickness
        (0x0018, 0x0080): "120",  # Repetition Time
        # Private Tags (should be removed if configured)
        (0x7777, 0x0010): "Private Creator",
        (0x7777, 0x1001): "Private Data Value",
    }


@pytest.fixture
def sample_image_data():
    """Create sample image data for testing."""
    # Create a simple 8x8 grayscale image
    import numpy as np

    image_array = np.random.randint(0, 256, (8, 8), dtype=np.uint8)
    return image_array.tobytes()


@pytest.fixture
def sample_encrypted_package():
    """Create a sample encrypted package for testing."""
    return {
        "version": "1.0",
        "encrypted_dek": "dGVzdC1lbmNyeXB0ZWQta2V5LWRhdGE=",
        "nonce": "dGVzdC1ub25jZS0xMjM=",
        "ciphertext": "dGVzdC1jaXBoZXJ0ZXh0LWRhdGE=",
        "aad": {
            "purpose": "ml_training",
            "timestamp": "2024-01-01T00:00:00Z",
            "policy_hash": "abc123def456",
            "metadata": {
                "original_format": "DICOM",
                "image_dimensions": "512x512",
                "bit_depth": 16,
            },
        },
        "kms_context": {
            "provider": "mock",
            "key_id": "test-key-123",
            "region": "us-east-1",
        },
    }


# Test data generators
def generate_test_dicom_file(temp_dir, metadata=None):
    """Generate a test DICOM file with specified metadata."""
    try:
        import pydicom
        from pydicom.dataset import Dataset, FileDataset
        import numpy as np

        # Create basic dataset
        ds = Dataset()

        # Add required DICOM elements
        ds.PatientName = (
            metadata.get((0x0010, 0x0010), "Test^Patient")
            if metadata
            else "Test^Patient"
        )
        ds.PatientID = (
            metadata.get((0x0010, 0x0020), "TEST001") if metadata else "TEST001"
        )
        ds.StudyInstanceUID = "1.2.3.4.5.6.7.8.9.10"
        ds.SeriesInstanceUID = "1.2.3.4.5.6.7.8.9.11"
        ds.SOPInstanceUID = "1.2.3.4.5.6.7.8.9.12"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"  # CT Image Storage

        # Add image data
        ds.Rows = 8
        ds.Columns = 8
        ds.BitsAllocated = 16
        ds.BitsStored = 12
        ds.HighBit = 11
        ds.PixelRepresentation = 0
        ds.SamplesPerPixel = 1
        ds.PhotometricInterpretation = "MONOCHROME2"

        # Generate simple image data
        pixel_array = np.random.randint(0, 4096, (8, 8), dtype=np.uint16)
        ds.PixelData = pixel_array.tobytes()

        # Add metadata if provided
        if metadata:
            for tag, value in metadata.items():
                if tag not in [(0x0010, 0x0010), (0x0010, 0x0020)]:  # Skip already set
                    try:
                        ds[tag] = value
                    except Exception:
                        pass  # Skip problematic tags

        # Save to file
        file_path = temp_dir / "test_image.dcm"
        file_meta = Dataset()
        file_meta.MediaStorageSOPClassUID = ds.SOPClassUID
        file_meta.MediaStorageSOPInstanceUID = ds.SOPInstanceUID
        file_meta.ImplementationClassUID = "1.2.3.4.5.6.7.8.9.13"

        file_ds = FileDataset(
            str(file_path), ds, file_meta, is_implicit_VR=True, is_little_endian=True
        )
        file_ds.save_as(str(file_path))

        return file_path

    except ImportError:
        # If pydicom not available, create a dummy file
        file_path = temp_dir / "test_image.dcm"
        file_path.write_bytes(b"DICM" + b"dummy_dicom_data" * 100)
        return file_path


def generate_test_image_file(temp_dir, format_type="PNG"):
    """Generate a test image file in specified format."""
    try:
        from PIL import Image
        import numpy as np

        # Create a simple 8x8 RGB image
        image_array = np.random.randint(0, 256, (8, 8, 3), dtype=np.uint8)
        image = Image.fromarray(image_array, "RGB")

        # Add some EXIF data for testing
        if format_type.upper() == "JPEG":
            file_path = temp_dir / "test_image.jpg"
            image.save(str(file_path), "JPEG", quality=95)
        elif format_type.upper() == "PNG":
            file_path = temp_dir / "test_image.png"
            image.save(str(file_path), "PNG")
        elif format_type.upper() == "TIFF":
            file_path = temp_dir / "test_image.tiff"
            image.save(str(file_path), "TIFF")
        else:
            raise ValueError(f"Unsupported format: {format_type}")

        return file_path

    except ImportError:
        # If PIL not available, create a dummy file
        extension = {"PNG": ".png", "JPEG": ".jpg", "TIFF": ".tiff"}[
            format_type.upper()
        ]
        file_path = temp_dir / f"test_image{extension}"
        file_path.write_bytes(b"dummy_image_data" * 100)
        return file_path


# Mock classes for testing
class MockAuditLogger:
    """Mock audit logger for testing."""

    def __init__(self):
        self.logs = []

    def log_event(self, action, details=None):
        self.logs.append(
            {
                "action": action,
                "details": details or {},
                "timestamp": "2024-01-01T00:00:00Z",
            }
        )

    def get_logs(self):
        return self.logs

    def verify_integrity(self):
        return True


class MockImageProcessor:
    """Mock image processor for testing."""

    def __init__(self):
        self.processed_files = []

    def process_image(self, file_path, output_path=None):
        self.processed_files.append(str(file_path))
        return {"status": "success", "processed": True}


# Test utilities
def assert_no_phi_in_metadata(metadata):
    """Assert that metadata contains no PHI."""
    phi_tags = [
        (0x0010, 0x0010),  # Patient Name
        (0x0010, 0x0020),  # Patient ID
        (0x0010, 0x0030),  # Patient Birth Date
        (0x0010, 0x1000),  # Other Patient IDs
        (0x0010, 0x1001),  # Other Patient Names
    ]

    for tag in phi_tags:
        assert tag not in metadata, f"PHI tag {tag} found in sanitized metadata"


def assert_technical_metadata_preserved(original_metadata, sanitized_metadata):
    """Assert that technical metadata is preserved during sanitization."""
    technical_tags = [
        (0x0028, 0x0010),  # Rows
        (0x0028, 0x0011),  # Columns
        (0x0028, 0x0100),  # Bits Allocated
        (0x0008, 0x0070),  # Manufacturer
    ]

    for tag in technical_tags:
        if tag in original_metadata:
            assert tag in sanitized_metadata, f"Technical tag {tag} not preserved"
            assert (
                original_metadata[tag] == sanitized_metadata[tag]
            ), f"Technical tag {tag} value changed"


def create_test_audit_log_entry():
    """Create a test audit log entry."""
    return {
        "timestamp": "2024-01-01T00:00:00.000Z",
        "action": "TEST_ACTION",
        "user": "test_user@example.com",
        "resource": "test_resource.dcm",
        "outcome": "SUCCESS",
        "details": {"test": "data"},
        "signature": "test_signature_hash",
        "anchor_hash": "test_anchor_hash",
    }
