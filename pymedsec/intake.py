"""
Medical image intake and tensor conversion.

Handles reading various medical image formats (DICOM, PNG, JPEG, TIFF)
and converting them to normalized tensors for ML training.
"""

import logging
import hashlib
from pathlib import Path
from contextlib import contextmanager

import numpy as np
from PIL import Image
import pydicom

from . import config

logger = logging.getLogger(__name__)


class ImageReader:
    """Base class for medical image readers."""

    def __init__(self, filepath):
        self.filepath = Path(filepath)
        self.dataset = None
        self.pixel_data = None

    def __enter__(self):
        self.load()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def load(self):
        """Load image data from file."""
        raise NotImplementedError("Subclasses must implement load()")

    def close(self):
        """Clean up resources."""
        self.dataset = None
        self.pixel_data = None

    def get_pixel_array(self):
        """Get pixel data as numpy array."""
        raise NotImplementedError("Subclasses must implement get_pixel_array()")

    def get_metadata(self):
        """Get image metadata dictionary."""
        raise NotImplementedError("Subclasses must implement get_metadata()")


class DicomReader(ImageReader):
    """DICOM image reader with PHI-aware handling."""

    def load(self):
        """Load DICOM dataset from file."""
        try:
            self.dataset = pydicom.dcmread(str(self.filepath))
            logger.debug("Loaded DICOM file: %s", self.filepath)
        except Exception as e:
            logger.error("Failed to load DICOM file %s: %s", self.filepath, e)
            raise

    def get_pixel_array(self):
        """Get pixel data as numpy array."""
        if self.dataset is None:
            raise RuntimeError("Dataset not loaded")

        try:
            pixel_array = self.dataset.pixel_array

            # Handle different photometric interpretations
            photometric = getattr(self.dataset, "PhotometricInterpretation", None)
            if photometric == "MONOCHROME1":
                # Invert grayscale for MONOCHROME1
                pixel_array = np.max(pixel_array) - pixel_array

            return pixel_array
        except Exception as e:
            logger.error("Failed to extract pixel array: %s", e)
            raise

    def get_metadata(self):
        """Get DICOM metadata dictionary."""
        if self.dataset is None:
            raise RuntimeError("Dataset not loaded")

        metadata = {}

        # Safe extraction of common metadata
        safe_tags = [
            "Modality",
            "SOPClassUID",
            "StudyInstanceUID",
            "SeriesInstanceUID",
            "InstanceNumber",
            "ImageOrientationPatient",
            "ImagePositionPatient",
            "PixelSpacing",
            "SliceThickness",
            "PhotometricInterpretation",
            "SamplesPerPixel",
            "BitsAllocated",
            "BitsStored",
            "HighBit",
            "Rows",
            "Columns",
        ]

        for tag in safe_tags:
            try:
                value = getattr(self.dataset, tag, None)
                if value is not None:
                    metadata[tag] = str(value)
            except Exception:
                continue

        return metadata


class StandardImageReader(ImageReader):
    """Reader for standard image formats (PNG, JPEG, TIFF)."""

    def load(self):
        """Load image using PIL."""
        try:
            self.image = Image.open(self.filepath)
            logger.debug("Loaded image file: %s", self.filepath)
        except Exception as e:
            logger.error("Failed to load image file %s: %s", self.filepath, e)
            raise

    def close(self):
        """Clean up PIL image."""
        if hasattr(self, "image"):
            self.image.close()
        super().close()

    def get_pixel_array(self):
        """Get pixel data as numpy array."""
        if not hasattr(self, "image"):
            raise RuntimeError("Image not loaded")

        return np.array(self.image)

    def get_metadata(self):
        """Get image metadata from EXIF."""
        if not hasattr(self, "image"):
            raise RuntimeError("Image not loaded")

        metadata = {
            "format": self.image.format,
            "mode": self.image.mode,
            "size": self.image.size,
        }

        # Extract basic EXIF info (before sanitization)
        try:
            exif = self.image.getexif()
            if exif:
                metadata["has_exif"] = True
                metadata["exif_keys"] = len(exif)
            else:
                metadata["has_exif"] = False
        except Exception:
            metadata["has_exif"] = False

        return metadata


def create_reader(filepath, format_hint=None):
    """Create appropriate reader for file format."""
    filepath = Path(filepath)

    if not filepath.exists():
        raise FileNotFoundError(f"File not found: {filepath}")

    # Determine format from hint or file extension
    if format_hint:
        format_hint = format_hint.lower()
    else:
        format_hint = filepath.suffix.lower()

    if format_hint in [".dcm", ".dicom", "dicom"]:
        return DicomReader(filepath)
    elif format_hint in [
        ".png",
        ".jpg",
        ".jpeg",
        ".tiff",
        ".tif",
        "png",
        "jpeg",
        "tiff",
    ]:
        return StandardImageReader(filepath)
    else:
        # Try to detect format by reading file header
        try:
            # Try DICOM first
            pydicom.dcmread(str(filepath), force=True)
            return DicomReader(filepath)
        except Exception:
            # Fall back to PIL
            try:
                Image.open(filepath)
                return StandardImageReader(filepath)
            except Exception:
                raise ValueError(f"Unsupported image format: {filepath}")


def to_tensor(data, format_hint=None):
    """Convert image data to normalized tensor for ML training."""
    cfg = config.get_config()

    # Handle different input types
    if isinstance(data, (str, Path)):
        # File path - load and convert
        with create_reader(data, format_hint) as reader:
            pixel_array = reader.get_pixel_array()
    elif hasattr(data, "pixel_array"):
        # DICOM dataset
        pixel_array = data.pixel_array
    elif isinstance(data, np.ndarray):
        # Already a numpy array
        pixel_array = data
    else:
        raise ValueError(f"Unsupported data type for tensor conversion: {type(data)}")

    # Convert to float32 and normalize to 0-1
    if pixel_array.dtype == np.uint8:
        tensor = pixel_array.astype(np.float32) / 255.0
    elif pixel_array.dtype == np.uint16:
        tensor = pixel_array.astype(np.float32) / 65535.0
    else:
        # Already float or other type - normalize to 0-1 range
        tensor = pixel_array.astype(np.float32)
        if tensor.max() > 1.0:
            tensor = tensor / tensor.max()

    # Ensure proper channel layout for ML frameworks
    if len(tensor.shape) == 2:
        # Grayscale: (H, W) -> (1, H, W)
        tensor = tensor[np.newaxis, ...]
    elif len(tensor.shape) == 3:
        if tensor.shape[2] in [1, 3, 4]:  # (H, W, C) -> (C, H, W)
            tensor = np.transpose(tensor, (2, 0, 1))
        # else assume already in (C, H, W) format

    logger.debug(
        "Converted to tensor shape: %s, dtype: %s, range: [%.3f, %.3f]",
        tensor.shape,
        tensor.dtype,
        tensor.min(),
        tensor.max(),
    )

    return tensor


def compute_pixel_hash(pixel_data):
    """Compute SHA-256 hash of pixel data for integrity verification."""
    if isinstance(pixel_data, np.ndarray):
        # Use array bytes for hashing
        data_bytes = pixel_data.tobytes()
    else:
        # Assume it's already bytes
        data_bytes = pixel_data

    sha256_hash = hashlib.sha256(data_bytes).hexdigest()
    return f"sha256:{sha256_hash}"


def extract_modality(metadata):
    """Extract modality from image metadata."""
    if "Modality" in metadata:
        return metadata["Modality"]
    elif "format" in metadata:
        # Map common image formats to modality
        format_map = {"PNG": "OT", "JPEG": "OT", "TIFF": "OT"}  # Other
        return format_map.get(metadata["format"], "OT")
    else:
        return "OT"  # Other/Unknown


@contextmanager
def open_image(filepath, format_hint=None):
    """Context manager for opening medical images."""
    reader = create_reader(filepath, format_hint)
    try:
        reader.load()
        yield reader
    finally:
        reader.close()


def validate_image_integrity(filepath, expected_hash=None):
    """Validate image file integrity."""
    try:
        with open_image(filepath) as reader:
            pixel_array = reader.get_pixel_array()
            current_hash = compute_pixel_hash(pixel_array)

            if expected_hash and current_hash != expected_hash:
                raise ValueError(
                    f"Image integrity check failed. Expected: {expected_hash}, Got: {current_hash}"
                )

            return current_hash
    except Exception as e:
        logger.error("Image integrity validation failed for %s: %s", filepath, e)
        raise


def get_image_info(filepath, format_hint=None):
    """Get comprehensive image information for audit logging."""
    try:
        with open_image(filepath, format_hint) as reader:
            metadata = reader.get_metadata()
            pixel_array = reader.get_pixel_array()

            info = {
                "filepath": str(filepath),
                "format": format_hint or Path(filepath).suffix,
                "shape": pixel_array.shape,
                "dtype": str(pixel_array.dtype),
                "size_bytes": Path(filepath).stat().st_size,
                "pixel_hash": compute_pixel_hash(pixel_array),
                "modality": extract_modality(metadata),
                "metadata": metadata,
            }

            return info
    except Exception as e:
        logger.error("Failed to get image info for %s: %s", filepath, e)
        raise
