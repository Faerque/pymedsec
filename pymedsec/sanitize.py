"""
Medical image sanitization and de-identification.

Handles DICOM PHI removal, EXIF stripping, and optional OCR-based redaction
for burned-in annotations in compliance with HIPAA/GDPR requirements.
"""

import logging
import hashlib
import secrets
from datetime import datetime
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw
import pydicom
from pydicom.uid import generate_uid

from . import config
from . import audit

logger = logging.getLogger(__name__)


# DICOM tags containing PHI that must be removed/pseudonymized
PHI_TAGS = [
    # Patient Information
    (0x0010, 0x0010),  # PatientName
    (0x0010, 0x0020),  # PatientID
    (0x0010, 0x0030),  # PatientBirthDate
    (0x0010, 0x0040),  # PatientSex
    (0x0010, 0x1000),  # OtherPatientIDs
    (0x0010, 0x1001),  # OtherPatientNames
    (0x0010, 0x1010),  # PatientAge
    (0x0010, 0x1020),  # PatientSize
    (0x0010, 0x1030),  # PatientWeight
    (0x0010, 0x1040),  # PatientAddress
    (0x0010, 0x1050),  # InsurancePlanIdentification
    (0x0010, 0x1060),  # PatientMotherBirthName
    (0x0010, 0x2154),  # PatientTelephoneNumbers
    (0x0010, 0x2160),  # EthnicGroup
    (0x0010, 0x21A0),  # SmokingStatus
    (0x0010, 0x21B0),  # AdditionalPatientHistory
    (0x0010, 0x21C0),  # PregnancyStatus
    (0x0010, 0x21D0),  # LastMenstrualDate
    (0x0010, 0x21F0),  # PatientReligiousPreference
    (0x0010, 0x4000),  # PatientComments

    # Study Information
    (0x0008, 0x0020),  # StudyDate
    (0x0008, 0x0030),  # StudyTime
    (0x0008, 0x0050),  # AccessionNumber
    (0x0008, 0x0090),  # ReferringPhysicianName
    (0x0008, 0x1010),  # StationName
    (0x0008, 0x1030),  # StudyDescription
    (0x0008, 0x103E),  # SeriesDescription
    (0x0008, 0x1040),  # InstitutionalDepartmentName
    (0x0008, 0x1048),  # PhysiciansOfRecord
    (0x0008, 0x1050),  # PerformingPhysicianName
    (0x0008, 0x1060),  # NameOfPhysiciansReadingStudy
    (0x0008, 0x1070),  # OperatorsName
    (0x0008, 0x1080),  # AdmittingDiagnosesDescription
    (0x0008, 0x1155),  # ReferencedSOPInstanceUID
    (0x0008, 0x2111),  # DerivationDescription

    # Institution Information
    (0x0008, 0x0080),  # InstitutionName
    (0x0008, 0x0081),  # InstitutionAddress
    (0x0008, 0x1010),  # StationName
    (0x0032, 0x1032),  # RequestingPhysician
    (0x0032, 0x1060),  # RequestedProcedureDescription

    # Equipment Information (some may be kept for technical reasons)
    (0x0008, 0x1010),  # StationName
    (0x0018, 0x1000),  # DeviceSerialNumber
    (0x0018, 0x1020),  # SoftwareVersions
]

# Technical tags that should be preserved for ML modeling
TECHNICAL_TAGS = [
    (0x0008, 0x0060),  # Modality
    (0x0008, 0x0016),  # SOPClassUID
    (0x0020, 0x000D),  # StudyInstanceUID (will be regenerated)
    (0x0020, 0x000E),  # SeriesInstanceUID (will be regenerated)
    (0x0020, 0x0013),  # InstanceNumber
    (0x0020, 0x0032),  # ImagePositionPatient
    (0x0020, 0x0037),  # ImageOrientationPatient
    (0x0028, 0x0030),  # PixelSpacing
    (0x0018, 0x0050),  # SliceThickness
    (0x0028, 0x0004),  # PhotometricInterpretation
    (0x0028, 0x0002),  # SamplesPerPixel
    (0x0028, 0x0100),  # BitsAllocated
    (0x0028, 0x0101),  # BitsStored
    (0x0028, 0x0102),  # HighBit
    (0x0028, 0x0010),  # Rows
    (0x0028, 0x0011),  # Columns
    (0x0028, 0x1050),  # WindowCenter
    (0x0028, 0x1051),  # WindowWidth
    (0x0028, 0x1052),  # RescaleIntercept
    (0x0028, 0x1053),  # RescaleSlope
]


class DeidentificationReport:
    """Report of de-identification operations performed."""

    def __init__(self):
        self.timestamp = datetime.utcnow().isoformat() + 'Z'
        self.removed_tags = []
        self.pseudonymized_tags = []
        self.regenerated_uids = []
        self.preserved_tags = []
        self.private_tags_removed = 0
        self.ocr_redaction_performed = False
        self.ocr_redaction_regions = []
        self.burned_in_annotation_status = None

    def to_dict(self):
        """Convert report to dictionary for serialization."""
        return {
            'timestamp': self.timestamp,
            'removed_tags': self.removed_tags,
            'pseudonymized_tags': self.pseudonymized_tags,
            'regenerated_uids': self.regenerated_uids,
            'preserved_tags': self.preserved_tags,
            'private_tags_removed': self.private_tags_removed,
            'ocr_redaction_performed': self.ocr_redaction_performed,
            'ocr_redaction_regions': self.ocr_redaction_regions,
            'burned_in_annotation_status': self.burned_in_annotation_status
        }


def sanitize_dicom(dataset, pseudo_pid=None, dataset_id=None):
    """
    Sanitize DICOM dataset by removing PHI and regenerating UIDs.

    Args:
        dataset: pydicom Dataset object
        pseudo_pid: Pseudonymized patient ID to use
        dataset_id: Dataset identifier for audit logging

    Returns:
        tuple: (sanitized_dataset, deidentification_report)
    """
    cfg = config.get_config()
    sanitization_config = cfg.get_sanitization_config()

    report = DeidentificationReport()

    # Create a copy to avoid modifying original
    sanitized = dataset.copy()

    # Remove PHI tags
    _remove_phi_tags(sanitized, report, sanitization_config)

    # Remove private tags if configured
    if sanitization_config.get('dicom', {}).get('remove_private_tags', True):
        _remove_private_tags(sanitized, report)

    # Pseudonymize patient ID if provided
    if pseudo_pid:
        sanitized.PatientID = pseudo_pid
        report.pseudonymized_tags.append('PatientID')

    # Regenerate UIDs if configured
    if sanitization_config.get('dicom', {}).get('regenerate_uids', True):
        _regenerate_uids(sanitized, report)

    # Handle burned-in annotation policy
    _handle_burned_in_annotation(sanitized, report, sanitization_config)

    # Audit the sanitization operation
    audit.log_operation(
        operation='sanitize_dicom',
        outcome='success',
        dataset_id=dataset_id,
        pseudo_pid=pseudo_pid,
        details=report.to_dict()
    )

    logger.info("DICOM sanitization completed for pseudo_pid=%s", pseudo_pid)

    return sanitized, report


def _remove_phi_tags(dataset, report, sanitization_config):
    """Remove PHI tags from DICOM dataset."""
    for tag in PHI_TAGS:
        if tag in dataset:
            tag_name = dataset[tag].keyword if hasattr(
                dataset[tag], 'keyword') else str(tag)

            # Preserve technical tags if configured
            if sanitization_config.get('dicom', {}).get('preserve_technical_tags', True):
                if tag in TECHNICAL_TAGS:
                    report.preserved_tags.append(tag_name)
                    continue

            del dataset[tag]
            report.removed_tags.append(tag_name)


def _remove_private_tags(dataset, report):
    """Remove all private tags from DICOM dataset."""
    tags_to_remove = []

    for tag in dataset.keys():
        if tag.group % 2 == 1:  # Odd group numbers are private
            tags_to_remove.append(tag)

    for tag in tags_to_remove:
        del dataset[tag]
        report.private_tags_removed += 1


def _regenerate_uids(dataset, report):
    """Regenerate Study and Series Instance UIDs."""
    if hasattr(dataset, 'StudyInstanceUID'):
        old_uid = dataset.StudyInstanceUID
        dataset.StudyInstanceUID = generate_uid()
        report.regenerated_uids.append(
            f"StudyInstanceUID: {old_uid} -> {dataset.StudyInstanceUID}")

    if hasattr(dataset, 'SeriesInstanceUID'):
        old_uid = dataset.SeriesInstanceUID
        dataset.SeriesInstanceUID = generate_uid()
        report.regenerated_uids.append(
            f"SeriesInstanceUID: {old_uid} -> {dataset.SeriesInstanceUID}")


def _handle_burned_in_annotation(dataset, report, sanitization_config):
    """Handle burned-in annotation detection and redaction."""
    cfg = config.get_config()

    # Get policy for burned-in annotations
    policy = sanitization_config.get('dicom', {}).get(
        'burned_in_annotation_policy', 'strict')

    if cfg.ocr_redaction and cfg.requires_ocr_redaction():
        # Perform OCR redaction
        try:
            pixel_array = dataset.pixel_array
            redacted_array, regions = _perform_ocr_redaction(pixel_array)

            # Update pixel data if redaction was performed
            if regions:
                dataset.PixelData = redacted_array.tobytes()
                report.ocr_redaction_performed = True
                report.ocr_redaction_regions = regions
                report.burned_in_annotation_status = "REDACTED"
            else:
                report.burned_in_annotation_status = "NO"

        except Exception as e:
            logger.error("OCR redaction failed: %s", e)
            if policy == 'strict':
                raise RuntimeError("OCR redaction required but failed") from e
            else:
                report.burned_in_annotation_status = "UNKNOWN"
    else:
        # Set based on policy when OCR is not available
        if policy == 'strict':
            report.burned_in_annotation_status = "UNKNOWN"
        else:
            report.burned_in_annotation_status = "NO"

    # Set DICOM tag
    dataset.BurnedInAnnotation = report.burned_in_annotation_status


def _perform_ocr_redaction(pixel_array):
    """Perform OCR-based redaction of burned-in text."""
    cfg = config.get_config()

    if not cfg.ocr_redaction:
        return pixel_array, []

    try:
        import pytesseract
        from PIL import Image

        # Convert to PIL Image for OCR
        if pixel_array.dtype != np.uint8:
            # Normalize to uint8
            normalized = ((pixel_array - pixel_array.min()) /
                          (pixel_array.max() - pixel_array.min()) * 255).astype(np.uint8)
        else:
            normalized = pixel_array

        pil_image = Image.fromarray(normalized)

        # Perform OCR to detect text regions
        try:
            data = pytesseract.image_to_data(
                pil_image, output_type=pytesseract.Output.DICT)
        except Exception as e:
            logger.warning("OCR processing failed: %s", e)
            return pixel_array, []

        # Find text regions with high confidence
        redaction_regions = []
        confidence_threshold = 60  # Configurable threshold

        for i, conf in enumerate(data['conf']):
            if int(conf) > confidence_threshold:
                x, y, w, h = data['left'][i], data['top'][i], data['width'][i], data['height'][i]
                text = data['text'][i].strip()

                # Filter out noise and keep only potential PHI
                if len(text) > 2 and any(c.isalnum() for c in text):
                    redaction_regions.append({
                        'x': x, 'y': y, 'width': w, 'height': h,
                        'text': text, 'confidence': conf
                    })

        # Apply redaction by blacking out detected regions
        if redaction_regions:
            redacted_array = pixel_array.copy()
            for region in redaction_regions:
                x1, y1 = region['x'], region['y']
                x2, y2 = x1 + region['width'], y1 + region['height']

                # Ensure coordinates are within image bounds
                y1, y2 = max(0, y1), min(redacted_array.shape[0], y2)
                x1, x2 = max(0, x1), min(redacted_array.shape[1], x2)

                # Black out the region
                redacted_array[y1:y2, x1:x2] = 0

            logger.info("OCR redaction completed: %d regions redacted",
                        len(redaction_regions))
            return redacted_array, redaction_regions
        else:
            logger.debug("No text regions detected for redaction")
            return pixel_array, []

    except ImportError:
        logger.warning("pytesseract not available for OCR redaction")
        return pixel_array, []
    except Exception as e:
        logger.error("OCR redaction failed: %s", e)
        raise


def sanitize_image(image_path, output_path=None, dataset_id=None):
    """
    Sanitize standard image formats by removing EXIF/metadata.

    Args:
        image_path: Path to input image
        output_path: Path for sanitized output (optional)
        dataset_id: Dataset identifier for audit logging

    Returns:
        tuple: (sanitized_image_path, sanitization_report)
    """
    cfg = config.get_config()

    image_path = Path(image_path)
    if output_path is None:
        output_path = image_path.with_suffix('.sanitized' + image_path.suffix)
    else:
        output_path = Path(output_path)

    report = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'input_path': str(image_path),
        'output_path': str(output_path),
        'metadata_removed': [],
        'ocr_redaction_performed': False
    }

    try:
        # Open and process image
        with Image.open(image_path) as img:
            # Record original metadata
            if hasattr(img, 'info') and img.info:
                report['metadata_removed'] = list(img.info.keys())

            # Create clean image without metadata
            clean_img = Image.new(img.mode, img.size)
            if img.mode in ['RGB', 'RGBA', 'L']:
                clean_img.paste(img)
            else:
                # Handle other modes by converting to RGB first
                rgb_img = img.convert('RGB')
                clean_img = Image.new('RGB', img.size)
                clean_img.paste(rgb_img)

            # Perform OCR redaction if enabled
            if cfg.ocr_redaction:
                try:
                    pixel_array = np.array(clean_img)
                    redacted_array, regions = _perform_ocr_redaction(
                        pixel_array)

                    if regions:
                        clean_img = Image.fromarray(redacted_array)
                        report['ocr_redaction_performed'] = True
                        report['ocr_redaction_regions'] = regions

                except Exception as e:
                    logger.warning(
                        "OCR redaction failed for image %s: %s", image_path, e)

            # Save sanitized image
            clean_img.save(output_path, optimize=True)

        # Audit the sanitization operation
        audit.log_operation(
            operation='sanitize_image',
            outcome='success',
            dataset_id=dataset_id,
            details=report
        )

        logger.info("Image sanitization completed: %s -> %s",
                    image_path, output_path)

        return output_path, report

    except Exception as e:
        logger.error("Image sanitization failed for %s: %s", image_path, e)
        audit.log_operation(
            operation='sanitize_image',
            outcome='failure',
            dataset_id=dataset_id,
            error=str(e)
        )
        raise


def validate_sanitization(dataset_or_path, expected_phi_removed=None):
    """
    Validate that sanitization was performed correctly.

    Args:
        dataset_or_path: DICOM dataset or path to sanitized file
        expected_phi_removed: List of expected removed PHI tags

    Returns:
        dict: Validation results
    """
    if isinstance(dataset_or_path, (str, Path)):
        dataset = pydicom.dcmread(str(dataset_or_path))
    else:
        dataset = dataset_or_path

    validation_results = {
        'is_valid': True,
        'violations': [],
        'warnings': [],
        'phi_tags_present': [],
        'private_tags_present': 0
    }

    # Check for remaining PHI tags
    for tag in PHI_TAGS:
        if tag in dataset:
            tag_name = dataset[tag].keyword if hasattr(
                dataset[tag], 'keyword') else str(tag)
            validation_results['phi_tags_present'].append(tag_name)
            validation_results['violations'].append(
                f"PHI tag still present: {tag_name}")
            validation_results['is_valid'] = False

    # Check for private tags
    for tag in dataset.keys():
        if tag.group % 2 == 1:  # Private tag
            validation_results['private_tags_present'] += 1

    if validation_results['private_tags_present'] > 0:
        validation_results['warnings'].append(
            f"{validation_results['private_tags_present']} private tags still present"
        )

    # Check burned-in annotation status
    if hasattr(dataset, 'BurnedInAnnotation'):
        if dataset.BurnedInAnnotation not in ['NO', 'REDACTED']:
            validation_results['warnings'].append(
                f"BurnedInAnnotation status unclear: {dataset.BurnedInAnnotation}"
            )
    else:
        validation_results['warnings'].append("BurnedInAnnotation tag not set")

    return validation_results


def generate_pseudo_patient_id(salt=None):
    """Generate a cryptographically secure pseudonymized patient ID."""
    if salt is None:
        salt = secrets.token_hex(8)

    # Generate random component
    random_component = secrets.token_hex(8)

    # Create pseudo ID with prefix
    pseudo_id = f"PX{salt}{random_component}".upper()

    return pseudo_id


def compute_sanitization_hash(dataset_or_path):
    """Compute hash of sanitized dataset for integrity verification."""
    if isinstance(dataset_or_path, (str, Path)):
        dataset = pydicom.dcmread(str(dataset_or_path))
    else:
        dataset = dataset_or_path

    # Create reproducible hash by sorting tags and computing hash
    tag_values = []

    for tag in sorted(dataset.keys()):
        element = dataset[tag]
        if element.VR != 'SQ':  # Skip sequences for simplicity
            tag_values.append(f"{tag}:{element.value}")

    combined_str = '|'.join(tag_values)
    return hashlib.sha256(combined_str.encode('utf-8')).hexdigest()


def sanitize_dicom_bytes(dicom_bytes, pseudo_pid=None, dataset_id=None):
    """Sanitize DICOM data from bytes.
    
    Args:
        dicom_bytes (bytes): Raw DICOM data
        pseudo_pid (str, optional): Pseudonymized patient ID to use
        dataset_id (str, optional): Dataset identifier for tracking
        
    Returns:
        tuple: (sanitized_bytes, sanitization_report)
    """
    try:
        import pydicom
        from io import BytesIO
        
        # Parse DICOM from bytes
        dataset = pydicom.dcmread(BytesIO(dicom_bytes))
        
        # Sanitize the dataset
        sanitized_dataset, report = sanitize_dicom(dataset, pseudo_pid, dataset_id)
        
        # Convert back to bytes
        output_buffer = BytesIO()
        sanitized_dataset.save_as(output_buffer)
        sanitized_bytes = output_buffer.getvalue()
        
        return sanitized_bytes, report
        
    except Exception as e:
        logger.error("Failed to sanitize DICOM bytes: %s", e)
        raise RuntimeError(f"DICOM bytes sanitization failed: {e}") from e
