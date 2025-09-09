"""
Tests for the sanitization module - PHI removal and metadata sanitization.
"""
import os
from unittest.mock import Mock, patch
import pytest

from pymedsec.sanitize import sanitize_dicom, sanitize_image
from pymedsec.config import SecurityConfig


class TestDicomSanitization:
    """Test cases for DICOM metadata sanitization."""

    def test_basic_phi_removal(self, mock_config, sample_dicom_metadata):
        """Test removal of basic PHI elements."""
        result = sanitize_dicom_metadata(sample_dicom_metadata, mock_config)

        # PHI should be removed
        phi_tags = [
            (0x0010, 0x0010),  # Patient Name
            (0x0010, 0x0020),  # Patient ID
            (0x0010, 0x0030),  # Patient Birth Date
        ]

        for tag in phi_tags:
            assert tag not in result, f"PHI tag {tag} was not removed"

    def test_technical_metadata_preservation(self, mock_config, sample_dicom_metadata):
        """Test that technical metadata is preserved."""
        result = sanitize_dicom_metadata(sample_dicom_metadata, mock_config)

        # Technical tags should be preserved
        technical_tags = [
            (0x0028, 0x0010),  # Rows
            (0x0028, 0x0011),  # Columns
            (0x0028, 0x0100),  # Bits Allocated
            (0x0008, 0x0070),  # Manufacturer
        ]

        for tag in technical_tags:
            if tag in sample_dicom_metadata:
                assert tag in result, f"Technical tag {tag} was removed"
                assert result[tag] == sample_dicom_metadata[
                    tag], f"Technical tag {tag} value changed"

    def test_private_tags_removal(self, mock_config, sample_dicom_metadata):
        """Test removal of private DICOM tags."""
        result = sanitize_dicom_metadata(sample_dicom_metadata, mock_config)

        # Private tags should be removed
        private_tags = [
            (0x7777, 0x0010),  # Private Creator
            (0x7777, 0x1001),  # Private Data
        ]

        for tag in private_tags:
            assert tag not in result, f"Private tag {tag} was not removed"

    def test_study_info_handling(self, mock_config, sample_dicom_metadata):
        """Test configurable study information handling."""
        # Test with preserve_study_info = False (default in mock_config)
        result = sanitize_dicom_metadata(sample_dicom_metadata, mock_config)

        # Study-related tags behavior depends on configuration
        study_tags = [
            (0x0020, 0x000D),  # Study Instance UID
            (0x0020, 0x0010),  # Study ID
        ]

        # With preserve_study_info = False, these should be removed or anonymized
        # Implementation may vary based on specific requirements
        for tag in study_tags:
            if tag in result:
                # If present, should be anonymized (different from original)
                assert result[tag] != sample_dicom_metadata[
                    tag], f"Study tag {tag} not anonymized"

    def test_empty_metadata_handling(self, mock_config):
        """Test handling of empty metadata."""
        empty_metadata = {}
        result = sanitize_dicom_metadata(empty_metadata, mock_config)

        assert result == {}

    def test_sanitization_levels(self, sample_dicom_metadata):
        """Test different sanitization levels."""
        # Mock different sanitization configurations
        basic_config = Mock()
        basic_config.get_sanitization_config.return_value = {
            'dicom': {
                'remove_private_tags': False,
                'remove_patient_info': True,
                'preserve_study_info': True
            }
        }

        aggressive_config = Mock()
        aggressive_config.get_sanitization_config.return_value = {
            'dicom': {
                'remove_private_tags': True,
                'remove_patient_info': True,
                'preserve_study_info': False
            }
        }

        basic_result = sanitize_dicom_metadata(
            sample_dicom_metadata, basic_config)
        aggressive_result = sanitize_dicom_metadata(
            sample_dicom_metadata, aggressive_config)

        # Aggressive should remove more elements than basic
        assert len(aggressive_result) <= len(basic_result)

    def test_pseudonymization(self, mock_config, sample_dicom_metadata):
        """Test patient ID pseudonymization."""
        # Configure for pseudonymization instead of removal
        mock_config.get_sanitization_config.return_value['dicom']['pseudonymize_ids'] = True

        result = sanitize_dicom_metadata(sample_dicom_metadata, mock_config)

        # Patient ID should be pseudonymized (present but different)
        if (0x0010, 0x0020) in result:
            assert result[(0x0010, 0x0020)
                          ] != sample_dicom_metadata[(0x0010, 0x0020)]
            assert len(result[(0x0010, 0x0020)]) > 0  # Should have some value


class TestExifSanitization:
    """Test cases for EXIF metadata sanitization."""

    def test_gps_removal(self, mock_config):
        """Test removal of GPS coordinates from EXIF."""
        exif_data = {
            'GPSInfo': {
                'GPSLatitude': [40, 45, 30],
                'GPSLongitude': [74, 0, 21],
                'GPSAltitude': 10
            },
            'Make': 'Canon',
            'Model': 'EOS 5D',
            'DateTime': '2024:01:01 12:00:00'
        }

        result = sanitize_exif_metadata(exif_data, mock_config)

        assert 'GPSInfo' not in result, "GPS information was not removed"

    def test_personal_info_removal(self, mock_config):
        """Test removal of personal information from EXIF."""
        exif_data = {
            'Artist': 'John Photographer',
            'Copyright': 'Copyright John Doe 2024',
            'UserComment': 'Photo taken at hospital',
            'Make': 'Canon',
            'Model': 'EOS 5D'
        }

        result = sanitize_exif_metadata(exif_data, mock_config)

        # Personal info should be removed
        personal_tags = ['Artist', 'Copyright', 'UserComment']
        for tag in personal_tags:
            assert tag not in result, f"Personal tag {tag} was not removed"

        # Technical info should be preserved
        technical_tags = ['Make', 'Model']
        for tag in technical_tags:
            if tag in exif_data:
                assert tag in result, f"Technical tag {tag} was removed"

    def test_timestamp_handling(self, mock_config):
        """Test handling of timestamp information in EXIF."""
        exif_data = {
            'DateTime': '2024:01:01 12:00:00',
            'DateTimeOriginal': '2024:01:01 11:55:00',
            'DateTimeDigitized': '2024:01:01 12:05:00'
        }

        # Configure to remove timestamps
        mock_config.get_sanitization_config.return_value['exif']['remove_timestamps'] = True

        result = sanitize_exif_metadata(exif_data, mock_config)

        timestamp_tags = ['DateTime', 'DateTimeOriginal', 'DateTimeDigitized']
        for tag in timestamp_tags:
            assert tag not in result, f"Timestamp tag {tag} was not removed"

    def test_empty_exif_handling(self, mock_config):
        """Test handling of empty EXIF data."""
        empty_exif = {}
        result = sanitize_exif_metadata(empty_exif, mock_config)

        assert result == {}


class TestImageSanitization:
    """Test cases for complete image sanitization."""

    def test_dicom_image_sanitization(self, mock_config, temp_dir):
        """Test sanitization of DICOM images."""
        # Create a test DICOM file
        dicom_file = temp_dir / "test.dcm"
        dicom_file.write_bytes(b"DICM" + b"test_dicom_data" * 100)

        with patch('pymedsec.sanitize.pydicom') as mock_pydicom:
            # Mock pydicom operations
            mock_dataset = Mock()
            mock_dataset.to_dict.return_value = {
                (0x0010, 0x0010): "Test^Patient",
                (0x0028, 0x0010): 512
            }
            mock_pydicom.dcmread.return_value = mock_dataset

            result = sanitize_image(str(dicom_file), mock_config)

            assert result['status'] == 'success'
            assert result['format'] == 'DICOM'
            assert 'sanitized_metadata' in result

    def test_non_dicom_image_sanitization(self, mock_config, temp_dir):
        """Test sanitization of non-DICOM images."""
        # Create a test PNG file
        png_file = temp_dir / "test.png"
        png_file.write_bytes(b"PNG_test_data" * 50)

        with patch('pymedsec.sanitize.Image') as mock_image:
            # Mock PIL operations
            mock_img = Mock()
            mock_img.format = "PNG"
            mock_img.info = {'Author': 'Test Author'}
            mock_image.open.return_value = mock_img

            result = sanitize_image(str(png_file), mock_config)

            assert result['status'] == 'success'
            assert result['format'] == 'PNG'

    def test_unsupported_format_handling(self, mock_config, temp_dir):
        """Test handling of unsupported file formats."""
        # Create a file with unsupported format
        unsupported_file = temp_dir / "test.xyz"
        unsupported_file.write_bytes(b"unsupported_data")

        result = sanitize_image(str(unsupported_file), mock_config)

        assert result['status'] == 'error'
        assert 'unsupported' in result['message'].lower()

    def test_corrupted_file_handling(self, mock_config, temp_dir):
        """Test handling of corrupted image files."""
        # Create a corrupted file
        corrupted_file = temp_dir / "corrupted.jpg"
        corrupted_file.write_bytes(b"corrupted_jpeg_data")

        with patch('pymedsec.sanitize.Image.open') as mock_open:
            mock_open.side_effect = Exception("Cannot identify image file")

            result = sanitize_image(str(corrupted_file), mock_config)

            assert result['status'] == 'error'
            assert 'corrupted' in result['message'].lower(
            ) or 'cannot' in result['message'].lower()

    def test_large_file_handling(self, mock_config, temp_dir):
        """Test handling of large image files."""
        # Create a large file (simulate)
        large_file = temp_dir / "large.dcm"
        large_file.write_bytes(b"DICM" + b"x" * (10 * 1024 * 1024))  # 10MB

        # Mock file size check
        with patch('os.path.getsize') as mock_getsize:
            mock_getsize.return_value = 2 * 1024 * 1024 * 1024  # 2GB

            result = sanitize_image(str(large_file), mock_config)

            # Should handle large files gracefully
            assert result['status'] in ['success', 'error']
            if result['status'] == 'error':
                assert 'size' in result['message'].lower()


class TestSanitizationSecurity:
    """Test security aspects of sanitization."""

    def test_phi_detection_completeness(self, mock_config):
        """Test that all types of PHI are detected and removed."""
        comprehensive_phi_metadata = {
            # Direct identifiers
            (0x0010, 0x0010): "Doe^John^M",           # Patient Name
            (0x0010, 0x0020): "123456789",            # Patient ID
            (0x0010, 0x0030): "19850615",             # Birth Date
            (0x0010, 0x1000): ["ALT-ID-001"],         # Other Patient IDs
            (0x0010, 0x1001): ["Doe^Johnny"],         # Other Patient Names

            # Indirect identifiers
            (0x0008, 0x0090): "Dr. Smith",            # Referring Physician
            # Name of Physician Reading Study
            (0x0008, 0x1060): "Dr. Johnson",
            (0x0010, 0x1040): "123 Main St",          # Patient Address
            (0x0010, 0x2154): "(555) 123-4567",       # Patient Phone Numbers

            # Dates (quasi-identifiers)
            (0x0008, 0x0020): "20240101",             # Study Date
            (0x0008, 0x0021): "20240101",             # Series Date
            (0x0008, 0x0023): "20240101",             # Content Date

            # Technical (should be preserved)
            (0x0028, 0x0010): 512,                    # Rows
            (0x0028, 0x0011): 512,                    # Columns
        }

        result = sanitize_dicom_metadata(
            comprehensive_phi_metadata, mock_config)

        # Verify PHI removal
        phi_tags = [
            (0x0010, 0x0010), (0x0010, 0x0020), (0x0010, 0x0030),
            (0x0010, 0x1000), (0x0010, 0x1001), (0x0008, 0x0090),
            (0x0008, 0x1060), (0x0010, 0x1040), (0x0010, 0x2154)
        ]

        for tag in phi_tags:
            assert tag not in result, f"PHI tag {tag} was not removed"

        # Verify technical preservation
        technical_tags = [(0x0028, 0x0010), (0x0028, 0x0011)]
        for tag in technical_tags:
            assert tag in result, f"Technical tag {tag} was removed"

    def test_sanitization_consistency(self, mock_config, sample_dicom_metadata):
        """Test that sanitization produces consistent results."""
        # Run sanitization multiple times
        result1 = sanitize_dicom_metadata(sample_dicom_metadata, mock_config)
        result2 = sanitize_dicom_metadata(sample_dicom_metadata, mock_config)
        result3 = sanitize_dicom_metadata(sample_dicom_metadata, mock_config)

        # Results should be identical
        assert result1 == result2 == result3

    def test_no_phi_leakage_in_errors(self, mock_config):
        """Test that error messages don't leak PHI."""
        phi_metadata = {
            (0x0010, 0x0010): "Sensitive^Patient^Name",
            (0x0010, 0x0020): "SENSITIVE-ID-123"
        }

        # Force an error condition
        with patch('pymedsec.sanitize.process_dicom_tag') as mock_process:
            mock_process.side_effect = Exception("Processing error occurred")

            try:
                sanitize_dicom_metadata(phi_metadata, mock_config)
            except Exception as e:
                error_message = str(e)
                # Error message should not contain PHI
                assert "Sensitive" not in error_message
                assert "SENSITIVE-ID-123" not in error_message

    def test_sanitization_audit_logging(self, mock_config, sample_dicom_metadata):
        """Test that sanitization operations are properly audited."""
        with patch('pymedsec.sanitize.audit_logger') as mock_audit:
            sanitize_dicom_metadata(sample_dicom_metadata, mock_config)

            # Should log sanitization operation
            mock_audit.log_event.assert_called()

            # Check audit log content doesn't contain PHI
            call_args = mock_audit.log_event.call_args
            if call_args:
                audit_data = call_args[0][0]  # First argument
                audit_str = str(audit_data)
                # Should not contain actual PHI values
                assert "Smith^John^A" not in audit_str


class TestSanitizationConfiguration:
    """Test configuration-driven sanitization behavior."""

    def test_configurable_phi_removal(self, sample_dicom_metadata):
        """Test that PHI removal can be configured."""
        # Configure to preserve some typically removed elements
        permissive_config = Mock()
        permissive_config.get_sanitization_config.return_value = {
            'dicom': {
                'remove_private_tags': False,
                'remove_patient_info': False,  # Don't remove patient info
                'preserve_study_info': True
            }
        }

        result = sanitize_dicom_metadata(
            sample_dicom_metadata, permissive_config)

        # Patient info should be preserved with this configuration
        assert (0x0010, 0x0010) in result or len(
            result) > 5  # More data preserved

    def test_strict_sanitization_mode(self, sample_dicom_metadata):
        """Test strict sanitization removes maximum PHI."""
        strict_config = Mock()
        strict_config.get_sanitization_config.return_value = {
            'dicom': {
                'remove_private_tags': True,
                'remove_patient_info': True,
                'preserve_study_info': False,
                'remove_dates': True,
                'remove_physician_info': True
            }
        }

        result = sanitize_dicom_metadata(sample_dicom_metadata, strict_config)

        # Should remove more elements in strict mode
        assert len(result) < len(sample_dicom_metadata)

        # Specific PHI should definitely be gone
        phi_tags = [
            (0x0010, 0x0010),  # Patient Name
            (0x0010, 0x0020),  # Patient ID
            (0x0008, 0x0090),  # Referring Physician
        ]

        for tag in phi_tags:
            assert tag not in result

    def test_custom_tag_handling(self, mock_config):
        """Test custom tag handling configuration."""
        custom_metadata = {
            (0x0008, 0x0080): "Custom Hospital Name",  # Institution Name
            (0x0008, 0x0081): "Custom Department",     # Institution Address
            (0x0018, 0x1000): "DEVICE-SERIAL-123",     # Device Serial Number
        }

        # Configure custom handling
        mock_config.get_sanitization_config.return_value['dicom']['custom_tag_actions'] = {
            (0x0008, 0x0080): 'remove',
            (0x0008, 0x0081): 'anonymize',
            (0x0018, 0x1000): 'preserve'
        }

        result = sanitize_dicom_metadata(custom_metadata, mock_config)

        # Check custom handling was applied
        assert (0x0008, 0x0080) not in result  # Should be removed
        assert (0x0018, 0x1000) in result      # Should be preserved

        if (0x0008, 0x0081) in result:
            # Should be anonymized (different value)
            assert result[(0x0008, 0x0081)
                          ] != custom_metadata[(0x0008, 0x0081)]
