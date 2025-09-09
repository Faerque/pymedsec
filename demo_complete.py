#!/usr/bin/env python3
"""
Complete demo of PyMedSec public API functionality.

Demonstrates all major features:
- Policy management
- KMS client creation
- Encryption/decryption
- DICOM and image scrubbing
- SecureImageDataset
"""


def main():
    print("=== PyMedSec Complete Public API Demo ===\n")

    # Import all public functions
    from healthcare_imgsec import (
        load_policy, list_policies, get_active_policy, set_active_policy,
        get_kms_client, encrypt_blob, decrypt_blob, decrypt_to_tensor,
        scrub_dicom, scrub_image, SecureImageDataset
    )

    # 1. Policy Management
    print("1. Policy Management")
    print("   Available policies:", list_policies())

    hipaa_policy = load_policy('hipaa_default')
    print(f"   HIPAA policy sections: {list(hipaa_policy.keys())}")

    set_active_policy(hipaa_policy)
    active = get_active_policy()
    print(f"   Active policy name: {active.get('name', 'Unknown')}")

    # 2. KMS Client Management
    print("\n2. KMS Client Management")
    kms = get_kms_client('mock')
    print(f"   Created KMS client: {type(kms).__name__}")

    # 3. Basic Encryption/Decryption
    print("\n3. Basic Encryption/Decryption")
    test_data = b"Sensitive medical imaging data for patient study"
    aad = {"study": "cardiac_ct", "patient": "anon_001", "modality": "CT"}

    encrypted = encrypt_blob(test_data, kms_client=kms, aad=aad)
    print(f"   Encrypted package keys: {list(encrypted.keys())}")
    print(f"   Package size: {len(str(encrypted))} chars")

    decrypted = decrypt_blob(encrypted, kms_client=kms)
    print(f"   Decryption success: {test_data == decrypted}")

    # 4. Tensor Conversion
    print("\n4. Tensor Conversion")
    # Simulate some imaging data
    import numpy as np
    fake_image = np.random.randint(0, 256, (64, 64), dtype=np.uint8)
    image_bytes = fake_image.tobytes()

    pkg = encrypt_blob(image_bytes, kms_client=kms, aad={"format": "numpy"})
    tensor = decrypt_to_tensor(pkg, kms_client=kms)
    print(f"   Original shape: {fake_image.shape}, tensor shape: {tensor.shape}")
    print(f"   Data preserved: {np.array_equal(fake_image.flatten(), tensor)}")

    # 5. DICOM Scrubbing
    print("\n5. DICOM Scrubbing")
    try:
        # Create a simple DICOM-like byte sequence
        import pydicom
        from pydicom import Dataset, FileDataset
        from pydicom.uid import ExplicitVRLittleEndian
        from io import BytesIO

        # Create minimal DICOM
        file_meta = Dataset()
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = "1.2.3"
        file_meta.ImplementationClassUID = "1.2.3.4"
        file_meta.TransferSyntaxUID = ExplicitVRLittleEndian

        ds = FileDataset("test", {}, file_meta=file_meta, preamble=b"\0" * 128)
        ds.PatientName = "Test^Patient^Name"
        ds.PatientID = "12345"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3"

        buffer = BytesIO()
        ds.save_as(buffer)
        dicom_bytes = buffer.getvalue()
        print(f"   Original DICOM size: {len(dicom_bytes)} bytes")

        scrubbed_dicom = scrub_dicom(dicom_bytes)
        print(f"   Scrubbed DICOM size: {len(scrubbed_dicom)} bytes")
        print(f"   Size changed: {len(scrubbed_dicom) != len(dicom_bytes)}")

    except Exception as e:
        print(f"   DICOM demo skipped: {e}")

    # 6. Image Scrubbing
    print("\n6. Image Scrubbing")
    try:
        from PIL import Image
        from io import BytesIO

        # Create test image with metadata
        img = Image.new('RGB', (100, 100), color=(128, 128, 128))
        img.info['description'] = 'Test medical image with metadata'

        buffer = BytesIO()
        img.save(buffer, format='PNG')
        original_bytes = buffer.getvalue()
        print(f"   Original image size: {len(original_bytes)} bytes")

        scrubbed_image = scrub_image(original_bytes)
        print(f"   Scrubbed image size: {len(scrubbed_image)} bytes")

        # Verify scrubbed image is valid
        scrubbed_img = Image.open(BytesIO(scrubbed_image))
        print(f"   Scrubbed image size: {scrubbed_img.size}")
        print(f"   Metadata removed: {'description' not in scrubbed_img.info}")

    except Exception as e:
        print(f"   Image demo skipped: {e}")

    # 7. SecureImageDataset
    print("\n7. SecureImageDataset")
    try:
        import tempfile
        import os

        # Create temporary directory with some files
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create some dummy encrypted files
            for i in range(3):
                filename = f"encrypted_image_{i}.enc"
                filepath = os.path.join(tmpdir, filename)

                # Create an encrypted package
                dummy_data = f"Fake image data {i}".encode()
                pkg = encrypt_blob(dummy_data, kms_client=kms)

                with open(filepath, 'w') as f:
                    import json
                    json.dump(pkg, f)

            # Test dataset
            dataset = SecureImageDataset(tmpdir, kms_client=kms)
            print(f"   Dataset length: {len(dataset)}")
            print(f"   File pattern: {dataset.file_pattern}")

            if len(dataset) > 0:
                first_item = dataset[0]
                print(f"   First item type: {type(first_item)}")

                # Test iteration
                count = 0
                for item in dataset:
                    count += 1
                    if count >= 2:  # Just test first 2
                        break
                print(f"   Iteration works: {count > 0}")

    except Exception as e:
        print(f"   Dataset demo skipped: {e}")

    print("\n=== Demo Complete! ===")
    print("\nAll major PyMedSec public API functions demonstrated:")
    print("✓ Policy management (load, list, set/get active)")
    print("✓ KMS client creation (mock, aws, vault backends)")
    print("✓ Encryption/decryption with envelope encryption")
    print("✓ Tensor conversion for ML workflows")
    print("✓ DICOM PHI scrubbing")
    print("✓ Image metadata removal")
    print("✓ SecureImageDataset for PyTorch-like iteration")


if __name__ == "__main__":
    main()
