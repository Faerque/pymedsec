# Publishing Guide for PyMedSec

This document provides step-by-step instructions for building and publishing the PyMedSec package to PyPI.

## Prerequisites

Before publishing, ensure you have:

1. **Python 3.8+ installed**
2. **Required build tools**:
   ```bash
   pip install build twine
   ```
3. **PyPI account** with API token
4. **TestPyPI account** for testing (recommended)

## Pre-Publishing Checklist

- [ ] Version number updated in `pyproject.toml` and `setup.cfg`
- [ ] CHANGELOG.md updated with release notes
- [ ] All tests passing: `python -m pytest`
- [ ] Code formatted: `python -m black pymedsec/`
- [ ] Linting clean: `python -m flake8 pymedsec/`
- [ ] Documentation reviewed and up-to-date
- [ ] Security scan completed

## Build Process

### 1. Clean Previous Builds

```bash
# Remove old build artifacts
rm -rf build/ dist/ *.egg-info/
```

### 2. Build the Package

```bash
# Build source distribution and wheel
python -m build

# Verify build outputs
ls -la dist/
# Should show:
# pymedsec-0.1.0.tar.gz
# pymedsec-0.1.0-py3-none-any.whl
```

### 3. Validate the Build

```bash
# Check package metadata
python -m twine check dist/*

# Test installation locally
pip install dist/pymedsec-0.1.0-py3-none-any.whl

# Quick smoke test
pymedsec --help
python -c "import pymedsec; print('Import successful')"
```

## Publishing to TestPyPI (Recommended First)

### 1. Configure TestPyPI

```bash
# Create/edit ~/.pypirc
cat > ~/.pypirc << EOF
[distutils]
index-servers =
    testpypi
    pypi

[testpypi]
repository = https://test.pypi.org/legacy/
username = __token__
password = pypi-YOUR_TESTPYPI_TOKEN_HERE

[pypi]
repository = https://upload.pypi.org/legacy/
username = __token__
password = pypi-YOUR_PYPI_TOKEN_HERE
EOF

chmod 600 ~/.pypirc
```

### 2. Upload to TestPyPI

```bash
# Upload to TestPyPI
python -m twine upload --repository testpypi dist/*

# Verify upload
# Visit: https://test.pypi.org/project/pymedsec/
```

### 3. Test Installation from TestPyPI

```bash
# Create fresh virtual environment
python -m venv test_env
source test_env/bin/activate  # On Windows: test_env\Scripts\activate

# Install from TestPyPI
pip install --index-url https://test.pypi.org/simple/ \
    --extra-index-url https://pypi.org/simple/ \
    pymedsec

# Test functionality
pymedsec --help
python -c "
import pymedsec
from pymedsec.config import SecurityConfig
print('TestPyPI installation successful')
"

# Cleanup
deactivate
rm -rf test_env
```

## Publishing to Production PyPI

### 1. Final Validation

```bash
# Ensure you're publishing the right version
grep version pyproject.toml
grep version setup.cfg

# Final test run
python -m pytest -v
```

### 2. Upload to PyPI

```bash
# Upload to production PyPI
python -m twine upload dist/*

# Monitor upload progress
# Visit: https://pypi.org/project/pymedsec/
```

### 3. Verify Production Installation

```bash
# Test installation from PyPI
pip install pymedsec

# Verify CLI works
pymedsec --version
pymedsec --help

# Test basic import
python -c "
import pymedsec
from pymedsec import sanitize, crypto, audit
print('Production PyPI installation successful')
"
```

## Post-Publishing Tasks

### 1. Tag the Release

```bash
# Create git tag
git tag -a v0.1.0 -m "Release version 0.1.0"
git push origin v0.1.0
```

### 2. Update Documentation

- [ ] Update project README with new installation instructions
- [ ] Update documentation site (if applicable)
- [ ] Announce release in relevant channels

### 3. Monitor Release

- [ ] Check PyPI download statistics
- [ ] Monitor for user issues/bug reports
- [ ] Prepare for next development iteration

## Troubleshooting

### Common Build Issues

**Missing files in distribution:**

```bash
# Check MANIFEST.in includes all necessary files
python -m build --sdist
tar -tzf dist/pymedsec-0.1.0.tar.gz | head -20
```

**Import errors:**

```bash
# Ensure package structure is correct
python -c "
import sys
sys.path.insert(0, '.')
import pymedsec
print('Local import successful')
"
```

### Upload Issues

**Authentication errors:**

- Verify API token in ~/.pypirc
- Check token permissions on PyPI
- Ensure username is `__token__`

**Version conflicts:**

- Check if version already exists on PyPI
- Update version in pyproject.toml and setup.cfg
- Rebuild package

**File size limits:**

- PyPI has 100MB limit per file
- Consider excluding large test files
- Use .gitignore patterns in MANIFEST.in

## Export Control Considerations

**Important**: This package includes cryptography components subject to export controls.

### US Export Administration Regulations (EAR)

- **Classification**: ECCN 5D002 (cryptographic software)
- **License Exception**: TSU (Technology and Software Unrestricted)
- **Notification**: Required for certain destinations

### Compliance Notes

1. **Dual-Use Software**: Contains AES-256 encryption capabilities
2. **Open Source**: Publicly available software qualifies for license exceptions
3. **Commercial Use**: Organizations should review export requirements
4. **International**: Comply with local import/export regulations

### Required Notifications

When distributing to certain countries/entities:

- File notification with Bureau of Industry and Security (BIS)
- Maintain records of distributions
- Review restricted party lists

**Disclaimer**: This is not legal advice. Consult export control specialists for specific compliance requirements.

## Security Best Practices

### Token Management

```bash
# Use environment variables instead of files
export TWINE_USERNAME=__token__
export TWINE_PASSWORD=pypi-YOUR_TOKEN_HERE

# Upload without saving token
python -m twine upload --repository pypi dist/*
```

### Build Security

```bash
# Verify package contents before upload
python -m zipfile -l dist/pymedsec-0.1.0-py3-none-any.whl

# Check for sensitive files
tar -tzf dist/pymedsec-0.1.0.tar.gz | grep -E "\.(key|pem|env|secret)"
```

### Release Signing

```bash
# Sign release with GPG (optional but recommended)
gpg --detach-sign -a dist/pymedsec-0.1.0.tar.gz
python -m twine upload dist/* --sign
```

## Automation

### GitHub Actions Example

```yaml
# .github/workflows/publish.yml
name: Publish to PyPI

on:
  release:
    types: [created]

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.8'
      - name: Install dependencies
        run: |
          pip install build twine
      - name: Build package
        run: python -m build
      - name: Publish to PyPI
        env:
          TWINE_USERNAME: __token__
          TWINE_PASSWORD: ${{ secrets.PYPI_API_TOKEN }}
        run: twine upload dist/*
```

## Support

For publishing support:

- PyPI Help: https://pypi.org/help/
- Packaging Guide: https://packaging.python.org/
- Security Issues: security@example.com

---

**Last Updated**: September 2025
**Version**: 1.0
