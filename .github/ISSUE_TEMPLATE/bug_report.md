---
name: Bug Report
about: Create a report to help us improve PyMedSec
title: '[BUG] '
labels: 'bug'
assignees: ''

---

## Bug Description
A clear and concise description of what the bug is.

## To Reproduce
Steps to reproduce the behavior:
1. Configure PyMedSec with...
2. Process image file...
3. See error...

## Expected Behavior
A clear and concise description of what you expected to happen.

## Environment
- PyMedSec version: [e.g. 0.1.0]
- Python version: [e.g. 3.11.5]
- OS: [e.g. Ubuntu 22.04]
- KMS Backend: [e.g. AWS KMS, Vault, Mock]

## Sample Code
```python
# Provide a minimal code example that reproduces the issue
from pymedsec import PyMedSec

pms = PyMedSec(policy="hipaa")
# ... your code here
```

## Error Output
```
Paste any error messages or stack traces here
```

## Additional Context
- Are you processing real medical data? (Please ensure no PHI is shared)
- File formats involved: [e.g. DICOM, PNG, JPEG]
- Compliance requirements: [e.g. HIPAA, GDPR, GxP]

## Security Considerations
- [ ] This bug does NOT involve sharing actual medical images or PHI
- [ ] I have removed any sensitive information from this report
