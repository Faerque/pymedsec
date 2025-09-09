# Security Policy

## Supported Versions

We actively support the following versions of PyMedSec with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

**⚠️ IMPORTANT: Do NOT report security vulnerabilities through public GitHub issues.**

PyMedSec handles sensitive medical data and security vulnerabilities could impact patient privacy and healthcare compliance. Please report security issues responsibly.

### How to Report

**Email**: security@pymedsec.org

**Include the following information:**

1. **Vulnerability Type**: [e.g. encryption bypass, PHI exposure, audit bypass]
2. **Impact Assessment**: Potential impact on medical data security
3. **Reproduction Steps**: How to reproduce the vulnerability
4. **Affected Versions**: Which versions are affected
5. **Compliance Impact**: Potential HIPAA/GDPR/GxP implications

### Response Timeline

- **Acknowledgment**: Within 24 hours
- **Initial Assessment**: Within 72 hours
- **Status Updates**: Every 7 days until resolution
- **Fix Timeline**: Critical issues within 14 days, others within 30 days

### Security Disclosure Process

1. **Report received** → Acknowledgment sent
2. **Vulnerability confirmed** → Security advisory created
3. **Fix developed** → Patch testing and validation
4. **Release prepared** → Security update published
5. **Public disclosure** → CVE assigned and published (30 days after fix)

## Security Best Practices

### For Users

- **Always use the latest version** of PyMedSec
- **Secure your KMS keys** according to your cloud provider's best practices
- **Regular audit log review** for compliance monitoring
- **Test security configurations** in non-production environments first
- **PHI handling compliance** - ensure you meet your local regulations

### For Developers

- **Code review required** for all security-related changes
- **Security testing** must pass before merging
- **Dependency scanning** for known vulnerabilities
- **Secrets management** - never commit keys or credentials

## Compliance and Healthcare Security

PyMedSec is designed for healthcare environments with strict security requirements:

- **HIPAA Compliance**: Administrative, physical, and technical safeguards
- **GDPR Alignment**: Privacy by design and data protection
- **GxP Validation**: Computer system validation for regulated environments
- **CLIA Requirements**: Laboratory information management security

## Encryption and Key Management

- **Envelope Encryption**: AES-256-GCM with KMS-managed keys
- **Key Rotation**: Regular key rotation supported
- **HSM Support**: Hardware security module integration via KMS
- **Audit Logging**: All cryptographic operations are logged

## Contact

- **Security Issues**: security@pymedsec.org
- **General Support**: opensource@pymedsec.org
- **Documentation**: https://pymedsec.readthedocs.io/security/
