# Contributing to PyMedSec

Thank you for your interest in contributing to PyMedSec! This document provides guidelines for contributing to this medical image security library.

## Code of Conduct

This project adheres to a code of conduct adapted for healthcare and security contexts. By participating, you are expected to uphold this code.

## Getting Started

### Prerequisites

- Python 3.8 or higher
- Git
- Understanding of medical imaging standards (DICOM) is helpful
- Basic knowledge of cryptography and security principles

### Development Setup

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/your-username/pymedsec.git
   cd pymedsec
   ```

3. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

4. Install development dependencies:
   ```bash
   pip install -e .[dev,test,docs]
   ```

5. Install pre-commit hooks:
   ```bash
   pre-commit install
   ```

## Development Workflow

### Branch Strategy

- `main`: Production-ready code
- `develop`: Integration branch for features
- `feature/*`: Feature branches
- `hotfix/*`: Critical bug fixes

### Making Changes

1. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes following the coding standards below

3. Run tests and linting:
   ```bash
   pytest tests/
   black pymedsec/ tests/
   flake8 pymedsec/ tests/
   ```

4. Commit your changes:
   ```bash
   git commit -m "feat: add your feature description"
   ```

5. Push and create a pull request

### Commit Message Convention

We use conventional commits:

- `feat:` New features
- `fix:` Bug fixes
- `docs:` Documentation changes
- `test:` Test additions/modifications
- `refactor:` Code refactoring
- `security:` Security improvements
- `chore:` Maintenance tasks

## Coding Standards

### Python Style

- Follow PEP 8 with line length of 88 characters
- Use Black for automatic formatting
- Use type hints where possible
- Write docstrings for all public functions and classes

### Security Requirements

- All cryptographic operations must use well-established libraries
- No hardcoded secrets or keys
- Input validation for all public APIs
- Proper error handling without information leakage
- Security-focused code review required

### Medical Compliance

- HIPAA compliance considerations for PHI handling
- GDPR compliance for EU data processing
- Audit trail requirements
- Data anonymization standards

## Testing

### Test Requirements

- All new features must include tests
- Maintain >90% code coverage
- Test both positive and negative cases
- Include security test cases
- Mock external dependencies

### Running Tests

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest tests/ --cov=pymedsec --cov-report=html

# Run specific test file
pytest tests/test_crypto.py

# Run with specific markers
pytest tests/ -m "not slow"
```

### Test Categories

- Unit tests: Fast, isolated tests
- Integration tests: Component interaction tests
- Security tests: Cryptographic and security validation
- Compliance tests: HIPAA/GDPR requirement validation

## Documentation

### Documentation Requirements

- Update README.md for user-facing changes
- Add docstrings to all public APIs
- Update API documentation
- Include usage examples
- Document security considerations

### Building Documentation

```bash
cd docs/
make html
```

## Security Considerations

### Vulnerability Reporting

Please report security vulnerabilities privately. See [SECURITY.md](SECURITY.md) for details.

### Security Review Process

1. All PRs undergo security review
2. Cryptographic changes require specialist review
3. External security audit for major releases
4. Automated security scanning in CI

## Pull Request Process

### PR Requirements

1. Feature branch based on `develop`
2. All tests pass
3. Code coverage maintained
4. Documentation updated
5. Security review completed
6. At least one approved review

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update
- [ ] Security improvement

## Testing
- [ ] Tests added/updated
- [ ] All tests pass
- [ ] Security tests included

## Compliance
- [ ] HIPAA considerations reviewed
- [ ] GDPR considerations reviewed
- [ ] Audit trail preserved

## Checklist
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Changelog updated
```

## Release Process

### Version Numbering

We follow Semantic Versioning (SemVer):
- MAJOR: Breaking changes
- MINOR: New features (backward compatible)
- PATCH: Bug fixes (backward compatible)

### Release Checklist

1. Update version in `pyproject.toml`
2. Update `CHANGELOG.md`
3. Run full test suite
4. Security scan
5. Create release tag
6. Automated PyPI publish

## Community

### Getting Help

- GitHub Issues for bug reports and feature requests
- GitHub Discussions for questions and community support
- Security issues: see [SECURITY.md](SECURITY.md)

### Recognition

Contributors are recognized in:
- README.md contributor section
- Release notes
- Annual contributor acknowledgments

## Medical and Legal Disclaimers

- This software is for research and development purposes
- Not FDA approved for clinical use
- Users responsible for compliance with local regulations
- No warranty provided for medical accuracy

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.

Thank you for contributing to PyMedSec and helping improve medical data security!
