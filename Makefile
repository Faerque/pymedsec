.PHONY: test lint fmt clean install dev-install

# Default Python executable
PYTHON ?= python3
PIP ?= pip

# Virtual environment
VENV = .venv
VENV_BIN = $(VENV)/bin

# Development dependencies
DEV_DEPS = pytest pytest-cov black flake8 mypy types-PyYAML types-python-dateutil

install:
	$(PIP) install -e .

dev-install:
	$(PIP) install -e ".[dev,aws,vault,ocr]"

test:
	$(PYTHON) -m pytest tests/ -v --tb=short --cov=healthcare_imgsec --cov-report=term-missing

test-quick:
	$(PYTHON) -m pytest tests/ -x -v

lint:
	$(PYTHON) -m flake8 healthcare_imgsec/ tests/ --max-line-length=88 --extend-ignore=E203,W503
	$(PYTHON) -m mypy healthcare_imgsec/ --ignore-missing-imports --no-strict-optional

fmt:
	$(PYTHON) -m black healthcare_imgsec/ tests/ --line-length=88

check-fmt:
	$(PYTHON) -m black healthcare_imgsec/ tests/ --check --line-length=88

clean:
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf build/ dist/ .coverage htmlcov/ .pytest_cache/ .mypy_cache/

venv:
	$(PYTHON) -m venv $(VENV)
	$(VENV_BIN)/pip install -U pip setuptools wheel

dev-setup: venv
	$(VENV_BIN)/pip install -e ".[dev,aws,vault,ocr]"

docs:
	@echo "Generating documentation..."
	@echo "See docs/ directory for compliance documentation"

# Security checks
security:
	$(PYTHON) -m pip audit

# Full validation pipeline
validate: clean lint test security
	@echo "All validation checks passed!"

# Build distribution packages
build:
	$(PYTHON) -m build

# Upload to PyPI (requires credentials)
upload: build
	$(PYTHON) -m twine upload dist/*

# Docker targets
docker:
	docker build -t pymedsec:latest .

docker-test:
	docker run --rm pymedsec:latest make test

# CI/CD targets
ci-test: dev-install lint test

# Generate test coverage report
coverage:
	$(PYTHON) -m pytest tests/ --cov=healthcare_imgsec --cov-report=html
	@echo "Coverage report generated in htmlcov/"

# Performance testing
perf:
	$(PYTHON) -m pytest tests/test_performance.py -v

# Integration tests (requires real KMS access)
integration:
	PYMEDSEC_KMS_BACKEND=aws $(PYTHON) -m pytest tests/test_integration.py -v

# Help target
help:
	@echo "Available targets:"
	@echo "  install      - Install package in development mode"
	@echo "  dev-install  - Install with all development dependencies"
	@echo "  test         - Run all tests with coverage"
	@echo "  test-quick   - Run tests with fast failure"
	@echo "  lint         - Run linting checks"
	@echo "  fmt          - Format code with black"
	@echo "  clean        - Remove build artifacts and cache files"
	@echo "  validate     - Run full validation pipeline"
	@echo "  build        - Build distribution packages"
	@echo "  security     - Run security audit"
	@echo "  coverage     - Generate HTML coverage report"
	@echo "  help         - Show this help message"
