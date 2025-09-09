#!/usr/bin/env bash

# PyMedSec Package Build Script
# This script builds the package for PyPI distribution

set -e

echo "🏗️  Building PyMedSec package..."

# Clean previous builds
echo "🧹 Cleaning previous builds..."
rm -rf build/ dist/ *.egg-info/

# Install build dependencies
echo "📦 Installing build dependencies..."
python -m pip install --upgrade pip build twine

# Build the package
echo "🔨 Building package..."
python -m build

# Check the built package
echo "✅ Checking package..."
twine check dist/*

echo "📋 Build Summary:"
echo "=================="
ls -la dist/

echo ""
echo "🚀 Ready for upload!"
echo "To upload to PyPI:"
echo "  twine upload dist/*"
echo ""
echo "To upload to Test PyPI:"
echo "  twine upload --repository testpypi dist/*"
