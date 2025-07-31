#!/bin/bash

# SecNode Development Environment Setup Script
# Usage: ./setup-dev.sh

set -e

echo "🚀 Setting up SecNode development environment..."

# Check if uv is installed
if ! command -v uv &> /dev/null; then
    echo "📦 Installing UV..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    source ~/.bashrc
fi

# Create virtual environment
echo "🐍 Creating virtual environment..."
if [ ! -d ".venv" ]; then
    uv venv .venv --python 3.12
    echo "✅ Virtual environment created at .venv/"
else
    echo "ℹ️  Virtual environment already exists"
fi

# Activate virtual environment
echo "🔄 Activating virtual environment..."
source .venv/bin/activate

# Install dependencies
echo "📚 Installing dependencies..."
if uv pip install -e .[dev]; then
    echo "✅ Dependencies installed successfully"
else
    echo "❌ Failed to install dependencies"
    echo "Try manually: uv pip install -e .[dev]"
    exit 1
fi

# Verify installation
echo "🧪 Verifying installation..."
if python -c "import secnode; print('✅ SecNode imported successfully')"; then
    echo "✅ Installation verified"
else
    echo "❌ Installation verification failed"
    echo "Check missing dependencies or import errors"
    exit 1
fi

# Run tests
echo "🎯 Running tests..."
if pytest tests/ -v --tb=short; then
    echo "✅ All tests passed"
else
    echo "⚠️  Some tests failed - check output above"
fi

echo ""
echo "🎉 Development environment setup complete!"
echo ""
echo "To start developing:"
echo "1. Activate environment: source .venv/bin/activate"
echo "2. Run tests: pytest tests/ -v"
echo "3. Start coding! 🚀"
echo ""
echo "See DEVELOPMENT.md for more details."