#!/bin/bash

# Quick activation script for SecNode development
# Usage: source activate.sh

if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
    echo "🐍 SecNode development environment activated!"
    echo "📁 Working directory: $(pwd)"
    echo "🐍 Python: $(which python)"
    echo "📦 Packages: $(pip list | wc -l) installed"
    echo ""
    echo "💡 Quick commands:"
    echo "  pytest tests/ -v          # Run all tests"
    echo "  python tests/test_all_policies.py  # Run specific test"
    echo "  black secnode/ tests/     # Format code"
    echo "  deactivate                # Exit environment"
else
    echo "❌ Virtual environment not found!"
    echo "Run: ./setup-dev.sh to create it"
fi