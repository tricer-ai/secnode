#!/bin/bash

# Quick dependency fix script
# Usage: ./fix-deps.sh

echo "🔧 Fixing SecNode dependencies..."

# Activate virtual environment if it exists
if [ -f ".venv/bin/activate" ]; then
    echo "🔄 Activating virtual environment..."
    source .venv/bin/activate
else
    echo "❌ Virtual environment not found! Run ./setup-dev.sh first"
    exit 1
fi

# Reinstall dependencies with the new aiohttp requirement
echo "📚 Reinstalling dependencies..."
uv pip install -e .[dev] --force-reinstall

# Verify installation
echo "🧪 Verifying installation..."
if python -c "import secnode; print('✅ SecNode imported successfully')"; then
    echo "✅ Installation verified successfully!"
    
    # Test basic functionality
    echo "🧪 Testing basic functionality..."
    python -c "
from secnode.policies.builtin import PromptInjectionPolicy
policy = PromptInjectionPolicy()
print('✅ PromptInjectionPolicy imported and created successfully')

from secnode.cloud import CloudSyncer
print('✅ CloudSyncer imported successfully')

from secnode import GuardNode, WrapperNode
print('✅ Graph components imported successfully')
"
    
    echo "🎯 Running quick test..."
    pytest tests/test_all_policies.py::TestPromptInjectionPolicy::test_clean_input -v
    
else
    echo "❌ Installation verification failed"
    echo "Checking import errors..."
    python -c "import secnode" 2>&1 | head -10
fi

echo ""
echo "🎉 Dependencies fixed! You can now run:"
echo "  python tests/test_all_policies.py"
echo "  pytest tests/ -v"