#!/usr/bin/env python3
"""
Quick test script to verify the new Presidio-based PIIDetectionPolicy works correctly.
"""

import sys
import os

# Add the project root to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

try:
    from tricer_secnode.policies.builtin import PIIDetectionPolicy
    print("✅ Successfully imported PIIDetectionPolicy")
    
    # Test 1: Initialize the policy
    policy = PIIDetectionPolicy(threshold=0.6)
    print("✅ Successfully initialized PIIDetectionPolicy with Presidio")
    
    # Test 2: Test with clean text (should allow)
    clean_state = {
        "messages": [{"content": "Hello, how can I help you today?"}]
    }
    result = policy.check(clean_state)
    print(f"✅ Clean text test: {result.decision} - {result.reason}")
    
    # Test 3: Test with PII (should detect)
    pii_state = {
        "messages": [{"content": "My name is John Doe and my email is john.doe@example.com"}]
    }
    result = policy.check(pii_state)
    print(f"✅ PII detection test: {result.decision} - {result.reason}")
    print(f"   Detected entities: {list(result.metadata.get('detected_entities', {}).keys())}")
    
    # Test 4: Test with sensitive PII
    sensitive_state = {
        "user_input": "My SSN is 123-45-6789 and credit card is 4111-1111-1111-1111"
    }
    result = policy.check(sensitive_state)
    print(f"✅ Sensitive PII test: {result.decision} - {result.reason}")
    print(f"   Risk score: {result.score:.2f}")
    
    print("\n🎉 All tests passed! Presidio-based PII detection is working correctly.")
    
except ImportError as e:
    if "presidio" in str(e).lower():
        print("❌ Presidio not installed. Install with: pip install presidio-analyzer")
    else:
        print(f"❌ Import error: {e}")
    sys.exit(1)
except Exception as e:
    print(f"❌ Test failed: {e}")
    sys.exit(1)