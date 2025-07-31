#!/usr/bin/env python3
"""
Test script specifically for the lightweight mode of PIIDetectionPolicy.
"""

from secnode.policies.builtin import PIIDetectionPolicy


def test_lightweight_vs_normal():
    """
    Compare lightweight and normal modes for the same content.
    """
    print("=== Lightweight Mode vs Standard Mode Comparison Test ===\n")
    
    # Test content with various PII types
    test_state = {
        'messages': [
            {'content': 'My name is John Smith and I work at Microsoft Corporation.'},
            {'content': 'Email: john.smith@microsoft.com Phone: (555) 123-4567'},
            {'content': 'Credit Card: 4532-0151-1283-0366 SSN: 123-45-6789'},
            {'content': 'Address: 123 Main St, Seattle, WA IP: 192.168.1.100'}
        ]
    }
    
    # Test lightweight mode
    print("📱 Lightweight Mode Test (no model download):")
    lightweight_policy = PIIDetectionPolicy(
        lightweight_mode=True,
        threshold=0.5
    )
    
    lightweight_result = lightweight_policy.check(test_state)
    print(f"  Decision: {lightweight_result.decision}")
    print(f"  Risk score: {lightweight_result.score}")
    print(f"  Detected entity types:")
    for entity, info in lightweight_result.metadata.get('detected_entities', {}).items():
        print(f"    - {entity}: {info['count']}entities (max confidence: {info['max_confidence']:.2f})")
    
    print(f"  Version identifier: {lightweight_result.metadata.get('presidio_version', 'unknown')}")
    print()
    
    # Test normal mode
    print("🎯 Standard Mode Test (using ML models):")
    normal_policy = PIIDetectionPolicy(
        lightweight_mode=False,
        threshold=0.5
    )
    
    normal_result = normal_policy.check(test_state)
    print(f"  Decision: {normal_result.decision}")
    print(f"  Risk score: {normal_result.score}")
    print(f"  Detected entity types:")
    for entity, info in normal_result.metadata.get('detected_entities', {}).items():
        print(f"    - {entity}: {info['count']}entities (max confidence: {info['max_confidence']:.2f})")
    
    print(f"  Version identifier: {normal_result.metadata.get('presidio_version', 'full')}")
    print()
    
    # Compare results
    print("📊 Comparison Analysis:")
    lightweight_entities = set(lightweight_result.metadata.get('detected_entities', {}).keys())
    normal_entities = set(normal_result.metadata.get('detected_entities', {}).keys())
    
    only_in_normal = normal_entities - lightweight_entities
    only_in_lightweight = lightweight_entities - normal_entities
    common_entities = lightweight_entities & normal_entities
    
    print(f"  Commonly detected: {list(common_entities)}")
    print(f"  Only detected by standard mode: {list(only_in_normal)}")
    print(f"  Only detected by lightweight mode: {list(only_in_lightweight)}")
    print()
    
    return lightweight_result, normal_result


def test_lightweight_performance():
    """
    Test performance characteristics of lightweight mode.
    """
    print("⚡ Performance Test:")
    
    import time
    
    test_content = "Contact john.doe@example.com, phone 555-123-4567, card 4532015112830366"
    test_state = {'messages': [{'content': test_content}]}
    
    # Test lightweight mode performance
    lightweight_policy = PIIDetectionPolicy(lightweight_mode=True)
    
    start_time = time.time()
    result = lightweight_policy.check(test_state)
    end_time = time.time()
    
    print(f"  Lightweight mode processing time: {(end_time - start_time)*1000:.2f}ms")
    print(f"  Detected {len(result.metadata.get('detected_entities', {}))} entity types")
    print()


def test_entity_filtering():
    """
    Test entity filtering in lightweight mode.
    """
    print("🔍 Entity Filtering Test:")
    
    test_state = {
        'messages': [
            {'content': 'Email: test@example.com Phone: 555-1234 Card: 4532015112830366'}
        ]
    }
    
    # Test with specific entities only
    filtered_policy = PIIDetectionPolicy(
        lightweight_mode=True,
        entities=["EMAIL_ADDRESS", "CREDIT_CARD"],  # Only email and credit card
        threshold=0.5
    )
    
    result = filtered_policy.check(test_state)
    print(f"  Only detect email and credit card:")
    print(f"  Detection results: {list(result.metadata.get('detected_entities', {}).keys())}")
    print(f"  Decision: {result.decision}")
    print()


if __name__ == "__main__":
    print("PIIDetectionPolicy Lightweight Mode Detailed Test\n")
    
    # Main comparison test
    lightweight_result, normal_result = test_lightweight_vs_normal()
    
    # Performance test
    test_lightweight_performance()
    
    # Entity filtering test
    test_entity_filtering()
    
    print("=== Summary ===")
    print("✅ Lightweight Mode Advantages:")
    print("  - No need to download large ML models (saves 400MB+ storage)")
    print("  - Faster initialization time")
    print("  - Lower memory usage")
    print("  - Rule-based, predictable results")
    print()
    print("⚠️  Lightweight Mode Limitations:")
    print("  - Cannot identify named entities like person names, locations, organizations")
    print("  - Relies on predefined regex patterns")
    print("  - May have more false positives and negatives")
    print()
    print("💡 Usage Recommendations:")
    print("  - Production environment with limited resources: Use lightweight mode")
    print("  - Need high-precision NER: Use standard mode")
    print("  - Can dynamically switch modes based on deployment environment")