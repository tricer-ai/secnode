#!/usr/bin/env python3
"""
Test script to demonstrate lightweight Presidio configurations
that don't require downloading large NLP models.
"""

from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_analyzer.predefined_recognizers import (
    EmailRecognizer, CreditCardRecognizer, PhoneRecognizer,
    IpRecognizer, UsSsnRecognizer
)
from presidio_analyzer.nlp_engine import NlpEngineProvider
import time


def test_rule_based_only():
    """
    Test pure rule-based PII detection without any NLP models.
    Uses only regex and pattern-based recognizers.
    """
    print("=== Test: Pure Rule-based Recognizer (No NLP Model) ===")
    
    # Create a minimal registry with only rule-based recognizers
    registry = RecognizerRegistry()
    
    # Add only rule-based recognizers that don't need NLP models
    registry.add_recognizer(EmailRecognizer())
    registry.add_recognizer(CreditCardRecognizer())
    registry.add_recognizer(PhoneRecognizer())
    registry.add_recognizer(IpRecognizer())
    registry.add_recognizer(UsSsnRecognizer())
    
    # Create analyzer without NLP engine (will use a mock one)
    analyzer = AnalyzerEngine(
        registry=registry,
        nlp_engine=None,  # No NLP engine
        supported_languages=["en"]
    )
    
    test_text = """
    Contact John at john.doe@example.com
    Phone: +1-555-123-4567
    Credit Card: 4532015112830366
    SSN: 123-45-6789
    IP: 192.168.1.1
    """
    
    start_time = time.time()
    results = analyzer.analyze(text=test_text, language="en")
    end_time = time.time()
    
    print(f"Detection Results ({len(results)} entities):")
    for result in results:
        detected_text = test_text[result.start:result.end]
        print(f"  - {result.entity_type}: '{detected_text}' (confidence: {result.score:.2f})")
    
    print(f"Processing time: {(end_time - start_time)*1000:.2f}ms\n")
    return results


def test_small_spacy_model():
    """
    Test with small spaCy model (en_core_web_sm) instead of large one.
    This provides NER capabilities with minimal model size.
    """
    print("=== Test: Lightweight spaCy Model (en_core_web_sm) ===")
    
    # Configure to use small spaCy model
    configuration = {
        "nlp_engine_name": "spacy",
        "models": [
            {"lang_code": "en", "model_name": "en_core_web_sm"},
        ],
    }
    
    try:
        # Create NLP engine with small model
        provider = NlpEngineProvider(nlp_configuration=configuration)
        nlp_engine = provider.create_engine()
        
        # Create analyzer with minimal model
        analyzer = AnalyzerEngine(
            nlp_engine=nlp_engine,
            supported_languages=["en"]
        )
        
        test_text = """
        Hi, my name is John Smith and I work at Microsoft.
        You can reach me at john.smith@microsoft.com or call 555-123-4567.
        My office is located in Seattle, Washington.
        """
        
        start_time = time.time()
        results = analyzer.analyze(text=test_text, language="en")
        end_time = time.time()
        
        print(f"Detection Results ({len(results)} entities):")
        for result in results:
            detected_text = test_text[result.start:result.end]
            print(f"  - {result.entity_type}: '{detected_text}' (confidence: {result.score:.2f})")
        
        print(f"Processing time: {(end_time - start_time)*1000:.2f}ms\n")
        return results
        
    except Exception as e:
        print(f"Error: Cannot load en_core_web_sm model: {e}")
        print("You can install the lightweight model using 'python -m spacy download en_core_web_sm'\n")
        return []


def test_current_implementation():
    """
    Test the current implementation with large model for comparison.
    """
    print("=== Test: Current Implementation (Full Model) ===")
    
    try:
        analyzer = AnalyzerEngine()
        
        test_text = """
        Hi, my name is John Smith and I work at Microsoft.
        You can reach me at john.smith@microsoft.com or call 555-123-4567.
        My office is located in Seattle, Washington.
        """
        
        start_time = time.time()
        results = analyzer.analyze(text=test_text, language="en")
        end_time = time.time()
        
        print(f"Detection Results ({len(results)} entities):")
        for result in results:
            detected_text = test_text[result.start:result.end]
            print(f"  - {result.entity_type}: '{detected_text}' (confidence: {result.score:.2f})")
        
        print(f"Processing time: {(end_time - start_time)*1000:.2f}ms\n")
        return results
        
    except Exception as e:
        print(f"Error: {e}\n")
        return []


def compare_model_sizes():
    """
    Compare different model configurations and their resource usage.
    """
    print("=== Model Size Comparison ===")
    print("1. Pure rule-based recognizer: ~0MB (no model files)")
    print("2. en_core_web_sm: ~15MB (lightweight spaCy model)")
    print("3. en_core_web_md: ~40MB (medium spaCy model)")
    print("4. en_core_web_lg: ~400MB (large spaCy model)")
    print("5. en_core_web_trf: ~438MB (Transformer model)")
    print()


if __name__ == "__main__":
    print("Presidio Lightweight Configuration Test\n")
    
    compare_model_sizes()
    
    # Test different configurations
    results_rule = test_rule_based_only()
    results_small = test_small_spacy_model()
    results_current = test_current_implementation()
    
    print("=== Recommendations ===")
    print("1. Production environment: Use pure rule-based recognizer, fast and no dependencies")
    print("2. Need NER: Use en_core_web_sm, small size with NER capability")
    print("3. High accuracy: Use en_core_web_lg, but requires 400MB storage space")
    print("\nFor SecNode project, recommend using lightweight_mode parameter to switch modes.")