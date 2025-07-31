"""
Test PII Detection Policy separately since it requires spacy models.

This test can be run independently and may take longer to load.
"""

import pytest
from secnode.policies.builtin import PIIDetectionPolicy


class TestPIIDetectionPolicy:
    """Test PII detection using Presidio (requires spacy models)."""
    
    def test_clean_content(self):
        """Test clean content without PII."""
        policy = PIIDetectionPolicy()
        
        state = {
            "messages": [{"content": "I like cats and dogs"}],
            "user_input": "Tell me about machine learning"
        }
        
        decision = policy.check(state)
        assert decision.decision == "ALLOW"
        assert decision.score == 0.0
    
    def test_email_detection(self):
        """Test email detection."""
        policy = PIIDetectionPolicy(threshold=0.3, block_high_confidence=False)
        
        state = {
            "messages": [{"content": "My email is john.doe@example.com"}]
        }
        
        decision = policy.check(state)
        # Should detect email (depending on Presidio model availability)
        print(f"Email detection - Decision: {decision.decision}, Score: {decision.score}")
        print(f"Detections: {decision.metadata.get('total_detections', 0)}")
        
        # At minimum, should not crash
        assert decision is not None
        assert decision.decision in ["ALLOW", "DENY", "REQUIRE_HUMAN_APPROVAL"]
    
    def test_phone_detection(self):
        """Test phone number detection."""
        policy = PIIDetectionPolicy(entities=["PHONE_NUMBER"], threshold=0.3)
        
        state = {
            "messages": [{"content": "Call me at 555-123-4567"}]
        }
        
        decision = policy.check(state)
        print(f"Phone detection - Decision: {decision.decision}, Score: {decision.score}")
        print(f"Detections: {decision.metadata.get('total_detections', 0)}")
        
        # At minimum, should not crash
        assert decision is not None
        assert decision.decision in ["ALLOW", "DENY", "REQUIRE_HUMAN_APPROVAL"]
    
    def test_mixed_pii_content(self):
        """Test content with multiple types of PII."""
        policy = PIIDetectionPolicy(threshold=0.5, block_high_confidence=True)
        
        state = {
            "messages": [{
                "content": "Hi John Smith, your email john@example.com and phone 555-1234 are on file"
            }]
        }
        
        decision = policy.check(state)
        print(f"Mixed PII - Decision: {decision.decision}, Score: {decision.score}")
        print(f"Detections: {decision.metadata.get('total_detections', 0)}")
        print(f"Detected entities: {decision.metadata.get('detected_entities', {})}")
        
        # Should handle mixed content gracefully
        assert decision is not None
        assert isinstance(decision.score, (int, float))
        assert 0.0 <= decision.score <= 1.0
    
    def test_presidio_error_handling(self):
        """Test that policy handles Presidio errors gracefully."""
        policy = PIIDetectionPolicy()
        
        # Test with various edge cases
        edge_cases = [
            {"messages": [{"content": ""}]},  # Empty content
            {"messages": [{"content": None}]},  # None content
            {"messages": []},  # Empty messages
            {},  # Empty state
        ]
        
        for state in edge_cases:
            decision = policy.check(state)
            assert decision is not None
            assert decision.decision in ["ALLOW", "DENY", "REQUIRE_HUMAN_APPROVAL"]
            # Should default to ALLOW for edge cases
            if not any(state.values()):  # If state is empty or has empty values
                assert decision.decision == "ALLOW"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])