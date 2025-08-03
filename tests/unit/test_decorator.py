"""
Tests for WrapperNode decorator functionality.
"""

import pytest
from secnode import GuardNode, WrapperNode, PromptInjectionPolicy


def test_decorator_basic():
    """Test basic decorator functionality."""
    
    @WrapperNode.protect(level="performance")
    def test_function(query: str) -> str:
        return f"Processed: {query}"
    
    # Test with safe input
    result = test_function("Hello world")
    assert "Processed: Hello world" in str(result)


def test_decorator_with_custom_policy():
    """Test decorator with custom policy."""
    
    @WrapperNode.protect(policy=PromptInjectionPolicy(sensitivity=0.5))
    def test_function(query: str) -> str:
        return f"Custom: {query}"
    
    # Test with safe input
    result = test_function("What's the weather?")
    assert "Custom: What's the weather?" in str(result)


def test_decorator_state_based():
    """Test decorator with state-based function."""
    
    @WrapperNode.protect(level="balanced")
    def test_function(state: dict) -> dict:
        return {
            **state,
            "processed": True,
            "result": f"Handled: {state.get('query', '')}"
        }
    
    # Test with state input
    state = {"query": "test query", "step": "processing"}
    result = test_function(state)
    
    assert isinstance(result, dict)
    assert result.get("processed") is True
    assert "Handled: test query" in result.get("result", "")


def test_wrappernode_integration():
    """Test integration with WrapperNode for advanced scenarios."""
    from secnode.presets import SecurityPresets
    
    def original_function(state: dict) -> str:
        return f"Original: {state.get('input', '')}"
    
    # Use WrapperNode directly for advanced control
    wrapped = WrapperNode.wrap(
        node=original_function,
        policy=SecurityPresets.performance(),
        name="TestWrapper"
    )
    
    # Test the wrapped function
    result = wrapped({"input": "test data"})
    assert "Original: test data" in str(result)


def test_factory_methods():
    """Test factory methods."""
    
    # Test different factory methods
    guards = {
        "default": GuardNode.create(),
        "performance": GuardNode.create("performance"),
        "chatbot": GuardNode.for_chatbot(),
        "search": GuardNode.for_search(),
        "enterprise": GuardNode.for_enterprise(),
    }
    
    test_state = {"query": "test", "messages": []}
    
    for name, guard in guards.items():
        decision = guard.invoke(test_state)
        assert decision.decision in ["ALLOW", "DENY", "REQUIRE_HUMAN_APPROVAL"]
        assert isinstance(decision.score, float)
        assert 0.0 <= decision.score <= 1.0


def test_decorator_error_handling():
    """Test decorator error handling."""
    
    @WrapperNode.protect(level="balanced", fail_open=True)
    def test_function(query: str) -> str:
        if query == "error":
            raise ValueError("Test error")
        return f"Success: {query}"
    
    # Test normal operation
    result = test_function("normal")
    assert "Success: normal" in str(result)
    
    # Test error handling
    with pytest.raises(ValueError):
        test_function("error")


if __name__ == "__main__":
    pytest.main([__file__])