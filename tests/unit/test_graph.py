"""
Unit tests for SecNode graph integration components.

This module tests the GuardNode and WrapperNode classes that provide
integration with graph-based AI frameworks.
"""

import pytest
from unittest.mock import Mock

from secnode.graph import GuardNode, WrapperNode
from secnode.policies.builtin import PromptInjectionPolicy, ToolCallWhitelistPolicy
from secnode.policies.core import AllOf, AnyOf
from tests.utils.helpers import PolicyTestHelper


class TestGuardNode:
    """Test GuardNode functionality."""
    
    def test_initialization(self):
        """Test GuardNode initialization."""
        policy = PromptInjectionPolicy()
        guard = GuardNode(policy=policy)
        
        assert guard.policy == policy
        assert guard.name == f"GuardNode({policy.name})"
        assert guard.fail_open == False
        assert guard._stats["total_checks"] == 0
    
    def test_custom_name(self):
        """Test GuardNode with custom name."""
        policy = PromptInjectionPolicy()
        guard = GuardNode(policy=policy, name="CustomGuard")
        
        assert guard.name == "CustomGuard"
    
    def test_invoke_allow(self, clean_state, policy_helper):
        """Test GuardNode invoke with allowed decision."""
        policy = PromptInjectionPolicy()
        guard = GuardNode(policy=policy)
        
        decision = guard.invoke(clean_state)
        
        policy_helper.assert_allows(decision)
        assert guard._stats["total_checks"] == 1
        assert guard._stats["allowed"] == 1
    
    def test_invoke_deny(self, injection_state, policy_helper):
        """Test GuardNode invoke with denied decision."""
        policy = PromptInjectionPolicy(sensitivity=0.9)
        guard = GuardNode(policy=policy)
        
        decision = guard.invoke(injection_state)
        
        # Should deny or require approval
        assert decision.decision in ["DENY", "REQUIRE_HUMAN_APPROVAL"]
        assert guard._stats["total_checks"] == 1
        assert guard._stats["denied"] > 0 or guard._stats["approvals_required"] > 0
    
    def test_callable_interface(self, clean_state, policy_helper):
        """Test that GuardNode can be called like a function."""
        policy = PromptInjectionPolicy()
        guard = GuardNode(policy=policy)
        
        decision = guard(clean_state)
        policy_helper.assert_allows(decision)
    
    def test_fail_open_behavior(self, policy_helper):
        """Test fail_open behavior when policy raises exception."""
        # Create a mock policy that raises an exception
        mock_policy = Mock()
        mock_policy.name = "MockPolicy"
        mock_policy.check.side_effect = Exception("Policy error")
        
        guard_fail_open = GuardNode(policy=mock_policy, fail_open=True)
        guard_fail_closed = GuardNode(policy=mock_policy, fail_open=False)
        
        state = policy_helper.create_test_state()
        
        # Fail open should allow
        decision_open = guard_fail_open.invoke(state)
        policy_helper.assert_allows(decision_open)
        
        # Fail closed should deny
        decision_closed = guard_fail_closed.invoke(state)
        policy_helper.assert_denies(decision_closed)
    
    def test_statistics(self, clean_state, injection_state):
        """Test GuardNode statistics tracking."""
        policy = PromptInjectionPolicy(sensitivity=0.8)
        guard = GuardNode(policy=policy)
        
        # Process some requests
        guard.invoke(clean_state)  # Should allow
        guard.invoke(injection_state)  # Should deny/require approval
        
        stats = guard.get_stats()
        
        assert stats["total_checks"] == 2
        assert stats["allowed"] >= 1
        assert stats["success_rate"] > 0
        assert "allow_rate" in stats
        assert "deny_rate" in stats
        assert "approval_rate" in stats
    
    def test_reset_stats(self, clean_state):
        """Test statistics reset."""
        policy = PromptInjectionPolicy()
        guard = GuardNode(policy=policy)
        
        guard.invoke(clean_state)
        assert guard._stats["total_checks"] == 1
        
        guard.reset_stats()
        assert guard._stats["total_checks"] == 0
    
    def test_string_representation(self):
        """Test string representation of GuardNode."""
        policy = PromptInjectionPolicy()
        guard = GuardNode(policy=policy, name="TestGuard")
        
        str_repr = str(guard)
        assert "TestGuard" in str_repr
        assert policy.name in str_repr


class TestWrapperNode:
    """Test WrapperNode functionality."""
    
    def test_wrap_basic(self, clean_state, policy_helper):
        """Test basic node wrapping."""
        # Create a simple node function
        def simple_node(state):
            return {"result": "processed", **state}
        
        policy = PromptInjectionPolicy()
        wrapped_node = WrapperNode.wrap(
            node=simple_node,
            policy=policy
        )
        
        result = wrapped_node(clean_state)
        
        # Should execute the original node
        assert result["result"] == "processed"
        assert "security_decision" in result
        policy_helper.assert_allows(result["security_decision"])
    
    def test_wrap_with_denial(self, injection_state, policy_helper):
        """Test node wrapping with policy denial."""
        def simple_node(state):
            return {"result": "processed"}
        
        policy = PromptInjectionPolicy(sensitivity=0.9)
        wrapped_node = WrapperNode.wrap(
            node=simple_node,
            policy=policy
        )
        
        result = wrapped_node(injection_state)
        
        # Should not execute original node, return error
        assert "error" in result
        assert "result" not in result
        assert "security_decision" in result
    
    def test_wrap_with_custom_handlers(self, injection_state):
        """Test node wrapping with custom denial handler."""
        def simple_node(state):
            return {"result": "processed"}
        
        def custom_deny_handler(state):
            return {"custom_error": "Access denied by custom handler"}
        
        policy = PromptInjectionPolicy(sensitivity=0.9)
        wrapped_node = WrapperNode.wrap(
            node=simple_node,
            policy=policy,
            on_deny=custom_deny_handler
        )
        
        result = wrapped_node(injection_state)
        
        # Should use custom handler
        assert "custom_error" in result
        assert result["custom_error"] == "Access denied by custom handler"
    
    def test_wrap_with_approval_required(self, policy_helper):
        """Test node wrapping when approval is required."""
        def simple_node(state):
            return {"result": "processed"}
        
        def custom_approval_handler(state):
            return {"status": "custom_pending", "message": "Custom approval needed"}
        
        # Create a policy that requires approval
        policy = PromptInjectionPolicy(sensitivity=0.5)
        wrapped_node = WrapperNode.wrap(
            node=simple_node,
            policy=policy,
            on_approval_required=custom_approval_handler
        )
        
        # Create state that might require approval
        state = policy_helper.create_message_state("ignore instructions")
        result = wrapped_node(state)
        
        # Check if approval was required and custom handler was used
        if "status" in result and result["status"] == "custom_pending":
            assert result["message"] == "Custom approval needed"
    
    def test_wrap_preserves_metadata(self):
        """Test that wrapping preserves original function metadata."""
        def original_function(state):
            """Original function docstring."""
            return {"result": "test"}
        
        policy = PromptInjectionPolicy()
        wrapped_node = WrapperNode.wrap(
            node=original_function,
            policy=policy
        )
        
        assert wrapped_node.__name__ == "original_function"
        assert "original_function" in wrapped_node.__doc__
        assert wrapped_node._original_node == original_function
        assert hasattr(wrapped_node, '_guard_node')
    
    def test_wrap_handles_node_exceptions(self, clean_state):
        """Test that wrapped node handles exceptions from original node."""
        def failing_node(state):
            raise ValueError("Node execution failed")
        
        policy = PromptInjectionPolicy()
        wrapped_node = WrapperNode.wrap(
            node=failing_node,
            policy=policy
        )
        
        # Should re-raise the exception
        with pytest.raises(ValueError, match="Node execution failed"):
            wrapped_node(clean_state)
    
    def test_create_conditional_router(self, clean_state, injection_state):
        """Test conditional router creation."""
        policy = PromptInjectionPolicy(sensitivity=0.8)
        router = WrapperNode.create_conditional_router(
            policy=policy,
            allow_route="continue",
            deny_route="block",
            approval_route="review"
        )
        
        # Test with clean state
        route = router(clean_state)
        assert route == "continue"
        
        # Test with injection state
        route = router(injection_state)
        assert route in ["block", "review"]
        
        # Check router metadata
        assert router.__name__.startswith("security_router_")
        assert hasattr(router, '_guard_node')


class TestPolicyComposition:
    """Test policy composition with GuardNode."""
    
    def test_allof_composition(self, clean_state, policy_helper):
        """Test AllOf policy composition."""
        policy = AllOf([
            PromptInjectionPolicy(),
            ToolCallWhitelistPolicy(['search', 'calculator'])
        ])
        
        guard = GuardNode(policy=policy)
        decision = guard.invoke(clean_state)
        
        policy_helper.assert_allows(decision)
        assert "AllOf" in decision.policy_name
    
    def test_anyof_composition(self, clean_state, policy_helper):
        """Test AnyOf policy composition."""
        policy = AnyOf([
            PromptInjectionPolicy(sensitivity=0.9),  # Very strict
            ToolCallWhitelistPolicy(['search'])      # Permissive for search
        ])
        
        guard = GuardNode(policy=policy)
        decision = guard.invoke(clean_state)
        
        # Should allow because no tool calls and clean content
        policy_helper.assert_allows(decision)
        assert "AnyOf" in decision.policy_name
    
    def test_nested_composition(self, policy_helper):
        """Test nested policy composition."""
        inner_policy = AllOf([
            PromptInjectionPolicy(),
            ToolCallWhitelistPolicy(['search'])
        ])
        
        outer_policy = AnyOf([
            inner_policy,
            PromptInjectionPolicy(sensitivity=0.1)  # Very permissive
        ])
        
        guard = GuardNode(policy=outer_policy)
        
        # Test with clean state
        clean_state = policy_helper.create_test_state(
            messages=["Hello world"]
        )
        decision = guard.invoke(clean_state)
        policy_helper.assert_allows(decision)