"""
Test helper functions for SecNode policies.

This module provides reusable testing utilities to reduce code duplication
and standardize test patterns across the test suite.
"""

from typing import Any, Dict, List, Optional, Union
from secnode.policies.core import PolicyDecision


class PolicyTestHelper:
    """Helper class for testing security policies."""
    
    @staticmethod
    def create_test_state(
        messages: Optional[List[Union[str, Dict[str, Any]]]] = None,
        user_input: Optional[str] = None,
        query: Optional[str] = None,
        tool_calls: Optional[List[Dict[str, Any]]] = None,
        response: Optional[str] = None,
        **kwargs: Any
    ) -> Dict[str, Any]:
        """
        Create a test state dictionary with common fields.
        
        Args:
            messages: List of messages (strings or dicts with 'content' key)
            user_input: User input string
            query: Query string
            tool_calls: List of tool call dictionaries
            response: Response string
            **kwargs: Additional state fields
            
        Returns:
            Dictionary representing agent state for testing
        """
        state = {}
        
        if messages is not None:
            # Normalize messages to dict format
            normalized_messages = []
            for msg in messages:
                if isinstance(msg, str):
                    normalized_messages.append({"content": msg})
                else:
                    normalized_messages.append(msg)
            state["messages"] = normalized_messages
        
        if user_input is not None:
            state["user_input"] = user_input
            
        if query is not None:
            state["query"] = query
            
        if tool_calls is not None:
            state["tool_calls"] = tool_calls
            
        if response is not None:
            state["response"] = response
        
        # Add any additional fields
        state.update(kwargs)
        
        return state
    
    @staticmethod
    def assert_policy_decision(
        decision: PolicyDecision,
        expected_decision: str,
        min_score: Optional[float] = None,
        max_score: Optional[float] = None,
        should_have_metadata: Optional[List[str]] = None
    ) -> None:
        """
        Assert that a policy decision meets expectations.
        
        Args:
            decision: The PolicyDecision to check
            expected_decision: Expected decision ("ALLOW", "DENY", "REQUIRE_HUMAN_APPROVAL")
            min_score: Minimum expected score (optional)
            max_score: Maximum expected score (optional)
            should_have_metadata: List of metadata keys that should be present
        """
        assert decision is not None, "Decision should not be None"
        assert decision.decision == expected_decision, \
            f"Expected decision '{expected_decision}', got '{decision.decision}'"
        
        # Check score bounds
        assert 0.0 <= decision.score <= 1.0, \
            f"Score should be between 0.0 and 1.0, got {decision.score}"
        
        if min_score is not None:
            assert decision.score >= min_score, \
                f"Score {decision.score} should be >= {min_score}"
        
        if max_score is not None:
            assert decision.score <= max_score, \
                f"Score {decision.score} should be <= {max_score}"
        
        # Check required metadata
        if should_have_metadata:
            for key in should_have_metadata:
                assert key in decision.metadata, \
                    f"Metadata should contain key '{key}'"
        
        # Basic structure checks
        assert isinstance(decision.reason, str), "Reason should be a string"
        assert len(decision.reason) > 0, "Reason should not be empty"
        assert isinstance(decision.metadata, dict), "Metadata should be a dict"
        assert isinstance(decision.policy_name, str), "Policy name should be a string"
    
    @staticmethod
    def assert_allows(decision: PolicyDecision, max_score: float = 0.1) -> None:
        """Assert that a decision allows the action with low risk."""
        PolicyTestHelper.assert_policy_decision(
            decision, "ALLOW", max_score=max_score
        )
    
    @staticmethod
    def assert_denies(decision: PolicyDecision, min_score: float = 0.5) -> None:
        """Assert that a decision denies the action with significant risk."""
        PolicyTestHelper.assert_policy_decision(
            decision, "DENY", min_score=min_score
        )
    
    @staticmethod
    def assert_requires_approval(decision: PolicyDecision, min_score: float = 0.3) -> None:
        """Assert that a decision requires human approval with moderate risk."""
        PolicyTestHelper.assert_policy_decision(
            decision, "REQUIRE_HUMAN_APPROVAL", min_score=min_score
        )
    
    @staticmethod
    def create_message_state(content: str) -> Dict[str, Any]:
        """Create a simple state with a single message."""
        return PolicyTestHelper.create_test_state(messages=[content])
    
    @staticmethod
    def create_tool_call_state(tool_name: str, **arguments: Any) -> Dict[str, Any]:
        """Create a state with a single tool call."""
        tool_call = {"name": tool_name}
        if arguments:
            tool_call["arguments"] = arguments
        return PolicyTestHelper.create_test_state(tool_calls=[tool_call])
    
    @staticmethod
    def create_code_state(code: str, language: str = "python") -> Dict[str, Any]:
        """Create a state with code content."""
        return PolicyTestHelper.create_test_state(
            code=code,
            language=language
        )
    
    @staticmethod
    def create_markdown_code_state(code: str, language: str = "python") -> Dict[str, Any]:
        """Create a state with markdown-formatted code."""
        content = f"```{language}\n{code}\n```"
        return PolicyTestHelper.create_message_state(content)
    
    @staticmethod
    def run_policy_tests(policy, test_cases: List[Dict[str, Any]]) -> None:
        """
        Run a series of test cases against a policy.
        
        Args:
            policy: The policy instance to test
            test_cases: List of test case dictionaries with keys:
                - 'state': The state to test
                - 'expected': Expected decision
                - 'description': Test description (optional)
                - 'min_score': Minimum expected score (optional)
                - 'max_score': Maximum expected score (optional)
        """
        for i, test_case in enumerate(test_cases):
            state = test_case['state']
            expected = test_case['expected']
            description = test_case.get('description', f'Test case {i+1}')
            
            try:
                decision = policy.check(state)
                PolicyTestHelper.assert_policy_decision(
                    decision,
                    expected,
                    min_score=test_case.get('min_score'),
                    max_score=test_case.get('max_score')
                )
                print(f"✅ {description}: {decision.decision}")
            except Exception as e:
                print(f"❌ {description}: {e}")
                raise