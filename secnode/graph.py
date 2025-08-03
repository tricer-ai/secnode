"""
Tricer SecNode Graph Integration

This module provides the main developer-facing components for integrating
SecNode security policies into AI agent workflows. The GuardNode and WrapperNode
classes enable seamless security enforcement in graph-based architectures
like LangGraph while remaining framework-agnostic.
"""

from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional, Union
from secnode.policies.core import BasePolicy, PolicyDecision
from secnode.state import TricerSecurityState, SecurityEvent, update_security_state


class GuardNode:
    """
    A security enforcement node for AI agent graphs.
    
    GuardNode wraps security policies and provides a standardized interface
    for integrating security checks into agent workflows. It evaluates the
    current state against configured policies and returns decisions that
    can be used for conditional routing in graph architectures.
    
    Example:
        guard = GuardNode(
            policy=AllOf([
                PromptInjectionPolicy(),
                ToolCallWhitelistPolicy(['search', 'calculator'])
            ])
        )
        
        # In a LangGraph workflow
        def security_gate(state):
            decision = guard.invoke(state)
            return {"sec_decision": decision, **state}
    """
    
    def __init__(
        self,
        policy: BasePolicy,
        name: Optional[str] = None,
        fail_open: bool = False,
    ):
        """
        Initialize the GuardNode with a security policy.
        
        Args:
            policy: The security policy to enforce
            name: Optional name for this guard node
            fail_open: If True, allow actions when policy evaluation fails
        """
        self.policy = policy
        self.name = name or f"GuardNode({policy.name})"
        self.fail_open = fail_open
        self._stats = {
            "total_checks": 0,
            "allowed": 0,
            "denied": 0,
            "approvals_required": 0,
            "errors": 0,
        }
    
    def invoke(self, state: Dict[str, Any]) -> PolicyDecision:
        """
        Evaluate the security policy against the current state.
        
        This is the main entry point for security evaluation. It runs
        the configured policy, logs the decision, and optionally syncs
        telemetry to the cloud.
        
        Args:
            state: Current agent state to evaluate
            
        Returns:
            PolicyDecision indicating whether to allow the action
        """
        self._stats["total_checks"] += 1
        
        try:
            # Run policy evaluation
            decision = self.policy.check(state)
            
            # Update statistics
            if decision.is_allowed():
                self._stats["allowed"] += 1
            elif decision.is_denied():
                self._stats["denied"] += 1
            else:  # requires approval
                self._stats["approvals_required"] += 1
            
            # Create security event for audit log
            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc).isoformat(),
                event_type="policy_check",
                policy_name=self.policy.name,
                decision=decision.decision,
                reason=decision.reason,
                metadata={
                    "guard_node": self.name,
                    "score": decision.score,
                    "policy_metadata": decision.metadata,
                }
            )
            
            # Update security state if it exists
            if isinstance(state, dict) and any(
                key in state for key in ["audit_log", "last_sec_decision"]
            ):
                update_security_state(state, event, decision.model_dump())
            
            return decision
            
        except Exception as e:
            self._stats["errors"] += 1
            
            # Create error decision
            error_decision = PolicyDecision(
                decision="ALLOW" if self.fail_open else "DENY",
                reason=f"Policy evaluation failed: {str(e)}",
                score=1.0 if not self.fail_open else 0.0,
                policy_name=self.name,
                metadata={"error": str(e), "fail_open": self.fail_open}
            )
            
            # Log error event
            error_event = SecurityEvent(
                timestamp=datetime.now(timezone.utc).isoformat(),
                event_type="policy_error", 
                policy_name=self.policy.name,
                decision=error_decision.decision,
                reason=error_decision.reason,
                metadata={"error": str(e), "guard_node": self.name}
            )
            
            if isinstance(state, dict) and any(
                key in state for key in ["audit_log", "last_sec_decision"]
            ):
                update_security_state(state, error_event, error_decision.model_dump())
            
            return error_decision
    
    def get_stats(self) -> Dict[str, Any]:
        """Get usage statistics for this guard node."""
        return {
            **self._stats,
            "success_rate": (
                (self._stats["total_checks"] - self._stats["errors"]) / 
                max(1, self._stats["total_checks"])
            ),
            "allow_rate": self._stats["allowed"] / max(1, self._stats["total_checks"]),
            "deny_rate": self._stats["denied"] / max(1, self._stats["total_checks"]),
            "approval_rate": self._stats["approvals_required"] / max(1, self._stats["total_checks"]),
        }
    
    def reset_stats(self) -> None:
        """Reset usage statistics."""
        for key in self._stats:
            self._stats[key] = 0
    
    def __call__(self, state: Dict[str, Any]) -> PolicyDecision:
        """Allow the guard node to be called like a function."""
        return self.invoke(state)
    
    def __str__(self) -> str:
        return f"GuardNode(name='{self.name}', policy='{self.policy.name}')"


class WrapperNode:
    """
    A factory for creating security-wrapped nodes in agent graphs.
    
    WrapperNode takes any callable node and a security policy, returning
    a new secured version that enforces the policy before executing the
    original node. This enables retrofitting existing nodes with security.
    
    Example:
        # Wrap an existing search function
        secure_search = WrapperNode.wrap(
            node=search_tool,
            policy=ToolCallWhitelistPolicy(['search']),
            on_deny=lambda state: {"error": "Search not allowed"}
        )
        
        # Use in workflow
        result = secure_search(state)
    """
    
    @staticmethod
    def wrap(
        node: Callable[[Dict[str, Any]], Any],
        policy: BasePolicy,
        name: Optional[str] = None,
        on_deny: Optional[Callable[[Dict[str, Any]], Any]] = None,
        on_approval_required: Optional[Callable[[Dict[str, Any]], Any]] = None,
        fail_open: bool = False,
    ) -> Callable[[Dict[str, Any]], Any]:
        """
        Wrap a node with security policy enforcement.
        
        Args:
            node: The original node/function to wrap
            policy: Security policy to enforce
            name: Optional name for the wrapper
            on_deny: Function to call when access is denied
            on_approval_required: Function to call when approval is needed
            fail_open: If True, execute node when policy evaluation fails
            
        Returns:
            A new secured version of the original node
        """
        guard = GuardNode(
            policy=policy,
            name=name or f"Wrapper({getattr(node, '__name__', 'unknown')})",
            fail_open=fail_open,
        )
        
        def wrapped_node(state: Dict[str, Any]) -> Any:
            """The security-wrapped version of the original node."""
            # Check security policy
            decision = guard.invoke(state)
            
            # Handle denial
            if decision.is_denied():
                if on_deny:
                    return on_deny(state)
                else:
                    return {
                        "error": f"Access denied by security policy: {decision.reason}",
                        "security_decision": decision.model_dump(),
                        **state
                    }
            
            # Handle approval requirement
            if decision.requires_approval():
                if on_approval_required:
                    return on_approval_required(state)
                else:
                    return {
                        "status": "pending_approval",
                        "approval_reason": decision.reason,
                        "security_decision": decision.model_dump(),
                        **state
                    }
            
            # Policy allows - execute original node
            try:
                result = node(state)
                
                # Add security metadata to result if it's a dict
                if isinstance(result, dict):
                    result["security_decision"] = decision
                
                return result
                
            except Exception as e:
                # Log execution error
                error_event = SecurityEvent(
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    event_type="node_execution_error",
                    policy_name=policy.name,
                    decision="ERROR",
                    reason=f"Node execution failed: {str(e)}",
                    metadata={"node_name": getattr(node, '__name__', 'unknown')}
                )
                
                if isinstance(state, dict) and any(
                    key in state for key in ["audit_log", "last_sec_decision"]
                ):
                    update_security_state(state, error_event)
                
                # Re-raise the exception
                raise
        
        # Preserve original function metadata
        wrapped_node.__name__ = getattr(node, '__name__', 'wrapped_node')
        wrapped_node.__doc__ = f"Security-wrapped version of {getattr(node, '__name__', 'unknown')}"
        wrapped_node._original_node = node
        wrapped_node._guard_node = guard
        
        return wrapped_node
    
    @staticmethod
    def create_conditional_router(
        policy: BasePolicy,
        allow_route: str = "allow",
        deny_route: str = "deny", 
        approval_route: str = "approval",
        name: Optional[str] = None,
    ) -> Callable[[Dict[str, Any]], str]:
        """
        Create a routing function for conditional edges in graph workflows.
        
        This creates a router that evaluates a security policy and returns
        the appropriate route name based on the decision. Perfect for
        LangGraph conditional edges.
        
        Args:
            policy: Security policy to evaluate
            allow_route: Route name when policy allows
            deny_route: Route name when policy denies
            approval_route: Route name when approval is required
            name: Optional name for the router
            
        Returns:
            A routing function that returns route names
        """
        guard = GuardNode(
            policy=policy,
            name=name or f"Router({policy.name})",
        )
        
        def router(state: Dict[str, Any]) -> str:
            """Security policy router for conditional edges."""
            decision = guard.invoke(state)
            
            if decision.is_allowed():
                return allow_route
            elif decision.is_denied():
                return deny_route
            else:  # requires approval
                return approval_route
        
        router.__name__ = f"security_router_{policy.name}"
        router._guard_node = guard
        
        return router