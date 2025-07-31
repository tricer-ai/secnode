"""
Tricer SecNode State Management

This module defines the standardized state dictionary structure for SecNode.
The TricerSecurityState provides a typed, extensible foundation for security
auditing and decision tracking across AI agent workflows.
"""

from typing import Any, Dict, List, NotRequired, Optional, TypedDict


class TricerSecurityState(TypedDict, total=False):
    """
    Standard security state dictionary for Tricer SecNode.
    
    This TypedDict defines the core security-related state that should be
    maintained across agent execution. It's designed to be easily inheritable
    and extensible for specific use cases.
    
    Attributes:
        audit_log: Chronological list of security events and decisions
        last_sec_decision: Most recent security policy decision
        security_context: Additional context for security evaluation
        risk_score: Current cumulative risk assessment (0.0-1.0)
        blocked_actions: List of actions that have been blocked
        approved_actions: List of actions that have been approved
        pending_approvals: Actions awaiting human review
    """
    
    # Core required fields for security tracking
    audit_log: List[Dict[str, Any]]
    last_sec_decision: Optional[Dict[str, Any]]
    
    # Extended security context (optional)
    security_context: NotRequired[Dict[str, Any]]
    risk_score: NotRequired[float] 
    blocked_actions: NotRequired[List[str]]
    approved_actions: NotRequired[List[str]]
    pending_approvals: NotRequired[List[Dict[str, Any]]]


class SecurityEvent(TypedDict):
    """
    Standardized structure for security audit log entries.
    
    Attributes:
        timestamp: ISO timestamp of the event
        event_type: Type of security event
        policy_name: Name of the policy that generated this event
        decision: Security decision made
        reason: Human-readable explanation
        metadata: Additional event-specific data
    """
    
    timestamp: str
    event_type: str  # "policy_check", "action_blocked", "approval_requested", etc.
    policy_name: str
    decision: str  # "ALLOW", "DENY", "REQUIRE_HUMAN_APPROVAL"
    reason: str
    metadata: NotRequired[Dict[str, Any]]


def create_security_state() -> TricerSecurityState:
    """
    Factory function to create a new TricerSecurityState with sensible defaults.
    
    Returns:
        A new TricerSecurityState dictionary with initialized values
    """
    return TricerSecurityState(
        audit_log=[],
        last_sec_decision=None,
        security_context={},
        risk_score=0.0,
        blocked_actions=[],
        approved_actions=[],
        pending_approvals=[],
    )


def update_security_state(
    state: TricerSecurityState,
    event: SecurityEvent,
    decision: Optional[Dict[str, Any]] = None,
) -> TricerSecurityState:
    """
    Helper function to update security state with a new event.
    
    Args:
        state: Current security state
        event: Security event to add to audit log
        decision: Optional decision to set as last_sec_decision
        
    Returns:
        Updated security state
    """
    # Add event to audit log
    state["audit_log"].append(dict(event))
    
    # Update last decision if provided
    if decision is not None:
        state["last_sec_decision"] = decision
        
    # Update risk score based on decision
    if decision and "score" in decision:
        current_risk = state.get("risk_score", 0.0)
        new_risk = min(1.0, max(0.0, current_risk + decision["score"] * 0.1))
        state["risk_score"] = new_risk
    
    return state