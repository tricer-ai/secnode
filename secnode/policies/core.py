"""
Tricer SecNode Core Policy Framework

This module defines the fundamental policy architecture for SecNode.
All security policies inherit from BasePolicy and return PolicyDecision objects.
The framework supports policy composition through AllOf and AnyOf combinators.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Literal, Optional, Union
from pydantic import BaseModel, Field


class PolicyDecision(BaseModel):
    """
    Represents the result of a security policy evaluation.
    
    This is the standardized response format for all SecNode policies,
    providing consistent decision making across the security framework.
    
    Attributes:
        decision: The security decision (ALLOW, DENY, or REQUIRE_HUMAN_APPROVAL)
        reason: Human-readable explanation for the decision
        score: Risk/confidence score from 0.0 (safe) to 1.0 (high risk)
        metadata: Additional policy-specific information
        policy_name: Name of the policy that made this decision
    """
    
    decision: Literal["ALLOW", "DENY", "REQUIRE_HUMAN_APPROVAL"]
    reason: str
    score: float = Field(ge=0.0, le=1.0, description="Risk score from 0.0 to 1.0")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)
    policy_name: str = Field(default="unknown")
    
    def is_allowed(self) -> bool:
        """Check if the decision allows the action to proceed."""
        return self.decision == "ALLOW"
    
    def is_denied(self) -> bool:
        """Check if the decision denies the action."""
        return self.decision == "DENY"
    
    def requires_approval(self) -> bool:
        """Check if the decision requires human approval."""
        return self.decision == "REQUIRE_HUMAN_APPROVAL"


class BasePolicy(ABC):
    """
    Abstract base class for all SecNode security policies.
    
    Policies are the core building blocks of SecNode's security engine.
    Each policy evaluates a specific security concern and returns a 
    PolicyDecision indicating whether an action should be allowed.
    
    Subclasses must implement the check() method to define their
    specific security logic.
    """
    
    def __init__(self, name: Optional[str] = None, **kwargs: Any) -> None:
        """
        Initialize the policy with an optional name and configuration.
        
        Args:
            name: Human-readable name for this policy instance
            **kwargs: Policy-specific configuration parameters
        """
        self.name = name or self.__class__.__name__
        self.config = kwargs
    
    @abstractmethod
    def check(self, state: Dict[str, Any]) -> PolicyDecision:
        """
        Evaluate the security policy against the current state.
        
        This is the core method that implements the policy's security logic.
        It should analyze the provided state and return a PolicyDecision
        indicating whether the current action should be allowed.
        
        Args:
            state: Current execution state including agent context
            
        Returns:
            PolicyDecision indicating the security verdict
        """
        pass
    
    def __str__(self) -> str:
        return f"{self.__class__.__name__}(name='{self.name}')"
    
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name='{self.name}', config={self.config})"


class AllOf(BasePolicy):
    """
    Policy combinator that requires ALL child policies to allow an action.
    
    This combinator implements AND logic - if any child policy denies
    the action, the entire AllOf policy denies it. If any policy requires
    human approval, the AllOf requires approval unless another denies.
    
    Example:
        policy = AllOf([
            PromptInjectionPolicy(),
            ToolCallWhitelistPolicy(['search', 'calculator'])
        ])
    """
    
    def __init__(self, policies: List[BasePolicy], name: Optional[str] = None):
        super().__init__(name=name)
        self.policies = policies
    
    def check(self, state: Dict[str, Any]) -> PolicyDecision:
        """
        Evaluate all child policies and combine results with AND logic.
        
        Returns DENY if any policy denies, REQUIRE_HUMAN_APPROVAL if any
        policy requires approval (and none deny), otherwise ALLOW.
        """
        decisions = [policy.check(state) for policy in self.policies]
        
        # Check for any DENY decisions first
        denied_decisions = [d for d in decisions if d.is_denied()]
        if denied_decisions:
            highest_risk = max(denied_decisions, key=lambda d: d.score)
            return PolicyDecision(
                decision="DENY",
                reason=f"AllOf policy denied due to: {highest_risk.reason}",
                score=highest_risk.score,
                policy_name=self.name,
                metadata={
                    "failed_policy": highest_risk.policy_name,
                    "total_policies": len(self.policies),
                    "failed_policies": len(denied_decisions),
                }
            )
        
        # Check for any REQUIRE_HUMAN_APPROVAL decisions
        approval_decisions = [d for d in decisions if d.requires_approval()]
        if approval_decisions:
            highest_risk = max(approval_decisions, key=lambda d: d.score)
            return PolicyDecision(
                decision="REQUIRE_HUMAN_APPROVAL",
                reason=f"AllOf policy requires approval due to: {highest_risk.reason}",
                score=highest_risk.score,
                policy_name=self.name,
                metadata={
                    "requesting_policy": highest_risk.policy_name,
                    "total_policies": len(self.policies),
                    "approval_policies": len(approval_decisions),
                }
            )
        
        # All policies allowed
        avg_score = sum(d.score for d in decisions) / len(decisions)
        return PolicyDecision(
            decision="ALLOW",
            reason=f"AllOf policy allowed - all {len(self.policies)} policies passed",
            score=avg_score,
            policy_name=self.name,
            metadata={
                "total_policies": len(self.policies),
                "average_score": avg_score,
            }
        )


class AnyOf(BasePolicy):
    """
    Policy combinator that requires ANY child policy to allow an action.
    
    This combinator implements OR logic - if any child policy allows
    the action, the entire AnyOf policy allows it. Only denies if ALL
    child policies deny the action.
    
    Example:
        policy = AnyOf([
            WhitelistPolicy(['safe_user']),
            LowRiskContentPolicy(threshold=0.3)
        ])
    """
    
    def __init__(self, policies: List[BasePolicy], name: Optional[str] = None):
        super().__init__(name=name)
        self.policies = policies
    
    def check(self, state: Dict[str, Any]) -> PolicyDecision:
        """
        Evaluate all child policies and combine results with OR logic.
        
        Returns ALLOW if any policy allows, REQUIRE_HUMAN_APPROVAL if any
        policy requires approval (and none allow), otherwise DENY.
        """
        decisions = [policy.check(state) for policy in self.policies]
        
        # Check for any ALLOW decisions first
        allowed_decisions = [d for d in decisions if d.is_allowed()]
        if allowed_decisions:
            lowest_risk = min(allowed_decisions, key=lambda d: d.score)
            return PolicyDecision(
                decision="ALLOW",
                reason=f"AnyOf policy allowed due to: {lowest_risk.reason}",
                score=lowest_risk.score,
                policy_name=self.name,
                metadata={
                    "allowing_policy": lowest_risk.policy_name,
                    "total_policies": len(self.policies),
                    "allowed_policies": len(allowed_decisions),
                }
            )
        
        # Check for any REQUIRE_HUMAN_APPROVAL decisions
        approval_decisions = [d for d in decisions if d.requires_approval()]
        if approval_decisions:
            lowest_risk = min(approval_decisions, key=lambda d: d.score)
            return PolicyDecision(
                decision="REQUIRE_HUMAN_APPROVAL",
                reason=f"AnyOf policy requires approval - best option: {lowest_risk.reason}",
                score=lowest_risk.score,
                policy_name=self.name,
                metadata={
                    "requesting_policy": lowest_risk.policy_name,
                    "total_policies": len(self.policies),
                    "approval_policies": len(approval_decisions),
                }
            )
        
        # All policies denied
        highest_risk = max(decisions, key=lambda d: d.score)
        return PolicyDecision(
            decision="DENY",
            reason=f"AnyOf policy denied - all {len(self.policies)} policies failed",
            score=highest_risk.score,
            policy_name=self.name,
            metadata={
                "total_policies": len(self.policies),
                "highest_risk_reason": highest_risk.reason,
            }
        )


class NotOf(BasePolicy):
    """
    Policy combinator that negates a child policy's decision.
    
    This combinator implements NOT logic - if the child policy allows
    an action, NotOf denies it. If the child policy denies an action,
    NotOf allows it. Approval requirements are converted to denials.
    
    Example:
        policy = NotOf(BlockedDomainPolicy(['malicious.com']))
        # Now allows malicious.com but blocks everything else
    """
    
    def __init__(self, policy: BasePolicy, name: Optional[str] = None):
        super().__init__(name=name)
        self.policy = policy
    
    def check(self, state: Dict[str, Any]) -> PolicyDecision:
        """
        Evaluate the child policy and negate its decision.
        
        Converts ALLOW to DENY, DENY to ALLOW, and REQUIRE_HUMAN_APPROVAL to DENY.
        """
        decision = self.policy.check(state)
        
        if decision.is_allowed():
            return PolicyDecision(
                decision="DENY",
                reason=f"NotOf policy denied - child policy allowed: {decision.reason}",
                score=1.0 - decision.score,  # Invert risk score
                policy_name=self.name,
                metadata={
                    "child_policy": decision.policy_name,
                    "child_decision": decision.decision,
                    "child_reason": decision.reason,
                }
            )
        elif decision.is_denied():
            return PolicyDecision(
                decision="ALLOW",
                reason=f"NotOf policy allowed - child policy denied: {decision.reason}",
                score=1.0 - decision.score,  # Invert risk score
                policy_name=self.name,
                metadata={
                    "child_policy": decision.policy_name,
                    "child_decision": decision.decision,
                    "child_reason": decision.reason,
                }
            )
        else:  # requires approval - convert to deny for security
            return PolicyDecision(
                decision="DENY",
                reason=f"NotOf policy denied - child policy required approval: {decision.reason}",
                score=decision.score,  # Keep original risk score for approval cases
                policy_name=self.name,
                metadata={
                    "child_policy": decision.policy_name,
                    "child_decision": decision.decision,
                    "child_reason": decision.reason,
                }
            )