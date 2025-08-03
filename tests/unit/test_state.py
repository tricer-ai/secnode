"""
Unit tests for SecNode state management.

This module tests the state management functionality including
TricerSecurityState and related utilities.
"""

import pytest
from datetime import datetime

from secnode.state import (
    TricerSecurityState, 
    SecurityEvent, 
    create_security_state,
    update_security_state
)


class TestTricerSecurityState:
    """Test TricerSecurityState functionality."""
    
    def test_create_security_state(self):
        """Test creating a new security state."""
        state = create_security_state()
        
        # Check required fields
        assert "audit_log" in state
        assert "last_sec_decision" in state
        assert isinstance(state["audit_log"], list)
        assert len(state["audit_log"]) == 0
        assert state["last_sec_decision"] is None
        
        # Check optional fields with defaults
        assert state.get("risk_score") == 0.0
        assert isinstance(state.get("blocked_actions"), list)
        assert isinstance(state.get("approved_actions"), list)
        assert isinstance(state.get("pending_approvals"), list)
        assert isinstance(state.get("security_context"), dict)
    
    def test_security_state_typing(self):
        """Test that security state follows TypedDict structure."""
        state = create_security_state()
        
        # Should be able to access as dict
        assert state["audit_log"] == []
        
        # Should be able to update
        state["risk_score"] = 0.5
        assert state["risk_score"] == 0.5
        
        # Should be able to add custom fields
        state["custom_field"] = "test"
        assert state["custom_field"] == "test"


class TestSecurityEvent:
    """Test SecurityEvent functionality."""
    
    def test_security_event_creation(self):
        """Test creating a security event."""
        event = SecurityEvent(
            timestamp="2024-01-01T12:00:00Z",
            event_type="policy_check",
            policy_name="TestPolicy",
            decision="ALLOW",
            reason="Test reason"
        )
        
        assert event["timestamp"] == "2024-01-01T12:00:00Z"
        assert event["event_type"] == "policy_check"
        assert event["policy_name"] == "TestPolicy"
        assert event["decision"] == "ALLOW"
        assert event["reason"] == "Test reason"
    
    def test_security_event_with_metadata(self):
        """Test security event with metadata."""
        event = SecurityEvent(
            timestamp="2024-01-01T12:00:00Z",
            event_type="policy_check",
            policy_name="TestPolicy",
            decision="DENY",
            reason="Test reason",
            metadata={"score": 0.8, "details": "test"}
        )
        
        assert event["metadata"]["score"] == 0.8
        assert event["metadata"]["details"] == "test"


class TestUpdateSecurityState:
    """Test security state update functionality."""
    
    def test_update_with_event_only(self):
        """Test updating state with event only."""
        state = create_security_state()
        
        event = SecurityEvent(
            timestamp="2024-01-01T12:00:00Z",
            event_type="policy_check",
            policy_name="TestPolicy",
            decision="ALLOW",
            reason="Test reason"
        )
        
        updated_state = update_security_state(state, event)
        
        # Should add event to audit log
        assert len(updated_state["audit_log"]) == 1
        assert updated_state["audit_log"][0]["event_type"] == "policy_check"
        assert updated_state["audit_log"][0]["decision"] == "ALLOW"
        
        # Should not change last_sec_decision without explicit decision
        assert updated_state["last_sec_decision"] is None
    
    def test_update_with_event_and_decision(self):
        """Test updating state with event and decision."""
        state = create_security_state()
        
        event = SecurityEvent(
            timestamp="2024-01-01T12:00:00Z",
            event_type="policy_check",
            policy_name="TestPolicy",
            decision="DENY",
            reason="Test reason"
        )
        
        decision = {
            "decision": "DENY",
            "reason": "Test reason",
            "score": 0.8,
            "policy_name": "TestPolicy"
        }
        
        updated_state = update_security_state(state, event, decision)
        
        # Should add event to audit log
        assert len(updated_state["audit_log"]) == 1
        
        # Should update last decision
        assert updated_state["last_sec_decision"] == decision
        
        # Should update risk score based on decision score
        assert updated_state["risk_score"] > 0.0
    
    def test_risk_score_accumulation(self):
        """Test risk score accumulation over multiple updates."""
        state = create_security_state()
        
        # First risky decision
        event1 = SecurityEvent(
            timestamp="2024-01-01T12:00:00Z",
            event_type="policy_check",
            policy_name="TestPolicy1",
            decision="DENY",
            reason="First risk"
        )
        decision1 = {"score": 0.5}
        
        state = update_security_state(state, event1, decision1)
        first_risk = state["risk_score"]
        assert first_risk > 0.0
        
        # Second risky decision
        event2 = SecurityEvent(
            timestamp="2024-01-01T12:01:00Z",
            event_type="policy_check",
            policy_name="TestPolicy2",
            decision="DENY",
            reason="Second risk"
        )
        decision2 = {"score": 0.7}
        
        state = update_security_state(state, event2, decision2)
        second_risk = state["risk_score"]
        
        # Risk should accumulate but be capped at 1.0
        assert second_risk > first_risk
        assert second_risk <= 1.0
    
    def test_risk_score_bounds(self):
        """Test risk score bounds (0.0 to 1.0)."""
        state = create_security_state()
        
        # Very high risk decision
        event = SecurityEvent(
            timestamp="2024-01-01T12:00:00Z",
            event_type="policy_check",
            policy_name="TestPolicy",
            decision="DENY",
            reason="High risk"
        )
        decision = {"score": 10.0}  # Artificially high score
        
        state = update_security_state(state, event, decision)
        
        # Risk score should be capped at 1.0
        assert state["risk_score"] <= 1.0
        assert state["risk_score"] >= 0.0
    
    def test_multiple_events_audit_log(self):
        """Test multiple events in audit log."""
        state = create_security_state()
        
        events = [
            SecurityEvent(
                timestamp="2024-01-01T12:00:00Z",
                event_type="policy_check",
                policy_name="Policy1",
                decision="ALLOW",
                reason="First check"
            ),
            SecurityEvent(
                timestamp="2024-01-01T12:01:00Z",
                event_type="policy_check",
                policy_name="Policy2",
                decision="DENY",
                reason="Second check"
            ),
            SecurityEvent(
                timestamp="2024-01-01T12:02:00Z",
                event_type="action_blocked",
                policy_name="Policy2",
                decision="DENY",
                reason="Action blocked"
            )
        ]
        
        for event in events:
            state = update_security_state(state, event)
        
        # Should have all events in audit log
        assert len(state["audit_log"]) == 3
        
        # Events should be in order
        assert state["audit_log"][0]["reason"] == "First check"
        assert state["audit_log"][1]["reason"] == "Second check"
        assert state["audit_log"][2]["reason"] == "Action blocked"
        
        # Should have different event types
        event_types = [event["event_type"] for event in state["audit_log"]]
        assert "policy_check" in event_types
        assert "action_blocked" in event_types
    
    def test_state_immutability_safety(self):
        """Test that state updates don't cause unexpected mutations."""
        state = create_security_state()
        original_audit_log_length = len(state["audit_log"])
        
        event = SecurityEvent(
            timestamp="2024-01-01T12:00:00Z",
            event_type="policy_check",
            policy_name="TestPolicy",
            decision="ALLOW",
            reason="Test"
        )
        
        # Update should modify the state (it's designed to be mutable)
        updated_state = update_security_state(state, event)
        
        # The returned state should be the same object (mutable update)
        assert updated_state is state
        assert len(state["audit_log"]) == original_audit_log_length + 1
    
    def test_event_serialization(self):
        """Test that events can be serialized (converted to dict)."""
        event = SecurityEvent(
            timestamp="2024-01-01T12:00:00Z",
            event_type="policy_check",
            policy_name="TestPolicy",
            decision="ALLOW",
            reason="Test reason",
            metadata={"key": "value"}
        )
        
        # Should be able to convert to dict
        event_dict = dict(event)
        
        assert event_dict["timestamp"] == "2024-01-01T12:00:00Z"
        assert event_dict["event_type"] == "policy_check"
        assert event_dict["metadata"]["key"] == "value"
        
        # Should be JSON serializable
        import json
        json_str = json.dumps(event_dict)
        assert "policy_check" in json_str