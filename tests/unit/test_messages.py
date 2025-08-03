"""
Unit tests for SecNode friendly message system.

This module tests the message formatting functionality that converts
technical policy decisions into user-friendly error messages.
"""

import pytest
from secnode.messages import MessageFormatter, FriendlyMessageBuilder, MessageSeverity


class TestMessageFormatter:
    """Test message formatting functions."""
    
    def test_format_prompt_injection_high_risk(self):
        """Test prompt injection formatting for high risk."""
        result = MessageFormatter.format_prompt_injection(
            patterns=["ignore instructions", "system prompt"],
            risk_score=0.9,
            detected_count=2
        )
        
        assert result["title"] == "Message blocked by security system"
        assert "manipulate the AI system" in result["description"]
        assert result["severity"] == "error"
        assert result["user_action"] == "Modify message content and retry"
    
    def test_format_prompt_injection_medium_risk(self):
        """Test prompt injection formatting for medium risk."""
        result = MessageFormatter.format_prompt_injection(
            patterns=["ignore"],
            risk_score=0.5,
            detected_count=1
        )
        
        assert result["title"] == "Message requires human review"
        assert "human review" in result["description"]
        assert result["severity"] == "warning"
        assert result["user_action"] == "Wait for review or rephrase"
    
    def test_format_prompt_injection_low_risk(self):
        """Test prompt injection formatting for low risk."""
        result = MessageFormatter.format_prompt_injection(
            patterns=[],
            risk_score=0.2,
            detected_count=0
        )
        
        assert result["title"] == "Potential risk content detected"
        assert result["severity"] == "info"
        assert result["user_action"] == "Check and confirm message content"
    
    def test_format_tool_blocked_single(self):
        """Test tool blocking formatting for single tool."""
        result = MessageFormatter.format_tool_blocked(
            blocked_tools=["dangerous_tool"],
            allowed_tools=["search", "calculator"]
        )
        
        assert result["title"] == "Requested function unavailable"
        assert "dangerous_tool" in result["description"]
        assert "search, calculator" in result["suggestion"]
        assert result["severity"] == "error"
    
    def test_format_tool_blocked_multiple(self):
        """Test tool blocking formatting for multiple tools."""
        result = MessageFormatter.format_tool_blocked(
            blocked_tools=["tool1", "tool2", "tool3"]
        )
        
        assert result["title"] == "Requested function unavailable"
        assert "tool1, tool2, tool3" in result["description"]
        assert result["severity"] == "error"
    
    def test_format_rate_limit(self):
        """Test rate limit formatting."""
        result = MessageFormatter.format_rate_limit(
            current=15,
            limit=10,
            window="minute"
        )
        
        assert result["title"] == "Messages sent too frequently"
        assert "15 messages" in result["description"]
        assert "limit of 10" in result["description"]
        assert "minute" in result["description"]
        assert result["severity"] == "warning"
    
    def test_format_pii_detected_high_confidence(self):
        """Test PII detection formatting for high confidence."""
        result = MessageFormatter.format_pii_detected(
            entities=["PERSON", "EMAIL_ADDRESS"],
            confidence=0.9
        )
        
        assert result["title"] == "Personal sensitive information detected"
        assert "name, email address" in result["description"]
        assert result["severity"] == "error"
        assert "Remove personal information and retry" in result["user_action"]
    
    def test_format_pii_detected_low_confidence(self):
        """Test PII detection formatting for low confidence."""
        result = MessageFormatter.format_pii_detected(
            entities=["PHONE_NUMBER"],
            confidence=0.5
        )
        
        assert result["title"] == "May contain personal information"
        assert "phone number" in result["description"]
        assert result["severity"] == "warning"
    
    def test_format_code_execution_blocked_with_patterns(self):
        """Test code execution blocking with dangerous patterns."""
        result = MessageFormatter.format_code_execution_blocked(
            language="python",
            dangerous_patterns=["file_operation", "system_call"]
        )
        
        assert result["title"] == "Code execution blocked"
        assert "python" in result["description"]
        assert "security risks" in result["description"]
        assert result["severity"] == "error"
    
    def test_format_code_execution_blocked_language_not_supported(self):
        """Test code execution blocking for unsupported language."""
        result = MessageFormatter.format_code_execution_blocked(
            language="javascript"
        )
        
        assert result["title"] == "Code execution blocked"
        assert "javascript" in result["description"]
        assert "not supported" in result["description"]
        assert result["severity"] == "error"
    
    def test_format_content_too_long(self):
        """Test content length formatting."""
        result = MessageFormatter.format_content_too_long(
            current_length=1500,
            max_length=1000,
            content_type="message"
        )
        
        assert result["title"] == "Message content too long"
        assert "1500 characters" in result["description"]
        assert "1000 characters" in result["description"]
        assert result["severity"] == "error"
    
    def test_format_url_blocked_single(self):
        """Test URL blocking formatting for single URL."""
        result = MessageFormatter.format_url_blocked(
            urls=["https://malicious.com"],
            reason="security policy"
        )
        
        assert result["title"] == "Link access restricted"
        assert "https://malicious.com" in result["description"]
        assert "security policy" in result["description"]
        assert result["severity"] == "warning"
    
    def test_format_url_blocked_multiple(self):
        """Test URL blocking formatting for multiple URLs."""
        result = MessageFormatter.format_url_blocked(
            urls=["url1", "url2", "url3"]
        )
        
        assert result["title"] == "Link access restricted"
        assert "3 links" in result["description"]
        assert result["severity"] == "warning"
    
    def test_format_keyword_filtered_high_severity(self):
        """Test keyword filtering for high severity."""
        result = MessageFormatter.format_keyword_filtered(
            keywords=["malware"],
            severity="high"
        )
        
        assert result["title"] == "Message contains inappropriate content"
        assert result["severity"] == "error"
        assert "civilized and polite" in result["suggestion"]
    
    def test_format_keyword_filtered_medium_severity(self):
        """Test keyword filtering for medium severity."""
        result = MessageFormatter.format_keyword_filtered(
            keywords=["spam"],
            severity="medium"
        )
        
        assert result["title"] == "Message content needs attention"
        assert result["severity"] == "warning"
    
    def test_format_data_leakage(self):
        """Test data leakage formatting."""
        result = MessageFormatter.format_data_leakage(
            leak_types=["system_path", "network_info"]
        )
        
        assert result["title"] == "Sensitive information leakage detected"
        assert "system path, network information" in result["description"]
        assert result["severity"] == "critical"
    
    def test_format_confidential_data_with_secrets(self):
        """Test confidential data formatting with secrets."""
        result = MessageFormatter.format_confidential_data(
            markers=["CONFIDENTIAL"],
            secret_count=2
        )
        
        assert result["title"] == "Confidential information detected"
        assert "2 possible confidential information" in result["description"]
        assert result["severity"] == "critical"
    
    def test_format_confidential_data_with_markers(self):
        """Test confidential data formatting with markers only."""
        result = MessageFormatter.format_confidential_data(
            markers=["SECRET", "INTERNAL"]
        )
        
        assert result["title"] == "Confidential information detected"
        assert "SECRET, INTERNAL" in result["description"]
        assert result["severity"] == "critical"
    
    def test_format_generic_error(self):
        """Test generic error formatting."""
        result = MessageFormatter.format_generic_error(
            policy_name="TestPolicy",
            reason="Test reason",
            score=0.7
        )
        
        assert result["title"] == "Security policy check failed"
        assert result["severity"] == "error"
        assert "technical_details" in result
        assert "TestPolicy" in result["technical_details"]


class TestFriendlyMessageBuilder:
    """Test friendly message builder."""
    
    def test_build_prompt_injection_message(self):
        """Test building prompt injection message."""
        result = FriendlyMessageBuilder.build_message(
            policy_name="PromptInjectionPolicy",
            decision="DENY",
            reason="Injection detected",
            score=0.8,
            metadata={"detected_patterns": ["ignore instructions"]}
        )
        
        assert result["title"] == "Message blocked by security system"
        assert result["severity"] == "error"
    
    def test_build_tool_whitelist_message(self):
        """Test building tool whitelist message."""
        result = FriendlyMessageBuilder.build_message(
            policy_name="ToolWhitelistPolicy",
            decision="DENY",
            reason="Tool blocked",
            score=0.9,
            metadata={
                "blocked_tools": ["dangerous_tool"],
                "allowed_tools": ["search", "calculator"]
            }
        )
        
        assert result["title"] == "Requested function unavailable"
        assert "dangerous_tool" in result["description"]
    
    def test_build_rate_limit_message(self):
        """Test building rate limit message."""
        result = FriendlyMessageBuilder.build_message(
            policy_name="RateLimitPolicy",
            decision="DENY",
            reason="Rate limit exceeded",
            score=0.5,
            metadata={"violations": ["15/10 per minute"]}
        )
        
        assert result["title"] == "Messages sent too frequently"
        assert "15 messages" in result["description"]
    
    def test_build_pii_detection_message(self):
        """Test building PII detection message."""
        result = FriendlyMessageBuilder.build_message(
            policy_name="PIIDetectionPolicy",
            decision="DENY",
            reason="PII detected",
            score=0.8,
            metadata={"detected_entities": {"PERSON": 0.9, "EMAIL_ADDRESS": 0.8}}
        )
        
        assert result["title"] == "Personal sensitive information detected"
        assert "name, email address" in result["description"]
    
    def test_build_code_execution_message(self):
        """Test building code execution message."""
        result = FriendlyMessageBuilder.build_message(
            policy_name="CodeExecutionPolicy",
            decision="DENY",
            reason="Dangerous code",
            score=0.7,
            metadata={
                "language_violations": ["javascript"],
                "dangerous_findings": ["file_operation"]
            }
        )
        
        assert result["title"] == "Code execution blocked"
        assert "javascript" in result["description"]
    
    def test_build_generic_message(self):
        """Test building generic message for unknown policy."""
        result = FriendlyMessageBuilder.build_message(
            policy_name="UnknownPolicy",
            decision="DENY",
            reason="Unknown reason",
            score=0.6,
            metadata={}
        )
        
        assert result["title"] == "Security policy check failed"
        assert result["severity"] == "error"
        assert "technical_details" in result
    
    def test_build_message_with_empty_metadata(self):
        """Test building message with empty metadata."""
        result = FriendlyMessageBuilder.build_message(
            policy_name="PromptInjectionPolicy",
            decision="DENY",
            reason="Test",
            score=0.5,
            metadata={}
        )
        
        # Should still work with empty metadata
        assert "title" in result
        assert "description" in result
        assert "severity" in result