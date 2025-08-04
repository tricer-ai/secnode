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
    
    def test_format_tool_blocked(self):
        """Test tool blocking formatting."""
        # Single tool with allowed tools
        result_single = MessageFormatter.format_tool_blocked(
            blocked_tools=["dangerous_tool"],
            allowed_tools=["search", "calculator"]
        )
        assert result_single["title"] == "Requested function unavailable"
        assert "dangerous_tool" in result_single["description"]
        assert "search, calculator" in result_single["suggestion"]
        assert result_single["severity"] == "error"
        
        # Multiple tools
        result_multiple = MessageFormatter.format_tool_blocked(
            blocked_tools=["tool1", "tool2", "tool3"]
        )
        assert result_multiple["title"] == "Requested function unavailable"
        assert "tool1, tool2, tool3" in result_multiple["description"]
        assert result_multiple["severity"] == "error"
    
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
    
    def test_format_pii_detected(self):
        """Test PII detection formatting."""
        # High confidence case
        result_high = MessageFormatter.format_pii_detected(
            entities=["PERSON", "EMAIL_ADDRESS"],
            confidence=0.9
        )
        assert result_high["title"] == "Personal sensitive information detected"
        assert "name, email address" in result_high["description"]
        assert result_high["severity"] == "error"
        
        # Low confidence case
        result_low = MessageFormatter.format_pii_detected(
            entities=["PHONE_NUMBER"],
            confidence=0.5
        )
        assert result_low["title"] == "May contain personal information"
        assert result_low["severity"] == "warning"
    
    def test_format_code_execution_blocked(self):
        """Test code execution blocking."""
        # With dangerous patterns
        result_patterns = MessageFormatter.format_code_execution_blocked(
            language="python",
            dangerous_patterns=["file_operation", "system_call"]
        )
        assert result_patterns["title"] == "Code execution blocked"
        assert "python" in result_patterns["description"]
        assert "security risks" in result_patterns["description"]
        assert result_patterns["severity"] == "error"
        
        # Unsupported language
        result_lang = MessageFormatter.format_code_execution_blocked(
            language="javascript"
        )
        assert result_lang["title"] == "Code execution blocked"
        assert "javascript" in result_lang["description"]
        assert "not supported" in result_lang["description"]
        assert result_lang["severity"] == "error"
    
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
    
    def test_format_url_blocked(self):
        """Test URL blocking formatting."""
        # Single URL
        result_single = MessageFormatter.format_url_blocked(
            urls=["https://malicious.com"],
            reason="security policy"
        )
        assert result_single["title"] == "Link access restricted"
        assert "https://malicious.com" in result_single["description"]
        assert "security policy" in result_single["description"]
        assert result_single["severity"] == "warning"
        
        # Multiple URLs
        result_multiple = MessageFormatter.format_url_blocked(
            urls=["url1", "url2", "url3"]
        )
        assert result_multiple["title"] == "Link access restricted"
        assert "3 links" in result_multiple["description"]
        assert result_multiple["severity"] == "warning"
    
    def test_format_keyword_filtered(self):
        """Test keyword filtering."""
        # High severity
        result_high = MessageFormatter.format_keyword_filtered(
            keywords=["malware"],
            severity="high"
        )
        assert result_high["title"] == "Message contains inappropriate content"
        assert result_high["severity"] == "error"
        assert "civilized and polite" in result_high["suggestion"]
        
        # Medium severity
        result_medium = MessageFormatter.format_keyword_filtered(
            keywords=["spam"],
            severity="medium"
        )
        assert result_medium["title"] == "Message content needs attention"
        assert result_medium["severity"] == "warning"
    
    def test_format_data_leakage(self):
        """Test data leakage formatting."""
        result = MessageFormatter.format_data_leakage(
            leak_types=["system_path", "network_info"]
        )
        
        assert result["title"] == "Sensitive information leakage detected"
        assert "system path, network information" in result["description"]
        assert result["severity"] == "critical"
    
    def test_format_confidential_data(self):
        """Test confidential data formatting."""
        # With secrets
        result_secrets = MessageFormatter.format_confidential_data(
            markers=["CONFIDENTIAL"],
            secret_count=2
        )
        assert result_secrets["title"] == "Confidential information detected"
        assert "2 possible confidential information" in result_secrets["description"]
        assert result_secrets["severity"] == "critical"
        
        # With markers only
        result_markers = MessageFormatter.format_confidential_data(
            markers=["SECRET", "INTERNAL"]
        )
        assert result_markers["title"] == "Confidential information detected"
        assert "SECRET, INTERNAL" in result_markers["description"]
        assert result_markers["severity"] == "critical"
    
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