"""
SecNode Friendly Error Message System

Provides user-friendly error message formatting, converting technical security 
policy decisions into clear explanations and specific solution suggestions 
that ordinary users can understand.
"""

from typing import Dict, List, Any, Optional
from enum import Enum


class MessageSeverity(Enum):
    """Error message severity levels"""
    INFO = "info"           # Information
    WARNING = "warning"     # Warning
    ERROR = "error"         # Error
    CRITICAL = "critical"   # Critical error


class MessageFormatter:
    """
    Error Message Formatter
    
    Converts technical policy decisions into user-friendly error messages,
    including clear problem descriptions and specific solution suggestions.
    """
    
    @staticmethod
    def format_prompt_injection(
        patterns: List[str], 
        risk_score: float, 
        detected_count: int = 0
    ) -> Dict[str, str]:
        """
        Format prompt injection error messages
        
        Args:
            patterns: List of detected patterns
            risk_score: Risk score
            detected_count: Number of detected patterns
            
        Returns:
            Dict: Dictionary containing friendly error messages
        """
        if risk_score >= 0.8:
            return {
                "title": "Message blocked by security system",
                "description": "Your message contains content that may attempt to manipulate the AI system. For system security, this type of request cannot be processed.",
                "suggestion": "Please reorganize your question using more direct and clear expressions. Avoid using language that might be misinterpreted as system instructions.",
                "severity": "error",
                "user_action": "Modify message content and retry"
            }
        elif risk_score >= 0.4:
            return {
                "title": "Message requires human review",
                "description": "Your message contains content that requires further confirmation. The system has marked it for human review.",
                "suggestion": "If this is a normal request, please wait a moment while our team reviews it. You can also try expressing your needs in a different way.",
                "severity": "warning",
                "user_action": "Wait for review or rephrase"
            }
        else:
            return {
                "title": "Potential risk content detected",
                "description": "Your message contains expressions that may pose risks, but the risk level is low.",
                "suggestion": "We recommend checking your message content to ensure clear and accurate expression.",
                "severity": "info",
                "user_action": "Check and confirm message content"
            }
    
    @staticmethod
    def format_tool_blocked(blocked_tools: List[str], allowed_tools: List[str] = None) -> Dict[str, str]:
        """
        Format tool blocking error messages
        
        Args:
            blocked_tools: List of blocked tools
            allowed_tools: List of allowed tools
            
        Returns:
            Dict: Dictionary containing friendly error messages
        """
        if len(blocked_tools) == 1:
            tool_name = blocked_tools[0]
            description = f"The requested function '{tool_name}' is currently unavailable. This is to ensure system security and stable operation."
        else:
            tools_str = ", ".join(blocked_tools)
            description = f"The requested functions ({tools_str}) are currently unavailable. This is to ensure system security and stable operation."
        
        suggestion = "Please try using other available functions to complete your task."
        if allowed_tools:
            available_tools = ", ".join(allowed_tools[:5])  # Only show first 5
            if len(allowed_tools) > 5:
                available_tools += ", etc."
            suggestion += f" Currently available functions include: {available_tools}."
        
        return {
            "title": "Requested function unavailable",
            "description": description,
            "suggestion": suggestion,
            "severity": "error",
            "user_action": "Use other available functions"
        }
    
    @staticmethod
    def format_rate_limit(current: int, limit: int, window: str, reset_time: str = None) -> Dict[str, str]:
        """
        Format rate limit error messages
        
        Args:
            current: Current request count
            limit: Limit count
            window: Time window
            reset_time: Reset time
            
        Returns:
            Dict: Dictionary containing friendly error messages
        """
        # Convert time window to English
        window_map = {
            "minute": "minute",
            "hour": "hour", 
            "day": "day",
            "second": "second"
        }
        
        english_window = window_map.get(window, window)
        
        description = f"You have sent {current} messages in the past {english_window}, exceeding the limit of {limit} messages."
        
        suggestion = f"Please wait a moment before sending new messages."
        if reset_time:
            suggestion += f" The limit will reset in {reset_time}."
        else:
            suggestion += f" You can continue using in the next {english_window}."
        
        return {
            "title": "Messages sent too frequently",
            "description": description,
            "suggestion": suggestion,
            "severity": "warning",
            "user_action": "Retry later"
        }
    
    @staticmethod
    def format_pii_detected(entities: List[str], confidence: float) -> Dict[str, str]:
        """
        Format PII detection error messages
        
        Args:
            entities: List of detected PII entity types
            confidence: Detection confidence
            
        Returns:
            Dict: Dictionary containing friendly error messages
        """
        # Entity type English mapping
        entity_map = {
            "PERSON": "name",
            "EMAIL_ADDRESS": "email address",
            "PHONE_NUMBER": "phone number",
            "SSN": "social security number",
            "CREDIT_CARD": "credit card number",
            "IP_ADDRESS": "IP address",
            "LOCATION": "location"
        }
        
        english_entities = [entity_map.get(entity, entity) for entity in entities]
        entities_str = ", ".join(english_entities)
        
        if confidence >= 0.8:
            return {
                "title": "Personal sensitive information detected",
                "description": f"Your message contains personal sensitive information ({entities_str}). To protect your privacy, the system cannot process requests containing such information.",
                "suggestion": "Please remove or replace personal information in your message, such as names, phone numbers, emails, etc., then resend. You can use dummy information or placeholders instead.",
                "severity": "error",
                "user_action": "Remove personal information and retry"
            }
        else:
            return {
                "title": "May contain personal information",
                "description": f"Your message may contain personal information ({entities_str}). Further confirmation is needed for privacy protection.",
                "suggestion": "Please check if your message contains personal information that should not be shared. If confirmed correct, please wait for human review.",
                "severity": "warning", 
                "user_action": "Check information or wait for review"
            }
    
    @staticmethod
    def format_code_execution_blocked(language: str, dangerous_patterns: List[str] = None) -> Dict[str, str]:
        """
        Format code execution blocking error messages
        
        Args:
            language: Programming language
            dangerous_patterns: List of dangerous patterns
            
        Returns:
            Dict: Dictionary containing friendly error messages
        """
        if dangerous_patterns:
            description = f"Your {language} code contains operations that may pose security risks, and the system cannot execute this code."
            suggestion = "Please check if your code contains potentially unsafe functions such as file operations, network requests, or system calls, and remove these contents."
        else:
            description = f"Execution of {language} code is currently not supported, or code execution functionality has been disabled."
            suggestion = "Please contact the administrator to understand the code execution policy, or try using other methods to complete your task."
        
        return {
            "title": "Code execution blocked",
            "description": description,
            "suggestion": suggestion,
            "severity": "error",
            "user_action": "Modify code or contact administrator"
        }
    
    @staticmethod
    def format_content_too_long(current_length: int, max_length: int, content_type: str = "message") -> Dict[str, str]:
        """
        Format content too long error messages
        
        Args:
            current_length: Current length
            max_length: Maximum length
            content_type: Content type
            
        Returns:
            Dict: Dictionary containing friendly error messages
        """
        return {
            "title": f"{content_type.capitalize()} content too long",
            "description": f"Your {content_type} length is {current_length} characters, exceeding the limit of {max_length} characters.",
            "suggestion": f"Please shorten your {content_type} content, or split long content into multiple shorter parts to send separately.",
            "severity": "error",
            "user_action": "Shorten content and retry"
        }
    
    @staticmethod
    def format_url_blocked(urls: List[str], reason: str = "security policy") -> Dict[str, str]:
        """
        Format URL blocking error messages
        
        Args:
            urls: List of blocked URLs
            reason: Blocking reason
            
        Returns:
            Dict: Dictionary containing friendly error messages
        """
        if len(urls) == 1:
            description = f"The link you provided ({urls[0]}) cannot be accessed due to {reason}."
        else:
            description = f"The {len(urls)} links you provided cannot be accessed due to {reason}."
        
        return {
            "title": "Link access restricted",
            "description": description,
            "suggestion": "Please confirm the security and validity of the links, or use other trusted link sources. If you have questions, please contact the administrator.",
            "severity": "warning",
            "user_action": "Use other links or contact administrator"
        }
    
    @staticmethod
    def format_keyword_filtered(keywords: List[str], severity: str = "high") -> Dict[str, str]:
        """
        Format keyword filtering error messages
        
        Args:
            keywords: List of triggered keywords
            severity: Severity level
            
        Returns:
            Dict: Dictionary containing friendly error messages
        """
        if severity == "high":
            return {
                "title": "Message contains inappropriate content",
                "description": "Your message contains inappropriate content and this request cannot be processed.",
                "suggestion": "Please use civilized and polite language to re-express your needs. Avoid using words that might offend others.",
                "severity": "error",
                "user_action": "Modify wording and retry"
            }
        else:
            return {
                "title": "Message content needs attention",
                "description": "Your message contains content that needs attention.",
                "suggestion": "We recommend checking your message wording to ensure appropriate and professional expression.",
                "severity": "warning",
                "user_action": "Check wording"
            }
    
    @staticmethod
    def format_data_leakage(leak_types: List[str]) -> Dict[str, str]:
        """
        Format data leakage error messages
        
        Args:
            leak_types: List of leakage types
            
        Returns:
            Dict: Dictionary containing friendly error messages
        """
        # Leakage type English mapping
        leak_map = {
            "system_path": "system path",
            "network_info": "network information",
            "database_info": "database information",
            "credentials": "authentication credentials"
        }
        
        english_types = [leak_map.get(leak_type, leak_type) for leak_type in leak_types]
        types_str = ", ".join(english_types)
        
        return {
            "title": "Sensitive information leakage detected",
            "description": f"The system detected possible sensitive information leakage ({types_str}). To protect system security, this content cannot be displayed.",
            "suggestion": "Please check the output content to ensure it does not contain sensitive data such as system paths, database connection information, passwords, etc.",
            "severity": "critical",
            "user_action": "Contact administrator to check system configuration"
        }
    
    @staticmethod
    def format_confidential_data(markers: List[str], secret_count: int = 0) -> Dict[str, str]:
        """
        Format confidential data error messages
        
        Args:
            markers: List of sensitivity markers
            secret_count: Number of detected secrets
            
        Returns:
            Dict: Dictionary containing friendly error messages
        """
        if secret_count > 0:
            description = f"Your message contains {secret_count} possible confidential information items (such as API keys, passwords, etc.)."
        else:
            markers_str = ", ".join(markers) if markers else "confidential markers"
            description = f"Your message contains confidential markers ({markers_str}), which may involve sensitive information."
        
        return {
            "title": "Confidential information detected",
            "description": description,
            "suggestion": "Please remove confidential information from your message, such as API keys, passwords, internal document markers, etc. If you need to handle confidential information, please use dedicated secure channels.",
            "severity": "critical",
            "user_action": "Remove confidential information or use secure channels"
        }
    
    @staticmethod
    def format_generic_error(policy_name: str, reason: str, score: float) -> Dict[str, str]:
        """
        Format generic error messages
        
        Args:
            policy_name: Policy name
            reason: Original error reason
            score: Risk score
            
        Returns:
            Dict: Dictionary containing friendly error messages
        """
        severity = "critical" if score >= 0.8 else ("error" if score >= 0.5 else "warning")
        
        return {
            "title": "Security policy check failed",
            "description": f"Your request did not pass security checks. The system detected possible security risks.",
            "suggestion": "Please check your request content to ensure it complies with usage guidelines. If you have questions, please contact technical support.",
            "severity": severity,
            "user_action": "Check request content or contact support",
            "technical_details": f"Policy: {policy_name}, Reason: {reason}, Risk score: {score:.2f}"
        }


class FriendlyMessageBuilder:
    """
    Friendly Message Builder
    
    Automatically selects appropriate message formatting methods based on 
    policy decisions to generate user-friendly error messages.
    """
    
    @staticmethod
    def build_message(policy_name: str, decision: str, reason: str, score: float, metadata: Dict[str, Any]) -> Dict[str, str]:
        """
        Build friendly messages based on policy information
        
        Args:
            policy_name: Policy name
            decision: Decision result
            reason: Original reason
            score: Risk score
            metadata: Metadata
            
        Returns:
            Dict: Friendly error message
        """
        # Select appropriate formatting method based on policy name
        if "PromptInjection" in policy_name:
            patterns = metadata.get("detected_patterns", [])
            return MessageFormatter.format_prompt_injection(patterns, score, len(patterns))
        
        elif "ToolWhitelist" in policy_name:
            blocked_tools = metadata.get("blocked_tools", [])
            allowed_tools = metadata.get("allowed_tools", [])
            return MessageFormatter.format_tool_blocked(blocked_tools, allowed_tools)
        
        elif "RateLimit" in policy_name:
            violations = metadata.get("violations", [])
            if violations:
                # Parse rate limit information
                violation = violations[0] if violations else ""
                parts = violation.split("/")
                if len(parts) >= 2:
                    try:
                        current = int(parts[0])
                        limit_part = parts[1].split(" ")[0]
                        limit = int(limit_part)
                        window = parts[1].split(" ")[-1] if " " in parts[1] else "minute"
                        return MessageFormatter.format_rate_limit(current, limit, window)
                    except (ValueError, IndexError):
                        pass
            return MessageFormatter.format_rate_limit(0, 0, "minute")
        
        elif "PIIDetection" in policy_name:
            detected_entities = metadata.get("detected_entities", {})
            entities = list(detected_entities.keys())
            confidence = max(detected_entities.values()) if detected_entities else score
            return MessageFormatter.format_pii_detected(entities, confidence)
        
        elif "CodeExecution" in policy_name:
            language_violations = metadata.get("language_violations", [])
            dangerous_findings = metadata.get("dangerous_findings", [])
            language = language_violations[0] if language_violations else "unknown"
            return MessageFormatter.format_code_execution_blocked(language, dangerous_findings)
        
        elif "ContentLength" in policy_name:
            violations = metadata.get("violations", [])
            if violations and "too long" in violations[0]:
                return MessageFormatter.format_content_too_long(0, 0)  # Simplified handling
            return MessageFormatter.format_content_too_long(0, 0)
        
        elif "URLBlacklist" in policy_name:
            suspicious_urls = metadata.get("suspicious_urls", [])
            urls = [url_info.get("url", "") for url_info in suspicious_urls]
            return MessageFormatter.format_url_blocked(urls)
        
        elif "KeywordFilter" in policy_name:
            high_severity = metadata.get("high_severity_issues", 0)
            severity = "high" if high_severity > 0 else "medium"
            return MessageFormatter.format_keyword_filtered([], severity)
        
        elif "DataLeakage" in policy_name:
            detected_leakage = metadata.get("detected_leakage", [])
            leak_types = [leak.get("category", "") for leak in detected_leakage]
            return MessageFormatter.format_data_leakage(leak_types)
        
        elif "ConfidentialData" in policy_name:
            sensitivity_markers = metadata.get("sensitivity_markers", 0)
            detected_secrets = metadata.get("detected_secrets", 0)
            return MessageFormatter.format_confidential_data([], detected_secrets)
        
        else:
            # Generic error message
            return MessageFormatter.format_generic_error(policy_name, reason, score)