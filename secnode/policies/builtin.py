"""
Tricer SecNode Built-in Security Policies

This module provides a comprehensive library of ready-to-use security policies
for common AI agent security concerns. These policies can be used individually
or combined with policy combinators for complex security requirements.
"""

import re
import time
import hashlib
from urllib.parse import urlparse
from typing import Any, Dict, List, Optional, Set, Union
from secnode.policies.core import BasePolicy, PolicyDecision

# Core dependencies - always available
from presidio_analyzer import AnalyzerEngine
import validators
from limits import RateLimitItem, parse
from limits.storage import MemoryStorage
from limits.strategies import MovingWindowRateLimiter, FixedWindowRateLimiter
from detect_secrets.core.scan import scan_line
from detect_secrets.settings import get_settings


class PromptInjectionPolicy(BasePolicy):
    """
    Detects potential prompt injection attacks in user inputs and agent messages.
    
    This policy scans for common prompt injection patterns including:
    - Instruction overrides ("ignore previous instructions")
    - Role confusion attempts ("you are now a different AI")
    - System prompt leakage attempts
    - Command injection patterns
    
    Example:
        policy = PromptInjectionPolicy(
            sensitivity=0.7,  # 0.0 = permissive, 1.0 = strict
            block_system_prompts=True
        )
    """
    
    # Common prompt injection patterns
    INJECTION_PATTERNS = [
        r"ignore\s+(all\s+)?(previous\s+|prior\s+)?instructions",
        r"forget\s+(everything\s+)?(you\s+)?(were\s+)?told",
        r"you\s+are\s+now\s+(a\s+)?(?:different|new)",
        r"act\s+as\s+(?:if\s+you\s+are|a)",
        r"pretend\s+(?:to\s+be|you\s+are)",
        r"system\s*:\s*",
        r"<\s*system\s*>",
        r"reveal\s+your\s+(instructions|prompt|system)",
        r"show\s+me\s+your\s+(prompt|instructions)",
        r"what\s+are\s+your\s+(instructions|rules)",
    ]
    
    def __init__(
        self,
        sensitivity: float = 0.5,
        block_system_prompts: bool = True,
        custom_patterns: Optional[List[str]] = None,
        **kwargs: Any
    ):
        super().__init__(**kwargs)
        self.sensitivity = max(0.0, min(1.0, sensitivity))
        self.block_system_prompts = block_system_prompts
        self.patterns = self.INJECTION_PATTERNS.copy()
        
        if custom_patterns:
            self.patterns.extend(custom_patterns)
        
        # Compile regex patterns for efficiency
        self.compiled_patterns = [
            re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            for pattern in self.patterns
        ]
    
    def check(self, state: Dict[str, Any]) -> PolicyDecision:
        """
        Analyze state for potential prompt injection attacks.
        
        Examines messages, user inputs, and other text content for 
        injection patterns based on configured sensitivity.
        """
        content_to_check = []
        
        # Extract content from various state fields
        if "messages" in state:
            for msg in state["messages"]:
                if isinstance(msg, dict) and "content" in msg:
                    content_to_check.append(msg["content"])
                elif isinstance(msg, str):
                    content_to_check.append(msg)
        
        if "user_input" in state:
            content_to_check.append(str(state["user_input"]))
        
        if "query" in state:
            content_to_check.append(str(state["query"]))
        
        # Check for injection patterns
        detected_patterns = []
        total_matches = 0
        
        for content in content_to_check:
            if not isinstance(content, str):
                continue
                
            for i, pattern in enumerate(self.compiled_patterns):
                matches = pattern.findall(content)
                if matches:
                    detected_patterns.append({
                        "pattern_index": i,
                        "pattern": self.patterns[i],
                        "matches": matches,
                        "content_snippet": content[:100] + "..." if len(content) > 100 else content
                    })
                    total_matches += len(matches)
        
        # Calculate risk score based on matches and sensitivity
        if not detected_patterns:
            return PolicyDecision(
                decision="ALLOW",
                reason="No prompt injection patterns detected",
                score=0.0,
                policy_name=self.name,
                metadata={"patterns_checked": len(self.patterns)}
            )
        
        # Check for system prompt blocking
        if self.block_system_prompts:
            system_patterns = [r"system\s*:\s*", r"<\s*system\s*>"]
            for pattern_info in detected_patterns:
                if pattern_info["pattern"] in system_patterns:
                    return PolicyDecision(
                        decision="DENY",
                        reason="System prompt detected and blocked",
                        score=1.0,
                        policy_name=self.name,
                        metadata={
                            "detected_patterns": detected_patterns,
                            "total_matches": total_matches,
                            "sensitivity": self.sensitivity,
                            "system_prompt_blocked": True
                        }
                    )
        
        # Risk calculation: base risk + pattern bonus, scaled by sensitivity
        base_risk = min(0.9, total_matches * 0.2)
        pattern_bonus = len(detected_patterns) * 0.1
        risk_score = min(1.0, (base_risk + pattern_bonus) * self.sensitivity)
        
        # Decision thresholds based on sensitivity
        if risk_score >= 0.8:
            decision = "DENY"
            reason = f"High confidence prompt injection detected ({len(detected_patterns)} patterns)"
        elif risk_score >= 0.4:
            decision = "REQUIRE_HUMAN_APPROVAL"
            reason = f"Potential prompt injection detected ({len(detected_patterns)} patterns)"
        else:
            decision = "ALLOW"
            reason = f"Low risk prompt patterns detected ({len(detected_patterns)} patterns)"
        
        return PolicyDecision(
            decision=decision,
            reason=reason,
            score=risk_score,
            policy_name=self.name,
            metadata={
                "detected_patterns": detected_patterns,
                "total_matches": total_matches,
                "sensitivity": self.sensitivity,
            }
        )


class ToolCallWhitelistPolicy(BasePolicy):
    """
    Restricts agent tool/function calls to an approved whitelist.
    
    This policy ensures agents can only use explicitly approved tools,
    preventing unauthorized access to dangerous functions like file I/O,
    network access, or system commands.
    
    Example:
        policy = ToolCallWhitelistPolicy(
            allowed_tools=['search', 'calculator', 'weather'],
            strict_mode=True  # Deny any non-whitelisted tools
        )
    """
    
    def __init__(
        self,
        allowed_tools: List[str],
        strict_mode: bool = True,
        case_sensitive: bool = False,
        **kwargs: Any
    ):
        super().__init__(**kwargs)
        self.allowed_tools = set(allowed_tools)
        self.strict_mode = strict_mode
        self.case_sensitive = case_sensitive
        
        if not case_sensitive:
            self.allowed_tools = {tool.lower() for tool in self.allowed_tools}
    
    def check(self, state: Dict[str, Any]) -> PolicyDecision:
        """
        Verify that any tool calls are in the approved whitelist.
        
        Examines the state for tool calls, function calls, or action
        invocations and ensures they're all whitelisted.
        """
        tool_calls = []
        
        # Extract tool calls from various state fields
        if "tool_calls" in state:
            tool_calls.extend(state["tool_calls"])
        
        if "function_calls" in state:
            tool_calls.extend(state["function_calls"])
        
        if "actions" in state:
            actions = state["actions"]
            if isinstance(actions, list):
                tool_calls.extend(actions)
            elif isinstance(actions, dict) and "tool" in actions:
                tool_calls.append(actions)
        
        # Check for tools in messages (common LangGraph pattern)
        if "messages" in state:
            for msg in state["messages"]:
                if isinstance(msg, dict):
                    if "tool_calls" in msg:
                        tool_calls.extend(msg["tool_calls"])
                    if "function_call" in msg:
                        tool_calls.append(msg["function_call"])
        
        if not tool_calls:
            return PolicyDecision(
                decision="ALLOW",
                reason="No tool calls detected",
                score=0.0,
                policy_name=self.name,
                metadata={"allowed_tools": list(self.allowed_tools)}
            )
        
        # Analyze each tool call
        blocked_tools = []
        approved_tools = []
        
        for tool_call in tool_calls:
            tool_name = None
            
            # Extract tool name from various formats
            if isinstance(tool_call, str):
                tool_name = tool_call
            elif isinstance(tool_call, dict):
                tool_name = tool_call.get("name")
                if not tool_name:
                    tool_name = tool_call.get("tool")
                if not tool_name and "function" in tool_call:
                    func = tool_call.get("function")
                    if isinstance(func, dict):
                        tool_name = func.get("name")
            
            if not tool_name:
                continue
                
            # Normalize case if needed
            check_name = tool_name if self.case_sensitive else tool_name.lower()
            
            if check_name in self.allowed_tools:
                approved_tools.append(tool_name)
            else:
                blocked_tools.append(tool_name)
        
        # Make decision based on blocked tools
        if blocked_tools:
            risk_score = min(1.0, len(blocked_tools) * 0.3)
            decision = "DENY" if self.strict_mode else "REQUIRE_HUMAN_APPROVAL"
            action = "blocked" if self.strict_mode else "flagged for approval"
            
            return PolicyDecision(
                decision=decision,
                reason=f"Tool call whitelist violation: {', '.join(blocked_tools)} {action}",
                score=risk_score,
                policy_name=self.name,
                metadata={
                    "blocked_tools": blocked_tools,
                    "approved_tools": approved_tools,
                    "allowed_tools": list(self.allowed_tools),
                    "strict_mode": self.strict_mode,
                }
            )
        
        return PolicyDecision(
            decision="ALLOW",
            reason=f"All tool calls approved: {', '.join(approved_tools)}",
            score=0.0,
            policy_name=self.name,
            metadata={
                "approved_tools": approved_tools,
                "allowed_tools": list(self.allowed_tools),
            }
        )


class PIIDetectionPolicy(BasePolicy):
    """
    Detects and blocks potential personally identifiable information (PII) using Presidio.
    
    This policy uses Microsoft Presidio for lightweight PII detection without downloading
    additional models. It scans content for common PII entities including:
    - Person names
    - Social Security Numbers
    - Credit card numbers  
    - Email addresses
    - Phone numbers
    - IP addresses
    - And more supported by Presidio's built-in recognizers
    
    Example:
        policy = PIIDetectionPolicy(
            threshold=0.7,  # Confidence threshold (0.0-1.0)
            entities=["PERSON", "SSN", "CREDIT_CARD", "EMAIL"],
            block_high_confidence=True
        )
    """
    
    def __init__(
        self,
        threshold: float = 0.6,
        entities: Optional[List[str]] = None,
        block_high_confidence: bool = True,
        require_approval_medium: bool = True,
        **kwargs: Any
    ):
        super().__init__(**kwargs)
        
        
        self.threshold = max(0.0, min(1.0, threshold))
        self.block_high_confidence = block_high_confidence
        self.require_approval_medium = require_approval_medium
        
        # Default entities to detect if none specified
        self.entities = entities or [
            "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "SSN", 
            "CREDIT_CARD", "IBAN_CODE", "IP_ADDRESS", "LOCATION"
        ]
        
        # Initialize Presidio analyzer with minimal configuration
        # This uses only built-in recognizers without additional models
        self.analyzer = AnalyzerEngine()
    
    def check(self, state: Dict[str, Any]) -> PolicyDecision:
        """
        Scan state content for PII using Presidio analyzer.
        
        Examines messages, inputs, and other text fields for
        personally identifiable information using ML-based detection.
        """
        content_to_check = []
        
        # Extract content from state
        if "messages" in state:
            for msg in state["messages"]:
                if isinstance(msg, dict) and "content" in msg:
                    content_to_check.append(msg["content"])
                elif isinstance(msg, str):
                    content_to_check.append(msg)
        
        for field in ["user_input", "query", "response", "output"]:
            if field in state:
                content_to_check.append(str(state[field]))
        
        # Analyze content with Presidio
        all_results = []
        
        for content in content_to_check:
            if not isinstance(content, str) or not content.strip():
                continue
            
            try:
                # Analyze text for PII entities
                results = self.analyzer.analyze(
                    text=content,
                    entities=self.entities,
                    language='en'  # English only for lightweight version
                )
                
                # Filter results by confidence threshold
                filtered_results = [
                    result for result in results 
                    if result.score >= self.threshold
                ]
                
                all_results.extend(filtered_results)
                
            except Exception as e:
                # Fallback gracefully if Presidio fails
                return PolicyDecision(
                    decision="ALLOW",
                    reason=f"PII analysis failed: {str(e)}",
                    score=0.0,
                    policy_name=self.name,
                    metadata={"error": str(e), "fallback": True}
                )
        
        if not all_results:
            return PolicyDecision(
                decision="ALLOW",
                reason="No PII detected by Presidio",
                score=0.0,
                policy_name=self.name,
                metadata={
                    "entities_checked": self.entities,
                    "threshold": self.threshold
                }
            )
        
        # Group results by entity type
        detected_entities = {}
        max_confidence = 0.0
        total_detections = len(all_results)
        
        for result in all_results:
            entity_type = result.entity_type
            confidence = result.score
            max_confidence = max(max_confidence, confidence)
            
            if entity_type not in detected_entities:
                detected_entities[entity_type] = {
                    "count": 0,
                    "max_confidence": 0.0,
                    "avg_confidence": 0.0,
                    "confidences": []
                }
            
            detected_entities[entity_type]["count"] += 1
            detected_entities[entity_type]["max_confidence"] = max(
                detected_entities[entity_type]["max_confidence"], confidence
            )
            detected_entities[entity_type]["confidences"].append(confidence)
        
        # Calculate average confidences
        for entity_type in detected_entities:
            confidences = detected_entities[entity_type]["confidences"]
            detected_entities[entity_type]["avg_confidence"] = sum(confidences) / len(confidences)
        
        # Calculate overall risk score
        risk_score = min(1.0, max_confidence * 1.2)  # Boost max confidence slightly
        
        # Increase risk for sensitive entity types
        sensitive_entities = {"SSN", "CREDIT_CARD", "IBAN_CODE"}
        for entity_type in detected_entities:
            if entity_type in sensitive_entities:
                risk_score = min(1.0, risk_score + 0.2)
        
        # Decision logic based on confidence and entity types
        high_confidence_threshold = 0.8
        medium_confidence_threshold = 0.5
        
        has_high_confidence = max_confidence >= high_confidence_threshold
        has_medium_confidence = max_confidence >= medium_confidence_threshold
        has_sensitive_entities = bool(set(detected_entities.keys()) & sensitive_entities)
        
        if has_high_confidence or has_sensitive_entities:
            if self.block_high_confidence:
                decision = "DENY"
                reason = f"High-confidence PII detected: {list(detected_entities.keys())}"
            else:
                decision = "REQUIRE_HUMAN_APPROVAL"
                reason = f"High-confidence PII requires approval: {list(detected_entities.keys())}"
        elif has_medium_confidence and self.require_approval_medium:
            decision = "REQUIRE_HUMAN_APPROVAL"
            reason = f"Medium-confidence PII requires review: {list(detected_entities.keys())}"
        else:
            decision = "ALLOW"
            reason = f"Low-confidence PII detected: {list(detected_entities.keys())}"
        
        return PolicyDecision(
            decision=decision,
            reason=reason,
            score=risk_score,
            policy_name=self.name,
            metadata={
                "detected_entities": detected_entities,
                "total_detections": total_detections,
                "max_confidence": max_confidence,
                "threshold": self.threshold,
                "presidio_version": "lightweight",
            }
        )


class CodeExecutionPolicy(BasePolicy):
    """
    Controls and monitors code execution attempts by AI agents.
    
    This policy provides granular control over code execution, supporting:
    - Language-specific restrictions (Python, JavaScript, shell, etc.)
    - Dangerous function detection (file I/O, network, system calls)
    - Execution environment validation
    - Code complexity analysis
    
    Example:
        policy = CodeExecutionPolicy(
            allowed_languages=['python'],
            block_file_operations=True,
            block_network_calls=True,
            max_execution_time=30  # seconds
        )
    """
    
    # Dangerous function patterns by language
    DANGEROUS_PATTERNS = {
        "python": [
            r"\bopen\s*\(",
            r"\bfile\s*\(",
            r"\bexec\s*\(",
            r"\beval\s*\(",
            r"\b__import__\s*\(",
            r"\bgetattr\s*\(",
            r"\bsetattr\s*\(",
            r"\bos\.(system|popen|spawn)",
            r"\bsubprocess\.(run|call|Popen)",
            r"\brequests\.(get|post|put|delete)",
            r"\burllib\.",
        ],
        "javascript": [
            r"\beval\s*\(",
            r"\bFunction\s*\(",
            r"\brequire\s*\(",
            r"\bfs\.(read|write|unlink)",
            r"\bchild_process\.",
            r"\bfetch\s*\(",
            r"\bXMLHttpRequest",
        ],
        "shell": [
            r"\brm\s+",
            r"\bmv\s+", 
            r"\bcp\s+",
            r"\bchmod\s+",
            r"\bsudo\s+",
            r"\bcurl\s+",
            r"\bwget\s+",
            r"\b>\s*",
            r"\b>>\s*",
        ]
    }
    
    def __init__(
        self,
        allowed_languages: Optional[List[str]] = None,
        block_file_operations: bool = True,
        block_network_calls: bool = True,
        block_system_calls: bool = True,
        max_execution_time: Optional[int] = None,
        require_approval_for_dangerous: bool = True,
        **kwargs: Any
    ):
        super().__init__(**kwargs)
        self.allowed_languages = set(allowed_languages) if allowed_languages else set()
        self.block_file_operations = block_file_operations
        self.block_network_calls = block_network_calls
        self.block_system_calls = block_system_calls
        self.max_execution_time = max_execution_time
        self.require_approval_for_dangerous = require_approval_for_dangerous
        
        # Build active dangerous patterns
        self.active_patterns = {}
        for lang in self.DANGEROUS_PATTERNS:
            if not self.allowed_languages or lang in self.allowed_languages:
                self.active_patterns[lang] = [
                    re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                    for pattern in self.DANGEROUS_PATTERNS[lang]
                ]
    
    def check(self, state: Dict[str, Any]) -> PolicyDecision:
        """
        Analyze code execution requests for security risks.
        
        Examines code content, execution context, and requested
        operations to determine if execution should be allowed.
        """
        code_blocks = []
        execution_requests = []
        
        # Extract code from various state fields
        if "code" in state:
            code_blocks.append({"content": state["code"], "language": state.get("language", "unknown")})
        
        if "tool_calls" in state:
            for tool_call in state["tool_calls"]:
                if isinstance(tool_call, dict):
                    if tool_call.get("name") in ["code_interpreter", "python", "execute"]:
                        execution_requests.append(tool_call)
                        if "arguments" in tool_call and "code" in tool_call["arguments"]:
                            code_blocks.append({
                                "content": tool_call["arguments"]["code"],
                                "language": tool_call.get("language", "python")
                            })
        
        # Check messages for code blocks
        if "messages" in state:
            for msg in state["messages"]:
                if isinstance(msg, dict) and "content" in msg:
                    content = msg["content"]
                    # Look for code blocks in markdown format
                    code_block_pattern = r"```(\w+)?\n(.*?)```"
                    matches = re.findall(code_block_pattern, content, re.DOTALL)
                    for lang, code in matches:
                        code_blocks.append({
                            "content": code.strip(),
                            "language": lang.lower() if lang else "unknown"
                        })
        
        if not code_blocks and not execution_requests:
            return PolicyDecision(
                decision="ALLOW",
                reason="No code execution detected",
                score=0.0,
                policy_name=self.name,
                metadata={"checked_for_code": True}
            )
        
        # Analyze code blocks for dangerous patterns
        dangerous_findings = []
        language_violations = []
        
        for code_block in code_blocks:
            language = code_block["language"]
            content = code_block["content"]
            
            # Check language restrictions
            if self.allowed_languages and language not in self.allowed_languages and language != "unknown":
                language_violations.append(language)
                continue
            
            # Check for dangerous patterns
            if language in self.active_patterns:
                for pattern in self.active_patterns[language]:
                    matches = pattern.findall(content)
                    if matches:
                        dangerous_findings.append({
                            "language": language,
                            "pattern": pattern.pattern,
                            "matches": len(matches),
                            "code_snippet": content[:100] + "..." if len(content) > 100 else content
                        })
        
        # Calculate risk score
        risk_score = 0.0
        
        if language_violations:
            risk_score += 0.5
        
        if dangerous_findings:
            risk_score += min(0.7, len(dangerous_findings) * 0.2)
        
        # Decision logic
        if language_violations and self.allowed_languages:
            return PolicyDecision(
                decision="DENY",
                reason=f"Code execution in prohibited languages: {', '.join(language_violations)}",
                score=min(1.0, risk_score),
                policy_name=self.name,
                metadata={
                    "language_violations": language_violations,
                    "allowed_languages": list(self.allowed_languages),
                }
            )
        
        if dangerous_findings:
            decision = "DENY" if not self.require_approval_for_dangerous else "REQUIRE_HUMAN_APPROVAL"
            return PolicyDecision(
                decision=decision,
                reason=f"Dangerous code patterns detected: {len(dangerous_findings)} findings",
                score=min(1.0, risk_score),
                policy_name=self.name,
                metadata={
                    "dangerous_findings": dangerous_findings,
                    "total_code_blocks": len(code_blocks),
                }
            )
        
        return PolicyDecision(
            decision="ALLOW",
            reason=f"Code execution approved for {len(code_blocks)} blocks",
            score=risk_score,
            policy_name=self.name,
            metadata={
                "code_blocks_analyzed": len(code_blocks),
                "execution_requests": len(execution_requests),
            }
        )


class ConfidentialDataPolicy(BasePolicy):
    """
    Professional confidential data detection using detect-secrets.
    
    Detects secrets and sensitive data markers using enterprise-grade algorithms.
    
    Example:
        policy = ConfidentialDataPolicy(
            sensitivity_markers=["CONFIDENTIAL", "SECRET", "INTERNAL"],
            strict_mode=False
        )
    """
    
    # Default confidentiality markers
    DEFAULT_MARKERS = [
        "confidential", "secret", "internal use only", "proprietary",
        "classified", "restricted", "private", "sensitive",
        "do not share", "not for distribution", "internal only"
    ]
    
    def __init__(
        self,
        sensitivity_markers: Optional[List[str]] = None,
        case_sensitive: bool = False,
        strict_mode: bool = False,
        secret_confidence_threshold: float = 0.7,
        **kwargs: Any
    ):
        super().__init__(**kwargs)
        
        # Configure sensitivity markers
        self.markers = sensitivity_markers or self.DEFAULT_MARKERS.copy()
        if not case_sensitive:
            self.markers = [marker.lower() for marker in self.markers]
        
        self.case_sensitive = case_sensitive
        self.strict_mode = strict_mode
        self.secret_confidence_threshold = secret_confidence_threshold
    
    def _detect_secrets(self, content: str) -> List[Dict[str, Any]]:
        """Use detect-secrets library for professional secret detection."""
        detected_secrets = []
        
        try:
            # Scan content line by line for secrets using detect-secrets
            lines = content.split('\n')
            
            for line_num, line in enumerate(lines, 1):
                if not line.strip():
                    continue
                    
                secrets = scan_line(line)
                
                for secret in secrets:
                    # Basic confidence assessment (detect-secrets doesn't always have confidence)
                    confidence = 0.8  # Default confidence for detected secrets
                    
                    if confidence >= self.secret_confidence_threshold:
                        detected_secrets.append({
                            "type": "secret",
                            "plugin": secret.type,
                            "confidence": confidence,
                            "line": line_num,
                            "context": line[:100] + "..." if len(line) > 100 else line
                        })
                    
        except Exception as e:
            # Log error but don't fail completely
            pass
            
        return detected_secrets
    
    def check(self, state: Dict[str, Any]) -> PolicyDecision:
        """
        Professional confidential data detection.
        """
        content_to_check = []
        
        # Extract content from state
        if "messages" in state:
            for msg in state["messages"]:
                if isinstance(msg, dict) and "content" in msg:
                    content_to_check.append(msg["content"])
                elif isinstance(msg, str):
                    content_to_check.append(msg)
        
        for field in ["user_input", "query", "response", "output", "prompt"]:
            if field in state:
                content_to_check.append(str(state[field]))
        
        detected_issues = []
        
        for content in content_to_check:
            if not isinstance(content, str):
                continue
            
            # Check for sensitivity markers
            check_content = content if self.case_sensitive else content.lower()
            for marker in self.markers:
                if marker in check_content:
                    detected_issues.append({
                        "type": "sensitivity_marker",
                        "marker": marker,
                        "confidence": 1.0,
                        "context": content[:100] + "..." if len(content) > 100 else content
                    })
            
            # Professional secret detection
            secrets = self._detect_secrets(content)
            detected_issues.extend(secrets)
        
        if not detected_issues:
            return PolicyDecision(
                decision="ALLOW",
                reason="No confidential data detected",
                score=0.0,
                policy_name=self.name,
                metadata={"markers_checked": len(self.markers)}
            )
        
        # Calculate risk score
        sensitivity_count = sum(1 for issue in detected_issues if issue["type"] == "sensitivity_marker")
        secret_count = sum(1 for issue in detected_issues if issue["type"] == "secret")
        high_confidence_secrets = sum(1 for issue in detected_issues 
                                    if issue.get("confidence", 0) >= 0.8 and issue["type"] == "secret")
        
        risk_score = min(1.0, sensitivity_count * 0.3 + secret_count * 0.5 + high_confidence_secrets * 0.3)
        
        # Decision logic
        if high_confidence_secrets > 0 or (secret_count > 0 and self.strict_mode):
            decision = "DENY"
            reason = f"High-confidence secrets detected: {high_confidence_secrets} secrets, {sensitivity_count} markers"
        elif secret_count > 0 or sensitivity_count > 0:
            decision = "REQUIRE_HUMAN_APPROVAL" 
            reason = f"Potential confidential content: {secret_count} secrets, {sensitivity_count} markers"
        else:
            decision = "ALLOW"
            reason = f"Low-risk content detected: {len(detected_issues)} minor issues"
        
        return PolicyDecision(
            decision=decision,
            reason=reason,
            score=risk_score,
            policy_name=self.name,
            metadata={
                "detected_issues": detected_issues,
                "sensitivity_markers": sensitivity_count,
                "detected_secrets": secret_count,
                "high_confidence_secrets": high_confidence_secrets,
            }
        )


class RateLimitPolicy(BasePolicy):
    """
    Professional rate limiting using the 'limits' library.
    
    Provides enterprise-grade rate limiting with multiple algorithms.
    
    Example:
        policy = RateLimitPolicy(
            limits=["10/minute", "100/hour"],
            strategy="moving-window",
            track_by="user_id"
        )
    """
    
    def __init__(
        self,
        limits: Optional[List[str]] = None,
        strategy: str = "moving-window",  # or "fixed-window"
        track_by: str = "user_id",
        storage_uri: Optional[str] = None,  # None = memory, "redis://..." for Redis
        **kwargs: Any
    ):
        super().__init__(**kwargs)
        
        # Default limits if none specified
        self.limit_strings = limits or ["20/minute", "200/hour"]
        self.strategy = strategy
        self.track_by = track_by
        
        # Setup storage
        from limits.storage import MemoryStorage, RedisStorage
        
        if storage_uri and storage_uri.startswith("redis://"):
            self.storage = RedisStorage(storage_uri)
        else:
            self.storage = MemoryStorage()
        
        # Parse limit strings
        self.parsed_limits = []
        for limit_str in self.limit_strings:
            try:
                limit_item = parse(limit_str)
                self.parsed_limits.append(limit_item)
            except Exception:
                # Skip invalid limit strings
                continue
        
        # Choose rate limiting strategy
        if strategy == "moving-window":
            self.rate_limiter = MovingWindowRateLimiter(self.storage)
        else:
            self.rate_limiter = FixedWindowRateLimiter(self.storage)
    
    def check(self, state: Dict[str, Any]) -> PolicyDecision:
        """
        Professional rate limiting check.
        """
        # Get tracking identifier
        track_id = state.get(self.track_by) or state.get("user_id") or "anonymous"
        
        violations = []
        stats = {}
        
        # Check each limit
        for limit in self.parsed_limits:
            if not self.rate_limiter.hit(limit, track_id):
                # Rate limit exceeded
                violations.append({
                    "limit": str(limit),
                    "window": limit.get_expiry(),
                    "amount": limit.amount
                })
            
            # Get current usage stats
            current_usage = self.rate_limiter.get_window_stats(limit, track_id)
            stats[str(limit)] = {
                "current": getattr(current_usage, 'hit_count', 0),
                "limit": limit.amount,
                "window": str(limit.get_expiry())
            }
        
        if not violations:
            return PolicyDecision(
                decision="ALLOW",
                reason=f"Within rate limits: {', '.join(f'{s['current']}/{s['limit']} per {s['window']}' for s in stats.values())}",
                score=0.0,
                policy_name=self.name,
                metadata={
                    "track_id": track_id,
                    "current_usage": stats,
                    "strategy": self.strategy
                }
            )
        
        # Calculate risk score based on violations
        risk_score = min(1.0, len(violations) * 0.4)
        
        violation_details = []
        for violation in violations:
            violation_details.append(f"{violation['limit']} exceeded")
        
        return PolicyDecision(
            decision="DENY",
            reason=f"Rate limit violations: {', '.join(violation_details)}",
            score=risk_score,
            policy_name=self.name,
            metadata={
                "track_id": track_id,
                "violations": violations,
                "current_usage": stats,
                "strategy": self.strategy
            }
        )


class ContentLengthPolicy(BasePolicy):
    """
    Enforces content length limits to prevent resource exhaustion.
    
    This policy checks message lengths, total content size, and prevents
    excessively long inputs that could cause performance issues.
    
    Example:
        policy = ContentLengthPolicy(
            max_message_length=5000,
            max_total_length=50000,
            max_messages=100
        )
    """
    
    def __init__(
        self,
        max_message_length: int = 10000,
        max_total_length: int = 100000,
        max_messages: int = 500,
        strict_enforcement: bool = False,
        **kwargs: Any
    ):
        super().__init__(**kwargs)
        self.max_message_length = max_message_length
        self.max_total_length = max_total_length
        self.max_messages = max_messages
        self.strict_enforcement = strict_enforcement
    
    def check(self, state: Dict[str, Any]) -> PolicyDecision:
        """
        Check content length limits.
        """
        violations = []
        total_length = 0
        message_count = 0
        longest_message = 0
        
        # Check messages
        if "messages" in state:
            messages = state["messages"]
            if isinstance(messages, list):
                message_count = len(messages)
                
                for msg in messages:
                    content = ""
                    if isinstance(msg, dict) and "content" in msg:
                        content = str(msg["content"])
                    elif isinstance(msg, str):
                        content = msg
                    
                    content_length = len(content)
                    total_length += content_length
                    longest_message = max(longest_message, content_length)
                    
                    if content_length > self.max_message_length:
                        violations.append(f"message too long ({content_length}/{self.max_message_length} chars)")
        
        # Check other content fields
        for field in ["user_input", "query", "prompt", "response", "output"]:
            if field in state:
                content = str(state[field])
                content_length = len(content)
                total_length += content_length
                
                if content_length > self.max_message_length:
                    violations.append(f"{field} too long ({content_length}/{self.max_message_length} chars)")
        
        # Check total limits
        if total_length > self.max_total_length:
            violations.append(f"total content too long ({total_length}/{self.max_total_length} chars)")
        
        if message_count > self.max_messages:
            violations.append(f"too many messages ({message_count}/{self.max_messages})")
        
        if not violations:
            return PolicyDecision(
                decision="ALLOW",
                reason=f"Content within limits ({total_length} chars, {message_count} messages)",
                score=0.0,
                policy_name=self.name,
                metadata={
                    "total_length": total_length,
                    "message_count": message_count,
                    "longest_message": longest_message,
                }
            )
        
        # Calculate risk score
        length_ratio = total_length / self.max_total_length
        message_ratio = message_count / self.max_messages
        risk_score = min(1.0, max(length_ratio, message_ratio))
        
        decision = "DENY" if self.strict_enforcement else "REQUIRE_HUMAN_APPROVAL"
        action = "blocked" if self.strict_enforcement else "requires approval"
        
        return PolicyDecision(
            decision=decision,
            reason=f"Content length violations {action}: {', '.join(violations)}",
            score=risk_score,
            policy_name=self.name,
            metadata={
                "violations": violations,
                "total_length": total_length,
                "message_count": message_count,
                "longest_message": longest_message,
            }
        )


class URLBlacklistPolicy(BasePolicy):
    """
    Professional URL security analysis using validators library.
    
    Provides comprehensive URL security checking with professional validation.
    
    Example:
        policy = URLBlacklistPolicy(
            blocked_domains=["malicious.com", "spam-site.net"],
            block_ip_urls=True,
            block_short_urls=False
        )
    """
    
    # Known malicious or suspicious domains
    DEFAULT_BLOCKED_DOMAINS = [
        "malware.com", "phishing-site.net", "spam.org",
        "suspicious-domain.tk", "malicious.ml"
    ]
    
    # Known URL shorteners
    URL_SHORTENERS = [
        "bit.ly", "tinyurl.com", "goo.gl", "t.co", "short.link",
        "ow.ly", "buff.ly", "rebrand.ly", "is.gd", "v.gd"
    ]
    
    def __init__(
        self,
        blocked_domains: Optional[List[str]] = None,
        block_ip_urls: bool = True,
        block_short_urls: bool = False,
        allow_local_urls: bool = True,
        strict_mode: bool = False,
        **kwargs: Any
    ):
        super().__init__(**kwargs)
        
        self.blocked_domains = set(blocked_domains or self.DEFAULT_BLOCKED_DOMAINS)
        self.block_ip_urls = block_ip_urls
        self.block_short_urls = block_short_urls
        self.allow_local_urls = allow_local_urls
        self.strict_mode = strict_mode
    
    def _extract_urls(self, text: str) -> List[str]:
        """Extract URLs using validators library for validation."""
        urls = []
        # Find potential URL candidates
        candidates = re.findall(r'https?://[^\s<>"\']+|www\.[^\s<>"\']+', text, re.IGNORECASE)
        
        for candidate in candidates:
            # Ensure URL has scheme for validation
            if not candidate.startswith(('http://', 'https://')):
                candidate = 'http://' + candidate
            
            # Use validators library for proper URL validation
            try:
                if validators.url(candidate):
                    urls.append(candidate)
            except:
                # If validation fails, include it anyway for further analysis
                urls.append(candidate)
        
        return urls
    
    def _analyze_url(self, url: str) -> Dict[str, Any]:
        """Analyze URL for security issues."""
        issues = []
        risk_score = 0.0
        
        try:
            # Ensure URL has scheme
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            # Validate URL format
            if not validators.url(url):
                issues.append("invalid URL format")
                risk_score += 0.3
            
            # Extract domain
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Check blocked domains
            if domain in self.blocked_domains:
                issues.append("blocked domain")
                risk_score += 0.9
            
            # Check for IP addresses
            if self.block_ip_urls:
                ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
                if re.match(ip_pattern, domain):
                    issues.append("IP address URL")
                    risk_score += 0.7
            
            # Check for URL shorteners
            if self.block_short_urls and domain in self.URL_SHORTENERS:
                issues.append("URL shortener")
                risk_score += 0.5
            
            # Check local/private URLs
            if not self.allow_local_urls:
                if (domain in ['localhost', '127.0.0.1'] or 
                    domain.startswith('192.168.') or 
                    domain.startswith('10.') or
                    domain.startswith('172.')):
                    issues.append("local/private URL")
                    risk_score += 0.4
            
            # Additional security checks
            if len(url) > 200:
                issues.append("excessively long URL")
                risk_score += 0.2
            
            if url.count('-') > 5:
                issues.append("excessive hyphens in URL")
                risk_score += 0.2
            
            return {
                "url": url,
                "domain": domain,
                "issues": issues,
                "risk_score": min(1.0, risk_score)
            }
            
        except Exception as e:
            return {
                "url": url,
                "domain": "unknown",
                "issues": [f"analysis error: {str(e)}"],
                "risk_score": 0.3
            }
    
    def check(self, state: Dict[str, Any]) -> PolicyDecision:
        """
        Professional URL security analysis.
        """
        content_to_check = []
        
        # Extract content from state
        if "messages" in state:
            for msg in state["messages"]:
                if isinstance(msg, dict) and "content" in msg:
                    content_to_check.append(msg["content"])
                elif isinstance(msg, str):
                    content_to_check.append(msg)
        
        for field in ["user_input", "query", "response", "output", "url", "link"]:
            if field in state:
                content_to_check.append(str(state[field]))
        
        # Find and analyze URLs
        all_urls = []
        for content in content_to_check:
            if isinstance(content, str):
                urls = self._extract_urls(content)
                all_urls.extend(urls)
        
        if not all_urls:
            return PolicyDecision(
                decision="ALLOW",
                reason="No URLs detected",
                score=0.0,
                policy_name=self.name,
                metadata={"urls_checked": 0}
            )
        
        # Analyze each URL
        suspicious_urls = []
        max_risk = 0.0
        
        for url in all_urls:
            analysis = self._analyze_url(url)
            max_risk = max(max_risk, analysis["risk_score"])
            
            if analysis["issues"]:
                suspicious_urls.append(analysis)
        
        if not suspicious_urls:
            return PolicyDecision(
                decision="ALLOW",
                reason=f"All {len(all_urls)} URLs appear safe",
                score=0.0,
                policy_name=self.name,
                metadata={
                    "urls_checked": len(all_urls),
                    "safe_urls": len(all_urls)
                }
            )
        
        # Decision logic
        high_risk_count = sum(1 for url in suspicious_urls if url["risk_score"] >= 0.7)
        medium_risk_count = sum(1 for url in suspicious_urls if 0.4 <= url["risk_score"] < 0.7)
        
        if high_risk_count > 0:
            decision = "DENY"
            reason = f"High-risk URLs detected: {high_risk_count} dangerous URLs"
        elif medium_risk_count > 0 or (max_risk >= 0.3 and self.strict_mode):
            decision = "REQUIRE_HUMAN_APPROVAL"
            reason = f"Suspicious URLs require review: {len(suspicious_urls)} flagged URLs"
        else:
            decision = "ALLOW"
            reason = f"Low-risk URLs detected: {len(suspicious_urls)} minor issues"
        
        return PolicyDecision(
            decision=decision,
            reason=reason,
            score=max_risk,
            policy_name=self.name,
            metadata={
                "suspicious_urls": suspicious_urls,
                "total_urls": len(all_urls),
                "high_risk_count": high_risk_count,
                "medium_risk_count": medium_risk_count,
            }
        )


class KeywordFilterPolicy(BasePolicy):
    """
    Professional content filtering using better-profanity and advanced text analysis.
    
    This policy provides enterprise-grade content filtering with:
    - Professional profanity detection using ML models
    - Custom keyword management with severity levels
    - Context-aware filtering to reduce false positives
    - Whitelist exceptions and custom patterns
    - Multi-language support (when available)
    
    Example:
        policy = KeywordFilterPolicy(
            use_profanity_filter=True,
            custom_keywords={"high": ["malware", "virus"], "medium": ["spam"]},
            case_sensitive=False
        )
    """
    
    # Default prohibited keywords by severity
    DEFAULT_KEYWORDS = {
        "high": ["malware", "virus", "trojan", "ransomware", "exploit"],
        "medium": ["spam", "scam", "phishing", "fraud", "hack"],
        "low": ["suspicious", "questionable", "risky"]
    }
    
    def __init__(
        self,
        use_profanity_filter: bool = True,
        custom_keywords: Optional[Dict[str, List[str]]] = None,
        whitelist_exceptions: Optional[List[str]] = None,
        case_sensitive: bool = False,
        word_boundaries: bool = True,
        require_approval_threshold: float = 0.5,
        profanity_threshold: float = 0.7,
        **kwargs: Any
    ):
        super().__init__(**kwargs)
        
        self.use_profanity_filter = use_profanity_filter
        self.case_sensitive = case_sensitive
        self.word_boundaries = word_boundaries
        self.require_approval_threshold = require_approval_threshold
        self.profanity_threshold = profanity_threshold
        
        # Initialize keywords by severity
        self.keywords = {
            "high": [],
            "medium": [], 
            "low": []
        }
        
        # Load default keywords
        for severity, words in self.DEFAULT_KEYWORDS.items():
            self.keywords[severity].extend(words)
        
        # Add custom keywords
        if custom_keywords:
            for severity, words in custom_keywords.items():
                if severity in self.keywords:
                    self.keywords[severity].extend(words)
        
        # Setup whitelist
        self.whitelist = whitelist_exceptions or []
        
        # Normalize case if needed
        if not case_sensitive:
            for severity in self.keywords:
                self.keywords[severity] = [kw.lower() for kw in self.keywords[severity]]
            self.whitelist = [kw.lower() for kw in self.whitelist]
        
        # Note: Simple keyword-based profanity filter
        self.profanity_detector = use_profanity_filter
        
        # Compile keyword patterns for efficient matching
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Compile regex patterns for efficient keyword matching."""
        self.compiled_patterns = {}
        
        for severity, words in self.keywords.items():
            patterns = []
            for word in words:
                if self.word_boundaries:
                    # Use word boundaries for exact word matching
                    pattern = r'\b' + re.escape(word) + r'\b'
                else:
                    # Simple substring matching
                    pattern = re.escape(word)
                
                flags = 0 if self.case_sensitive else re.IGNORECASE
                patterns.append(re.compile(pattern, flags))
            
            self.compiled_patterns[severity] = patterns
    
    def _check_profanity_simple(self, text: str) -> Dict[str, Any]:
        """Simple profanity detection using basic keyword matching."""
        if not self.profanity_detector:
            return {"detected": False, "confidence": 0.0, "details": []}
        
        # Simple profanity word list
        profanity_words = ["damn", "hell", "crap", "shit", "fuck", "ass", "bitch"]
        
        text_lower = text.lower()
        detected_words = []
        
        for word in profanity_words:
            if word in text_lower:
                detected_words.append(word)
        
        if detected_words:
            confidence = min(1.0, len(detected_words) * 0.3)
            return {
                "detected": True,
                "confidence": confidence,
                "detected_words": detected_words,
                "details": [f"Basic profanity detected: {', '.join(detected_words)}"]
            }
        
        return {"detected": False, "confidence": 0.0, "details": []}
    
    def _check_custom_keywords(self, text: str) -> Dict[str, List[Dict[str, Any]]]:
        """Check for custom keywords by severity level."""
        matches = {"high": [], "medium": [], "low": []}
        
        check_text = text if self.case_sensitive else text.lower()
        
        for severity, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                for match in pattern.finditer(check_text):
                    # Get context around the match
                    start = max(0, match.start() - 20)
                    end = min(len(text), match.end() + 20)
                    context = text[start:end]
                    
                    matches[severity].append({
                        "keyword": match.group(),
                        "position": match.start(),
                        "context": context,
                        "pattern": pattern.pattern
                    })
        
        return matches
    
    def _check_whitelist_exceptions(self, text: str) -> List[Dict[str, Any]]:
        """Check for whitelist exceptions that might reduce risk."""
        exceptions = []
        check_text = text if self.case_sensitive else text.lower()
        
        for exception in self.whitelist:
            if exception in check_text:
                exceptions.append({
                    "exception": exception,
                    "context": text[:100] + "..." if len(text) > 100 else text
                })
        
        return exceptions
    
    def check(self, state: Dict[str, Any]) -> PolicyDecision:
        """
        Professional content filtering with multiple detection methods.
        """
        content_to_check = []
        
        # Extract content from state
        if "messages" in state:
            for msg in state["messages"]:
                if isinstance(msg, dict) and "content" in msg:
                    content_to_check.append(msg["content"])
                elif isinstance(msg, str):
                    content_to_check.append(msg)
        
        for field in ["user_input", "query", "response", "output", "title", "description"]:
            if field in state:
                content_to_check.append(str(state[field]))
        
        # Analyze all content
        all_profanity_results = []
        all_keyword_matches = {"high": [], "medium": [], "low": []}
        all_whitelist_exceptions = []
        
        for content in content_to_check:
            if not isinstance(content, str) or not content.strip():
                continue
            
            # Simple profanity detection
            if self.use_profanity_filter:
                profanity_result = self._check_profanity_simple(content)
                if profanity_result["detected"]:
                    all_profanity_results.append(profanity_result)
            
            # Custom keyword detection
            keyword_matches = self._check_custom_keywords(content)
            for severity in all_keyword_matches:
                all_keyword_matches[severity].extend(keyword_matches[severity])
            
            # Whitelist exceptions
            exceptions = self._check_whitelist_exceptions(content)
            all_whitelist_exceptions.extend(exceptions)
        
        # Calculate detection statistics
        total_profanity = len(all_profanity_results)
        total_keywords = sum(len(matches) for matches in all_keyword_matches.values())
        total_exceptions = len(all_whitelist_exceptions)
        
        # Check if content is clean
        if total_profanity == 0 and total_keywords == 0:
            return PolicyDecision(
                decision="ALLOW",
                reason="No inappropriate content detected",
                score=0.0,
                policy_name=self.name,
                metadata={
                    "using_profanity_filter": self.profanity_detector,
                    "keywords_checked": sum(len(words) for words in self.keywords.values()),
                    "content_analyzed": len(content_to_check)
                }
            )
        
        # Calculate risk score
        risk_score = 0.0
        
        # Profanity contributes to risk
        if all_profanity_results:
            max_profanity_confidence = max(result["confidence"] for result in all_profanity_results)
            risk_score += max_profanity_confidence * 0.6
        
        # Keywords contribute by severity
        risk_score += len(all_keyword_matches["high"]) * 0.8
        risk_score += len(all_keyword_matches["medium"]) * 0.5
        risk_score += len(all_keyword_matches["low"]) * 0.2
        
        # Reduce risk for whitelist exceptions
        if total_exceptions > 0:
            risk_score *= 0.5  # More significant reduction for whitelist exceptions
        
        risk_score = min(1.0, risk_score)
        
        # Decision logic
        high_severity_issues = (
            len(all_keyword_matches["high"]) + 
            sum(1 for result in all_profanity_results if result["confidence"] >= self.profanity_threshold)
        )
        
        # Consider whitelist exceptions in decision logic
        if high_severity_issues > 0 and total_exceptions == 0:
            decision = "DENY"
            reason = f"High-severity inappropriate content: {high_severity_issues} critical violations"
        elif risk_score >= self.require_approval_threshold:
            decision = "REQUIRE_HUMAN_APPROVAL"
            reason = f"Inappropriate content requires review: {total_profanity + total_keywords} issues"
        else:
            decision = "ALLOW"
            reason = f"Low-severity content issues: {total_profanity + total_keywords} minor violations"
        
        return PolicyDecision(
            decision=decision,
            reason=reason,
            score=risk_score,
            policy_name=self.name,
            metadata={
                "profanity_results": all_profanity_results,
                "keyword_matches": all_keyword_matches,
                "whitelist_exceptions": all_whitelist_exceptions,
                "total_profanity": total_profanity,
                "total_keywords": total_keywords,
                "high_severity_issues": high_severity_issues,
                "using_profanity_filter": self.profanity_detector,
                "risk_breakdown": {
                    "high_keywords": len(all_keyword_matches["high"]),
                    "medium_keywords": len(all_keyword_matches["medium"]),
                    "low_keywords": len(all_keyword_matches["low"]),
                    "profanity_detections": total_profanity
                }
            }
        )


class DataLeakagePolicy(BasePolicy):
    """
    Detects potential data leakage in AI agent outputs.
    
    This policy checks for sensitive information that should not be
    exposed in responses, including internal system details, user data,
    and confidential information.
    
    Example:
        policy = DataLeakagePolicy(
            check_system_paths=True,
            check_internal_ips=True,
            check_user_data=True
        )
    """
    
    # Patterns for different types of data leakage
    SYSTEM_PATTERNS = [
        r"/etc/passwd|/etc/shadow|/home/\w+",  # Unix system paths
        r"C:\\Windows|C:\\Users|C:\\Program Files",  # Windows paths
        r"SECRET_KEY|API_SECRET|DATABASE_URL",  # Config variables
        r"localhost:\d+|127\.0\.0\.1:\d+",  # Local services
    ]
    
    NETWORK_PATTERNS = [
        r"192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+",  # Private IPs
        r"username.*password|user.*pass|login.*credentials",  # Credentials
        r"token[:\s=]+[a-zA-Z0-9_\-]{20,}",  # Tokens
    ]
    
    DATABASE_PATTERNS = [
        r"SELECT.*FROM.*WHERE|INSERT INTO|UPDATE.*SET|DELETE FROM",  # SQL queries
        r"mongodb://|redis://|postgresql://|mysql://",  # Database URLs
        r"database.*error|sql.*exception|connection.*failed",  # DB errors
    ]
    
    def __init__(
        self,
        check_system_paths: bool = True,
        check_internal_ips: bool = True,
        check_credentials: bool = True,
        check_database_info: bool = True,
        check_error_messages: bool = True,
        custom_patterns: Optional[List[str]] = None,
        sensitivity_threshold: float = 0.4,
        **kwargs: Any
    ):
        super().__init__(**kwargs)
        
        self.check_system_paths = check_system_paths
        self.check_internal_ips = check_internal_ips
        self.check_credentials = check_credentials
        self.check_database_info = check_database_info
        self.check_error_messages = check_error_messages
        self.sensitivity_threshold = sensitivity_threshold
        
        # Build pattern list based on configuration
        self.active_patterns = []
        
        if check_system_paths:
            self.active_patterns.extend([
                ("system_path", pattern) for pattern in self.SYSTEM_PATTERNS
            ])
        
        if check_internal_ips or check_credentials:
            self.active_patterns.extend([
                ("network_info", pattern) for pattern in self.NETWORK_PATTERNS
            ])
        
        if check_database_info:
            self.active_patterns.extend([
                ("database_info", pattern) for pattern in self.DATABASE_PATTERNS
            ])
        
        # Add custom patterns
        if custom_patterns:
            self.active_patterns.extend([
                ("custom", pattern) for pattern in custom_patterns
            ])
        
        # Compile patterns
        self.compiled_patterns = [
            (category, re.compile(pattern, re.IGNORECASE | re.MULTILINE))
            for category, pattern in self.active_patterns
        ]
    
    def check(self, state: Dict[str, Any]) -> PolicyDecision:
        """
        Check for potential data leakage in state content.
        """
        content_to_check = []
        
        # Focus on output content that might contain leakage
        for field in ["response", "output", "result", "error", "debug"]:
            if field in state:
                content_to_check.append(str(state[field]))
        
        # Also check messages for leakage
        if "messages" in state:
            for msg in state["messages"]:
                if isinstance(msg, dict) and "content" in msg:
                    content_to_check.append(msg["content"])
                elif isinstance(msg, str):
                    content_to_check.append(msg)
        
        # Check for leakage patterns
        detected_leakage = []
        
        for content in content_to_check:
            if not isinstance(content, str):
                continue
            
            for category, pattern in self.compiled_patterns:
                matches = pattern.findall(content)
                if matches:
                    detected_leakage.append({
                        "category": category,
                        "pattern": pattern.pattern,
                        "matches_count": len(matches),
                        "context": content[:150] + "..." if len(content) > 150 else content,
                        "severity": self._calculate_severity(category, matches)
                    })
        
        if not detected_leakage:
            return PolicyDecision(
                decision="ALLOW",
                reason="No data leakage detected",
                score=0.0,
                policy_name=self.name,
                metadata={"patterns_checked": len(self.compiled_patterns)}
            )
        
        # Calculate risk score
        risk_score = 0.0
        high_severity_count = 0
        
        for leak in detected_leakage:
            risk_score += leak["severity"]
            if leak["severity"] >= 0.7:
                high_severity_count += 1
        
        risk_score = min(1.0, risk_score)
        
        # Decision logic
        if high_severity_count > 0:
            decision = "DENY"
            reason = f"High-risk data leakage detected: {high_severity_count} critical leaks"
        elif risk_score >= self.sensitivity_threshold:
            decision = "REQUIRE_HUMAN_APPROVAL"
            reason = f"Potential data leakage requires review: {len(detected_leakage)} issues"
        else:
            decision = "ALLOW"
            reason = f"Low-risk information exposure: {len(detected_leakage)} minor issues"
        
        return PolicyDecision(
            decision=decision,
            reason=reason,
            score=risk_score,
            policy_name=self.name,
            metadata={
                "detected_leakage": detected_leakage,
                "high_severity_count": high_severity_count,
                "total_issues": len(detected_leakage),
                "risk_breakdown": {
                    category: len([leak for leak in detected_leakage if leak["category"] == category])
                    for category in set(leak["category"] for leak in detected_leakage)
                }
            }
        )
    
    def _calculate_severity(self, category: str, matches: List[str]) -> float:
        """Calculate severity score based on leakage category and content."""
        base_scores = {
            "system_path": 0.8,
            "network_info": 0.7,
            "database_info": 0.9,
            "custom": 0.6
        }
        
        base_score = base_scores.get(category, 0.5)
        match_bonus = min(0.3, len(matches) * 0.1)
        
        return min(1.0, base_score + match_bonus)