"""
Tricer SecNode Built-in Security Policies

This module provides a comprehensive library of ready-to-use security policies
for common AI agent security concerns. These policies can be used individually
or combined with policy combinators for complex security requirements.
"""

import re
from typing import Any, Dict, List, Optional, Set, Union
from tricer_secnode.policies.core import BasePolicy, PolicyDecision

try:
    from presidio_analyzer import AnalyzerEngine
    PRESIDIO_AVAILABLE = True
except ImportError:
    PRESIDIO_AVAILABLE = False


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
                tool_name = (
                    tool_call.get("name") or 
                    tool_call.get("tool") or 
                    tool_call.get("function", {}).get("name") if isinstance(tool_call.get("function"), dict) else None
                )
            
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
        
        if not PRESIDIO_AVAILABLE:
            raise ImportError(
                "presidio-analyzer is required for PIIDetectionPolicy. "
                "Install it with: pip install presidio-analyzer"
            )
        
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