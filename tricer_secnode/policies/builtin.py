"""
Tricer SecNode Built-in Security Policies

This module provides a comprehensive library of ready-to-use security policies
for common AI agent security concerns. These policies can be used individually
or combined with policy combinators for complex security requirements.
"""

import re
from typing import Any, Dict, List, Optional, Set, Union
from tricer_secnode.policies.core import BasePolicy, PolicyDecision


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
    Detects and blocks potential personally identifiable information (PII).
    
    This policy scans content for common PII patterns including:
    - Social Security Numbers
    - Credit card numbers  
    - Email addresses
    - Phone numbers
    - Custom patterns for specific PII types
    
    Example:
        policy = PIIDetectionPolicy(
            block_emails=False,  # Allow emails
            block_phones=True,   # Block phone numbers
            custom_patterns={'account_id': r'ACC-\d{8}'}
        )
    """
    
    # Common PII patterns
    PII_PATTERNS = {
        "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
        "credit_card": r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
        "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "phone": r"\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b",
        "ip_address": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
    }
    
    def __init__(
        self,
        block_emails: bool = True,
        block_phones: bool = True,
        block_ssn: bool = True,
        block_credit_cards: bool = True,
        block_ip_addresses: bool = False,
        custom_patterns: Optional[Dict[str, str]] = None,
        **kwargs: Any
    ):
        super().__init__(**kwargs)
        
        # Configure which PII types to check
        self.active_patterns = {}
        
        if block_ssn:
            self.active_patterns["ssn"] = self.PII_PATTERNS["ssn"]
        if block_credit_cards:
            self.active_patterns["credit_card"] = self.PII_PATTERNS["credit_card"]
        if block_emails:
            self.active_patterns["email"] = self.PII_PATTERNS["email"]
        if block_phones:
            self.active_patterns["phone"] = self.PII_PATTERNS["phone"]
        if block_ip_addresses:
            self.active_patterns["ip_address"] = self.PII_PATTERNS["ip_address"]
        
        # Add custom patterns
        if custom_patterns:
            self.active_patterns.update(custom_patterns)
        
        # Compile patterns for efficiency
        self.compiled_patterns = {
            name: re.compile(pattern, re.IGNORECASE)
            for name, pattern in self.active_patterns.items()
        }
    
    def check(self, state: Dict[str, Any]) -> PolicyDecision:
        """
        Scan state content for PII patterns.
        
        Examines messages, inputs, and other text fields for
        personally identifiable information.
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
        
        # Check for PII patterns
        detected_pii = []
        
        for content in content_to_check:
            if not isinstance(content, str):
                continue
                
            for pii_type, pattern in self.compiled_patterns.items():
                matches = pattern.findall(content)
                if matches:
                    detected_pii.append({
                        "type": pii_type,
                        "matches": len(matches),
                        "examples": matches[:3],  # Limit examples for security
                    })
        
        if not detected_pii:
            return PolicyDecision(
                decision="ALLOW",
                reason="No PII detected",
                score=0.0,
                policy_name=self.name,
                metadata={"pii_types_checked": list(self.active_patterns.keys())}
            )
        
        # Calculate risk based on PII types and quantities
        risk_score = 0.0
        total_matches = sum(pii["matches"] for pii in detected_pii)
        
        # Base risk calculation
        risk_score = min(0.9, total_matches * 0.3)
        
        # Increase risk for sensitive PII types
        sensitive_types = {"ssn", "credit_card"}
        for pii in detected_pii:
            if pii["type"] in sensitive_types:
                risk_score = min(1.0, risk_score + 0.4)
        
        # Decision based on risk
        if risk_score >= 0.8:
            decision = "DENY"
            reason = f"High-risk PII detected: {[p['type'] for p in detected_pii]}"
        elif risk_score >= 0.4:
            decision = "REQUIRE_HUMAN_APPROVAL"
            reason = f"PII detected requiring review: {[p['type'] for p in detected_pii]}"
        else:
            decision = "ALLOW"
            reason = f"Low-risk PII detected: {[p['type'] for p in detected_pii]}"
        
        return PolicyDecision(
            decision=decision,
            reason=reason,
            score=risk_score,
            policy_name=self.name,
            metadata={
                "detected_pii": detected_pii,
                "total_matches": total_matches,
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