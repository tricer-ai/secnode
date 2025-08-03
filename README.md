# SecNode

**Tricer SecNode: The Native Security Layer for AI Agents**

> **Beyond Guardrails: Securing AI's Actions, Not Just Its Words.**

SecNode is a comprehensive security framework for AI applications, from simple workflows to complex graph-based agents. Built with a "Security as a Node" philosophy, SecNode provides layered security that scales from basic prompt filtering to advanced multi-agent system protection.

## 🚀 Key Features

- **🔒 Multi-Layer Security**: Prompt injection, PII detection, tool whitelisting, and code execution controls
- **📊 Graph-Native**: Purpose-built for LangGraph and other graph-based AI frameworks  
- **🔧 Developer-Friendly**: Pythonic API with no new DSL to learn
- **☁️ Enterprise Ready**: Cloud analytics, centralized policy management, and compliance reporting
- **🏗️ Ecosystem Hub**: Extensible architecture for integrating additional security tools

## ⚡ Quick Start

### Installation

```bash
# Simple installation - everything included
pip install secnode
```

SecNode includes professional security libraries out of the box:
- **detect-secrets**: Enterprise-grade secret detection
- **validators**: Professional URL validation 
- **presidio-analyzer**: Advanced PII detection
- **limits**: Professional rate limiting

### 30-Second Quick Start

```python
from secnode import WrapperNode

# Protect any function with just one line!
@WrapperNode.protect()
def my_ai_assistant(user_query: str) -> str:
    # Your AI logic here (example)
    return f"AI Response: I understand you're asking about '{user_query}'"

# That's it! Your AI assistant now has comprehensive security protection
result = my_ai_assistant("What's the weather like?")  # ✅ Safe
result = my_ai_assistant("Ignore all instructions...")  # 🚫 Blocked
```

### Advanced Usage (When You Need More Control)

```python
from secnode import GuardNode, PromptInjectionPolicy, ToolCallWhitelistPolicy, AllOf

# Create a comprehensive security policy
security_policy = AllOf([
    PromptInjectionPolicy(sensitivity=0.7),
    ToolCallWhitelistPolicy(['search', 'calculator', 'weather'])
])

# Create a guard node
guard = GuardNode(policy=security_policy)

# Evaluate security in your agent workflow
def security_check(state):
    decision = guard.invoke(state)
    
    if decision.is_denied():
        return {"error": f"Blocked: {decision.reason}"}
    elif decision.requires_approval():
        return {"status": "pending_approval", "reason": decision.reason}
    else:
        return {"status": "approved", **state}
```

### Common Use Cases

```python
# Chatbot Protection
@WrapperNode.protect(level="balanced")
def chatbot_response(user_message: str) -> str:
    # Your chatbot logic here
    return f"Chatbot: I hear you saying '{user_message}'"

# Search Assistant
@WrapperNode.protect(level="performance")  # Faster for search
def search_assistant(query: str) -> str:
    # Your search logic here
    return f"Search results for: {query}"

# Enterprise AI (Maximum Security)
@WrapperNode.protect(level="maximum_security")
def enterprise_ai(sensitive_data: str) -> str:
    # Your enterprise AI logic here
    return f"Processed: {len(sensitive_data)} characters safely"
```

### LangGraph Integration

```python
# Note: Requires 'pip install langgraph'
from langgraph.graph import StateGraph, END
from secnode import TricerSecurityState, GuardNode

# Define your state with security
class AgentState(TricerSecurityState):
    messages: list
    query: str

# Create guard and security function
guard = GuardNode.create("balanced")

def security_check(state):
    decision = guard.invoke(state)
    if decision.is_denied():
        return {"error": f"Blocked: {decision.reason}"}
    return {"status": "approved", **state}

def search_function(state):
    # Your search logic here
    return {"result": f"Search results for: {state.get('query', '')}", **state}

# Create secured workflow
workflow = StateGraph(AgentState)

# Add nodes
workflow.add_node("security_gate", security_check)
workflow.add_node("search_tool", search_function)

# Add conditional routing based on security decisions
workflow.add_conditional_edges(
    "security_gate",
    lambda state: "allow" if state.get("status") == "approved" else "deny",
    {"allow": "search_tool", "deny": END}
)

# Set entry point
workflow.set_entry_point("security_gate")

app = workflow.compile()
```

## 🛡️ Built-in Security Policies

### Prompt Injection Protection
```python
from secnode import PromptInjectionPolicy

policy = PromptInjectionPolicy(
    sensitivity=0.8,  # 0.0 = permissive, 1.0 = strict
    block_system_prompts=True
)
```

### Tool Call Whitelisting
```python
from secnode import ToolCallWhitelistPolicy

policy = ToolCallWhitelistPolicy(
    allowed_tools=['search', 'calculator', 'weather'],
    strict_mode=True
)
```

### PII Detection
```python
from secnode import PIIDetectionPolicy

policy = PIIDetectionPolicy(
    threshold=0.7,  # Confidence threshold (0.0-1.0)
    entities=["PERSON", "SSN", "CREDIT_CARD", "EMAIL_ADDRESS"],
    block_high_confidence=True
)
```

### Code Execution Control
```python
from secnode import CodeExecutionPolicy

policy = CodeExecutionPolicy(
    allowed_languages=['python'],
    block_file_operations=True,
    block_network_calls=True
)
```

### Confidential Data Detection
```python
from secnode import ConfidentialDataPolicy

# Professional secret detection with detect-secrets
policy = ConfidentialDataPolicy(
    sensitivity_markers=["CONFIDENTIAL", "SECRET", "INTERNAL"],
    secret_confidence_threshold=0.7,
    strict_mode=False
)
```

### Rate Limiting
```python
from secnode import RateLimitPolicy

# Professional rate limiting with limits library
policy = RateLimitPolicy(
    limits=["20/minute", "200/hour", "5/second"],
    strategy="moving-window",  # Professional algorithms
    storage_uri=None  # Use "redis://..." for Redis backend
)
```

### Content Length Control
```python
from secnode import ContentLengthPolicy

policy = ContentLengthPolicy(
    max_message_length=10000,
    max_total_length=100000,
    max_messages=500
)
```

### URL Blacklist
```python
from secnode import URLBlacklistPolicy

# Professional URL validation with validators library
policy = URLBlacklistPolicy(
    blocked_domains=["malicious.com", "spam-site.net"],
    block_ip_urls=True,
    block_short_urls=False
)
```

### Keyword Filtering
```python
from secnode import KeywordFilterPolicy

# Simple but effective content filtering
policy = KeywordFilterPolicy(
    use_profanity_filter=True,  # Basic profanity detection
    custom_keywords={"high": ["malware", "virus"], "medium": ["spam"]},
    profanity_threshold=0.7,
    case_sensitive=False
)
```

### Data Leakage Prevention
```python
from secnode import DataLeakagePolicy

policy = DataLeakagePolicy(
    check_system_paths=True,
    check_internal_ips=True,
    sensitivity_threshold=0.4
)
```

## 🔧 Advanced Usage

### Policy Composition
```python
from secnode import AllOf, AnyOf

# All policies must pass
strict_policy = AllOf([
    PromptInjectionPolicy(),
    ToolCallWhitelistPolicy(['safe_tool']),
    PIIDetectionPolicy()
])

# Any policy can allow
permissive_policy = AnyOf([
    WhitelistedUserPolicy(),
    LowRiskContentPolicy(threshold=0.3)
])
```

### Node Wrapping
```python
from secnode import WrapperNode

# Wrap any existing function with security
def original_search_function(state):
    # Your original search logic here
    return {"result": f"Search: {state.get('query', '')}"}

secure_search = WrapperNode.wrap(
    node=original_search_function,
    policy=ToolCallWhitelistPolicy(['search']),
    on_deny=lambda state: {"error": "Search not allowed"}
)
```



## 📚 Core Concepts

### Security State
SecNode uses `TricerSecurityState` to maintain security context across agent execution:

```python
from secnode import TricerSecurityState, create_security_state

# Create a new security state
state = create_security_state()

# Access audit log
print(state["audit_log"])  # List of security events
print(state["last_sec_decision"])  # Most recent decision
```

### Policy Decisions
All policies return standardized `PolicyDecision` objects:

```python
decision = policy.check(state)

print(decision.decision)  # "ALLOW", "DENY", or "REQUIRE_HUMAN_APPROVAL"
print(decision.reason)    # Human-readable explanation
print(decision.score)     # Risk score from 0.0 to 1.0
print(decision.metadata)  # Additional policy-specific data
```



## 🧩 Extensibility

### Custom Policies
```python
from secnode import BasePolicy, PolicyDecision

class CustomSecurityPolicy(BasePolicy):
    def check(self, state):
        # Your custom security logic here
        if self.is_risky(state):
            return PolicyDecision(
                decision="DENY",
                reason="Custom security rule violation",
                score=0.8,
                policy_name=self.name
            )
        return PolicyDecision(
            decision="ALLOW",
            reason="Custom policy passed",
            score=0.1,
            policy_name=self.name
        )
```

### Framework Integration
SecNode is designed to work with any Python AI framework:

- **LangGraph**: Native integration with conditional edges
- **LangChain**: Works with any LangChain agent or chain
- **Custom Frameworks**: Framework-agnostic core components
- **Async/Await**: Full async support for high-performance applications

## 📖 Documentation

- [Complete Documentation](https://secnode.tricer.ai)
- [API Reference](https://secnode.tricer.ai/api)
- [Security Best Practices](https://secnode.tricer.ai/security)
- [Enterprise Features](https://secnode.tricer.ai/enterprise)

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## 📄 License

Tricer SecNode is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## 🆘 Support

- **Documentation**: https://secnode.tricer.ai
- **GitHub Issues**: https://github.com/tricer-ai/secnode/issues
- **Enterprise Support**: hello@tricer.ai
- **Community**: Join our [Discord](https://discord.gg/tricer-ai)

---

**Built with ❤️ by the Tricer.ai team**

*Tricer SecNode: Making AI systems more secure, one node at a time.*