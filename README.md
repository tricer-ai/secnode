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
pip install secnode
```

### Basic Usage

```python
from tricer_secnode import GuardNode, PromptInjectionPolicy, ToolCallWhitelistPolicy, AllOf

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

### LangGraph Integration

```python
from langgraph.graph import StateGraph
from tricer_secnode import TricerSecurityState, GuardNode, WrapperNode

# Define your state with security
class AgentState(TricerSecurityState):
    messages: list
    query: str

# Create secured workflow
workflow = StateGraph(AgentState)

# Add security gate
workflow.add_node("security_gate", security_check)
workflow.add_node("search_tool", search_function)

# Add conditional routing based on security decisions
workflow.add_conditional_edges(
    "security_gate",
    lambda state: "allow" if state.get("status") == "approved" else "deny",
    {"allow": "search_tool", "deny": END}
)

app = workflow.compile()
```

## 🛡️ Built-in Security Policies

### Prompt Injection Protection
```python
from tricer_secnode import PromptInjectionPolicy

policy = PromptInjectionPolicy(
    sensitivity=0.8,  # 0.0 = permissive, 1.0 = strict
    block_system_prompts=True
)
```

### Tool Call Whitelisting
```python
from tricer_secnode import ToolCallWhitelistPolicy

policy = ToolCallWhitelistPolicy(
    allowed_tools=['search', 'calculator', 'weather'],
    strict_mode=True
)
```

### PII Detection
```python
from tricer_secnode import PIIDetectionPolicy

policy = PIIDetectionPolicy(
    block_emails=False,
    block_phones=True,
    block_ssn=True,
    custom_patterns={'account_id': r'ACC-\\d{8}'}
)
```

### Code Execution Control
```python
from tricer_secnode import CodeExecutionPolicy

policy = CodeExecutionPolicy(
    allowed_languages=['python'],
    block_file_operations=True,
    block_network_calls=True
)
```

## 🔧 Advanced Usage

### Policy Composition
```python
from tricer_secnode import AllOf, AnyOf

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
from tricer_secnode import WrapperNode

# Wrap any existing function with security
secure_search = WrapperNode.wrap(
    node=original_search_function,
    policy=ToolCallWhitelistPolicy(['search']),
    on_deny=lambda state: {"error": "Search not allowed"}
)
```

### Cloud Integration
```python
from tricer_secnode import CloudSyncer

# Enable enterprise features
cloud_syncer = CloudSyncer(
    api_key="your-tricer-api-key",
    enable_analytics=True,
    enable_compliance=True
)

guard = GuardNode(
    policy=your_policy,
    cloud_syncer=cloud_syncer
)
```

## 📚 Core Concepts

### Security State
SecNode uses `TricerSecurityState` to maintain security context across agent execution:

```python
from tricer_secnode import TricerSecurityState, create_security_state

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

## 🏢 Enterprise Features

### Analytics & Monitoring
- Real-time security event streaming
- Policy effectiveness metrics  
- Risk trend analysis
- Custom dashboards

### Centralized Policy Management
- Policy versioning and rollback
- A/B testing for security policies
- Environment-specific configurations
- Automated policy updates

### Compliance & Reporting
- SOC 2, GDPR, HIPAA compliance templates
- Automated audit trails
- Risk assessment reports
- Incident response workflows

## 🧩 Extensibility

### Custom Policies
```python
from tricer_secnode import BasePolicy, PolicyDecision

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