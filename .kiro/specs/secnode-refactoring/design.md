# SecNode Project Refactoring Design Document

## Overview

This design document details the technical approach for SecNode project refactoring, including specific implementation plans for cloud functionality removal, test file organization, and code optimization.

## Architecture Design

### Overall Architecture Changes

```
Before Refactoring:
secnode/
├── __init__.py (contains CloudSyncer)
├── cloud.py (cloud functionality)
├── graph.py (depends on CloudSyncer)
├── policies/
└── state.py

After Refactoring:
secnode/
├── __init__.py (CloudSyncer removed)
├── graph.py (cloud dependencies removed)
├── policies/
├── state.py
└── utils/
    ├── __init__.py
    ├── testing.py (test utilities)
    └── common.py (common functions)
```

## Component Design

### 1. Cloud Functionality Removal Design

#### 1.1 File Deletion
- **Delete file**: `secnode/cloud.py`
- **Impact scope**: All modules that reference `CloudSyncer`

#### 1.2 Dependency Cleanup
- **Remove dependency**: `aiohttp>=3.8.0` from pyproject.toml
- **Keep dependencies**: Core security functionality related dependencies

#### 1.3 Code Modification Strategy
```python
# Before modification (graph.py)
from secnode.cloud import CloudSyncer

class GuardNode:
    def __init__(self, policy, cloud_syncer=None):
        self.cloud_syncer = cloud_syncer

# After modification (graph.py)  
class GuardNode:
    def __init__(self, policy):
        # Remove cloud_syncer parameter
```

### 2. Test File Organization Design

#### 2.1 Target Test Structure
```
tests/
├── __init__.py
├── conftest.py (pytest configuration)
├── unit/
│   ├── __init__.py
│   ├── test_policies.py
│   ├── test_graph.py
│   └── test_state.py
├── integration/
│   ├── __init__.py
│   └── test_full_workflow.py
└── utils/
    ├── __init__.py
    ├── fixtures.py (test data)
    └── helpers.py (test utility functions)
```

#### 2.2 File Migration Plan
- **Delete**: `test_*.py` files in root directory
- **Merge**: Combine similar functionality tests into unified files
- **Reorganize**: Reorganize tests by functional modules

### 3. Code Optimization Design

#### 3.1 Common Utility Class Design
```python
# secnode/utils/common.py
class PolicyUtils:
    @staticmethod
    def extract_content_from_state(state: Dict[str, Any]) -> List[str]:
        """Common method for extracting text content from state"""
        
    @staticmethod
    def calculate_risk_score(factors: List[float]) -> float:
        """Common method for calculating risk score"""
```

#### 3.2 Test Utility Class Design
```python
# tests/utils/helpers.py
class PolicyTestHelper:
    @staticmethod
    def create_test_state(**kwargs) -> Dict[str, Any]:
        """Utility function for creating test state"""
        
    @staticmethod
    def assert_policy_decision(decision, expected_decision, min_score=None):
        """Utility function for asserting policy decisions"""
```

#### 3.3 Exception Handling Standardization
```python
# Unified exception handling pattern
try:
    result = policy.check(state)
except SpecificException as e:
    # Specific exception handling
    logger.warning(f"Specific error: {e}")
    return default_decision
except Exception as e:
    # General exception handling
    logger.error(f"Unexpected error: {e}")
    return error_decision
```

## Data Models

### Configuration Model Simplification
```python
# Remove cloud configuration related data models
# Keep core policy configuration models
class PolicyConfig(BaseModel):
    name: str
    enabled: bool = True
    parameters: Dict[str, Any] = Field(default_factory=dict)
```

## Error Handling

### Unified Error Handling Strategy
1. **Policy-level errors**: Return clear PolicyDecision
2. **System-level errors**: Log and return safe default decisions
3. **Configuration errors**: Throw clear exceptions during initialization

## Testing Strategy

### Test Layering
1. **Unit tests**: Test individual policies and components
2. **Integration tests**: Test policy combinations and workflows
3. **Performance tests**: Verify performance commitments

### Test Data Management
- Use fixtures to manage test data
- Create reusable test state generators
- Unified test assertion methods

## Backward Compatibility

### API Compatibility Guarantee
- Keep core APIs unchanged
- Mark cloud functionality related parameters as deprecated
- Provide migration guide

### Progressive Migration
- Phase 1: Remove cloud functionality
- Phase 2: Organize test structure  
- Phase 3: Optimize duplicate code

## Performance Considerations

### Optimization Goals
- Reduce import time (remove heavy dependencies)
- Improve policy execution efficiency
- Optimize memory usage

### Performance Monitoring
- Add simple performance timing
- Monitor memory usage
- Provide performance benchmarks