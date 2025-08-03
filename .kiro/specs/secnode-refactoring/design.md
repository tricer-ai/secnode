# SecNode 项目重构设计文档

## 概述

本设计文档详细描述了 SecNode 项目重构的技术方案，包括云端功能删除、测试文件整理和代码优化的具体实现方案。

## 架构设计

### 整体架构变化

```
重构前:
secnode/
├── __init__.py (包含 CloudSyncer)
├── cloud.py (云端功能)
├── graph.py (依赖 CloudSyncer)
├── policies/
└── state.py

重构后:
secnode/
├── __init__.py (移除 CloudSyncer)
├── graph.py (移除云端依赖)
├── policies/
├── state.py
└── utils/
    ├── __init__.py
    ├── testing.py (测试工具)
    └── common.py (公共函数)
```

## 组件设计

### 1. 云端功能删除设计

#### 1.1 文件删除
- **删除文件**: `secnode/cloud.py`
- **影响范围**: 所有引用 `CloudSyncer` 的模块

#### 1.2 依赖清理
- **移除依赖**: `aiohttp>=3.8.0` 从 pyproject.toml
- **保留依赖**: 核心安全功能相关的依赖

#### 1.3 代码修改策略
```python
# 修改前 (graph.py)
from secnode.cloud import CloudSyncer

class GuardNode:
    def __init__(self, policy, cloud_syncer=None):
        self.cloud_syncer = cloud_syncer

# 修改后 (graph.py)  
class GuardNode:
    def __init__(self, policy):
        # 移除 cloud_syncer 参数
```

### 2. 测试文件整理设计

#### 2.1 目标测试结构
```
tests/
├── __init__.py
├── conftest.py (pytest 配置)
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
    ├── fixtures.py (测试数据)
    └── helpers.py (测试工具函数)
```

#### 2.2 文件迁移计划
- **删除**: 根目录下的 `test_*.py` 文件
- **合并**: 将相似功能的测试合并到统一文件
- **重组**: 按功能模块重新组织测试

### 3. 代码优化设计

#### 3.1 公共工具类设计
```python
# secnode/utils/common.py
class PolicyUtils:
    @staticmethod
    def extract_content_from_state(state: Dict[str, Any]) -> List[str]:
        """从状态中提取文本内容的通用方法"""
        
    @staticmethod
    def calculate_risk_score(factors: List[float]) -> float:
        """计算风险分数的通用方法"""
```

#### 3.2 测试工具类设计
```python
# tests/utils/helpers.py
class PolicyTestHelper:
    @staticmethod
    def create_test_state(**kwargs) -> Dict[str, Any]:
        """创建测试状态的工具函数"""
        
    @staticmethod
    def assert_policy_decision(decision, expected_decision, min_score=None):
        """断言策略决策的工具函数"""
```

#### 3.3 异常处理标准化
```python
# 统一异常处理模式
try:
    result = policy.check(state)
except SpecificException as e:
    # 具体异常处理
    logger.warning(f"Specific error: {e}")
    return default_decision
except Exception as e:
    # 通用异常处理
    logger.error(f"Unexpected error: {e}")
    return error_decision
```

## 数据模型

### 配置模型简化
```python
# 移除云端配置相关的数据模型
# 保留核心策略配置模型
class PolicyConfig(BaseModel):
    name: str
    enabled: bool = True
    parameters: Dict[str, Any] = Field(default_factory=dict)
```

## 错误处理

### 统一错误处理策略
1. **策略级错误**: 返回明确的 PolicyDecision
2. **系统级错误**: 记录日志并返回安全的默认决策
3. **配置错误**: 在初始化时抛出明确的异常

## 测试策略

### 测试分层
1. **单元测试**: 测试单个策略和组件
2. **集成测试**: 测试策略组合和工作流
3. **性能测试**: 验证性能承诺

### 测试数据管理
- 使用 fixtures 管理测试数据
- 创建可复用的测试状态生成器
- 统一测试断言方法

## 向后兼容性

### API 兼容性保证
- 保持核心 API 不变
- 云端功能相关参数标记为 deprecated
- 提供迁移指南

### 渐进式迁移
- 第一阶段：删除云端功能
- 第二阶段：整理测试结构  
- 第三阶段：优化重复代码

## 性能考虑

### 优化目标
- 减少导入时间（移除重型依赖）
- 提高策略执行效率
- 优化内存使用

### 性能监控
- 添加简单的性能计时
- 监控内存使用情况
- 提供性能基准测试