# 知识库使用指南

本文档说明如何使用双后端知识管理系统（OpenViking + ChromaDB）。

## 📋 目录

- [架构概述](#架构概述)
- [安装配置](#安装配置)
- [导入静态知识](#导入静态知识)
- [存储动态知识](#存储动态知识)
- [搜索知识](#搜索知识)
- [API 参考](#api 参考)

---

## 🏗️ 架构概述

```
┌─────────────────────────────────────────────────┐
│              KnowledgeRouter                     │
│                   (路由器)                       │
└───────────────┬─────────────────────────────────┘
                │
        ┌───────┴────────┐
        │                │
        ▼                ▼
┌──────────────┐  ┌──────────────────┐
│  OpenViking  │  │    ChromaDB      │
│   (静态知识)  │  │   (动态知识)     │
└──────────────┘  └──────────────────┘
        │                │
        │                ├─ experience (攻击经验)
        │                ├─ general (通用知识)
        │                └─ task_memory (任务记忆)
        │
        ├─ payloads (PayloadsAllTheThings)
        └─ howtohunt (HowToHunt 方法论)
```

### 设计原则

- **静态知识**: 预定义的、不变的知识库（如 Payloads、HowToHunt）
  - 存储到 OpenViking
  - 支持 L0(摘要)、L1(概览)、L2(全文) 三层检索
  
- **动态知识**: AI 运行时产生的经验、洞察、任务记忆
  - 存储到 ChromaDB
  - 支持实时更新和语义搜索

---

## 📦 安装配置

### 1. 安装依赖

```bash
# 安装 OpenViking（可选，用于静态知识）
pip install openviking

# 安装 ChromaDB（必需，用于动态知识）
pip install chromadb

# 其他依赖
pip install structlog pathlib
```

### 2. 配置 OpenViking（可选）

如果使用 OpenViking 存储静态知识：

```bash
# 创建配置文件
mkdir -p ~/.openviking
cat > ~/.openviking/ov.conf << EOF
[database]
path = ~/.openviking/data

[embedding]
model = text-embedding-3-small
EOF
```

### 3. 初始化

在代码中初始化知识路由器：

```python
from deepagent.knowledge.router import KnowledgeRouter
from deepagent.knowledge.viking import VikingKnowledgeBackend

# 初始化 OpenViking 后端（可选）
viking = VikingKnowledgeBackend(
    data_path="~/.openviking/data",
    config_file="~/.openviking/ov.conf"
)
viking.initialize()

# 创建知识路由器
router = KnowledgeRouter(
    viking_backend=viking,  # 或 None
    chroma_path="./chroma_data"  # ChromaDB 持久化路径
)
```

---

## 📥 导入静态知识

### 方法 1: 使用命令行工具

```bash
# 进入项目目录
cd /Users/admin/PycharmProjects/langGraph

# 运行导入脚本
python deepagent/knowledge/import_static_knowledge.py
```

### 方法 2: 在代码中导入

```python
from deepagent.knowledge.viking import VikingKnowledgeBackend

# 初始化
viking = VikingKnowledgeBackend()
viking.initialize()

# 导入 PayloadsAllTheThings
payloads_count = viking.import_static_knowledge(
    source_path="deepagent/knowledge/reference/PayloadsAllTheThings/PayloadsAllTheThings-master",
    category="payloads"
)

# 导入 HowToHunt
howtohunt_count = viking.import_static_knowledge(
    source_path="deepagent/knowledge/reference/HowToHunt/HowToHunt-master",
    category="howtohunt"
)

print(f"导入了 {payloads_count + howtohunt_count} 个文件")
```

### 支持的静态知识类别

| 类别 | 描述 | 源目录 |
|------|------|--------|
| `payloads` | PayloadsAllTheThings 漏洞利用集合 | `reference/PayloadsAllTheThings/` |
| `howtohunt` | HowToHunt 漏洞挖掘方法论 | `reference/HowToHunt/` |
| `vulnerabilities` | 漏洞详情（预留） | - |

---

## 💾 存储动态知识

### 1. 添加单条知识

```python
knowledge = {
    "title": "SQL Injection Discovery",
    "content": "在登录表单发现 SQL 注入漏洞，使用 ' OR '1'='1 可绕过认证",
    "source": "ai_runtime",
    "severity": "high",
    "applicable_scenarios": ["authentication", "login"]
}

doc_id = router.add_runtime_knowledge(
    knowledge=knowledge,
    category="experience"  # 或 "general", "task_memory"
)
```

### 2. 批量添加知识

```python
knowledge_list = [
    {
        "title": "API Rate Limit Test",
        "content": "/api/login 端点限流测试通过...",
        "source": "automated_test"
    },
    {
        "title": "Subdomain Discovery",
        "content": "发现 3 个子域名...",
        "source": "recon_tool"
    }
]

count = router.batch_add_runtime_knowledge(
    knowledge_list=knowledge_list,
    category="task_memory"
)
```

### 3. 添加 STE 格式经验

STE = Strategy-Tactics-Example

```python
ste_experience = {
    "title": "XSS 漏洞利用",
    "content": "完整的 XSS 攻击流程...",
    "strategy": "Client-side Code Injection",
    "tactics": ["Input Detection", "Filter Bypass", "Script Execution"],
    "source": "ai_learning",
    "timestamp": "2024-01-01T12:00:00"
}

doc_id = router.add_runtime_knowledge(
    knowledge=ste_experience,
    category="experience"
)
```

### 动态知识类别

| 类别 | 用途 | 示例 |
|------|------|------|
| `experience` | 攻击经验、策略战术 | STE 格式经验、漏洞利用心得 |
| `general` | 通用知识、临时发现 | 一般性观察、工具使用技巧 |
| `task_memory` | 任务特定记忆 | 扫描结果、测试记录、发现列表 |

---

## 🔍 搜索知识

### 1. 按类别搜索

```python
# 搜索静态知识（OpenViking）
payloads = router.search(
    query="SQL injection",
    category="payloads",
    limit=5
)

# 搜索动态经验（ChromaDB）
experiences = router.search(
    query="XSS bypass",
    category="experience",
    limit=5
)
```

### 2. 组合搜索

```python
# 搜索所有相关知识（静态 + 动态）
all_results = router.search(
    query="authentication bypass",
    limit=10
)
```

### 3. 获取完整内容

```python
# 从 OpenViking 获取详情
detail = router.get_detail("viking://resources/payloads/sqli.md")

# 从 ChromaDB 获取详情
detail = router.get_detail(doc_uuid)
```

---

## 📚 API 参考

### VikingKnowledgeBackend

```python
class VikingKnowledgeBackend:
    def initialize(self) -> bool:
        """初始化 OpenViking 客户端"""
    
    def import_static_knowledge(
        source_path: str,
        category: str,
        file_pattern: str = "*.md"
    ) -> int:
        """导入静态知识库"""
    
    def search(
        query: str,
        n_results: int = 5,
        category: Optional[str] = None
    ) -> List[VikingKnowledgeResult]:
        """搜索静态知识"""
    
    def get_detail(uri: str) -> Optional[VikingKnowledgeResult]:
        """获取完整内容"""
    
    def get_overview(uri: str) -> Optional[str]:
        """获取结构化概览 (L1)"""
```

### KnowledgeRouter

```python
class KnowledgeRouter:
    def search(
        query: str,
        category: Optional[str] = None,
        limit: int = 5
    ) -> List[Dict[str, Any]]:
        """搜索知识（支持静态 + 动态）"""
    
    def add_runtime_knowledge(
        knowledge: Dict[str, Any],
        category: str = "general"
    ) -> str:
        """添加运行时知识"""
    
    def batch_add_runtime_knowledge(
        knowledge_list: List[Dict[str, Any]],
        category: str = "general"
    ) -> int:
        """批量添加运行时知识"""
    
    def get_detail(entry_id: str) -> Optional[Dict[str, Any]]:
        """获取完整内容"""
```

---

## 🎯 使用示例

### 完整工作流示例

```python
import asyncio
from deepagent.knowledge.router import KnowledgeRouter
from deepagent.knowledge.viking import VikingKnowledgeBackend

async def main():
    # 1. 初始化
    viking = VikingKnowledgeBackend()
    viking.initialize()
    
    router = KnowledgeRouter(
        viking_backend=viking,
        chroma_path="./chroma_data"
    )
    
    # 2. 导入静态知识（首次运行）
    viking.import_static_knowledge(
        "deepagent/knowledge/reference/PayloadsAllTheThings/PayloadsAllTheThings-master",
        "payloads"
    )
    
    # 3. AI 运行时发现新知识
    discovery = {
        "title": "New Vulnerability Found",
        "content": "在 /api/users 端点发现 IDOR 漏洞...",
        "source": "ai_agent",
        "severity": "critical"
    }
    
    router.add_runtime_knowledge(discovery, category="experience")
    
    # 4. 搜索相关知识
    results = router.search("IDOR vulnerability", limit=5)
    
    for result in results:
        print(f"- {result['title']} ({result['type']})")

if __name__ == "__main__":
    asyncio.run(main())
```

---

## ❓ 常见问题

### Q: 必须安装 OpenViking 吗？

A: 不是必须的。如果不安装 OpenViking，静态知识会降级到 ChromaDB 存储，但功能会受限（不支持 L1/L2分层检索）。

### Q: ChromaDB 数据存在哪里？

A: 默认存储在内存中。如果指定 `chroma_path` 参数，会持久化到该目录。

### Q: 如何清空已存储的知识？

A: 删除 ChromaDB 数据目录或 OpenViking 数据目录即可：

```bash
rm -rf ./chroma_data
rm -rf ~/.openviking/data
```

### Q: 支持哪些文件格式？

A: 
- 静态知识：主要支持 Markdown (.md)
- 动态知识：任意文本内容

---

## 📝 最佳实践

1. **定期备份**: 定期备份 ChromaDB 和 OpenViking 数据目录
2. **分类存储**: 根据知识类型选择合适的类别（payloads/experience/task_memory）
3. **及时清理**: 定期清理过时的任务记忆，保持知识库精简
4. **元数据丰富**: 添加详细的元数据（source、severity、scenarios）便于检索
5. **增量更新**: 静态知识库只需初次导入，后续可定期更新

---

## 🤝 贡献

如有问题或建议，欢迎提交 Issue 或 Pull Request！
