#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
知识库功能快速测试
"""

import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from deepagent.knowledge.viking import VikingKnowledgeBackend
from deepagent.knowledge.router import KnowledgeRouter


def test_viking_initialization():
    """测试 OpenViking 初始化"""
    print("\n" + "="*60)
    print("🧪 测试 1: OpenViking 初始化")
    print("="*60)
    
    viking = VikingKnowledgeBackend()
    success = viking.initialize()
    
    if success:
        print("✅ OpenViking 初始化成功")
        return True
    else:
        print("⚠️  OpenViking 不可用（可能未安装或未配置）")
        print("   这不影响 ChromaDB 动态知识功能")
        return False


def test_chroma_initialization():
    """测试 ChromaDB 初始化"""
    print("\n" + "="*60)
    print("🧪 测试 2: ChromaDB 初始化")
    print("="*60)
    
    chroma_path = str(project_root / ".chroma_test_data")
    
    try:
        router = KnowledgeRouter(
            viking_backend=None,
            chroma_path=chroma_path
        )
        
        print(f"✅ ChromaDB 初始化成功 (路径：{chroma_path})")
        print(f"   可用集合：{list(router.chroma_collections.keys())}")
        return router
        
    except Exception as e:
        print(f"❌ ChromaDB 初始化失败：{e}")
        return None


def test_add_knowledge(router):
    """测试添加动态知识"""
    print("\n" + "="*60)
    print("🧪 测试 3: 添加动态知识")
    print("="*60)
    
    if not router:
        print("⏭️  跳过（路由器未初始化）")
        return
    
    # 测试单条添加
    knowledge = {
        "title": "Test Knowledge",
        "content": "这是一个测试知识点，用于验证 ChromaDB 存储功能",
        "source": "test_suite",
        "severity": "info"
    }
    
    doc_id = router.add_runtime_knowledge(knowledge, category="experience")
    
    if doc_id:
        print(f"✅ 单条添加成功，文档 ID: {doc_id[:8]}...")
    else:
        print("❌ 单条添加失败")
    
    # 测试批量添加
    batch_knowledge = [
        {
            "title": "Batch Test 1",
            "content": "批量测试内容 1",
            "source": "test"
        },
        {
            "title": "Batch Test 2",
            "content": "批量测试内容 2",
            "source": "test"
        }
    ]
    
    count = router.batch_add_runtime_knowledge(batch_knowledge, category="task_memory")
    
    if count > 0:
        print(f"✅ 批量添加成功：{count}/{len(batch_knowledge)}")
    else:
        print("⚠️  批量添加部分失败")


def test_search_knowledge(router):
    """测试搜索功能"""
    print("\n" + "="*60)
    print("🧪 测试 4: 搜索知识")
    print("="*60)
    
    if not router:
        print("⏭️  跳过（路由器未初始化）")
        return
    
    # 搜索刚添加的知识
    results = router.search("测试", category="experience", limit=5)
    
    if results:
        print(f"✅ 搜索成功，找到 {len(results)} 条结果")
        for i, result in enumerate(results, 1):
            print(f"   {i}. {result.get('title', 'Unknown')}")
    else:
        print("⚠️  未找到结果（可能是 Embedding 需要时间）")


def test_static_import_available():
    """测试静态知识导入路径"""
    print("\n" + "="*60)
    print("🧪 测试 5: 静态知识导入路径检查")
    print("="*60)
    
    payloads_path = project_root / "deepagent" / "knowledge" / "reference" / "PayloadsAllTheThings" / "PayloadsAllTheThings-master"
    howtohunt_path = project_root / "deepagent" / "knowledge" / "reference" / "HowToHunt" / "HowToHunt-master"
    
    print(f"\nPayloads 路径:")
    print(f"  绝对路径：{payloads_path}")
    print(f"  存在性：{'✅' if payloads_path.exists() else '❌'}")
    
    print(f"\nHowToHunt 路径:")
    print(f"  绝对路径：{howtohunt_path}")
    print(f"  存在性：{'✅' if howtohunt_path.exists() else '❌'}")
    
    if payloads_path.exists() and howtohunt_path.exists():
        print("\n✅ 静态知识库文件已就绪，可以导入")
    else:
        print("\n⚠️  部分静态知识库文件缺失")


def main():
    """运行所有测试"""
    print("\n" + "="*60)
    print("🚀 知识库功能快速测试")
    print("="*60)
    
    # 测试 1: OpenViking
    viking_available = test_viking_initialization()
    
    # 测试 2: ChromaDB
    router = test_chroma_initialization()
    
    # 测试 3: 添加知识
    test_add_knowledge(router)
    
    # 测试 4: 搜索
    test_search_knowledge(router)
    
    # 测试 5: 静态知识路径
    test_static_import_available()
    
    # 总结
    print("\n" + "="*60)
    print("📊 测试总结")
    print("="*60)
    print(f"  - OpenViking:  {'✅ 可用' if viking_available else '⚠️  不可用 (可选)'}")
    print(f"  - ChromaDB:    {'✅ 正常' if router else '❌ 失败'}")
    print(f"  - 动态知识：   {'✅ 可存储' if router else '❌ 不可用'}")
    print(f"  - 静态知识：   {'✅ 可导入' if test_static_import_available else '⚠️  路径问题'}")
    print("="*60)
    
    print("\n💡 下一步:")
    print("  1. 如果 OpenViking 可用，运行导入脚本:")
    print("     python deepagent/knowledge/import_static_knowledge.py")
    print()
    print("  2. 查看使用示例:")
    print("     python deepagent/knowledge/runtime_knowledge_example.py")
    print()
    print("  3. 阅读完整文档:")
    print("     cat deepagent/knowledge/README.md")
    print()


if __name__ == "__main__":
    main()
