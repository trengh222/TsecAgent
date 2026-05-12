#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
静态知识库导入工具 - 将 reference 下的 Markdown 文件导入到 OpenViking

使用方法:
    python import_static_knowledge.py

或者在代码中调用:
    from deepagent.knowledge.viking import VikingKnowledgeBackend

    viking = VikingKnowledgeBackend()
    viking.initialize()

    # 导入 Payloads
    viking.import_static_knowledge(
        source_path="deepagent/knowledge/reference/PayloadsAllTheThings/PayloadsAllTheThings-master",
        category="payloads"
    )

    # 导入 HowToHunt
    viking.import_static_knowledge(
        source_path="deepagent/knowledge/reference/HowToHunt/HowToHunt-master",
        category="howtohunt"
    )
"""

import os
import sys
import shutil
from pathlib import Path

# 添加项目根目录到路径
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from deepagent.knowledge.viking import VikingKnowledgeBackend
import structlog

logger = structlog.get_logger(__name__)


def import_payloads(viking: VikingKnowledgeBackend) -> int:
    """导入 PayloadsAllTheThings 知识库"""
    payloads_path = project_root / "knowledge" / "reference" / "PayloadsAllTheThings" / "PayloadsAllTheThings-master"

    if not payloads_path.exists():
        logger.warning(f"Payloads path not found: {payloads_path}")
        return 0

    print(f"\n{'=' * 60}")
    print(f"📚 导入 Payloads 知识库")
    print(f"{'=' * 60}")
    print(f"源路径：{payloads_path}")

    count = viking.import_static_knowledge(
        source_path=str(payloads_path),
        category="PayloadsAllTheThings",  # 匹配 CATEGORY_URI_MAP 中的 key
        file_pattern="*.md"
    )

    print(f"✅ 成功导入 {count} 个 Payload 文件到 OpenViking")
    return count


def import_howtohunt(viking: VikingKnowledgeBackend) -> int:
    """导入 HowToHunt 知识库"""
    howtohunt_path = project_root / "knowledge" / "reference" / "HowToHunt" / "HowToHunt-master"

    if not howtohunt_path.exists():
        logger.warning(f"HowToHunt path not found: {howtohunt_path}")
        return 0

    print(f"\n{'=' * 60}")
    print(f"📚 导入 HowToHunt 知识库")
    print(f"{'=' * 60}")
    print(f"源路径：{howtohunt_path}")

    count = viking.import_static_knowledge(
        source_path=str(howtohunt_path),
        category="HowToHunt",  # 匹配 CATEGORY_URI_MAP 中的 key
        file_pattern="*.md"
    )

    print(f"✅ 成功导入 {count} 个 HowToHunt 文件到 OpenViking")
    return count


def verify_import(viking: VikingKnowledgeBackend, category: str, sample_query: str = "sql"):
    """验证导入是否成功"""
    print(f"\n{'=' * 60}")
    print(f"🔍 验证 {category} 知识库导入")
    print(f"{'=' * 60}")

    results = viking.search(
        query=sample_query,
        category=category,
        n_results=3
    )

    if results:
        print(f"✅ 搜索成功，找到 {len(results)} 个结果")
        for i, result in enumerate(results, 1):
            print(f"\n  {i}. {result.title}")
            print(f"     URI: {result.id}")
            print(f"     摘要: {result.content[:100]}...")
    else:
        print(f"⚠️ 搜索无结果，可能导入有问题")

    return len(results) > 0


def main():
    """主函数"""
    print("\n" + "=" * 60)
    print("🚀 开始导入静态知识库到 OpenViking")
    print("=" * 60)

    # 初始化 OpenViking 后端
    viking = VikingKnowledgeBackend()

    if not viking.initialize():
        print("\n❌ OpenViking 初始化失败")
        print("请确保:")
        print("  1. 已安装 openviking_cli 包")
        print("  2. 配置文件存在：~/.openviking/ov.conf")
        print("  3. 数据目录可访问")
        return 1

    print("\n✅ OpenViking 初始化成功")
    print(f"📁 数据目录: {viking.data_path}")
    print(f"⚙️  配置文件: {viking.config_file}")

    # 显示数据目录内容
    data_dir = Path(viking.data_path).expanduser()
    if data_dir.exists():
        print(f"\n📂 当前数据目录内容:")
        for item in data_dir.iterdir():
            if item.is_dir():
                size = sum(f.stat().st_size for f in item.rglob('*') if f.is_file())
                print(f"  - {item.name}/ ({size // 1024} KB)")
            else:
                print(f"  - {item.name}")

    # 导入 Payloads
    payloads_count = import_payloads(viking)

    # 导入 HowToHunt
    howtohunt_count = import_howtohunt(viking)

    # 验证导入
    print("\n" + "=" * 60)
    print("🔍 验证导入结果")
    print("=" * 60)

    if payloads_count > 0:
        verify_import(viking, "PayloadsAllTheThings", "injection")

    if howtohunt_count > 0:
        verify_import(viking, "HowToHunt", "bug bounty")

    # 显示数据目录最终状态
    print(f"\n{'=' * 60}")
    print(f"📂 导入后的数据目录结构")
    print(f"{'=' * 60}")
    if data_dir.exists():
        for root, dirs, files in os.walk(data_dir):
            level = root.replace(str(data_dir), '').count(os.sep)
            indent = ' ' * 2 * level
            print(f'{indent}{os.path.basename(root)}/')
            subindent = ' ' * 2 * (level + 1)
            for file in files[:5]:  # 只显示前5个文件
                print(f'{subindent}{file}')
            if len(files) > 5:
                print(f'{subindent}... 共 {len(files)} 个文件')

    # 总结
    total = payloads_count + howtohunt_count

    print("\n" + "=" * 60)
    print("📊 导入完成总结")
    print("=" * 60)
    print(f"  - PayloadsAllTheThings:    {payloads_count} 个文件")
    print(f"  - HowToHunt:               {howtohunt_count} 个文件")
    print(f"  - 总计：                   {total} 个文件")
    print("=" * 60)

    if total > 0:
        print("\n✨ 静态知识库已成功导入 OpenViking!")
        print("\n💡 使用提示:")
        print("  - 在 KnowledgeRouter 中使用 category='PayloadsAllTheThings' 或 'HowToHunt' 搜索")
        print("  - 动态知识会自动存储到 ChromaDB (experience/general/task_memory)")
        print(f"  - 文件已复制到: {data_dir}")
        print()
    else:
        print("\n⚠️ 没有导入任何文件，请检查路径和配置")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())