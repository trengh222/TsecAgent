#!/usr/bin/env python3
"""
知识库导入工具 - 支持多种格式 + 语义切割

支持导入：
- P0: Dictionary 词表文件
- P1: OWASP WSTG（Markdown，按章节切割）
- P1: HackTricks（Markdown，按漏洞分类切割）
- P2: Nuclei Templates（YAML，提取 info 块按类别分块）
- 已有: PayloadsAllTheThings / HowToHunt

切割策略：
1. Markdown 文件 → 按 H2/H3 标题切割，每个块保留完整上下文
2. Nuclei YAML → 提取 info 块，同目录同类型的模板合并为块
3. 词表文件 → 按语义分组，每组 50 个词为一个块，附带类型描述

使用方法:
    python import_knowledge.py --all
    python import_knowledge.py --nuclei
    python import_knowledge.py --dictionary
    python import_knowledge.py --wstg
    python import_knowledge.py --hacktricks
    python import_knowledge.py --clone-all   # 下载缺失仓库
"""

import os
import re
import sys
import subprocess
import yaml
import json
import shutil
from pathlib import Path
from typing import List, Tuple

project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from deepagent.knowledge.viking import VikingKnowledgeBackend
from deepagent.knowledge.router import KnowledgeRouter
import structlog

logger = structlog.get_logger(__name__)

REFERENCE_DIR = Path(__file__).parent / "reference"
CHROMA_PATH = str(Path(__file__).parent.parent / ".chromadb")

# 切割参数
_MAX_CHUNK_CHARS = 800  # 每个块最大字符数（适配向量嵌入）
_MIN_CHUNK_CHARS = 100  # 最小字符数，太短的块合并到相邻块


def _clone_repo(url: str, dest: Path, depth: int = 1) -> bool:
    """尝试 git clone，支持多种 URL 变体。"""
    if dest.exists() and (dest / ".git").exists():
        return True

    mirrors = [
        url,
        url.replace("https://github.com/", "https://gitclone.com/github.com/"),
    ]

    for mirror_url in mirrors:
        print(f"  尝试 clone: {mirror_url}")
        try:
            result = subprocess.run(
                ["git", "clone", "--depth", str(depth), mirror_url, str(dest)],
                capture_output=True, text=True, timeout=300,
            )
            if result.returncode == 0:
                print(f"  ✅ clone 成功")
                return True
            else:
                print(f"  ⚠️  失败: {result.stderr[:120]}")
        except subprocess.TimeoutExpired:
            print(f"  ⚠️  超时")
        except Exception as e:
            print(f"  ⚠️  {e}")

    # 清理失败目录
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    return False


def clone_wstg() -> Path | None:
    """下载 OWASP WSTG 仓库。"""
    dest = REFERENCE_DIR / "wstg"
    print("\n📥 下载 OWASP WSTG...")
    if _clone_repo("https://github.com/OWASP/wstg.git", dest):
        return dest
    return None


def clone_hacktricks() -> Path | None:
    """下载 HackTricks 仓库。"""
    dest = REFERENCE_DIR / "hacktricks"
    print("\n📥 下载 HackTricks...")
    if _clone_repo("https://github.com/hacktricks-wiki/hacktricks.git", dest):
        return dest
    return None


# ═══════════════════════════════════════════════════════════════════
# 切割函数
# ═══════════════════════════════════════════════════════════════════

def chunk_markdown_by_headings(md_path: Path) -> List[Tuple[str, str]]:
    """按 H2/H3 标题切割 Markdown 文件，返回 [(标题, 内容), ...]。

    每个块包含：
    - 完整标题上下文（文件主标题 + 章节标题）
    - 完整的代码块、表格、列表
    - 超过 _MAX_CHUNK_CHARS 时会进一步按子标题切割
    """
    content = md_path.read_text(encoding="utf-8", errors="ignore")
    if len(content.strip()) < _MIN_CHUNK_CHARS:
        return []

    file_title = _extract_first_heading(content) or md_path.stem.replace("_", " ").title()

    # 按 H2 标题切割
    h2_pattern = re.compile(r'^##\s+(.+)$', re.MULTILINE)
    sections = []

    h2_matches = list(h2_pattern.finditer(content))
    if not h2_matches:
        # 无 H2，返回整个文件
        if len(content.strip()) >= _MIN_CHUNK_CHARS:
            sections.append((file_title, content))
        return sections

    for i, match in enumerate(h2_matches):
        heading = match.group(1).strip()
        section_content = content[match.start():]
        if i + 1 < len(h2_matches):
            section_content = content[match.start():h2_matches[i + 1].start()]

        full_title = f"{file_title} > {heading}"

        # 如果块太大，进一步按 H3 切割
        if len(section_content) > _MAX_CHUNK_CHARS:
            h3_pattern = re.compile(r'^###\s+(.+)$', re.MULTILINE)
            h3_matches = list(h3_pattern.finditer(section_content))
            if h3_matches:
                for j, h3_match in enumerate(h3_matches):
                    h3_heading = h3_match.group(1).strip()
                    sub_content = section_content[h3_match.start():]
                    if j + 1 < len(h3_matches):
                        sub_content = section_content[h3_match.start():h3_matches[j + 1].start()]
                    sub_title = f"{full_title} > {h3_heading}"
                    if len(sub_content.strip()) >= _MIN_CHUNK_CHARS:
                        sections.append((sub_title, sub_content))
            else:
                # 无法进一步切割，直接保留
                sections.append((full_title, section_content))
        else:
            sections.append((full_title, section_content))

    return sections


def _extract_first_heading(content: str) -> str:
    """从 Markdown 中提取第一个 # 标题。"""
    match = re.match(r'^#\s+(.+)$', content, re.MULTILINE)
    return match.group(1).strip() if match else ""


def chunk_nuclei_templates(category_dir: Path) -> List[Tuple[str, str]]:
    """从 Nuclei 模板目录提取 info 块，同类模板合并为块。

    切割策略：
    - 每个 YAML 文件的 info 块作为独立条目
    - 同目录下 5 个模板合并为一个块（保持语义相关性）
    - 每个条目包含：name + description + remediation + severity + references
    """
    yaml_files = list(category_dir.glob("*.yaml")) + list(category_dir.glob("*.yml"))
    if not yaml_files:
        return []

    # 目录名作为类别标签（如 "ssl", "sqli", "xss"）
    category = category_dir.name.replace("-", " ").replace("_", " ")
    parent_dir = category_dir.parent.name

    entries = []
    for yf in yaml_files:
        try:
            entry = _parse_nuclei_yaml(yf)
            if entry:
                entries.append(entry)
        except Exception:
            continue

    # 每 5 个模板合并为一个块
    chunks: List[Tuple[str, str]] = []
    batch_size = 5
    for i in range(0, len(entries), batch_size):
        batch = entries[i:i + batch_size]
        if len(batch) == 1:
            title = f"Nuclei: {parent_dir}/{category} - {batch[0]['name']}"
            chunks.append((title, batch[0]['text']))
        else:
            title = f"Nuclei: {parent_dir}/{category} ({len(batch)} 个模板)"
            text_parts = [e['text'] for e in batch]
            combined = "\n\n".join(text_parts)
            chunks.append((title, combined))

    return chunks


def _parse_nuclei_yaml(yf: Path) -> dict | None:
    """解析单个 Nuclei YAML 文件，提取 info 信息。"""
    try:
        with open(yf, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
    except Exception:
        return None

    if not isinstance(data, dict):
        return None

    info = data.get("info", {})
    if not isinstance(info, dict):
        return None

    name = info.get("name", yf.stem)
    description = info.get("description", "")
    severity = info.get("severity", "unknown")
    remediation = info.get("remediation", "")
    references = info.get("reference", [])
    tags = info.get("tags", "")
    template_id = data.get("id", yf.stem)

    if not description:
        return None  # 跳过无描述的模板

    ref_text = ""
    if isinstance(references, list):
        ref_text = "\n参考: " + ", ".join(references[:3])
    elif isinstance(references, str):
        ref_text = f"\n参考: {references}"

    tag_text = f"\n标签: {tags}" if tags else ""
    rem_text = f"\n修复: {remediation}" if remediation else ""

    text = (
        f"检测项: {name}\n"
        f"严重程度: {severity}\n"
        f"描述: {description}{rem_text}{ref_text}{tag_text}"
    )

    return {
        "name": name,
        "text": text,
        "severity": severity,
        "template_id": template_id,
    }


def chunk_dictionary_wordlist(filepath: Path) -> List[Tuple[str, str]]:
    """将词表文件切割为语义块。

    切割策略：
    - 每 50 个词为一个块
    - 块标题包含词表类型描述
    - 跳过空行和注释行（# 开头）
    """
    content = filepath.read_text(encoding="utf-8", errors="ignore")
    lines = [l.strip() for l in content.splitlines() if l.strip() and not l.startswith("#")]

    if not lines:
        return []

    category = filepath.stem.replace("_", " ").replace("-", " ")
    description = _dictionary_description(category)

    chunks = []
    batch_size = 50
    for i in range(0, len(lines), batch_size):
        batch = lines[i:i + batch_size]
        title = f"词表: {category} ({i // batch_size + 1})"
        text = f"{description}\n\n" + "\n".join(batch)
        chunks.append((title, text))

    return chunks


def _dictionary_description(category: str) -> str:
    """为每个词表类型生成描述前缀，便于向量检索时匹配语义。"""
    descriptions = {
        "username": "常见用户名/登录名/账号名列表，用于暴力破解和字典攻击。",
        "password": "常用密码/弱口令列表，用于密码字典攻击和凭证填充。",
        "parameter": "常见 HTTP 参数名列表，用于参数发现和注入测试。",
        "SQL": "SQL 注入相关关键字/函数名/语法片段，用于 SQLi 测试和绕过。",
        "SSTI": "服务端模板注入 (SSTI) payload 和语法，用于模板引擎注入测试。",
        "Java_file": "Java 常见文件路径/类名/包名，用于目录遍历和文件包含。",
        "Java_path_file": "Java Web 常见配置文件路径，用于信息泄露和路径遍历。",
        "AngularJS": "AngularJS 相关语法和 payload，用于 XSS 和客户端注入。",
        "CloudService": "云服务/云存储路径和 URL 格式，用于云安全测试。",
        "JNDI": "JNDI 注入相关 payload，用于 Log4j2 等 JNDI 漏洞利用。",
        "StrongPassword": "强密码策略测试用例，用于密码复杂度检测。",
        "ViewState": "ASP.NET ViewState 相关 payload，用于状态篡改测试。",
        "webshell": "WebShell 常见文件名/路径/特征，用于后门检测。",
        "CN_username1W": "中文常见用户名/昵称/账号（1万条），用于国内系统测试。",
        "CN_username3000": "中文常见用户名/昵称/账号（3000条），用于国内系统测试。",
        "markdown": "Markdown 语法和注入相关 payload。",
    }
    # 模糊匹配
    for key, desc in descriptions.items():
        if key.lower() in category.lower():
            return desc
    return f"{category} 词表文件，包含渗透测试常用字典条目。"


# ═══════════════════════════════════════════════════════════════════
# 导入函数
# ═══════════════════════════════════════════════════════════════════

def import_with_chunking(
        viking: VikingKnowledgeBackend,
        source_dir: Path,
        category: str,
        file_pattern: str = "*.md",
        chunk_fn=None,
) -> int:
    """通用导入函数：收集文件 → 切割 → 写入 OpenViking。"""
    if not viking.is_available:
        logger.warning("OpenViking not available")
        return 0

    files = list(source_dir.rglob(file_pattern))
    if not files:
        logger.warning(f"No files matching {file_pattern} in {source_dir}")
        return 0

    print(f"\n{'=' * 60}")
    print(f"📚 导入 {category}")
    print(f"{'=' * 60}")
    print(f"源路径：{source_dir}")
    print(f"文件数：{len(files)}")

    total_chunks = 0
    chunk_fn = chunk_fn or chunk_markdown_by_headings

    for i, fp in enumerate(files):
        try:
            chunks = chunk_fn(fp)
            if not chunks:
                continue

            for title, content in chunks:
                uri = f"{viking.CATEGORY_URI_MAP.get(category, 'viking://resources/')}{fp.relative_to(source_dir).with_suffix('.chunk.md')}"
                _import_chunk_to_viking(viking, uri, title, content, category)
                total_chunks += 1

            if (i + 1) % 20 == 0:
                print(f"  已处理 {i + 1}/{len(files)} 文件，累计 {total_chunks} 个块")
        except Exception as e:
            logger.error(f"Failed to process {fp}", error=str(e))

    print(f"✅ 成功导入 {total_chunks} 个知识块")
    return total_chunks


def _import_chunk_to_viking(viking: VikingKnowledgeBackend, uri: str, title: str, content: str, category: str):
    """将单个块写入 OpenViking。"""
    try:
        workspace_root = Path(viking.data_path).expanduser()
        # URI 转本地路径
        # viking://resources/Category/sub/path -> workspace/resources/Category/sub/
        rel_path = uri.replace("viking://", "").rstrip("/").split("/")[-1]
        target_file = workspace_root / "resources" / category / rel_path
        target_file.parent.mkdir(parents=True, exist_ok=True)
        target_file.write_text(f"# {title}\n\n{content}", encoding="utf-8")
    except Exception as e:
        logger.error(f"Failed to write chunk {title}", error=str(e))


def import_nuclei_templates(viking: VikingKnowledgeBackend) -> int:
    """导入 Nuclei 模板到 OpenViking。"""
    nuclei_dir = REFERENCE_DIR / "nuclei-templates"
    if not nuclei_dir.exists():
        print("⚠️  Nuclei templates 目录不存在，请先 clone 仓库")
        return 0

    print(f"\n{'=' * 60}")
    print(f"📚 导入 Nuclei Templates")
    print(f"{'=' * 60}")

    total_chunks = 0
    # 递归遍历所有子目录（排除根目录的非 yaml 文件）
    for sub_dir in sorted(nuclei_dir.rglob("*")):
        if not sub_dir.is_dir():
            continue
        # 跳过 .git 目录
        if ".git" in str(sub_dir):
            continue
        # 检查是否有 yaml 文件
        yaml_files = list(sub_dir.glob("*.yaml")) + list(sub_dir.glob("*.yml"))
        if not yaml_files:
            continue

        chunks = chunk_nuclei_templates(sub_dir)
        if not chunks:
            continue

        for title, content in chunks:
            rel = sub_dir.relative_to(nuclei_dir)
            chunk_file = f"{rel}/chunk.md"
            uri = f"viking://resources/nuclei/{chunk_file}"
            _import_chunk_to_viking(viking, uri, title, content, "nuclei")
            total_chunks += 1

        print(f"  {rel}: {len(chunks)} 个块")

    print(f"✅ 成功导入 {total_chunks} 个 Nuclei 知识块")
    return total_chunks


def import_dictionary(viking: VikingKnowledgeBackend) -> int:
    """导入 Dictionary 词表到 ChromaDB（通过 KnowledgeRouter）。"""
    dict_dir = REFERENCE_DIR / "Dictionary"
    if not dict_dir.exists():
        print("⚠️  Dictionary 目录不存在")
        return 0

    print(f"\n{'=' * 60}")
    print(f"📚 导入 Dictionary 词表")
    print(f"{'=' * 60}")

    # 使用 KnowledgeRouter（ChromaDB）存储词表
    router = KnowledgeRouter(chroma_path=CHROMA_PATH)

    total_chunks = 0
    for fp in sorted(dict_dir.glob("*.txt")):
        if fp.name == "LICENSE":
            continue
        try:
            chunks = chunk_dictionary_wordlist(fp)
            if not chunks:
                continue

            for title, content in chunks:
                doc_id = router.save(
                    content=content,
                    title=title,
                    category="general",
                    tags=["dictionary", fp.stem, "wordlist"],
                    extra_meta={"source": "dictionary", "type": fp.stem},
                )
                if doc_id:
                    total_chunks += 1

            print(f"  {fp.name}: {len(chunks)} 个块")
        except Exception as e:
            logger.error(f"Failed to import {fp}", error=str(e))

    print(f"✅ 成功导入 {total_chunks} 个词表块到 ChromaDB")
    return total_chunks


def import_wstg(viking: VikingKnowledgeBackend) -> int:
    """导入 OWASP WSTG，如果目录不存在则尝试自动 clone。"""
    candidates = [
        REFERENCE_DIR / "wstg",
        REFERENCE_DIR / "wstg_temp",
        REFERENCE_DIR / "wstg/docs",
    ]
    wstg_dir = None
    for c in candidates:
        if c.exists():
            wstg_dir = c
            break

    if not wstg_dir:
        print("⚠️  WSTG 目录不存在，尝试自动下载...")
        cloned = clone_wstg()
        if cloned:
            wstg_dir = cloned

    if not wstg_dir:
        print("⚠️  跳过 WSTG 导入（网络不可达）")
        print("   手动下载: git clone --depth 1 https://github.com/OWASP/wstg.git")
        return 0

    # 找到文档目录
    docs_candidates = [
        wstg_dir / "document" / "markdown" / "Chinese",
        wstg_dir / "document" / "markdown",
        wstg_dir / "docs",
        wstg_dir / "content",
        wstg_dir,
    ]
    actual_docs = None
    for d in docs_candidates:
        if d.exists() and list(d.rglob("*.md")):
            actual_docs = d
            break

    if not actual_docs:
        print("⚠️  WSTG Markdown 文件未找到")
        return 0

    print(f"\n{'=' * 60}")
    print(f"📚 导入 OWASP WSTG")
    print(f"{'=' * 60}")
    print(f"文档路径：{actual_docs}")

    total_chunks = 0
    files = list(actual_docs.rglob("*.md"))
    print(f"文件数：{len(files)}")

    for i, fp in enumerate(files):
        try:
            chunks = chunk_markdown_by_headings(fp)
            if not chunks:
                continue

            for title, content in chunks:
                rel = fp.relative_to(actual_docs)
                chunk_file = f"{rel.with_suffix('.chunk.md')}"
                uri = f"viking://resources/wstg/{chunk_file}"
                _import_chunk_to_viking(viking, uri, title, content, "wstg")
                total_chunks += 1

            if (i + 1) % 10 == 0:
                print(f"  已处理 {i + 1}/{len(files)} 文件，累计 {total_chunks} 个块")
        except Exception as e:
            logger.error(f"Failed to process {fp}", error=str(e))

    print(f"✅ 成功导入 {total_chunks} 个 WSTG 知识块")
    return total_chunks


def import_hacktricks(viking: VikingKnowledgeBackend) -> int:
    """导入 HackTricks，如果目录不存在则尝试自动 clone。"""
    ht_dir = REFERENCE_DIR / "hacktricks"
    if not ht_dir.exists():
        print("⚠️  HackTricks 目录不存在，尝试自动下载...")
        cloned = clone_hacktricks()
        if cloned:
            ht_dir = cloned

    if not ht_dir.exists():
        print("⚠️  跳过 HackTricks 导入（网络不可达）")
        print("   手动下载: git clone --depth 1 https://github.com/hacktricks-wiki/hacktricks.git")
        return 0

    print(f"\n{'=' * 60}")
    print(f"📚 导入 HackTricks")
    print(f"{'=' * 60}")

    files = list(ht_dir.rglob("*.md"))
    print(f"文件数：{len(files)}")

    total_chunks = 0
    for i, fp in enumerate(files):
        try:
            chunks = chunk_markdown_by_headings(fp)
            if not chunks:
                continue

            for title, content in chunks:
                rel = fp.relative_to(ht_dir)
                chunk_file = f"{rel.with_suffix('.chunk.md')}"
                uri = f"viking://resources/hacktricks/{chunk_file}"
                _import_chunk_to_viking(viking, uri, title, content, "hacktricks")
                total_chunks += 1

            if (i + 1) % 50 == 0:
                print(f"  已处理 {i + 1}/{len(files)} 文件，累计 {total_chunks} 个块")
        except Exception as e:
            logger.error(f"Failed to process {fp}", error=str(e))

    print(f"✅ 成功导入 {total_chunks} 个 HackTricks 知识块")
    return total_chunks


# ═══════════════════════════════════════════════════════════════════
# 主函数
# ═══════════════════════════════════════════════════════════════════

def main():
    args = sys.argv[1:]
    do_all = "--all" in args
    do_nuclei = "--nuclei" in args
    do_dict = "--dictionary" in args or "--dict" in args
    do_wstg = "--wstg" in args
    do_hacktricks = "--hacktricks" in args
    do_payloads = "--payloads" in args
    do_howtohunt = "--howtohunt" in args
    do_clone_all = "--clone-all" in args

    if not any([do_all, do_nuclei, do_dict, do_wstg, do_hacktricks, do_payloads, do_howtohunt, do_clone_all]):
        do_all = True  # 默认全部

    print("\n" + "=" * 60)
    print("🚀 知识库导入工具")
    print("=" * 60)

    # 如果需要 clone
    if do_clone_all or do_all:
        if not (REFERENCE_DIR / "wstg").exists():
            clone_wstg()
        if not (REFERENCE_DIR / "hacktricks").exists():
            clone_hacktricks()

    # 初始化
    viking = VikingKnowledgeBackend()
    if not viking.initialize():
        print("\n❌ OpenViking 初始化失败")
        print("   请确保: pip install openviking_cli")
        print("   且配置文件: ~/.openviking/ov.conf")
        return 1

    print(f"\n✅ OpenViking 已就绪: {viking.data_path}")

    results = {}

    if do_all or do_payloads:
        results["PayloadsAllTheThings"] = viking.import_static_knowledge(
            source_path=str(REFERENCE_DIR / "PayloadsAllTheThings" / "PayloadsAllTheThings-master"),
            category="PayloadsAllTheThings",
            file_pattern="*.md",
        )

    if do_all or do_howtohunt:
        results["HowToHunt"] = viking.import_static_knowledge(
            source_path=str(REFERENCE_DIR / "HowToHunt" / "HowToHunt-master"),
            category="HowToHunt",
            file_pattern="*.md",
        )

    if do_all or do_wstg:
        results["OWASP_WSTG"] = import_wstg(viking)

    if do_all or do_hacktricks:
        results["HackTricks"] = import_hacktricks(viking)

    if do_all or do_nuclei:
        results["Nuclei_Templates"] = import_nuclei_templates(viking)

    if do_all or do_dict:
        results["Dictionary"] = import_dictionary(viking)

    # 总结
    print("\n" + "=" * 60)
    print("📊 导入完成总结")
    print("=" * 60)
    total = 0
    for name, count in results.items():
        print(f"  - {name}: {count}")
        total += count
    print(f"  - 总计: {total}")
    print("=" * 60)

    # 验证搜索
    print("\n🔍 验证搜索...")
    router = KnowledgeRouter(viking_backend=viking, chroma_path=CHROMA_PATH)
    for query in ["SQL injection", "SSRF internal request", "common username", "self-signed certificate"]:
        r = router.search(query, limit=2)
        if r:
            print(f"  ✓ '{query}' → {len(r)} 结果: {r[0].get('title', 'N/A')[:50]}")
        else:
            print(f"  ✗ '{query}' → 无结果")

    return 0


if __name__ == "__main__":
    sys.exit(main())
