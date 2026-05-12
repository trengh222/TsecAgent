# src/agent/knowledge/viking.py
import os
import asyncio
import shutil
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
import structlog

logger = structlog.get_logger(__name__)


@dataclass
class VikingKnowledgeResult:
    """兼容 KnowledgeEntry 的轻量结果对象"""
    id: str = ""  # viking:// URI（作为路由信号）
    title: str = ""
    content: str = ""  # L0 abstract（搜索时）或 L2 完整内容（详情时）
    category: str = "general"
    type: str = "general"
    severity: str = "info"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "content": self.content,
            "category": self.category,
            "type": self.type,
            "severity": self.severity,
            "metadata": self.metadata,
        }


class VikingKnowledgeBackend:
    """OpenViking 知识库后端封装"""

    # 类别到 OpenViking URI 的映射
    CATEGORY_URI_MAP = {
        "PayloadsAllTheThings": "viking://resources/PayloadsAllTheThings/",
        "HowToHunt": "viking://resources/HowToHunt/",
        "wstg": "viking://resources/wstg/",
        "hacktricks": "viking://resources/hacktricks/",
        "nuclei": "viking://resources/nuclei/",
    }

    def __init__(
            self,
            data_path: Optional[str] = None,
            config_file: Optional[str] = None,
    ):
        self.data_path = data_path or os.getenv("OPENVIKING_DATA_PATH", "~/.openviking/data")
        self.config_file = config_file or os.getenv("OPENVIKING_CONFIG_FILE")
        self._client = None
        self._available = False
        self._initialized = False

    def initialize(self) -> bool:
        """初始化 OpenViking 客户端"""
        try:
            from openviking_cli import OpenViking
        except ImportError:
            try:
                import openviking as ov
                OpenViking = ov.OpenViking
            except ImportError:
                logger.warning("OpenViking package not installed, knowledge search will fallback to ChromaDB")
                return False

        try:
            # 设置配置文件路径
            if not self.config_file:
                default_conf = Path.home() / ".openviking" / "ov.conf"
                if default_conf.exists():
                    self.config_file = str(default_conf)
                    os.environ["OPENVIKING_CONFIG_FILE"] = self.config_file
                    logger.info(f"Using config file: {self.config_file}")

            # 展开数据路径
            data_path = str(Path(self.data_path).expanduser())

            # 确保数据目录存在
            Path(data_path).mkdir(parents=True, exist_ok=True)

            # 初始化客户端
            self._client = OpenViking(
                config_path=self.config_file,
                workspace=data_path
            )

            # 尝试初始化连接
            if hasattr(self._client, 'initialize'):
                self._client.initialize()
            elif hasattr(self._client, 'start'):
                self._client.start()

            self._available = True
            self._initialized = True
            logger.info("OpenViking backend initialized", data_path=data_path, config=self.config_file)
            return True

        except Exception as e:
            logger.error("Failed to initialize OpenViking", error=str(e), exc_info=True)
            self._available = False
            return False

    @property
    def is_available(self) -> bool:
        return self._available and self._initialized

    def search(
            self,
            query: str,
            n_results: int = 5,
            category: Optional[str] = None,
    ) -> List[VikingKnowledgeResult]:
        """在 OpenViking 中搜索"""
        if not self.is_available:
            return []

        try:
            # 确定搜索的目标 URI
            target_uri = self.CATEGORY_URI_MAP.get(category, "viking://resources/")

            # 使用 find 方法进行语义搜索
            if hasattr(self._client, 'find'):
                results = self._client.find(
                    query=query,
                    target_uri=target_uri,
                    limit=n_results,
                )
            elif hasattr(self._client, 'search'):
                results = self._client.search(
                    query=query,
                    uri=target_uri,
                    limit=n_results,
                )
            else:
                logger.warning("No search method available in OpenViking client")
                return []

            # 转换为统一格式
            viking_results = []
            for r in results:
                # 处理返回结果
                if isinstance(r, dict):
                    result_id = r.get("uri", r.get("id", ""))
                    result_title = r.get("title", r.get("name", Path(result_id).stem if result_id else "Unknown"))
                    result_content = r.get("abstract", r.get("content", r.get("snippet", "")))
                    similarity = r.get("score", r.get("similarity", 0.0))
                else:
                    # 如果是对象
                    result_id = getattr(r, 'uri', getattr(r, 'id', ''))
                    result_title = getattr(r, 'title',
                                           getattr(r, 'name', Path(result_id).stem if result_id else "Unknown"))
                    result_content = getattr(r, 'abstract', getattr(r, 'content', getattr(r, 'snippet', '')))
                    similarity = getattr(r, 'score', getattr(r, 'similarity', 0.0))

                # 如果没有标题，从文件路径提取
                if not result_title or result_title == "Unknown":
                    if result_id:
                        result_title = Path(result_id.split("/")[-1]).stem.replace("-", " ").title()

                viking_results.append(VikingKnowledgeResult(
                    id=result_id,
                    title=result_title,
                    content=result_content[:500] if result_content else "",
                    category=category or "general",
                    type="static",
                    metadata={
                        "similarity": similarity,
                        "source": "openviking",
                        "uri": result_id,
                    }
                ))

            logger.debug(
                "OpenViking search completed",
                query=query[:50],
                category=category,
                results_count=len(viking_results),
            )
            return viking_results

        except Exception as e:
            logger.error("OpenViking search failed", error=str(e), exc_info=True)
            return []

    def get_detail(self, uri: str) -> Optional[VikingKnowledgeResult]:
        """获取完整文档内容 (L2)"""
        if not self.is_available:
            return None

        try:
            # 适配不同的读取方法
            content = None
            if hasattr(self._client, 'read'):
                content = self._client.read(uri)
            elif hasattr(self._client, 'get_content'):
                content = self._client.get_content(uri)
            elif hasattr(self._client, 'get'):
                content = self._client.get(uri)

            if not content:
                return None

            # 从 URI 中提取标题
            title = uri.split("/")[-1] if uri else "Unknown"
            # 移除文件扩展名
            title = Path(title).stem

            return VikingKnowledgeResult(
                id=uri,
                title=title,
                content=content,
                type="static",
                metadata={"source": "openviking", "level": "L2"},
            )

        except Exception as e:
            logger.error("Failed to get OpenViking detail", uri=uri, error=str(e))
            return None

    def get_overview(self, uri: str) -> Optional[str]:
        """获取结构化概览 (L1)"""
        if not self.is_available:
            return None

        try:
            if hasattr(self._client, 'overview'):
                return self._client.overview(uri)
            elif hasattr(self._client, 'get_overview'):
                return self._client.get_overview(uri)
            else:
                # 如果没有 overview 方法，返回摘要
                detail = self.get_detail(uri)
                if detail and detail.content:
                    # 返回前 500 字符作为概览
                    return detail.content[:500] + ("..." if len(detail.content) > 500 else "")
                return None
        except Exception as e:
            logger.error("Failed to get OpenViking overview", uri=uri, error=str(e))
            return None

    def import_static_knowledge(
            self,
            source_path: str,
            category: str,
            file_pattern: str = "*.md",
    ) -> int:
        """将静态知识库导入 OpenViking

        通过复制文件到 OpenViking workspace 来实现导入，
        OpenViking 会自动索引这些文件。

        Args:
            source_path: 源文件路径（目录或文件）
            category: 类别 (PayloadsAllTheThings/HowToHunt)
            file_pattern: 文件匹配模式

        Returns:
            成功导入的文件数量
        """
        if not self.is_available:
            logger.warning("OpenViking not available, skipping import")
            return 0

        import shutil
        source = Path(source_path).expanduser()
        if not source.exists():
            logger.error(f"Source path does not exist: {source_path}")
            return 0

        imported_count = 0

        # 确定目标 URI 前缀和目录
        uri_prefix = self.CATEGORY_URI_MAP.get(category, "viking://resources/")

        # 获取 workspace 根目录
        workspace_root = Path(self.data_path).expanduser()

        # 构建目标目录路径（从 URI 转换）
        # viking://resources/PayloadsAllTheThings/ -> workspace/resources/PayloadsAllTheThings/
        target_dir = workspace_root / "resources" / category

        # 创建目标目录
        try:
            target_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"Target directory: {target_dir}")
        except Exception as e:
            logger.error(f"Failed to create target directory: {e}")
            return 0

        # 收集所有 Markdown 文件
        files_to_import = []
        if source.is_dir():
            files_to_import = list(source.rglob(file_pattern))
        else:
            files_to_import = [source] if source.exists() else []

        logger.info(f"Importing {len(files_to_import)} files from {source_path}")

        for file_path in files_to_import:
            try:
                # 生成相对路径
                if source.is_dir():
                    rel_path = file_path.relative_to(source)
                else:
                    rel_path = Path(file_path.name)

                # 目标文件路径
                target_file = target_dir / rel_path

                # 创建目标子目录
                target_file.parent.mkdir(parents=True, exist_ok=True)

                # 复制文件
                shutil.copy2(file_path, target_file)

                imported_count += 1

                if imported_count % 100 == 0:
                    logger.info(f"Imported {imported_count}/{len(files_to_import)} files")

                logger.debug(f"Imported: {rel_path} -> {target_file}")

            except Exception as e:
                logger.error(f"Failed to import {file_path}", error=str(e))

        logger.info(f"Successfully imported {imported_count}/{len(files_to_import)} files to OpenViking")

        if imported_count > 0:
            logger.info("✅ Files copied to OpenViking workspace")
            logger.info("📌 OpenViking will automatically index these files")

            # 可选：触发重新索引
            try:
                if hasattr(self._client, 'wait_processed'):
                    self._client.wait_processed()
                    logger.info("Waiting for OpenViking to process imported files...")
            except Exception as e:
                logger.debug(f"Could not wait for processing: {e}")

        return imported_count

    def _extract_markdown_title(self, content: str, fallback: str) -> str:
        """从 Markdown 内容中提取标题"""
        import re
        lines = content.split('\n')
        for line in lines[:10]:  # 在前 10 行查找
            match = re.match(r'^#\s+(.+)$', line.strip())
            if match:
                return match.group(1).strip()
        return fallback.replace('.md', '').replace('_', ' ').title()

    def close(self):
        """关闭 OpenViking 连接"""
        if self._client:
            try:
                if hasattr(self._client, 'close'):
                    self._client.close()
                elif hasattr(self._client, 'stop'):
                    self._client.stop()
                logger.info("OpenViking connection closed")
            except Exception as e:
                logger.warning(f"Error closing OpenViking: {e}")
        self._available = False
        self._initialized = False