# src/mcp/executors/KnowledgeExecutor.py
"""
知识库执行器 - 渗透测试知识检索与沉淀

支持两种知识源：
  - 静态（OpenViking）：PayloadsAllTheThings、HowToHunt
  - 动态（ChromaDB）：experience、general、task_memory

category 速查表：
  PayloadsAllTheThings / payloads  → 攻击载荷、利用代码
  HowToHunt / howtohunt            → 漏洞挖掘方法论
  experience                       → Agent 过往成功经验（STE）
  general                          → 通用安全知识
  task_memory                      → 当前任务记忆
"""

import asyncio
import os
from functools import partial
from pathlib import Path
from typing import Optional

import structlog

logger = structlog.get_logger(__name__)


class KnowledgeExecutor:
    """MCP 知识库执行器，封装 KnowledgeRouter 为异步接口。"""

    def __init__(self, config: dict = None):
        self.config = config or {}
        self._router = None

    # ------------------------------------------------------------------
    # 延迟初始化
    # ------------------------------------------------------------------

    def _get_router(self):
        """延迟初始化 KnowledgeRouter，避免在服务启动时就加载重型依赖。"""
        if self._router is not None:
            return self._router

        from deepagent.knowledge.router import KnowledgeRouter
        from deepagent.knowledge.viking import VikingKnowledgeBackend

        # Viking 后端（可选）
        viking = None
        if self.config.get("viking_enabled", False):
            viking = VikingKnowledgeBackend(
                data_path=self.config.get("viking_path",        os.getenv("OPENVIKING_DATA_PATH", "~/.openviking/data")),
                config_file=self.config.get("viking_config_file", os.getenv("OPENVIKING_CONFIG_FILE")),
            )
            if not viking.initialize():
                logger.warning("viking_init_failed_fallback_chroma")
                viking = None

        chroma_path = self.config.get("chroma_path") or os.getenv("CHROMA_PATH", "./data/chroma")
        embedding_model = self.config.get("embedding_model", "default")

        # 确保 chroma 路径存在
        Path(chroma_path).mkdir(parents=True, exist_ok=True)

        self._router = KnowledgeRouter(
            viking_backend=viking,
            chroma_path=chroma_path,
            embedding_model=embedding_model,
        )
        logger.info("knowledge_router_ready", chroma_path=chroma_path)
        return self._router

    async def _run_sync(self, fn, *args, **kwargs):
        """在线程池中运行同步函数，避免阻塞事件循环。"""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, partial(fn, *args, **kwargs))
    # ------------------------------------------------------------------
    # MCP 工具方法
    # ------------------------------------------------------------------

    async def search(
            self,
            query: str,
            category: Optional[str] = None,
            limit: int = 5,
    ) -> dict:
        """搜索知识库。

        Args:
            query:    搜索关键词或自然语言描述
            category: 知识类别（见模块 docstring）
            limit:    返回条数，默认 5

        Returns:
            {"success": bool, "results": [...], "count": int, "query": str}
        """
        try:
            router = self._get_router()
            results = await self._run_sync(router.search, query, category, limit)
            return {
                "success": True,
                "query": query,
                "category": category,
                "count": len(results),
                "results": results,
            }
        except Exception as e:
            logger.error("knowledge_search_failed", query=query, error=str(e))
            return {"success": False, "error": str(e), "results": [], "count": 0}

    async def get_detail(self, entry_id: str) -> dict:
        """获取知识条目的完整内容。

        Args:
            entry_id: search 结果中的 id 字段
                      viking:// 前缀 → 静态知识
                      UUID → ChromaDB 动态知识

        Returns:
            {"success": bool, "entry": {...}}
        """
        try:
            router = self._get_router()
            entry = await self._run_sync(router.get_detail, entry_id)
            if entry:
                return {"success": True, "entry": entry}
            return {"success": False, "error": f"Entry not found: {entry_id}"}
        except Exception as e:
            logger.error("knowledge_get_detail_failed", entry_id=entry_id, error=str(e))
            return {"success": False, "error": str(e)}

    async def save(
            self,
            content: str,
            title: str = "",
            category: str = "experience",
            tags: Optional[list] = None,
    ) -> dict:
        """将知识沉淀到 ChromaDB（仅支持动态集合）。

        Args:
            content:  知识内容（Markdown 或纯文本）
            title:    标题
            category: experience（默认）| general | task_memory
            tags:     标签列表，用于后续过滤

        Returns:
            {"success": bool, "doc_id": str}
        """
        if not content.strip():
            return {"success": False, "error": "content 不能为空"}
        try:
            router = self._get_router()
            doc_id = await self._run_sync(router.save, content, title, category, tags)
            if doc_id:
                return {"success": True, "doc_id": doc_id, "category": category}
            return {"success": False, "error": "写入失败，请检查 ChromaDB 配置"}
        except Exception as e:
            logger.error("knowledge_save_failed", error=str(e))
            return {"success": False, "error": str(e)}
