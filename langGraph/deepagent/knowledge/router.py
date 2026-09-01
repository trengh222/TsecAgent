from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any

import chromadb
import logging
import structlog
from chromadb.config import Settings
from chromadb.utils import embedding_functions

# posthog 版本与 chromadb 不兼容时会产生噪音日志，直接静默
logging.getLogger("chromadb.telemetry.product.posthog").setLevel(logging.CRITICAL)

from .viking import VikingKnowledgeBackend, VikingKnowledgeResult

logger = structlog.get_logger(__name__)

# ChromaDB 动态集合
_DYNAMIC_COLLECTIONS = ("experience", "general", "task_memory")

# 静态知识类别 → OpenViking URI map（保持一致）
_STATIC_CATEGORY_URI = {
    "PayloadsAllTheThings": "viking://resources/PayloadsAllTheThings/",
    "HowToHunt": "viking://resources/HowToHunt/",
    "wstg": "viking://resources/wstg/",
    "hacktricks": "viking://resources/hacktricks/",
    "nuclei": "viking://resources/nuclei/",
}

# 静态类别 → ChromaDB 集合名（OpenViking 不可用时的降级映射）
_STATIC_TO_CHROMA = {
    "PayloadsAllTheThings": "payloads",
    "HowToHunt": "howtohunt",
    "wstg": "wstg",
    "hacktricks": "hacktricks",
    "nuclei": "nuclei",
}

# 用户友好别名 → 标准 key
_CATEGORY_ALIASES = {
    "payloads":   "PayloadsAllTheThings",
    "howtohunt":  "HowToHunt",
    "payload":    "PayloadsAllTheThings",
    "hunt":       "HowToHunt",
    "wstg":       "wstg",
    "owasp":      "wstg",
    "testing":    "wstg",
    "hacktricks": "hacktricks",
    "hack":       "hacktricks",
    "nuclei":     "nuclei",
    "cve":        "nuclei",
    "templates":  "nuclei",
}


def _build_embedding_fn(model: str):
    """构建嵌入函数，按优先级自动选择：local → sentence-transformers → OpenAI。"""
    if not model or model == "default":
        # ChromaDB 内置的 ONNX 模型，无需 API key
        return embedding_functions.DefaultEmbeddingFunction()
    if model.startswith("text-embedding"):
        return embedding_functions.OpenAIEmbeddingFunction(model_name=model)
    # 尝试 sentence-transformers
    try:
        return embedding_functions.SentenceTransformerEmbeddingFunction(model_name=model)
    except Exception:
        logger.warning("sentence_transformer_unavailable", model=model, fallback="default")
        return embedding_functions.DefaultEmbeddingFunction()


class KnowledgeRouter:
    """双后端知识路由器 - OpenViking（静态）+ ChromaDB（动态）"""

    def __init__(
            self,
            viking_backend: Optional[VikingKnowledgeBackend] = None,
            chroma_path: Optional[str] = None,
            embedding_model: str = "default",
    ):
        self.viking = viking_backend
        self.chroma_client: Optional[chromadb.Client] = None
        self.chroma_collections: Dict[str, Any] = {}

        embedding_fn = _build_embedding_fn(embedding_model)

        # 初始化 ChromaDB（关闭匿名遥测，避免 posthog 版本不兼容的噪音日志）
        _settings = Settings(anonymized_telemetry=False)
        if chroma_path:
            self.chroma_client = chromadb.PersistentClient(path=chroma_path, settings=_settings)
        else:
            self.chroma_client = chromadb.EphemeralClient(settings=_settings)

        self._init_chroma_collections(embedding_fn)

        logger.info(
            "knowledge_router_initialized",
            viking_available=self.viking.is_available if self.viking else False,
            chroma_collections=list(self.chroma_collections.keys()),
        )

    # ------------------------------------------------------------------
    # 初始化
    # ------------------------------------------------------------------

    def _init_chroma_collections(self, embedding_fn) -> None:
        for name in _DYNAMIC_COLLECTIONS:
            try:
                self.chroma_collections[name] = self.chroma_client.get_or_create_collection(
                    name=name,
                    embedding_function=embedding_fn,
                )
            except Exception as e:
                logger.warning("chroma_collection_init_failed", name=name, error=str(e))
        # 静态知识 ChromaDB 集合（OpenViking 不可用时的降级方案）
        for name in _STATIC_TO_CHROMA.values():
            if name not in self.chroma_collections:
                try:
                    self.chroma_collections[name] = self.chroma_client.get_or_create_collection(
                        name=name,
                        embedding_function=embedding_fn,
                    )
                except Exception as e:
                    logger.warning("chroma_collection_init_failed", name=name, error=str(e))

    # ------------------------------------------------------------------
    # 搜索
    # ------------------------------------------------------------------

    def search(
            self,
            query: str,
            category: Optional[str] = None,
            limit: int = 5,
    ) -> List[Dict[str, Any]]:
        """按类别路由搜索，支持别名。

        category 可选值:
          静态: PayloadsAllTheThings | payloads | HowToHunt | howtohunt
          动态: experience | general | task_memory
          空值: 同时搜索静态 + 动态，按相似度合并
        """
        # 别名统一
        normalized = _CATEGORY_ALIASES.get(category, category) if category else None

        # 静态知识 → OpenViking
        if normalized in _STATIC_CATEGORY_URI:
            return self._search_static(query, normalized, limit)

        # 动态知识 → ChromaDB
        if normalized in _DYNAMIC_COLLECTIONS:
            return self._search_chroma(query, normalized, limit)

        # 无类别 → 合并搜索
        return self._search_combined(query, limit)

    def _search_static(self, query: str, category: str, limit: int) -> List[Dict[str, Any]]:
        if self.viking and self.viking.is_available:
            results = self.viking.search(query, limit, category)
            return [r.to_dict() for r in results]
        # Viking 不可用时降级到对应的 ChromaDB 集合
        chroma_coll = _STATIC_TO_CHROMA.get(category, "general")
        logger.debug("viking_unavailable_fallback_chroma", category=category, collection=chroma_coll)
        return self._search_chroma(query, chroma_coll, limit)

    def _search_combined(self, query: str, limit: int) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []

        # 动态集合各取 limit//3
        per_dynamic = max(1, limit // 3)
        for name in _DYNAMIC_COLLECTIONS:
            results.extend(self._search_chroma(query, name, per_dynamic))

        # 静态集合取一半：按优先级 wstg > hacktricks > nuclei > payloads > howtohunt
        static_categories = ["wstg", "hacktricks", "nuclei", "PayloadsAllTheThings", "HowToHunt"]
        per_static = max(1, limit // len(static_categories))
        if self.viking and self.viking.is_available:
            for cat in static_categories:
                static = self.viking.search(query, per_static, cat)
                results.extend(r.to_dict() for r in static)
        else:
            # Viking 不可用时从对应的 ChromaDB 集合搜索
            for cat in static_categories:
                chroma_coll = _STATIC_TO_CHROMA.get(cat, "general")
                results.extend(self._search_chroma(query, chroma_coll, per_static))

        results.sort(key=lambda x: x.get("metadata", {}).get("similarity", 0.0), reverse=True)
        return results[:limit]

    def _search_chroma(self, query: str, category: str, limit: int) -> List[Dict[str, Any]]:
        collection = self.chroma_collections.get(category)
        if not collection:
            return []
        try:
            n = max(1, limit)
            raw = collection.query(query_texts=[query], n_results=n)

            ids       = (raw.get("ids")       or [[]])[0]
            metadatas = (raw.get("metadatas") or [[]])[0]
            documents = (raw.get("documents") or [[]])[0]
            distances = (raw.get("distances") or [[]])[0]

            results = []
            for i, doc_id in enumerate(ids):
                meta     = metadatas[i] if i < len(metadatas) else {}
                content  = documents[i] if i < len(documents) else ""
                distance = distances[i] if i < len(distances) else 1.0
                # ChromaDB L2 distance → 近似相似度
                similarity = round(max(0.0, 1.0 - distance), 4)

                results.append({
                    "id":       doc_id,
                    "title":    meta.get("title", "Unknown"),
                    "content":  content,
                    "category": category,
                    "type":     "dynamic",
                    "metadata": {
                        "similarity": similarity,
                        "source":     meta.get("source", "chromadb"),
                        "tags":       meta.get("tags", ""),
                        "timestamp":  meta.get("timestamp", ""),
                    },
                })
            return results
        except Exception as e:
            logger.error("chroma_search_failed", category=category, error=str(e))
            return []

    # ------------------------------------------------------------------
    # 详情
    # ------------------------------------------------------------------

    def get_detail(self, entry_id: str) -> Optional[Dict[str, Any]]:
        if entry_id.startswith("viking://"):
            if self.viking and self.viking.is_available:
                result = self.viking.get_detail(entry_id)
                return result.to_dict() if result else None
            return {"error": "OpenViking backend unavailable"}
        return self._get_chroma_detail(entry_id)

    def _get_chroma_detail(self, entry_id: str) -> Optional[Dict[str, Any]]:
        for name, collection in self.chroma_collections.items():
            try:
                raw = collection.get(ids=[entry_id])
                ids = (raw.get("ids") or [])
                if ids and ids[0]:
                    docs = (raw.get("documents") or [[]])[0]
                    metas = (raw.get("metadatas") or [[]])[0]
                    return {
                        "id":       entry_id,
                        "title":    metas[0].get("title", "Unknown") if metas else "Unknown",
                        "content":  docs[0] if docs else "",
                        "category": name,
                        "type":     "dynamic",
                    }
            except Exception:
                continue
        return None

    # ------------------------------------------------------------------
    # 写入
    # ------------------------------------------------------------------

    def save(
            self,
            content: str,
            title: str = "",
            category: str = "general",
            tags: Optional[List[str]] = None,
            extra_meta: Optional[Dict[str, Any]] = None,
    ) -> str:
        """统一写入接口，将知识持久化到 ChromaDB。

        Returns:
            doc_id（成功）或空字符串（失败）
        """
        # 别名统一后确认是动态集合
        target = _CATEGORY_ALIASES.get(category, category)
        if target not in _DYNAMIC_COLLECTIONS:
            target = "general"

        collection = self.chroma_collections.get(target)
        if not collection:
            logger.warning("chroma_collection_missing", target=target)
            return ""

        doc_id = str(uuid.uuid4())
        meta: Dict[str, Any] = {
            "title":      title or "Untitled",
            "source":     "agent",
            "timestamp":  datetime.now().isoformat(),
            "tags":       ",".join(tags) if tags else "",
        }
        if extra_meta:
            # ChromaDB metadata 只接受 str/int/float/bool
            for k, v in extra_meta.items():
                meta[k] = str(v) if isinstance(v, (list, dict)) else v

        try:
            collection.add(ids=[doc_id], documents=[content], metadatas=[meta])
            logger.info("knowledge_saved", doc_id=doc_id, title=title, category=target)
            return doc_id
        except Exception as e:
            logger.error("knowledge_save_failed", error=str(e))
            return ""

    def save_ste_experience(self, ste) -> str:
        """将 STEExperience 对象持久化到 experience 集合。"""
        content = f"""策略: {ste.strategy}

战术:
{chr(10).join(f"  - {t}" for t in ste.tactics)}

示例:
{ste.example}

适用场景: {", ".join(ste.applicable_scenarios)}"""

        return self.save(
            content=content,
            title=ste.strategy[:80],
            category="experience",
            tags=ste.applicable_scenarios[:5],
            extra_meta={"strategy": ste.strategy},
        )

    # ------------------------------------------------------------------
    # 跨会话加载
    # ------------------------------------------------------------------

    def load_experience_for_target(self, target_url: str = "", limit: int = 5) -> List[Dict[str, Any]]:
        """为新目标加载历史经验，用于首次 planner 启动时注入上下文。"""
        query = target_url or "penetration testing"
        return self._search_chroma(query, "experience", limit)

    def load_vulns_for_target(self, query: str = "", limit: int = 5) -> List[Dict[str, Any]]:
        """从 general 集合加载历史确认漏洞记录。"""
        if not query:
            query = "confirmed vulnerability"
        return self._search_chroma(query, "general", limit)

    def get_experience_count(self) -> int:
        """获取 experience 集合的文档总数。"""
        collection = self.chroma_collections.get("experience")
        if collection:
            try:
                return collection.count()
            except Exception:
                return 0
        return 0

    def get_vuln_count(self) -> int:
        """获取 general 集合的文档总数。"""
        collection = self.chroma_collections.get("general")
        if collection:
            try:
                return collection.count()
            except Exception:
                return 0
        return 0

    # ------------------------------------------------------------------
    # 旧接口兼容（保留 add_experience / add_runtime_knowledge）
    # ------------------------------------------------------------------

    def add_experience(self, experience: Dict[str, Any], collection: str = "experience") -> str:
        return self.save(
            content=experience.get("content", ""),
            title=experience.get("title", ""),
            category=collection,
            extra_meta={k: experience[k] for k in ("strategy", "tactics", "timestamp") if k in experience},
        )

    def add_runtime_knowledge(self, knowledge: Dict[str, Any], category: str = "general") -> str:
        return self.save(
            content=knowledge.get("content", ""),
            title=knowledge.get("title", ""),
            category=category,
            extra_meta={k: knowledge[k] for k in ("source", "severity", "applicable_scenarios") if k in knowledge},
        )

    def batch_add_runtime_knowledge(self, knowledge_list: List[Dict[str, Any]], category: str = "general") -> int:
        return sum(1 for k in knowledge_list if self.add_runtime_knowledge(k, category))

    def get_overview(self, entry_id: str) -> Optional[str]:
        if entry_id.startswith("viking://") and self.viking and self.viking.is_available:
            return self.viking.get_overview(entry_id)
        return None
