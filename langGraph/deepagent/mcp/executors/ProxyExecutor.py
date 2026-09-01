# src/mcp/executors/ProxyExecutor.py
"""
代理流量执行器 - 基于 Caido GraphQL API (v0.55.3)

配置方式（.env）：
  PROXY_CAIDO_URL=http://127.0.0.1:8080
  PROXY_CAIDO_TOKEN=<token>   # Caido → Settings → API → Generate Token

Caido v0.55.3 已确认的 mutation 名：
  deleteInterceptEntries(filter: HTTPQL, scopeId: ID)  — 批量删除历史（无参数=全部）
  deleteInterceptEntry(id: ID!)                        — 删除单条
  createReplaySession(input: CreateReplaySessionInput!) — 创建重放会话
  startReplayTask(sessionId: ID!, input: StartReplayTaskInput!) — 触发重放
"""

import asyncio
from typing import Optional

import structlog

logger = structlog.get_logger(__name__)

try:
    import httpx
    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False
    logger.warning("httpx_not_installed", hint="pip install httpx")


# ─────────────────────────────────────────────────────────────────────────────
# GraphQL 查询常量（基于 v0.55.3 introspection 校准）
# ─────────────────────────────────────────────────────────────────────────────

# 列出 HTTP 历史请求（支持 HTTPQL 服务端过滤）
# filter 示例：'req.host.eq:"example.com"'  |  'req.host.eq:"example.com" AND req.method.eq:"POST"'
#              'req.path.cont:"/admin"'       |  'resp.code.gte:400'
_GQL_LIST_REQUESTS = """
query ListRequests($first: Int, $filter: HTTPQL) {
  requests(first: $first, filter: $filter) {
    edges {
      node {
        id
        host
        port
        isTls
        method
        path
        length
        createdAt
        response {
          statusCode
          length
        }
      }
    }
  }
}
"""

# 获取所有请求 ID（clear_traffic 步骤1）
_GQL_ALL_IDS = """
query AllRequestIds {
  requests {
    edges {
      node {
        id
      }
    }
  }
}
"""

# 获取单条请求详情
_GQL_GET_REQUEST = """
query GetRequest($id: ID!) {
  request(id: $id) {
    id
    host
    port
    isTls
    method
    path
    query
    raw
    response {
      statusCode
      raw
    }
  }
}
"""

# 清空全部历史：deleteInterceptEntries 不传 filter/scopeId = 删除全部
# 返回类型由 Caido 决定，可能是 Int、Boolean 或对象；
# 若报 "Field selection required" 错误，可改为 { deletedCount } 等字段
_GQL_CLEAR_ALL = """
mutation ClearInterceptEntries {
  deleteInterceptEntries {
    task {
      id
    }
  }
}
"""

# 重放步骤1：从历史请求创建 Replay Session
_GQL_CREATE_REPLAY_SESSION = """
mutation CreateReplaySession($input: CreateReplaySessionInput!) {
  createReplaySession(input: $input) {
    session {
      id
    }
  }
}
"""

# 重放步骤2：触发重放任务
_GQL_START_REPLAY_TASK = """
mutation StartReplayTask($sessionId: ID!, $input: StartReplayTaskInput!) {
  startReplayTask(sessionId: $sessionId, input: $input) {
    task {
      id
    }
  }
}
"""


# ─────────────────────────────────────────────────────────────────────────────
# ProxyExecutor
# ─────────────────────────────────────────────────────────────────────────────

class ProxyExecutor:
    """Caido 代理流量执行器（v0.55.3）。

    方法速览：
      list_traffic(limit, filter_host)  → 列出 HTTP 历史请求（摘要）
      get_flow(flow_id)                 → 获取单条请求/响应完整内容
      clear_traffic()                   → 清空所有历史请求
      replay_flow(flow_id)              → 重放指定请求（两步：建 Session → 触发任务）
    """

    def __init__(self, config: dict = None):
        self.config = config or {}
        caido_url = self.config.get("caido_url", "http://127.0.0.1:8080").rstrip("/")
        self._token = (self.config.get("caido_token") or "").strip()
        self._graphql_url = f"{caido_url}/graphql"
        self._enabled = bool(self._token)

        # 解析 Caido URL 以提供兼容的 proxy_port 和 api_port 属性
        from urllib.parse import urlparse
        parsed = urlparse(caido_url)
        self.host = parsed.hostname or "127.0.0.1"
        self.proxy_port = parsed.port or 8080  # 默认 Caido 端口
        self.api_port = parsed.port or 8080    # Caido 的 GraphQL API 在同一个端口

        if not self._enabled:
            logger.warning(
                "proxy_caido_no_token",
                hint="在 .env 中设置 PROXY_CAIDO_TOKEN 以启用 Caido 代理集成",
            )
        else:
            logger.info("proxy_caido_ready", url=self._graphql_url)

    # ------------------------------------------------------------------
    # GraphQL 基础调用
    # ------------------------------------------------------------------

    async def _gql(self, query: str, variables: dict = None) -> dict:
        if not _HTTPX_AVAILABLE:
            raise RuntimeError("httpx 未安装，请执行: pip install httpx")

        payload: dict = {"query": query}
        if variables:
            payload["variables"] = variables

        async with httpx.AsyncClient(
            headers={
                "Authorization": f"Bearer {self._token}",
                "Content-Type":  "application/json",
            },
            timeout=15.0,
            verify=False,
        ) as client:
            resp = await client.post(self._graphql_url, json=payload)
            resp.raise_for_status()
            body = resp.json()

        if errors := body.get("errors"):
            raise RuntimeError(f"GraphQL 错误: {errors[0].get('message', errors)}")
        return body.get("data", {})

    def _not_enabled(self) -> dict:
        return {
            "success": False,
            "error":   "Caido 未配置，请在 .env 中设置 PROXY_CAIDO_TOKEN",
            "hint":    "PROXY_CAIDO_URL=http://127.0.0.1:8080\nPROXY_CAIDO_TOKEN=<token>",
        }

    # ------------------------------------------------------------------
    # MCP 工具方法
    # ------------------------------------------------------------------

    async def list_traffic(
        self,
        limit: int = 50,
        target_host: Optional[str] = None,
    ) -> dict:
        """列出 HTTP 历史请求（摘要）。

        Args:
            limit:       最多返回条数，默认 50
            target_host: 目标主机名（如 "example.com"），传入后通过 HTTPQL
                         服务端过滤，只返回该 host 的流量，排除浏览器自发请求
        """
        if not self._enabled:
            return self._not_enabled()

        try:
            # 构造 HTTPQL 服务端过滤（只在有 target_host 时启用）
            httpql_filter = f'req.host.eq:"{target_host}"' if target_host else None
            variables = {"first": limit}
            if httpql_filter:
                variables["filter"] = httpql_filter

            try:
                data = await self._gql(_GQL_LIST_REQUESTS, variables)
            except RuntimeError as gql_err:
                if httpql_filter and "HTTPQL" in str(gql_err):
                    # HTTPQL 语法不受支持，退回全量拉取 + 客户端过滤
                    logger.warning(
                        "proxy_httpql_fallback",
                        filter=httpql_filter,
                        error=str(gql_err),
                    )
                    httpql_filter = None
                    data = await self._gql(_GQL_LIST_REQUESTS, {"first": limit * 5})
                else:
                    raise

            edges = (data.get("requests") or {}).get("edges", [])

            flows = []
            for edge in edges:
                node = edge.get("node", {})
                resp = node.get("response") or {}
                host = node.get("host", "")

                # 客户端兜底过滤（HTTPQL 降级时生效）
                if target_host and httpql_filter is None:
                    if target_host.lower() not in host.lower():
                        continue

                path = node.get("path", "/")

                # 截断过长的 path，避免输出膨胀
                if len(path) > 100:
                    path = path[:97] + "..."

                scheme = "https" if node.get("isTls") else "http"
                flows.append({
                    "id":        node.get("id", ""),
                    "method":    node.get("method", ""),
                    "url":       f"{scheme}://{host}{path}",
                    "status":    resp.get("statusCode"),
                    "size":      resp.get("length", 0),
                    "timestamp": node.get("createdAt"),
                })

            logger.info("proxy_list_traffic_ok", count=len(flows), filter=httpql_filter)
            return {
                "success": True,
                "count":   len(flows),
                "filter":  httpql_filter,
                "flows":   flows,
            }

        except Exception as e:
            logger.warning("proxy_list_traffic_failed", error=str(e))
            return {
                "success": False,
                "error":   str(e),
                "hint":    f"GraphQL 端点: {self._graphql_url}",
                "flows":   [],
                "count":   0,
            }

    async def get_flow(self, flow_id: str) -> dict:
        """获取单条请求/响应的完整内容（含 raw 报文）。"""
        if not self._enabled:
            return self._not_enabled()

        try:
            data = await self._gql(_GQL_GET_REQUEST, {"id": flow_id})
            node = data.get("request")
            if not node:
                return {"success": False, "error": f"Request not found: {flow_id}"}

            scheme   = "https" if node.get("isTls") else "http"
            port     = node.get("port", 443 if node.get("isTls") else 80)
            port_str = f":{port}" if port not in (80, 443) else ""
            path     = node.get("path", "/")
            query    = node.get("query", "")
            url      = f"{scheme}://{node.get('host', '')}{port_str}{path}"
            if query:
                url += f"?{query}"

            resp = node.get("response") or {}

            def _trunc(s: str, limit: int = 10000) -> str:
                if s and len(s) > limit:
                    return s[:limit] + f"\n… [截断，共 {len(s)} 字符]"
                return s or ""

            return {
                "success": True,
                "flow": {
                    "id": node.get("id"),
                    "request": {
                        "method": node.get("method", ""),
                        "url":    url,
                        "raw":    _trunc(node.get("raw", "")),
                    },
                    "response": {
                        "status": resp.get("statusCode"),
                        "raw":    _trunc(resp.get("raw", "")),
                    } if resp else None,
                },
            }

        except Exception as e:
            logger.warning("proxy_get_flow_failed", flow_id=flow_id, error=str(e))
            return {"success": False, "error": str(e)}

    async def clear_traffic(self) -> dict:
        """清空所有 HTTP 历史请求。

        使用 deleteInterceptEntries（不传 filter = 全部删除）。
        此为 v0.55.3 中唯一可用的批量删除 mutation。
        """
        if not self._enabled:
            return self._not_enabled()

        try:
            data    = await self._gql(_GQL_CLEAR_ALL)
            payload = data.get("deleteInterceptEntries") or {}
            task_id = (payload.get("task") or {}).get("id")
            logger.info("proxy_traffic_cleared", task_id=task_id)
            return {
                "success": True,
                "task_id": task_id,
                "message": "已提交清空任务，Caido 将在后台删除所有 HTTP 历史请求",
            }
        except Exception as e:
            logger.warning("proxy_clear_traffic_failed", error=str(e))
            return {"success": False, "error": str(e)}

    async def replay_flow(self, flow_id: str) -> dict:
        """重放指定请求。

        v0.55.3 中重放分两步：
          1. createReplaySession(input: { requestId }) → 获取 session.id
          2. startReplayTask(sessionId, input: {})    → 触发重放

        Args:
            flow_id: list_traffic 返回的请求 ID

        Returns:
            {"success": bool, "flow_id": str, "session_id": str}
        """
        if not self._enabled:
            return self._not_enabled()

        try:
            # 步骤1：创建 Replay Session
            sess_data  = await self._gql(
                _GQL_CREATE_REPLAY_SESSION,
                {"input": {"requestId": flow_id}},
            )
            session_id = (
                (sess_data.get("createReplaySession") or {})
                .get("session", {})
                .get("id")
            )
            if not session_id:
                return {
                    "success": False,
                    "error":   "createReplaySession 未返回 session.id",
                    "raw":     sess_data,
                }

            # 步骤2：触发重放任务
            task_data = await self._gql(
                _GQL_START_REPLAY_TASK,
                {"sessionId": session_id, "input": {}},
            )
            task_id = (
                (task_data.get("startReplayTask") or {})
                .get("task", {})
                .get("id")
            )

            logger.info("proxy_flow_replayed", flow_id=flow_id, session_id=session_id)
            return {
                "success":    True,
                "flow_id":    flow_id,
                "session_id": session_id,
                "task_id":    task_id,
                "message":    "重放任务已触发，可在 Caido Replay 面板查看结果",
            }

        except Exception as e:
            logger.warning("proxy_replay_flow_failed", flow_id=flow_id, error=str(e))
            return {"success": False, "error": str(e)}

    def stop(self) -> None:
        """Caido 为外部进程，此方法为空操作（兼容 chat_server shutdown）。"""
        pass
