# src/mcp/meta_executor.py
import asyncio
import base64
import os
import re
import time
from typing import Any, Dict, Callable
from tenacity import retry, stop_after_attempt, wait_exponential_jitter, retry_if_exception
import structlog

logger = structlog.get_logger(__name__)

# 快照保存目录（相对于本文件的上两级 data/snapshots/）
_SNAPSHOT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "data", "snapshots",
)

# 安全测试高价值关键词——出现时优先保留上下文
_VULN_KEYWORDS = (
    # SQL 注入
    "syntax error", "mysql_", "ora-0", "sqlstate", "you have an error in your sql",
    "unclosed quotation", "unterminated string", "warning: mysql", "pg_query",
    "sqlite_", "mssql", "odbc", "jdbc", "sql syntax",
    # 通用错误/调试
    "exception", "traceback", "stack trace", "fatal error",
    "undefined variable", "null pointer", "index out of range",
    # 认证/访问控制
    "access denied", "unauthorized", "permission denied",
    # 文件包含/路径穿越
    "failed to open stream", "no such file or directory",
    # XSS
    "alert(", "onerror=", "<script>",
    # SSRF / 内网
    "169.254.169.254", "connection refused", "internal server error",
)


def _smart_trim(text: str, max_chars: int) -> str:
    """
    智能截断：头部(40%) + 关键词上下文(30%) + 尾部(30%)。
    比纯头部截断多保留中部和末尾的错误信息、SQL 报错等诊断线索。
    """
    if len(text) <= max_chars:
        return text

    original_len = len(text)
    head_sz  = max_chars * 2 // 5   # 40%
    tail_sz  = max_chars * 3 // 10  # 30%
    kw_sz    = max_chars - head_sz - tail_sz  # 30%

    head_part = text[:head_sz]
    tail_part = text[-tail_sz:] if len(text) - tail_sz > head_sz else ""

    # 扫描关键词，提取周边片段（避免与头部重叠）
    lower = text.lower()
    kw_snippets = []
    kw_used = 0
    seen_buckets: set = set()

    for kw in _VULN_KEYWORDS:
        pos = lower.find(kw, head_sz)  # 只在头部之后扫描，避免重复
        while pos != -1 and kw_used < kw_sz:
            bucket = pos // 400  # 粗粒度去重：400字符区间内只取一次
            if bucket not in seen_buckets:
                seen_buckets.add(bucket)
                start = max(head_sz, pos - 80)
                end   = min(len(text) - tail_sz, pos + 400)
                if end > start:
                    snippet = f"\n…[pos={start}]…\n{text[start:end]}"
                    kw_snippets.append(snippet)
                    kw_used += len(snippet)
            pos = lower.find(kw, pos + 1)

    kw_part = "".join(kw_snippets)
    result  = head_part + kw_part
    if tail_part:
        result += f"\n…[末尾]…\n{tail_part}"
    if len(result) > max_chars:
        result = result[:max_chars]
    return result + f"\n…[智能截断，原始长度 {original_len} 字符]"


def _extract_html_clues(html: str, max_chars: int) -> str:
    """
    HTML 智能截断：额外提取表单/输入控件结构（注入点），再做智能截断。
    保留 head + 表单结构 + 关键词上下文 + tail。
    """
    if len(html) <= max_chars:
        return html

    # 提取 form 标签（注入点关键）
    forms  = re.findall(r'<form[^>]*>.*?</form>', html, re.IGNORECASE | re.DOTALL)
    inputs = re.findall(r'<(?:input|select|textarea)[^>]*>', html, re.IGNORECASE)
    form_block = ""
    if forms or inputs:
        snippets = [f[:300] for f in forms[:3]] + [i[:150] for i in inputs[:8]]
        form_block = "\n[页面表单/输入结构]:\n" + "\n".join(snippets)
        form_block = form_block[:600]

    # 剩余预算给智能截断
    remaining = max(max_chars - len(form_block), max_chars // 2)
    trimmed = _smart_trim(html, remaining)
    return trimmed + form_block


class MetaToolExecutor:
    """Meta-Tooling 执行器 - 统一工具调用入口"""

    def __init__(self, tools: Dict[str, Callable], max_retries: int = 3, timeout: int = 300):
        self.tools = tools
        self.max_retries = max_retries
        self.timeout = timeout

    async def execute(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """执行工具调用

        Args:
            task: 包含 tool 和 arguments 的任务字典

        Returns:
            标准化执行结果
        """
        tool_name = task.get("tool")
        arguments = task.get("arguments", {})
        tool_func = self.tools.get(tool_name)

        if not tool_func:
            return {
                "success": False,
                "tool": tool_name,
                "error": f"Tool '{tool_name}' not found",
                "execution_time": 0,
                "attribution": {"level": "L1", "reason": "工具不存在"}
            }

        start_time = time.time()

        # 过滤参数：只保留函数签名接受的参数
        filtered_args = self._filter_arguments(tool_func, arguments)

        # 创建重试装饰器
        retry_decorator = self._create_retry_decorator()

        @retry_decorator
        async def _call_with_retry():
            return await asyncio.wait_for(
                tool_func(**filtered_args),
                timeout=self.timeout
            )

        try:
            output = await _call_with_retry()
            output = self._sanitize_output(tool_name, output)
            execution_time = time.time() - start_time

            logger.info(
                "Tool executed successfully",
                tool=tool_name,
                execution_time=execution_time
            )

            return {
                "success": True,
                "tool": tool_name,
                "output": output,
                "execution_time": execution_time,
                "error": None
            }

        except asyncio.TimeoutError:
            execution_time = time.time() - start_time
            logger.error("Tool execution timeout", tool=tool_name, timeout=self.timeout)

            return {
                "success": False,
                "tool": tool_name,
                "error": f"Tool execution timed out after {self.timeout} seconds",
                "execution_time": execution_time,
                "attribution": {"level": "L1", "reason": "执行超时"}
            }

        except Exception as e:
            execution_time = time.time() - start_time
            logger.error("Tool execution failed", tool=tool_name, error=str(e))

            return {
                "success": False,
                "tool": tool_name,
                "error": f"Tool execution failed: {str(e)}",
                "execution_time": execution_time,
                "attribution": {"level": "L1", "reason": str(e)}
            }

    def _sanitize_output(self, tool_name: str, output: Any) -> Any:
        """清洗工具输出，截断/替换大体积数据，避免 LLM 上下文膨胀。"""
        if not isinstance(output, dict):
            if isinstance(output, str) and len(output) > 8000:
                return _smart_trim(output, 8000)
            return output

        result = dict(output)

        # ── 截图：将 base64 写入磁盘文件，上下文只保留路径 ──────────────
        if "image_base64" in result:
            img_b64 = result.pop("image_base64")
            size_kb = len(img_b64) * 3 // 4 // 1024
            saved_path = ""
            try:
                os.makedirs(_SNAPSHOT_DIR, exist_ok=True)
                ts = int(time.time() * 1000)
                saved_path = os.path.join(_SNAPSHOT_DIR, f"screenshot_{ts}.png")
                with open(saved_path, "wb") as f:
                    f.write(base64.b64decode(img_b64))
                logger.info("screenshot_saved", path=saved_path, size_kb=size_kb)
            except Exception as e:
                logger.warning("screenshot_save_failed", error=str(e))
            result["image_note"] = (
                f"[截图已保存至 {saved_path}，约 {size_kb}KB，URL={result.get('url', '')}]"
                if saved_path else
                f"[截图完成但保存失败，约 {size_kb}KB，URL={result.get('url', '')}]"
            )

        # ── browser_get_content：智能截断 HTML，保留表单结构和关键片段 ──
        if "content" in result and isinstance(result["content"], str):
            html = result["content"]
            if len(html) > 5000:
                result["content"] = _extract_html_clues(html, 5000)

        # ── 通用大文本截断（stdout / stderr / result / data）──────────────
        _MAX_TEXT = 6000
        for field in ("stdout", "stderr", "result", "data", "output"):
            val = result.get(field)
            if isinstance(val, str) and len(val) > _MAX_TEXT:
                result[field] = _smart_trim(val, _MAX_TEXT)

        # ── proxy_list_traffic 等可能返回大列表 ───────────────────────────
        for field in ("flows", "traffic", "items", "results"):
            val = result.get(field)
            if isinstance(val, list) and len(val) > 30:
                result[field] = val[:30]
                result[f"{field}_note"] = f"[列表已截断，仅展示前 30 条，共 {len(val)} 条]"

        return result

    def _filter_arguments(self, tool_func, arguments: dict) -> dict:
        """只保留函数签名接受的参数，忽略多余参数（防止 LLM 传错参数导致崩溃）。"""
        import inspect
        sig = inspect.signature(tool_func)
        params = set(sig.parameters.keys())
        # 移除 self 和 cls
        params.discard("self")
        params.discard("cls")
        return {k: v for k, v in arguments.items() if k in params}

    def _create_retry_decorator(self):
        """创建重试装饰器"""

        def is_retryable(exception: Exception) -> bool:
            """判断是否可重试"""
            retryable_types = (
                ConnectionError,
                TimeoutError,
                ConnectionRefusedError,
                ConnectionResetError,
            )

            if isinstance(exception, retryable_types):
                return True

            # 检查 HTTP 错误码
            if hasattr(exception, "status_code"):
                status = exception.status_code
                if status in (408, 429, 500, 502, 503, 504):
                    return True

            return False

        return retry(
            retry=retry_if_exception(is_retryable),
            wait=wait_exponential_jitter(initial=0.3, max=10, jitter=0.5),
            stop=stop_after_attempt(self.max_retries),
            reraise=True,
        )