# src/mcp/executors/JSAnalyzer.py
"""
JS 分析器 - 从页面 JS 文件中提取 API 端点和敏感信息

依赖：httpx（pip install httpx）

提取内容：
  endpoints — API 路径、fetch/axios 调用、路由定义
  secrets   — API Key、Token、JWT、AWS Key、Password、私钥等
"""

import re
import time
from typing import Optional
from urllib.parse import urljoin, urlparse

import structlog

logger = structlog.get_logger(__name__)

try:
    import httpx
    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False

# 敏感信息特征规则
_SECRET_PATTERNS = [
    ("API Key",     r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,64})["\']'),
    ("Token",       r'(?:token|access[_-]?token)\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{20,200})["\']'),
    ("AWS Key",     r'AKIA[0-9A-Z]{16}'),
    ("Private Key", r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY'),
    ("Password",    r'(?:password|passwd|pwd)\s*[:=]\s*["\']([^\s"\']{6,50})["\']'),
    ("Secret",      r'(?:secret|client[_-]?secret)\s*[:=]\s*["\']([A-Za-z0-9_\-]{8,64})["\']'),
    ("JWT",         r'eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}'),
    ("Email",       r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'),
]

# API 端点提取规则
_ENDPOINT_PATTERNS = [
    r'["\'](/(?:api|v\d|rest|graphql|admin|auth|user|account)[^\s"\'<>]*)["\']',
    r'["\']([/\w\-]+/[/\w\-]+\.\w{2,5})["\']',
    r'(?:url|endpoint|path|route|href)\s*[:=]\s*["\']([/][^\s"\'<>]{3,100})["\']',
    r'fetch\(["\']([^"\']+)["\']',
    r'axios\.\w+\(["\']([^"\']+)["\']',
]

_STATIC_EXTENSIONS = (".png", ".jpg", ".gif", ".svg", ".woff", ".ttf", ".ico", ".css")


def _extract_script_urls(html: str, base: str, page_url: str) -> list[str]:
    urls = []
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', html, re.I):
        src = m.group(1)
        if src.startswith("http"):
            urls.append(src)
        elif src.startswith("//"):
            urls.append("https:" + src)
        elif src.startswith("/"):
            urls.append(base + src)
        else:
            urls.append(urljoin(page_url, src))
    return urls


def _extract_endpoints(js: str) -> list[str]:
    found = set()
    for pat in _ENDPOINT_PATTERNS:
        for m in re.finditer(pat, js, re.I):
            path = m.group(1)
            if not any(path.endswith(ext) for ext in _STATIC_EXTENSIONS):
                found.add(path)
    return sorted(found)


def _extract_secrets(js: str, source_url: str) -> list[dict]:
    found = []
    for label, pattern in _SECRET_PATTERNS:
        for m in re.finditer(pattern, js, re.I):
            found.append({
                "type":   label,
                "match":  m.group(0)[:120],
                "source": source_url,
            })
    return found


class JSAnalyzer:
    """JavaScript 文件分析器：提取 API 端点和敏感信息。"""

    def __init__(self, config: dict = None):
        self.config = config or {}

    def _http_client(self, timeout: float = 15.0) -> "httpx.AsyncClient":
        return httpx.AsyncClient(
            timeout=timeout,
            verify=False,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; DeepAgent/1.0)"},
        )

    async def analyze(self, url: str, max_scripts: int = 10) -> dict:
        """分析目标页面的所有外部 JS 文件。

        Args:
            url:         目标页面 URL
            max_scripts: 最多下载并分析的 JS 文件数量

        Returns:
            {"success", "url",
             "scripts":   已分析的 JS URL 列表,
             "endpoints": 提取到的 API 路径列表（去重，最多 200 条）,
             "secrets":   疑似敏感信息列表（最多 50 条）,
             "elapsed"}
        """
        if not _HTTPX_AVAILABLE:
            return {"success": False, "error": "httpx 未安装: pip install httpx"}

        start  = time.monotonic()
        parsed = urlparse(url)
        base   = f"{parsed.scheme}://{parsed.netloc}"

        try:
            async with self._http_client() as client:
                resp        = await client.get(url)
                script_urls = _extract_script_urls(resp.text, base, url)[:max_scripts]

                all_endpoints: list[str] = []
                all_secrets:   list[dict] = []
                analyzed:      list[str]  = []

                for js_url in script_urls:
                    try:
                        js_resp = await client.get(js_url)
                        all_endpoints.extend(_extract_endpoints(js_resp.text))
                        all_secrets.extend(_extract_secrets(js_resp.text, js_url))
                        analyzed.append(js_url)
                    except Exception as e:
                        logger.debug("js_fetch_failed", url=js_url, error=str(e))

            unique_ep = sorted(set(all_endpoints))
            logger.info("js_analysis_done", url=url, scripts=len(analyzed),
                        endpoints=len(unique_ep), secrets=len(all_secrets))
            return {
                "success":   True,
                "url":       url,
                "scripts":   analyzed,
                "endpoints": unique_ep[:200],
                "secrets":   all_secrets[:50],
                "elapsed":   round(time.monotonic() - start, 2),
            }
        except Exception as e:
            return {"success": False, "error": str(e), "url": url}
