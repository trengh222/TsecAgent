# src/mcp/executors/HttpSearchExecutor.py
"""
HTTP 轻量搜索执行器 — 不依赖 playwright。

使用 aiohttp 直接发起 HTTP 请求，通过 DuckDuckGo Lite / Bing 获取搜索结果。
适用于 playwright 无法联网的环境。
"""

import re
import time
from html import unescape
from typing import Optional
from urllib.parse import quote_plus

import structlog

try:
    import aiohttp
    _AIOHTTP_OK = True
except ImportError:
    _AIOHTTP_OK = False

logger = structlog.get_logger(__name__)


def _strip_tags(html: str) -> str:
    """去除 HTML 标签，还原 HTML 实体。"""
    text = re.sub(r"<[^>]+>", " ", html)
    return unescape(re.sub(r"\s+", " ", text)).strip()


def _parse_ddg_html(html: str, max_results: int) -> list[dict]:
    """从 DuckDuckGo HTML 接口提取搜索结果。"""
    results = []
    # DDG HTML endpoint 结果块：<div class="result results_links results_links_deep web-result">
    # 标题/URL：<a class="result__a" href="...">Title</a>
    # 摘要：<a class="result__snippet">...</a>
    blocks = re.findall(
        r'<div[^>]+class="[^"]*result[^"]*web-result[^"]*"[^>]*>(.*?)</div>\s*</div>',
        html, re.S)
    if not blocks:
        # fallback: 直接匹配 result__a 链接
        links    = re.findall(r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>',
                              html, re.S)
        snippets = re.findall(r'class="result__snippet"[^>]*>(.*?)</a>', html, re.S)
        for i, (url, title) in enumerate(links[:max_results]):
            snippet = _strip_tags(snippets[i]) if i < len(snippets) else ""
            results.append({
                "title":   _strip_tags(title),
                "url":     url.strip(),
                "snippet": snippet,
            })
        return results

    for block in blocks[:max_results]:
        link_m = re.search(r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>',
                           block, re.S)
        snip_m = re.search(r'class="result__snippet"[^>]*>(.*?)</a>', block, re.S)
        if link_m:
            results.append({
                "title":   _strip_tags(link_m.group(2)),
                "url":     link_m.group(1).strip(),
                "snippet": _strip_tags(snip_m.group(1)) if snip_m else "",
            })
    return results


def _parse_bing(html: str, max_results: int) -> list[dict]:
    """从 Bing 的 HTML 里提取搜索结果。"""
    results = []
    # Bing 结果块：<li class="b_algo">
    blocks = re.findall(r'<li class="b_algo">(.*?)</li>', html, re.S)
    for block in blocks[:max_results]:
        title_m = re.search(r'<h2[^>]*>.*?<a[^>]*href="([^"]+)"[^>]*>(.*?)</a>', block, re.S)
        snip_m  = re.search(r'<p[^>]*>(.*?)</p>', block, re.S)
        if title_m:
            results.append({
                "title":   _strip_tags(title_m.group(2)),
                "url":     title_m.group(1).strip(),
                "snippet": _strip_tags(snip_m.group(1)) if snip_m else "",
            })
    return results


class HttpSearchExecutor:
    """基于 aiohttp 的纯 HTTP 搜索工具，不需要 playwright。

    search() 依次尝试 DuckDuckGo Lite → Bing，两者都失败时返回 error。
    """

    def __init__(self, config: dict = None):
        self.config = config or {}
        self._timeout = self.config.get("timeout", 10)

    async def search(self, query: str, max_results: int = 5) -> dict:
        """搜索并返回结果列表。

        Returns:
            {"success": bool, "query": str, "results": [{"title", "url", "snippet"}], ...}
        """
        if not _AIOHTTP_OK:
            return {"success": False, "error": "aiohttp 未安装，请执行: pip install aiohttp"}

        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        }
        timeout = aiohttp.ClientTimeout(total=self._timeout)

        engines = [
            ("DuckDuckGo",
             f"https://html.duckduckgo.com/html/?q={quote_plus(query)}",
             _parse_ddg_html),
            ("Bing",
             f"https://www.bing.com/search?q={quote_plus(query)}&setlang=zh-hans",
             _parse_bing),
        ]

        start = time.monotonic()
        last_error = ""

        # 跳过 SSL 验证（企业/代理环境常见自签名证书场景）
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(headers=headers, connector=connector) as session:
            for engine_name, url, parser in engines:
                try:
                    async with session.get(url, timeout=timeout,
                                           allow_redirects=True) as resp:
                        if resp.status != 200:
                            last_error = f"{engine_name} 返回 HTTP {resp.status}"
                            logger.warning("http_search_bad_status",
                                           engine=engine_name, status=resp.status)
                            continue
                        html = await resp.text(errors="replace")

                    results = parser(html, max_results)
                    if results:
                        logger.info("http_search_ok", engine=engine_name,
                                    query=query[:60], count=len(results))
                        return {
                            "success": True,
                            "query":   query,
                            "engine":  engine_name,
                            "results": results,
                            "execution_time": round(time.monotonic() - start, 3),
                        }
                    last_error = f"{engine_name} 未返回结果（可能触发验证码）"
                    logger.warning("http_search_no_results", engine=engine_name)

                except Exception as e:
                    last_error = f"{engine_name} 请求失败: {e}"
                    logger.warning("http_search_error", engine=engine_name, error=str(e))

        return {
            "success": False,
            "query":   query,
            "error":   last_error,
            "execution_time": round(time.monotonic() - start, 3),
        }
