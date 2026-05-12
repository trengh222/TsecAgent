# src/mcp/executors/ReconExecutor.py
"""
侦察执行器 - 资产测绘、指纹识别、工作流编排

保留功能：
  fingerprint_scan         — Web 指纹识别（webtech / HTTP 探测）
  cyberspace_search        — FOFA / Quake 网络空间测绘
  smart_directory_scan     — 基于指纹的智能字典目录扫描
  run_recon_workflow       — 一键侦察工作流（编排各子模块）

子模块（独立文件）：
  PortScanner.py      — nmap 端口扫描
  DirectoryScanner.py — gobuster / ffuf 目录扫描
  JSAnalyzer.py       — JS 端点 & 敏感信息提取
  AuthBypassFuzzer.py — 鉴权绕过 Fuzz

API 密钥（.env）：
  FOFA_EMAIL / FOFA_API_KEY   — FOFA 网络空间测绘
  QUAKE_TOKEN                 — Quake 360 网络空间测绘

Python 依赖：
  pip install httpx webtech
"""

import asyncio
import base64
import time
from typing import Optional, List

import structlog

from .PortScanner import PortScanner
from .DirectoryScanner import DirectoryScanner
from .JSAnalyzer import JSAnalyzer
from .AuthBypassFuzzer import AuthBypassFuzzer

logger = structlog.get_logger(__name__)

try:
    import httpx
    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False

_TECH_SIGNATURES = [
    ("WordPress",  "wp-content"),
    ("Drupal",     "drupal"),
    ("Joomla",     "joomla"),
    ("Laravel",    "laravel"),
    ("Django",     "csrfmiddlewaretoken"),
    ("React",      "react.production"),
    ("Vue.js",     "vue.js"),
    ("Angular",    "ng-version"),
    ("jQuery",     "jquery"),
    ("Bootstrap",  "bootstrap.min"),
    ("Nginx",      "nginx"),
    ("Apache",     "apache"),
    ("Cloudflare", "cloudflare"),
]

# 技术栈 → 推荐字典关键字（按优先级排列，取前 max_wordlists 个可用字典）
_TECH_WORDLIST_MAP = {
    "java":        ["java", "java_path", "webshell", "jndi"],
    "java/tomcat": ["java", "java_path", "webshell"],
    "tomcat":      ["java", "java_path", "webshell"],
    "spring":      ["java", "java_path"],
    "struts":      ["java", "java_path"],
    "php":         ["webshell", "common"],
    "asp.net":     ["webshell", "viewstate", "common"],
    "iis":         ["webshell", "viewstate", "common"],
    "django":      ["ssti", "common"],
    "flask":       ["ssti", "common"],
    "laravel":     ["webshell", "common"],
    "angular":     ["angular", "common"],
    "wordpress":   ["common", "webshell"],
    "drupal":      ["common", "webshell"],
    "joomla":      ["common", "webshell"],
    "cloudflare":  ["cloud", "common"],
    "nginx":       ["common", "webshell"],
    "apache":      ["common", "webshell"],
}


def _select_wordlists(technologies: List[str], max_wordlists: int = 2) -> List[str]:
    """根据检测到的技术栈选择最匹配的字典关键字列表（去重，保序）。"""
    selected = []
    seen = set()
    tech_lower = [t.lower() for t in technologies]

    for tech in tech_lower:
        # 精确匹配或部分匹配
        for key, wordlists in _TECH_WORDLIST_MAP.items():
            if key in tech or tech in key:
                for w in wordlists:
                    if w not in seen:
                        seen.add(w)
                        selected.append(w)

    # 若未匹配任何技术，使用通用字典
    if not selected:
        selected = ["webshell", "common"]

    return selected[:max_wordlists]


def _detect_technologies(resp) -> list[str]:
    techs   = []
    headers = {k.lower(): v for k, v in resp.headers.items()}
    body    = resp.text[:5000].lower()
    if server := headers.get("server"):
        techs.append(f"Server:{server}")
    if powered := headers.get("x-powered-by"):
        techs.append(f"X-Powered-By:{powered}")
    for name, sig in _TECH_SIGNATURES:
        if sig.lower() in body or sig.lower() in str(headers):
            techs.append(name)
    cookie = headers.get("set-cookie", "").lower()
    if "phpsessid"  in cookie: techs.append("PHP")
    if "jsessionid" in cookie: techs.append("Java/Tomcat")
    if "asp.net"    in cookie: techs.append("ASP.NET")
    return list(dict.fromkeys(techs))


# ─────────────────────────────────────────────────────────────────────────────
# ReconExecutor
# ─────────────────────────────────────────────────────────────────────────────

class ReconExecutor:
    """侦察执行器：资产测绘、指纹识别、工作流编排。

    方法速览：
      fingerprint_scan(url)                         → Web 指纹识别
      cyberspace_search(query, engine, size, page)  → FOFA/Quake 空间测绘
      run_recon_workflow(target, options)            → 一键侦察工作流
    """

    def __init__(self, config: dict = None):
        self.config       = config or {}
        self.port_scanner = PortScanner(config)
        self.dir_scanner  = DirectoryScanner(config)
        self.js_analyzer  = JSAnalyzer(config)
        self.auth_fuzzer  = AuthBypassFuzzer(config)

    def _http_client(self, timeout: float = 15.0) -> "httpx.AsyncClient":
        return httpx.AsyncClient(
            timeout=timeout,
            verify=False,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; DeepAgent/1.0)"},
        )

    # ── 指纹识别 ──────────────────────────────────────────

    async def fingerprint_scan(self, url: str) -> dict:
        """识别 Web 技术栈（CMS、框架、服务器、WAF 等）。

        优先使用 Python webtech 库（pip install webtech），
        未安装时退回 HTTP 响应头轻量探测。

        Returns:
            {"success", "tool", "url", "technologies": [...], "headers": {...}, "elapsed"}
        """
        start = time.monotonic()

        # ── webtech 模式（优先）──────────────────────────────
        try:
            import webtech as _webtech

            def _run() -> dict:
                wt = _webtech.WebTech(options={"json": True})
                return wt.start_from_url(url)

            loop   = asyncio.get_event_loop()
            report = await loop.run_in_executor(None, _run)

            techs = []
            for t in report.get("tech", []):
                name = t.get("name", "")
                ver  = t.get("version", "")
                techs.append(f"{name} {ver}".strip() if ver else name)

            headers_raw = report.get("headers", [])
            return {
                "success":      True,
                "tool":         "webtech",
                "url":          url,
                "technologies": techs,
                "headers":      {h["name"]: h["value"] for h in headers_raw},
                "elapsed":      round(time.monotonic() - start, 2),
            }

        except ImportError:
            logger.debug("webtech_not_installed", hint="pip install webtech")
        except Exception as e:
            logger.warning("webtech_error", url=url, error=str(e))

        # ── HTTP 轻量探测（兜底）────────────────────────────
        if not _HTTPX_AVAILABLE:
            return {"success": False, "error": "httpx / webtech 均未安装"}
        try:
            async with self._http_client() as client:
                resp = await client.get(url)
            return {
                "success":      True,
                "tool":         "http_probe",
                "url":          str(resp.url),
                "status":       resp.status_code,
                "server":       resp.headers.get("server", ""),
                "technologies": _detect_technologies(resp),
                "headers":      dict(resp.headers),
                "elapsed":      round(time.monotonic() - start, 2),
            }
        except Exception as e:
            return {"success": False, "error": str(e), "url": url}

    # ── 网络空间测绘 ──────────────────────────────────────

    async def cyberspace_search(
        self, query: str, engine: str = "fofa", size: int = 20, page: int = 1
    ) -> dict:
        """FOFA / Quake 网络空间搜索，查询互联网暴露资产。

        Args:
            query:  搜索语法，如 'domain="example.com"'（FOFA）
            engine: "fofa" 或 "quake"
            size:   返回条数（最大 100）
            page:   FOFA 分页

        Returns:
            {"success", "engine", "query", "total", "results": [...]}
        """
        if not _HTTPX_AVAILABLE:
            return {"success": False, "error": "httpx 未安装: pip install httpx"}
        engine = engine.lower()
        if engine == "fofa":
            return await self._search_fofa(query, page, size)
        if engine == "quake":
            return await self._search_quake(query, size)
        return {"success": False, "error": f"未知引擎 {engine}，支持 fofa / quake"}

    async def _search_fofa(self, query: str, page: int, size: int) -> dict:
        email = self.config.get("fofa_email", "")
        key   = self.config.get("fofa_key", "")
        if not email or not key:
            return {"success": False,
                    "error": "FOFA 未配置，请在 .env 中设置 FOFA_EMAIL / FOFA_API_KEY"}
        params = {
            "email": email, "key": key,
            "qbase64": base64.b64encode(query.encode()).decode(),
            "fields": "ip,port,domain,title,protocol,country,org",
            "page": page, "size": min(size, 100),
        }
        try:
            async with self._http_client(30) as client:
                resp = await client.get("https://fofa.info/api/v1/search/all", params=params)
                data = resp.json()
            if data.get("error"):
                return {"success": False, "error": data.get("errmsg", str(data))}
            fields  = data.get("fields", [])
            results = [dict(zip(fields, row)) for row in data.get("results", [])]
            return {"success": True, "engine": "fofa", "query": query,
                    "total": data.get("size", len(results)), "results": results}
        except Exception as e:
            return {"success": False, "error": str(e), "engine": "fofa"}

    async def _search_quake(self, query: str, size: int) -> dict:
        token = self.config.get("quake_token", "")
        if not token:
            return {"success": False, "error": "Quake 未配置，请在 .env 中设置 QUAKE_TOKEN"}
        try:
            async with self._http_client(30) as client:
                resp = await client.post(
                    "https://quake.360.net/api/v3/search/quake_service",
                    headers={"X-QuakeToken": token},
                    json={"query": query, "start": 0,
                          "size": min(size, 100), "ignore_cache": False},
                )
                data = resp.json()
            if data.get("code") != 0:
                return {"success": False, "error": data.get("message", str(data))}
            results = []
            for item in data.get("data", []):
                svc = item.get("service", {})
                loc = item.get("location", {})
                results.append({
                    "ip":      item.get("ip", ""),
                    "port":    svc.get("port", ""),
                    "domain":  ",".join(item.get("domain", [])),
                    "title":   svc.get("http", {}).get("title", ""),
                    "service": svc.get("name", ""),
                    "country": loc.get("country_cn", ""),
                })
            return {
                "success": True, "engine": "quake", "query": query,
                "total":   data.get("meta", {}).get("pagination", {}).get("total", len(results)),
                "results": results,
            }
        except Exception as e:
            return {"success": False, "error": str(e), "engine": "quake"}

    # ── 智能字典扫描 ──────────────────────────────────────

    async def smart_directory_scan(
        self,
        url: str,
        technologies: Optional[List[str]] = None,
        max_wordlists: int = 2,
        threads: int = 10,
    ) -> dict:
        """根据目标技术栈自动选择字典，执行目录扫描。

        流程：
          1. 若未提供 technologies，先运行指纹识别获取技术栈
          2. 根据 _TECH_WORDLIST_MAP 匹配最优字典
          3. 依次使用每个字典运行 directory_scan，合并去重结果

        Args:
            url:           目标 URL
            technologies:  已知技术栈列表（如 ["PHP","Apache"]）；
                           为空时自动指纹识别
            max_wordlists: 最多使用几个字典（默认 2）
            threads:       并发线程数

        Returns:
            {"success", "url", "technologies", "wordlists_used",
             "found": [...], "total", "elapsed", "scans": [...]}
        """
        start = time.monotonic()

        # Step 1: 指纹识别
        if not technologies:
            fp = await self.fingerprint_scan(url)
            technologies = fp.get("technologies", [])
            logger.info("smart_scan_fingerprint", url=url, technologies=technologies)

        # Step 2: 选择字典
        wordlist_keys = _select_wordlists(technologies, max_wordlists)
        logger.info("smart_scan_wordlists", url=url, wordlists=wordlist_keys)

        # Step 3: 依次扫描并合并
        all_found: list = []
        seen_paths: set = set()
        scans: list = []

        for wl_key in wordlist_keys:
            result = await self.dir_scanner.scan(url, wordlist=wl_key, threads=threads)
            scans.append({
                "wordlist": wl_key,
                "success": result.get("success"),
                "total": result.get("total", 0),
                "tool": result.get("tool", ""),
            })
            for item in result.get("found", []):
                path = item.get("path", "")
                if path and path not in seen_paths:
                    seen_paths.add(path)
                    all_found.append(item)

        elapsed = round(time.monotonic() - start, 2)
        logger.info("smart_scan_done", url=url, total=len(all_found), elapsed=elapsed)
        return {
            "success": True,
            "url": url,
            "technologies": technologies,
            "wordlists_used": wordlist_keys,
            "found": all_found,
            "total": len(all_found),
            "elapsed": elapsed,
            "scans": scans,
        }

    # ── 工作流编排 ────────────────────────────────────────

    async def run_recon_workflow(self, target: str, options: Optional[dict] = None) -> dict:
        """一键执行完整侦察工作流。

        流程：端口扫描 → 指纹识别 → 目录扫描 → JS 分析

        Args:
            target:  目标域名或 IP（不含协议）
            options: 可选参数
                       scheme      "http" 或 "https"，默认 "https"
                       ports       端口范围，默认 "1-1000"
                       wordlist    目录词表，默认 "common"
                       threads     扫描线程数，默认 10
                       skip        跳过的步骤列表，如 ["port_scan", "js_analysis"]

        Returns:
            {"success", "target", "elapsed",
             "steps": {"port_scan","fingerprint","directory_scan","js_analysis"}}
        """
        opts     = options or {}
        scheme   = opts.get("scheme", "https")
        skip     = set(opts.get("skip", []))
        base_url = f"{scheme}://{target}"
        steps: dict = {}
        start = time.monotonic()
        logger.info("recon_workflow_start", target=target)

        if "port_scan" not in skip:
            steps["port_scan"] = await self.port_scanner.scan(
                target, ports=opts.get("ports", "1-1000")
            )
        if "fingerprint" not in skip:
            steps["fingerprint"] = await self.fingerprint_scan(base_url)
        if "directory_scan" not in skip:
            steps["directory_scan"] = await self.dir_scanner.scan(
                base_url,
                wordlist=opts.get("wordlist", "common"),
                threads=opts.get("threads", 10),
            )
        if "js_analysis" not in skip:
            steps["js_analysis"] = await self.js_analyzer.analyze(base_url)

        elapsed = round(time.monotonic() - start, 2)
        logger.info("recon_workflow_done", target=target, elapsed=elapsed)
        return {"success": True, "target": target, "elapsed": elapsed, "steps": steps}

    # ── 代理方法（直接委托子模块，供 mcp_ser.py 统一注册）────────────

    async def port_scan(self, target: str, ports: str = "1-1000", timeout: int = 300) -> dict:
        return await self.port_scanner.scan(target, ports, timeout)

    async def directory_scan(self, url: str, wordlist: str = "common", threads: int = 10) -> dict:
        return await self.dir_scanner.scan(url, wordlist, threads)

    async def analyze_js(self, url: str, max_scripts: int = 10) -> dict:
        return await self.js_analyzer.analyze(url, max_scripts)

    async def fuzz_auth_bypass(
        self, url: str, method: str = "GET",
        data: Optional[dict] = None, headers: Optional[dict] = None,
    ) -> dict:
        return await self.auth_fuzzer.fuzz(url, method, data, headers)
