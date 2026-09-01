# src/mcp/executors/BrowserExecutor.py
import asyncio
import base64
import time
from typing import Optional, Dict
import structlog

logger = structlog.get_logger(__name__)

try:
    from playwright.async_api import (
        async_playwright,
        Browser,
        BrowserContext,
        Page,
        Playwright,
    )
    _PLAYWRIGHT_AVAILABLE = True
except ImportError:
    _PLAYWRIGHT_AVAILABLE = False
    logger.warning(
        "playwright_not_installed",
        hint="pip install playwright && playwright install chromium",
    )


class BrowserSession:
    """单浏览器上下文，隔离 Cookie / Storage，跨调用保留登录态。

    每个 session_id 对应一个独立的 BrowserContext + Page，互不影响。
    """

    def __init__(self, context: "BrowserContext", page: "Page"):
        self.context = context
        self.page = page


class BrowserExecutor:
    """浏览器自动化执行器 - 基于 Playwright 封装

    双模式运行（通过 config 配置自动选择）：

    ┌─ CDP 模式（无代理）──────────────────────────────────────────────────┐
    │  config["cdp_url"] = "http://localhost:9222"                         │
    │  连接已有 Chrome/Chromium 实例，浏览器网络配置由宿主管理。           │
    │  适用：本地调试、需要保留用户登录态等场景。                          │
    └──────────────────────────────────────────────────────────────────────┘

    ┌─ Playwright 模式（可配置代理）──────────────────────────────────────┐
    │  未设置 cdp_url 时自动启动 headless Chromium。                       │
    │  config["proxy"] = {"server": "http://127.0.0.1:8080"}              │
    │  将全部流量导入 HTTP 代理（与 Caido / mitmproxy 联动抓包）。        │
    └──────────────────────────────────────────────────────────────────────┘

    Session 说明：
      每个 session_id 对应独立的 BrowserContext，Cookie / localStorage 完全隔离。
      navigate / execute_js / screenshot 共享同一 session 的页面状态。
    """

    def __init__(self, config: dict = None):
        self.config = config or {}
        self._playwright: Optional["Playwright"] = None
        self._browser: Optional["Browser"] = None
        self._sessions: Dict[str, BrowserSession] = {}
        self._browser_lock = asyncio.Lock()
        self._session_lock = asyncio.Lock()
        # 确定运行模式
        self._cdp_url: Optional[str] = self.config.get("cdp_url")
        self._operating_mode = "cdp" if self._cdp_url else "playwright"

    @property
    def operating_mode(self) -> str:
        """返回当前运行模式：'cdp' 或 'playwright'。"""
        return self._operating_mode

    # ------------------------------------------------------------------
    # 浏览器 / 会话生命周期
    # ------------------------------------------------------------------

    async def _ensure_browser(self):
        """延迟初始化浏览器实例，线程安全。"""
        async with self._browser_lock:
            if self._browser is not None and self._browser.is_connected():
                return

            if not _PLAYWRIGHT_AVAILABLE:
                raise RuntimeError(
                    "playwright 未安装，请执行: pip install playwright && playwright install chromium"
                )

            if self._playwright is None:
                self._playwright = await async_playwright().start()

            cdp_url = self._cdp_url
            if cdp_url:
                # CDP 模式：连接已有 Chrome 实例
                self._browser = await self._playwright.chromium.connect_over_cdp(cdp_url)
                logger.info("browser_cdp_connected", url=cdp_url)
            else:
                # Playwright 模式：启动独立 Chromium，可配置 HTTP 代理
                self._browser = await self._playwright.chromium.launch(
                    headless=self.config.get("headless", True),
                    args=[
                        "--no-sandbox",
                        "--disable-setuid-sandbox",
                        "--disable-dev-shm-usage",
                        "--ignore-certificate-errors",          # 信任代理自签证书（Caido/mitmproxy）
                        "--ignore-certificate-errors-spki-list",
                    ],
                    proxy=self.config.get("proxy"),
                )
                logger.info("browser_launched", headless=self.config.get("headless", True))

    async def _get_session(self, session_id: str) -> BrowserSession:
        """获取或创建指定会话，double-check 防并发重复创建。"""
        if session_id in self._sessions:
            return self._sessions[session_id]

        async with self._session_lock:
            if session_id not in self._sessions:
                await self._ensure_browser()
                context = await self._browser.new_context(
                    viewport={"width": 1280, "height": 720},
                    ignore_https_errors=self.config.get("ignore_https_errors", True),
                    user_agent=self.config.get("user_agent"),
                )
                page = await context.new_page()
                self._sessions[session_id] = BrowserSession(context, page)
                logger.info("browser_session_created", session_id=session_id)

        return self._sessions[session_id]

    async def close_session(self, session_id: str) -> bool:
        """关闭并销毁指定会话（清除 Cookie / Storage）。"""
        async with self._session_lock:
            if session_id in self._sessions:
                sess = self._sessions.pop(session_id)
                await sess.context.close()
                logger.info("browser_session_closed", session_id=session_id)
                return True
        return False

    async def close(self):
        """关闭所有会话及浏览器实例。"""
        for session_id in list(self._sessions.keys()):
            await self.close_session(session_id)
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()

    # ------------------------------------------------------------------
    # 工具方法
    # ------------------------------------------------------------------

    async def navigate(self, url: str, wait_ms: int = 2000, session_id: str = "default") -> dict:
        """导航到 URL，等待 DOMContentLoaded 后额外等待 wait_ms 毫秒。

        代理模式下若返回 502/503 或连接失败，自动降级为无代理直连会话重试。

        Returns:
            {"success": bool, "url": str, "status": int, "title": str, "execution_time": float}
        """
        start = time.monotonic()
        try:
            sess = await self._get_session(session_id)
            response = await sess.page.goto(url, wait_until="domcontentloaded", timeout=20_000)
            if wait_ms > 0:
                await sess.page.wait_for_timeout(wait_ms)
            status = response.status if response else None
            # 代理返回 502/503 时降级到无代理直连
            if status in (502, 503) and self.config.get("proxy"):
                logger.warning("browser_proxy_bad_gateway", status=status, url=url, hint="fallback to direct")
                return await self._navigate_direct(url, wait_ms, start)
            return {
                "success": True,
                "url": sess.page.url,
                "status": status,
                "title": await sess.page.title(),
                "execution_time": round(time.monotonic() - start, 4),
            }
        except Exception as e:
            err = str(e)
            logger.warning("browser_navigate_error", url=url, error=err)
            # 代理连接失败时降级到无代理直连
            if self.config.get("proxy") and any(k in err for k in ("PROXY", "ERR_TOO_MANY_RETRIES", "ERR_TUNNEL")):
                logger.warning("browser_proxy_failed", url=url, hint="fallback to direct")
                return await self._navigate_direct(url, wait_ms, start)
            return {
                "success": False,
                "error": err,
                "execution_time": round(time.monotonic() - start, 4),
            }

    async def _navigate_direct(self, url: str, wait_ms: int, start: float) -> dict:
        """无代理直连会话（降级专用），使用独立 session_id 避免污染主会话。"""
        _DIRECT_SID = "__direct_fallback__"
        try:
            # 临时创建无代理 context（覆盖 proxy 配置）
            await self._ensure_browser()
            async with self._session_lock:
                if _DIRECT_SID not in self._sessions:
                    context = await self._browser.new_context(
                        viewport={"width": 1280, "height": 720},
                        ignore_https_errors=True,
                        proxy=None,  # 强制无代理
                    )
                    page = await context.new_page()
                    self._sessions[_DIRECT_SID] = BrowserSession(context, page)
            sess = self._sessions[_DIRECT_SID]
            response = await sess.page.goto(url, wait_until="domcontentloaded", timeout=20_000)
            if wait_ms > 0:
                await sess.page.wait_for_timeout(wait_ms)
            return {
                "success": True,
                "url": sess.page.url,
                "status": response.status if response else None,
                "title": await sess.page.title(),
                "execution_time": round(time.monotonic() - start, 4),
                "note": "proxy unavailable, used direct connection",
            }
        except Exception as e2:
            return {
                "success": False,
                "error": str(e2),
                "execution_time": round(time.monotonic() - start, 4),
            }

    async def execute_js(self, code: str = None, script: str = None, timeout: int = 30, session_id: str = "default") -> dict:
        """在当前页面上下文中执行 JavaScript，返回执行结果。

        参数 code 和 script 均接受（兼容 LLM 的不同命名习惯）。
        含 return 语句时包成箭头函数，Playwright evaluate 会自动调用它。

        Returns:
            {"success": bool, "result": Any, "url": str, "execution_time": float}
        """
        js = code or script
        if not js:
            return {"success": False, "error": "missing argument: code or script required"}
        start = time.monotonic()
        # 含 return 语句时包成箭头函数，Playwright evaluate 会自动调用它
        import re as _re
        if _re.search(r'\breturn\b', js):
            js = f"() => {{\n{js}\n}}"
        try:
            sess = await self._get_session(session_id)
            result = await asyncio.wait_for(
                sess.page.evaluate(js),
                timeout=timeout,
            )
            return {
                "success": True,
                "result": result,
                "url": sess.page.url,
                "execution_time": round(time.monotonic() - start, 4),
            }
        except asyncio.TimeoutError:
            return {
                "success": False,
                "error": f"JavaScript execution timed out after {timeout} seconds",
                "execution_time": round(time.monotonic() - start, 4),
            }
        except Exception as e:
            logger.warning("browser_execute_js_error", error=str(e))
            error_str = str(e)
            extra = {}
            # 对 DOM 方法不存在的错误，尝试获取页面上下文信息
            if "is not a function" in error_str and "submit" in error_str:
                try:
                    form_count = await sess.page.eval_on_selector_all("form", "els => els.length")
                    extra["hint"] = f"页面中共有 {form_count} 个 <form> 元素，目标元素可能不是 form 或不支持 .submit()。请检查 selector 是否指向了正确的元素类型。"
                except Exception:
                    extra["hint"] = "无法获取页面 form 信息，请检查目标元素类型是否支持该操作。"
            return {
                "success": False,
                "error": error_str,
                "url": sess.page.url if 'sess' in locals() else None,
                "execution_time": round(time.monotonic() - start, 4),
                **extra,
            }

    async def get_content(self, session_id: str = "default") -> dict:
        """获取当前页面的完整 HTML 源码。

        Returns:
            {"success": bool, "url": str, "content": str}
        """
        try:
            sess = await self._get_session(session_id)
            return {
                "success": True,
                "url": sess.page.url,
                "content": await sess.page.content(),
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def screenshot(self, full_page: bool = False, session_id: str = "default") -> dict:
        """截图当前页面，返回 base64 编码的 PNG 图像。

        Returns:
            {"success": bool, "url": str, "image_base64": str}
        """
        try:
            sess = await self._get_session(session_id)
            screenshot_bytes = await sess.page.screenshot(type="png", full_page=full_page)
            return {
                "success": True,
                "url": sess.page.url,
                "image_base64": base64.b64encode(screenshot_bytes).decode(),
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
