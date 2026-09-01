# src/mcp/mcp_ser.py
import json
import logging
import os
from typing import Dict, Optional, Callable
from mcp.server import Server, NotificationOptions
from mcp.server.models import InitializationOptions
import mcp.server.stdio
import mcp.types as types

from deepagent.mcp.executors import (
    PythonExecutor,
    TerminalExecutor,
    BrowserExecutor,
    ProxyExecutor,
    KnowledgeExecutor,
)
from deepagent.mcp.executors.meta_executor import MetaToolExecutor
from deepagent.mcp.failure_attribution import FailureAttributor
from deepagent.mcp.anti_addiction import AntiAddictionGuard

logger = logging.getLogger(__name__)


def _default_dir_hint() -> str:
    """工具 schema 中展示的默认工作目录（与 TerminalExecutor 实际兜底一致）。"""
    return os.environ.get(
        "TERMINAL_DEFAULT_DIR",
        os.path.join(os.environ.get("TEMP", os.path.expanduser("~")), "tsecagent-sandbox")
        if os.name == "nt" else "/home/daytona",
    )


class MCPToolServer:
    """MCP 服务器 - Meta-Tooling 层核心"""

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.server = Server("mcp-tool-server")

        # 初始化执行器
        self.python_executor = PythonExecutor(config.get("python", {}))
        self.terminal_executor = TerminalExecutor(config.get("terminal", {}))
        self.browser_executor = BrowserExecutor(config.get("browser", {}))
        self.proxy_executor = ProxyExecutor(config.get("proxy", {}))
        self.knowledge_executor = KnowledgeExecutor(config.get("knowledge", {}))

        # 初始化辅助组件
        self.anti_addiction = AntiAddictionGuard()
        self.failure_attributor = FailureAttributor()

        # 注册所有工具
        self._register_tools()

        logger.info("MCP Tool Server initialized")

    def _register_tools(self):
        """注册所有工具到 MCP 服务器"""

        @self.server.list_tools()
        async def handle_list_tools() -> list[types.Tool]:
            """列出所有可用工具"""
            return [
                # Python 执行工具
                types.Tool(
                    name="execute_python",
                    description="Execute Python code in isolated sandbox",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "code": {"type": "string", "description": "Python code to execute"},
                            "timeout": {"type": "integer", "description": "Timeout in seconds", "default": 120},
                            "session_id": {"type": "string", "description": "Session ID to share state across calls"}
                        },
                        "required": ["code"]
                    }
                ),
                # Shell 命令工具
                types.Tool(
                    name="execute_shell",
                    description="Execute shell command in isolated terminal session",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "command": {"type": "string", "description": "Shell command to execute"},
                            "working_dir": {"type": "string", "description": "Working directory",
                                            "default": _default_dir_hint()},
                            "timeout": {"type": "integer", "description": "Timeout in seconds", "default": 300},
                            "session_id": {"type": "string", "description": "Session ID to persist CWD and env vars across calls"}
                        },
                        "required": ["command"]
                    }
                ),
                # 浏览器自动化工具
                types.Tool(
                    name="browser_navigate",
                    description="Navigate to URL using browser automation",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "url": {"type": "string", "description": "Target URL"},
                            "wait_ms": {"type": "integer", "description": "Wait milliseconds after load",
                                        "default": 2000},
                            "session_id": {"type": "string", "description": "Browser session ID (shares cookies/state)", "default": "default"}
                        },
                        "required": ["url"]
                    }
                ),
                types.Tool(
                    name="browser_execute_js",
                    description="Execute JavaScript in browser context",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "code": {"type": "string", "description": "JavaScript code to execute"},
                            "timeout": {"type": "integer", "description": "Timeout in seconds", "default": 30},
                            "session_id": {"type": "string", "description": "Browser session ID (shares cookies/state)", "default": "default"}
                        },
                        "required": ["code"]
                    }
                ),
                types.Tool(
                    name="browser_get_content",
                    description="Get full HTML source of current browser page",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "session_id": {"type": "string", "description": "Browser session ID", "default": "default"}
                        }
                    }
                ),
                types.Tool(
                    name="browser_screenshot",
                    description="Take a screenshot of the current browser page, returns base64 PNG",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "full_page": {"type": "boolean", "description": "Capture full scrollable page", "default": False},
                            "session_id": {"type": "string", "description": "Browser session ID", "default": "default"}
                        }
                    }
                ),
                # 代理流量工具
                types.Tool(
                    name="proxy_list_traffic",
                    description="List HTTP traffic captured by proxy (summary format)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "limit":       {"type": "integer", "description": "Maximum entries to return", "default": 50},
                            "filter_host": {"type": "string",  "description": "Filter by host substring, e.g. 'example.com'"}
                        }
                    }
                ),
                types.Tool(
                    name="proxy_get_flow",
                    description="Get full request/response details of a specific captured flow",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "flow_id": {"type": "string", "description": "Flow ID from proxy_list_traffic results"}
                        },
                        "required": ["flow_id"]
                    }
                ),
                types.Tool(
                    name="proxy_clear_traffic",
                    description="Clear all captured HTTP flows from the proxy",
                    inputSchema={
                        "type": "object",
                        "properties": {}
                    }
                ),
                types.Tool(
                    name="proxy_replay_flow",
                    description="Replay a captured HTTP request (useful for payload testing and vulnerability verification)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "flow_id": {"type": "string", "description": "Flow ID to replay"}
                        },
                        "required": ["flow_id"]
                    }
                ),
                # 知识库工具
                types.Tool(
                    name="knowledge_search",
                    description=(
                        "Search penetration testing knowledge base. "
                        "category options: "
                        "payloads/PayloadsAllTheThings (attack payloads & exploits), "
                        "howtohunt/HowToHunt (bug hunting methodology), "
                        "experience (past successful STE experiences), "
                        "general (general security knowledge), "
                        "task_memory (current task findings). "
                        "Leave category empty to search all sources."
                    ),
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "query":    {"type": "string",  "description": "Search query or natural language description"},
                            "category": {"type": "string",  "description": "Knowledge category (see description)"},
                            "limit":    {"type": "integer", "description": "Maximum results", "default": 5}
                        },
                        "required": ["query"]
                    }
                ),
                types.Tool(
                    name="knowledge_get_detail",
                    description="Get full content of a knowledge entry by its ID from search results",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "entry_id": {"type": "string", "description": "Entry ID from knowledge_search results"}
                        },
                        "required": ["entry_id"]
                    }
                ),
                types.Tool(
                    name="knowledge_save",
                    description=(
                        "Save a finding, experience, or insight to the dynamic knowledge base. "
                        "Use this to persist what you learned during the current task so future tasks can benefit."
                    ),
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "content":  {"type": "string", "description": "Knowledge content (Markdown supported)"},
                            "title":    {"type": "string", "description": "Short descriptive title"},
                            "category": {"type": "string", "description": "experience | general | task_memory", "default": "experience"},
                            "tags":     {"type": "array",  "items": {"type": "string"}, "description": "Optional tags for filtering"}
                        },
                        "required": ["content", "title"]
                    }
                ),
            ]

        @self.server.call_tool()
        async def handle_call_tool(
                name: str,
                arguments: dict
        ) -> list[types.TextContent]:
            """处理工具调用请求"""

            # 1. 防沉迷检查
            is_looping, warning = self.anti_addiction.check_and_record({
                "tool": name,
                "arguments": arguments
            })
            if is_looping:
                return [types.TextContent(
                    type="text",
                    text=warning
                )]

            # 2. 路由到对应执行器
            executor_map = {
                "execute_python": self._execute_python,
                "execute_shell": self._execute_shell,
                "browser_navigate": self._browser_navigate,
                "browser_execute_js": self._browser_execute_js,
                "browser_get_content": self._browser_get_content,
                "browser_screenshot": self._browser_screenshot,
                "proxy_list_traffic":  self._proxy_list_traffic,
                "proxy_get_flow":       self._proxy_get_flow,
                "proxy_clear_traffic":  self._proxy_clear_traffic,
                "proxy_replay_flow":    self._proxy_replay_flow,
                "knowledge_search": self._knowledge_search,
                "knowledge_get_detail": self._knowledge_get_detail,
                "knowledge_save": self._knowledge_save,
            }

            executor = executor_map.get(name)
            if not executor:
                return [types.TextContent(
                    type="text",
                    text=f"Unknown tool: {name}"
                )]

            # 3. 执行工具（带重试和超时）
            result = await self._execute_with_meta(executor, name, arguments)

            # 4. 失败归因（如果失败）
            if not result.get("success"):
                attribution = self.failure_attributor.attribute(
                    tool_name=name,
                    arguments=arguments,
                    error=result.get("error", ""),
                    output=result.get("output", "")
                )
                result["attribution"] = attribution

            # 5. 返回标准化结果
            return [types.TextContent(
                type="text",
                text=json.dumps(result, indent=2, ensure_ascii=False)
            )]

    async def _execute_with_meta(self, executor: Callable, tool_name: str, arguments: dict) -> dict:
        """使用 Meta-Tooling 层执行工具"""
        meta_executor = MetaToolExecutor({tool_name: executor})
        task = {"tool": tool_name, "arguments": arguments}
        return await meta_executor.execute(task)

    async def _execute_python(self, code: str, timeout: int = 120, session_id: str = None) -> dict:
        """执行 Python 代码"""
        return await self.python_executor.execute(code, timeout, session_id)

    async def _execute_shell(self, command: str, working_dir: str = None, timeout: int = 300, session_id: str = None) -> dict:
        """执行 Shell 命令"""
        return await self.terminal_executor.execute(command, working_dir, timeout, session_id)

    async def _browser_navigate(self, url: str, wait_ms: int = 2000, session_id: str = "default") -> dict:
        """浏览器导航"""
        return await self.browser_executor.navigate(url, wait_ms, session_id)

    async def _browser_execute_js(self, code: str = None, script: str = None, timeout: int = 30, session_id: str = "default") -> dict:
        """执行 JavaScript"""
        return await self.browser_executor.execute_js(code=code, script=script, timeout=timeout, session_id=session_id)

    async def _browser_get_content(self, session_id: str = "default") -> dict:
        """获取页面 HTML 源码"""
        return await self.browser_executor.get_content(session_id)

    async def _browser_screenshot(self, full_page: bool = False, session_id: str = "default") -> dict:
        """截图当前页面"""
        return await self.browser_executor.screenshot(full_page, session_id)

    async def _proxy_list_traffic(self, limit: int = 50, filter_host: str = None) -> dict:
        """列出代理流量"""
        return await self.proxy_executor.list_traffic(limit, filter_host)

    async def _proxy_get_flow(self, flow_id: str) -> dict:
        """获取单条 flow 完整详情"""
        return await self.proxy_executor.get_flow(flow_id)

    async def _proxy_clear_traffic(self) -> dict:
        """清空所有已捕获的流量"""
        return await self.proxy_executor.clear_traffic()

    async def _proxy_replay_flow(self, flow_id: str) -> dict:
        """重放指定请求"""
        return await self.proxy_executor.replay_flow(flow_id)

    async def _knowledge_search(self, query: str, category: str = None, limit: int = 5) -> dict:
        """搜索知识库"""
        return await self.knowledge_executor.search(query, category, limit)

    async def _knowledge_get_detail(self, entry_id: str) -> dict:
        """获取知识条目详情"""
        return await self.knowledge_executor.get_detail(entry_id)

    async def _knowledge_save(self, content: str, title: str = "", category: str = "experience", tags: list = None) -> dict:
        """保存知识到动态知识库"""
        return await self.knowledge_executor.save(content, title, category, tags)

    async def run(self):
        """启动 MCP 服务器"""
        async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="mcp-tool-server",
                    server_version="1.0.0",
                    capabilities=self.server.get_capabilities(
                        notification_options=NotificationOptions(),
                        experimental_capabilities={},
                    ),
                ),
            )