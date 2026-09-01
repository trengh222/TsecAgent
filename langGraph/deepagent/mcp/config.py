# src/mcp/config.py
"""MCP 服务器配置加载器

优先级（高 → 低）：环境变量 > .env 文件 > 默认值

使用方式：
    from deepagent.mcp.config import load_config
    from deepagent.mcp.mcp_ser import MCPToolServer

    server = MCPToolServer(load_config())
"""

import os
import sys
import tempfile
from typing import Any, Dict, Optional

# 可选依赖：python-dotenv（pip install python-dotenv）
try:
    from dotenv import load_dotenv
    load_dotenv()  # 自动加载项目根目录的 .env 文件
except ImportError:
    pass  # 未安装时直接读系统环境变量


def _bool(val: Optional[str], default: bool) -> bool:
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes")


def _int(val: Optional[str], default: int) -> int:
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


def _proxy(server: Optional[str]) -> Optional[Dict[str, str]]:
    """将 'http://host:port' 转换为 Playwright proxy dict。"""
    if not server:
        return None
    return {"server": server}


def _default_terminal_dir() -> str:
    """平台默认终端工作目录：Windows 用专用沙箱目录，POSIX 保持原值。"""
    if sys.platform == "win32":
        sandbox = os.path.join(tempfile.gettempdir(), "tsecagent-sandbox")
        try:
            os.makedirs(sandbox, exist_ok=True)
        except OSError:
            pass
        return sandbox
    return "/home/daytona"


def load_config() -> Dict[str, Any]:
    """从环境变量构建 MCPToolServer 所需的配置字典。

    环境变量列表
    ─────────────────────────────────────────────────
    Python 执行器
      PYTHON_DEFAULT_TIMEOUT   默认超时（秒），默认 30
      PYTHON_MAX_TIMEOUT       最大超时（秒），默认 120

    Terminal 执行器
      TERMINAL_DEFAULT_DIR     默认工作目录，Windows 默认 %TEMP%\tsecagent-sandbox，
                               POSIX 默认 /home/daytona

    Browser 执行器
      BROWSER_HEADLESS         是否无头模式，默认 true
      BROWSER_CDP_URL          CDP 连接地址，如 http://localhost:9222
                               （设置后忽略 BROWSER_HEADLESS）
      BROWSER_PROXY            代理地址，如 http://127.0.0.1:8080
                               （与 BurpSuite / mitmproxy 联动）
      BROWSER_IGNORE_HTTPS     是否忽略 HTTPS 错误，默认 true
      BROWSER_USER_AGENT       自定义 User-Agent

    Proxy 执行器（Caido）
      PROXY_CAIDO_URL    Caido 地址，默认 http://127.0.0.1:8080
      PROXY_CAIDO_TOKEN  Caido API 令牌（Caido → Settings → API → Generate Token）

    Knowledge 后端
      OPENVIKING_ENABLED       是否启用 OpenViking，默认 false
      OPENVIKING_DATA_PATH     数据目录，默认 ~/.openviking/data
      OPENVIKING_CONFIG_FILE   配置文件路径，默认自动查找 ~/.openviking/ov.conf
      CHROMA_PATH              ChromaDB 持久化路径，默认 ./data/chroma
      EMBEDDING_MODEL          嵌入模型，默认 default（ChromaDB 内置 ONNX，无需 API Key）
                               可选：text-embedding-3-small（OpenAI）
                                     all-MiniLM-L6-v2（sentence-transformers）
    ─────────────────────────────────────────────────
    """
    return {
        "python": {
            "default_timeout": _int(os.getenv("PYTHON_DEFAULT_TIMEOUT"), 30),
            "max_timeout":     _int(os.getenv("PYTHON_MAX_TIMEOUT"), 120),
        },
        "terminal": {
            "default_dir": os.getenv("TERMINAL_DEFAULT_DIR") or _default_terminal_dir(),
        },
        "browser": {
            "headless":            _bool(os.getenv("BROWSER_HEADLESS"), True),
            "cdp_url":             os.getenv("BROWSER_CDP_URL"),
            "proxy":               _proxy(os.getenv("BROWSER_PROXY")),
            "ignore_https_errors": _bool(os.getenv("BROWSER_IGNORE_HTTPS"), True),
            "user_agent":          os.getenv("BROWSER_USER_AGENT"),
        },
        "proxy": {
            "caido_url":   os.getenv("PROXY_CAIDO_URL",   "http://127.0.0.1:8080"),
            "caido_token": os.getenv("PROXY_CAIDO_TOKEN"),
        },
        "recon": {
            "fofa_email": os.getenv("FOFA_EMAIL", ""),
            "fofa_key":   os.getenv("FOFA_API_KEY", ""),
            "quake_token": os.getenv("QUAKE_TOKEN", ""),
        },
        "knowledge": {
            "viking_enabled":     _bool(os.getenv("OPENVIKING_ENABLED"), False),
            "viking_path":        os.getenv("OPENVIKING_DATA_PATH",    "~/.openviking/data"),
            "viking_config_file": os.getenv("OPENVIKING_CONFIG_FILE"),   # None → 自动查找
            "chroma_path":        os.getenv("CHROMA_PATH",             "./data/chroma"),
            "embedding_model":    os.getenv("EMBEDDING_MODEL",         "default"),
        },
    }
