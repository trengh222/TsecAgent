#!/usr/bin/env python3
"""
DeepAgent MCP 服务器启动脚本

用法:
    python run_server.py               # 使用 .env 配置启动
    python run_server.py --debug       # 启用 DEBUG 日志
    python run_server.py --print-config  # 打印当前配置后退出

MCP stdio 模式说明:
    服务器通过 stdin/stdout 与 MCP 客户端通信，
    所有日志必须输出到 stderr，避免污染协议流。
"""

import argparse
import asyncio
import logging
import sys
import os

# 确保项目根目录在 Python 路径中
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import structlog
from deepagent.mcp.config import load_config
from deepagent.mcp.mcp_ser import MCPToolServer

def setup_logging(debug: bool = False) -> None:
    """配置 structlog + 标准库 logging，日志全部输出到 stderr。"""
    level = logging.DEBUG if debug else logging.INFO

    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        level=level,
        stream=sys.stderr,  # MCP stdio 模式：日志必须走 stderr
    )

    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S"),
            structlog.dev.ConsoleRenderer(colors=False),  # stderr 不一定支持颜色
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def print_config(config: dict) -> None:
    """打印当前生效配置（隐藏敏感字段）。"""
    import json

    safe = {}
    for section, values in config.items():
        if not isinstance(values, dict):
            safe[section] = values
            continue
        safe_values = {}
        for k, v in values.items():
            if any(word in k.lower() for word in ("token", "key", "secret", "password")):
                safe_values[k] = "***"
            else:
                safe_values[k] = v
        safe[section] = safe_values

    print(json.dumps(safe, indent=2, ensure_ascii=False))


async def main() -> None:
    parser = argparse.ArgumentParser(
        description="DeepAgent MCP Tool Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--debug", action="store_true", help="启用 DEBUG 日志")
    parser.add_argument("--print-config", action="store_true", help="打印当前配置后退出")
    args = parser.parse_args()

    setup_logging(debug=args.debug)
    logger = structlog.get_logger(__name__)

    config = load_config()

    if args.print_config:
        print_config(config)
        return

    logger.info(
        "deepagent_mcp_server_starting",
        browser_mode="cdp" if config["browser"].get("cdp_url") else "local",
        browser_headless=config["browser"].get("headless"),
        python_timeout=config["python"].get("default_timeout"),
    )

    try:
        server = MCPToolServer(config)
        await server.run()
    except KeyboardInterrupt:
        logger.info("deepagent_mcp_server_stopped")
    except Exception as e:
        logger.error("deepagent_mcp_server_error", error=str(e))
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
