# src/agent/tools.py
import asyncio
from tenacity import retry, stop_after_attempt, wait_exponential_jitter, retry_if_exception_type
from typing import Any


class MetaToolExecutor:
    def __init__(self, tools: dict):
        self.tools = tools  # 所有可用工具的字典 {"tool_name": tool_function}

    async def execute(self, task: dict) -> dict:
        tool_name = task.get("tool")
        arguments = task.get("arguments", {})
        tool_func = self.tools.get(tool_name)
        if not tool_func:
            return {"error": f"Tool {tool_name} not found."}

        # 为每个工具调用包装重试、超时和错误处理
        @retry(stop=stop_after_attempt(3),
               wait=wait_exponential_jitter(initial=0.3, max=10, jitter=0.5),
               retry=retry_if_exception_type(ConnectionError))
        async def _call_with_retry():
            return await asyncio.wait_for(tool_func(**arguments), timeout=300)

        try:
            output = await _call_with_retry()
            return {"success": True, "output": output}
        except asyncio.TimeoutError:
            return {"success": False, "error": f"Tool {tool_name} timed out after 300 seconds."}
        except Exception as e:
            # 这里可以加入更精细的错误归因逻辑
            return {"success": False, "error": f"Tool execution failed: {e}"}