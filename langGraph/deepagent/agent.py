"""Deep Agent 主类"""

import os
from typing import Any, Dict, Optional
from langchain_core.language_models import BaseChatModel
import structlog

from .graph import DeepAgentGraph
from .context import DeepAgentState

logger = structlog.get_logger(__name__)


class DeepAgent:
    """Deep Agent - Planner-Executor-Reflector 架构

    Args:
        llm:              LangChain LLM 实例
        tools:            工具字典 {"tool_name": tool_function}
        max_iterations:   最大迭代轮次，默认 50
        mcp_config:       MCPToolServer 配置，来自 mcp.config.load_config()
        knowledge_router: KnowledgeRouter 实例，用于自动回写 STE 经验
    """

    def __init__(
            self,
            llm: BaseChatModel,
            tools: Dict[str, Any],
            max_iterations: int = 50,
            mcp_config: Optional[Dict[str, Any]] = None,
            knowledge_router=None,
    ):
        self.llm = llm
        self.tools = tools
        self.max_iterations = max_iterations
        self.mcp_config = mcp_config or {}
        self.knowledge_router = knowledge_router

        # 构建 STE 回写回调
        ste_callback = None
        if knowledge_router is not None:
            async def _ste_callback(ste):
                import asyncio
                loop = asyncio.get_running_loop()
                await loop.run_in_executor(None, knowledge_router.save_ste_experience, ste)
            ste_callback = _ste_callback

        self.graph = DeepAgentGraph(
            llm=llm,
            tools=tools,
            max_iterations=max_iterations,
            ste_callback=ste_callback,
            knowledge_router=knowledge_router,
        )

        logger.info(
            "deep_agent_initialized",
            tool_count=len(tools),
            tool_names=list(tools.keys()),
            max_iterations=max_iterations,
            ste_persistence=knowledge_router is not None,
        )

    async def run(self, goal: str, thread_id: str = "default") -> Dict[str, Any]:
        """运行 Agent 直到目标完成或达到最大迭代次数。

        Args:
            goal:      任务目标描述
            thread_id: 线程 ID，用于 InMemorySaver 的多会话隔离

        Returns:
            {"success": bool, "goal": str, "state": dict | None, "error": str | None}
        """
        logger.info("deep_agent_run_start", goal=goal, thread_id=thread_id)

        try:
            final_state = await self.graph.run(goal, thread_id)

            # final_state 可能是 Pydantic 模型或 dict（取决于 LangGraph 版本）
            if final_state is None:
                state_dump = None
            elif isinstance(final_state, DeepAgentState):
                state_dump = final_state.model_dump()
            elif isinstance(final_state, dict):
                state_dump = final_state
            else:
                state_dump = None

            rounds = (
                final_state.execution_round
                if isinstance(final_state, DeepAgentState)
                else state_dump.get("execution_round", 0) if state_dump else 0
            )

            logger.info("deep_agent_run_done", execution_round=rounds, goal=goal)

            return {
                "success": True,
                "goal": goal,
                "state": state_dump,
                "error": None,
            }

        except Exception as e:
            logger.error("deep_agent_run_failed", error=str(e), goal=goal)
            return {
                "success": False,
                "goal": goal,
                "state": None,
                "error": str(e),
            }

    async def stream(self, goal: str, thread_id: str = "default"):
        """流式运行 Agent，逐节点 yield 状态更新事件。

        Yields:
            LangGraph 事件字典 {"node_name": state}
        """
        # PER 循环每轮消耗 3 步，LangGraph 默认 recursion_limit=25 只够约 8 轮，需按 max_iterations 放大
        config = {
            "configurable": {"thread_id": thread_id},
            "recursion_limit": max(40, self.max_iterations * 3 + 15),
        }
        initial_state = DeepAgentState(
            current_goal=goal,
            messages=[{"role": "user", "content": goal}],
        )
        # 每次新 goal 都需要传入 initial_state 让图从头开始跑完整的 PER 循环。
        # 使用独立 thread_id 隔离每次对话轮次，避免 checkpoint 携带上轮残留状态。
        async for event in self.graph.app.astream(initial_state, config):
            yield event
