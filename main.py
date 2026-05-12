# example.py
import asyncio
from langchain_openai import ChatOpenAI
from langchain_community.tools import DuckDuckGoSearchRun, Calculator
from langchain_anthropic import ChatAnthropic
import os
from deepagent.agent import DeepAgent


# 定义工具
def search(query: str) -> str:
    """搜索工具"""
    return DuckDuckGoSearchRun().run(query)


def calculate(expression: str) -> str:
    """计算器工具"""
    return Calculator().run(expression)


tools = {
    "search": search,
    "calculate": calculate
}


async def main():
    # 初始化 LLM
    os.environ["ANTHROPIC_BASE_URL"] = "https://cn.luckyapi.chat"
    os.environ["ANTHROPIC_API_KEY"] = ""
    os.environ["ANTHROPIC_AUTH_TOKEN"] = "sk-PWUKOsM1bse7ONpALusn49M9DFRhhGTk8q0u3Y46G9em2GMJ"  # 中转密钥

    llm = ChatAnthropic(
        model_name="claude-3-plus-20240607",
        temperature=0.7,
        stop=["\n\nHuman:"],
        timeout=120,
        streaming=True,
        # 可选：显式指定 base_url
        base_url="https://cn.luckyapi.chat"
    )

    # 创建 Deep Agent
    agent = DeepAgent(
        llm=llm,
        tools=tools,
        max_iterations=10
    )

    # 运行任务
    result = await agent.run(
        goal="查找 2024 年 AI 领域的重要突破，然后计算这些突破的数量"
    )

    print(f"结果: {result}")


if __name__ == "__main__":
    asyncio.run(main())