# src/agent/memory.py
from typing import List, Dict, Any, Optional
from langchain_core.messages import BaseMessage, SystemMessage


class ContextCompressor:
    def __init__(self, llm, max_tokens: int = 100_000, message_threshold: int = 50):
        self.llm = llm
        self.max_tokens = max_tokens
        self.message_threshold = message_threshold

    def should_compress(self, messages: List[BaseMessage], execution_round: int) -> bool:
        total_chars = sum(len(str(m.content)) for m in messages)
        if total_chars / 4 > self.max_tokens:
            return True
        if len(messages) > self.message_threshold:
            return True
        if execution_round > 0 and execution_round % 10 == 0:
            return True
        return False

    async def compress(
        self,
        messages: List[BaseMessage],
        context: Optional[Dict[str, Any]] = None,
    ) -> List[BaseMessage]:
        """用 LLM 生成摘要，保留系统消息和最近 10 条消息。"""
        if len(messages) <= 12:
            return messages

        system_msg = messages[0] if isinstance(messages[0], SystemMessage) else None
        recent_messages = messages[-10:]
        history_to_compress = messages[1:-10] if system_msg else messages[:-10]

        if not history_to_compress:
            return messages

        history_text = "\n".join(f"{m.type}: {m.content}" for m in history_to_compress)

        # 从 context 中提取结构化信息供 LLM 压缩时参考
        extra = ""
        if context and context.get("reflector", {}).get("persistent_insights"):
            insights = context["reflector"]["persistent_insights"]
            extra = "\n\n关键经验（必须在摘要中保留）:\n" + "\n".join(
                f"  · {i.get('strategy', '')} → {i.get('example', '')}"
                for i in insights if i.get("strategy")
            )

        compress_prompt = f"""请将以下渗透测试对话历史压缩成一个简洁的摘要，保留：
1. 所有重要决策和行动（按时间顺序）
2. 关键工具调用及其结果（含成功/失败状态）
3. 失败原因和教训
4. 已确认的漏洞和证据
5. 测试过的 OWASP Top10 方向及结论（confirmed/suspected/no_finding）
{extra}

对话历史:
{history_text}

摘要:"""

        try:
            summary = await self.llm.ainvoke(compress_prompt)
            result = []
            if system_msg:
                result.append(system_msg)
            result.append(summary)
            result.extend(recent_messages)
            return result
        except Exception:
            return messages
