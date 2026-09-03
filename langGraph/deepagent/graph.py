"""LangGraph 状态图 - Planner-Executor-Reflector 循环"""

import asyncio
import json
import os
import re
from collections import deque
from typing import Literal, Optional, Any, Dict, List, Callable, Set

from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import InMemorySaver
from langchain_core.language_models import BaseChatModel
import structlog

from .context import DeepAgentState, STEExperience, PlannerContext, ReflectorContext, ExecutorContext
from .guard import AntiAddictionGuard
from .mcp.executors.meta_executor import MetaToolExecutor
from .memory import ContextCompressor

logger = structlog.get_logger(__name__)

# 侦察操作手册目录（静态 markdown，agent 运行时按需用 execute_shell 读取，
# 替代专项 recon_* MCP 工具，释放工具面并恢复参数自由度）
_RECON_PLAYBOOK_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "knowledge", "reference", "recon-playbook",
)

# Web+AI 安全测试知识库目录（静态 markdown，agent 运行时按漏洞类型用
# execute_shell 读取对应 reference 获取 Payload/绕过技巧/方法论，替代凭
# 印象输出 payload 的幻觉风险）。知识源：WooYun 88,636 案例 + 先知 L1-L4
# + GAARM 173 + OWASP LLM/ASI/WSTG，共 48 个 reference 文件。
_SECKNOWLEDGE_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "knowledge", "reference", "secknowledge-skill",
)

# OWASP 方向 → secknowledge 参考文件（确定性注入映射：Planner 不再依赖
# "自觉 cat"，服务端按当前方向直接把对应手册的 payload/绕过片段喂进提示词）
_SKILL_BY_DIR = {
    "A01": "web-logic-auth.md",
    "A02": "web-modern-protocols.md",
    "A03": "web-sqli.md",
    "A04": "web-logic-auth.md",
    "A05": "web-leak.md",
    "A06": "web-deployment-security.md",
    "A07": "web-logic-auth.md",
    "A08": "web-deser.md",
    "A09": "web-modern-protocols.md",
    "A10": "web-ssrf-misc.md",
}

# 任务描述关键词 → 补充文件（跨方向场景，如方向为 A05 但任务实际是反序列化）
_SKILL_KEYWORD_FILES = [
    ("serialize|unserialize|反序列|pickle|phar|pop链|__wakeup", "web-deser.md"),
    ("upload|文件上传|webshell", "web-upload.md"),
    ("include|包含|traversal|../|路径穿越|任意文件读", "web-traversal.md"),
    ("xss|跨站脚本|cookie窃取", "web-xss.md"),
    ("xxe|外部实体|DOCTYPE", "web-xxe.md"),
    ("rce|命令执行|system[(]|eval[(]|webshell", "web-rce.md"),
    ("ssrf|内网探测|169.254", "web-ssrf-misc.md"),
    ("log|日志", "web-modern-protocols.md"),
]


async def _llm_invoke_with_retry(llm, prompt: str, max_retries: int = 4, temperature: Optional[float] = None, fast: bool = False) -> str:
    """调用 LLM，每次创建全新客户端（防止代理积累对话上下文），遇到网络错误时指数退避重试。

    provider 由 LLM_PROVIDER 选择：anthropic（默认，原生 Anthropic SDK）或
    openai（OpenAI 兼容端点，覆盖 OpenAI/DeepSeek/Qwen/GLM/Kimi/Yi/MiniMax/
    Doubao/Baichuan/Gemini-openai-compat/xAI）。key/base 用通用 LLM_API_KEY/
    LLM_BASE_URL，缺省回退 ANTHROPIC_*（向后兼容）。

    fast=True（Reflector/STE 等高频判定调用）时优先使用 LLM_FAST_MODEL /
    LLM_FAST_API_KEY / LLM_FAST_BASE_URL（快速小模型分流，未配置则原样回退）。
    """
    _provider = (os.environ.get("LLM_PROVIDER") or "anthropic").strip().strip("'\"").lower() or "anthropic"
    _is_anthropic = _provider == "anthropic"

    # fast 分流：专用模型/key/base，缺省回退主模型配置（不改行为）
    _fast_model = os.environ.get("LLM_FAST_MODEL", "").strip().strip("'\"")
    _fast_key = os.environ.get("LLM_FAST_API_KEY", "").strip().strip("'\"")
    _fast_base = os.environ.get("LLM_FAST_BASE_URL", "").strip().strip("'\"")

    # 通用 key/base（向后兼容：缺省回退 ANTHROPIC_*）
    _api_key  = (os.environ.get("LLM_API_KEY") or os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN", "")).strip().strip("'\"")
    _base_url = (os.environ.get("LLM_BASE_URL") or os.environ.get("ANTHROPIC_BASE_URL", "")).strip().strip("'\"")
    if not _base_url:
        _base_url = "https://api.anthropic.com" if _is_anthropic else "https://api.openai.com/v1"
    _model    = os.environ.get("LLM_MODEL", "claude-sonnet-4-6" if _is_anthropic else "gpt-4o")
    if fast and _fast_model:
        _api_key = _fast_key or _api_key
        _base_url = _fast_base or _base_url
        _model = _fast_model
    _max_tok  = int(os.environ.get("LLM_MAX_TOKENS", "16384"))
    # temperature 可按调用点覆盖：判定类调用（Reflector/方向预筛）传低温减少随机性
    _temp     = float(os.environ.get("LLM_TEMPERATURE", "0.7")) if temperature is None else float(temperature)
    # 每个汉字约 1.5 token，每个英文字符约 0.25 token；保守估计：字符数 / 2 ≈ token 数
    # context_window(200k) - max_tokens(16384) - buffer(2000) ≈ 180k tokens ≈ 360k chars
    _MAX_PROMPT_CHARS = int(os.environ.get("LLM_MAX_PROMPT_CHARS", "80000"))

    # 若提示词超长，截断到安全长度后再调用
    current_prompt = prompt
    if len(current_prompt) > _MAX_PROMPT_CHARS:
        logger.warning("prompt_truncated", original_len=len(current_prompt), limit=_MAX_PROMPT_CHARS)
        current_prompt = current_prompt[:_MAX_PROMPT_CHARS]

    delay = 2.0
    last_err = None
    for attempt in range(max_retries):
        try:
            # 每次创建全新客户端：新 HTTP 连接 = 代理侧新会话 = 无历史积累
            if _is_anthropic:
                import anthropic as _anthropic
                client = _anthropic.AsyncAnthropic(
                    api_key=_api_key,
                    base_url=_base_url,
                    timeout=120.0,
                )
                try:
                    message = await client.messages.create(
                        model=_model,
                        max_tokens=_max_tok,
                        temperature=_temp,
                        messages=[{"role": "user", "content": current_prompt}],
                    )
                    return message.content[0].text
                finally:
                    await client.close()
            else:
                # OpenAI 兼容端点（openai SDK 2.x：AsyncOpenAI + chat.completions.create）
                import openai as _openai
                client = _openai.AsyncOpenAI(
                    api_key=_api_key,
                    base_url=_base_url,
                    timeout=120.0,
                )
                try:
                    resp = await client.chat.completions.create(
                        model=_model,
                        max_tokens=_max_tok,
                        temperature=_temp,
                        messages=[{"role": "user", "content": current_prompt}],
                    )
                    return resp.choices[0].message.content or ""
                finally:
                    await client.close()
        except Exception as e:
            last_err = e
            msg = str(e)
            is_retryable = any(code in msg for code in (
                "502", "503", "Connection", "timeout", "Timeout",
                "RemoteProtocol", "No generations", "stream",
            ))
            # 400 上下文过长时：截断 prompt 后重试一次
            is_context_too_long = "400" in msg and attempt == 0 and len(current_prompt) > 2000
            if (is_retryable or is_context_too_long) and attempt < max_retries - 1:
                if is_context_too_long:
                    current_prompt = current_prompt[:len(current_prompt) // 2]
                    logger.warning("llm_retry_prompt_halved", new_len=len(current_prompt), error=msg[:120])
                else:
                    logger.warning("llm_retry", attempt=attempt + 1, delay=delay, error=msg[:120])
                await asyncio.sleep(delay)
                delay = min(delay * 2, 30)
                continue
            raise
    raise last_err


def _extract_json(content: str) -> Optional[dict]:
    """从 LLM 输出中提取 JSON，优先匹配 markdown 代码块，再回退到裸 JSON，最后尝试截断恢复。"""
    # 1. markdown 代码块完整解析
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", content, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    # 2. 裸 JSON 完整解析
    start = content.find("{")
    end = content.rfind("}") + 1
    if start != -1 and end > start:
        try:
            return json.loads(content[start:end])
        except json.JSONDecodeError:
            pass

    # 3. 截断恢复：JSON 字符串内的换行是 \n 字面量，结构层换行是真实 \n
    #    遍历行，找到最后一个以 }, 或 } 结尾的结构行，尝试闭合后解析
    if start != -1:
        raw = content[start:]
        lines = raw.split("\n")
        # 从后往前找最后一个可能是结构性闭合的行
        for i in range(len(lines) - 1, 0, -1):
            stripped = lines[i].rstrip()
            if not stripped or stripped in ("{", "["):
                continue
            # 尝试在第 i 行之后关闭 JSON
            partial = "\n".join(lines[:i + 1]).rstrip(",\r\n ")
            # 尝试不同的闭合方式（先补 }]}，再补 ]}，再补 }）
            for suffix in [']}', '}]}', '"\n]}', '"\n}\n]}', ']}\n}', '}', '}\n]}']:
                try:
                    result = json.loads(partial + "\n" + suffix)
                    if isinstance(result, dict) and result.get("tasks"):
                        logger.info("json_truncation_recovered",
                                    tasks=len(result["tasks"]), suffix=suffix)
                        return result
                except Exception:
                    pass

    return None


def _real_goal(goal: str, max_len: int = 300) -> str:
    """从 enriched_goal 中提取纯目标文本，去掉会话历史前缀。"""
    marker = "【当前目标】"
    idx = goal.rfind(marker)
    if idx != -1:
        return goal[idx + len(marker):].strip()[:max_len]
    return goal[:max_len]


def _history_of_goal(goal: str, max_len: int = 2000) -> str:
    """从 enriched_goal 中提取会话历史前缀（【当前目标】之前的部分，与 _real_goal 互补）。"""
    marker = "【当前目标】"
    idx = goal.rfind(marker)
    if idx != -1:
        return goal[:idx].strip()[:max_len]
    return ""


# OWASP Top10 规范方向名（短横格式为内部 canonical）。存入 state 前一律经
# _norm_dir 归一，避免 LLM 输出 "A03 SQL注入"/"A03-SQL注入"/"A03" 等不同写法
# 导致 completed/stalled 判定与 goal_achieved 失效。pivot 的 all_top10 与
# _analyze_target_directions 的 _all 均引用此常量，保证归一映射与比较列表同源。
_OWASP_DIRECTIONS = [
    "A01-访问控制", "A02-加密失败", "A03-SQL注入", "A04-不安全设计",
    "A05-安全配置错误", "A06-已知漏洞组件", "A07-身份认证失败",
    "A08-完整性失败", "A09-日志缺失", "A10-SSRF",
]
_DIR_BY_PREFIX = {d[:3]: d for d in _OWASP_DIRECTIONS}  # "A03" → "A03-SQL注入"


def _norm_dir(name: str) -> str:
    """将任意方向名归一化为 canonical 短横格式。

    A03 SQL注入 / A03-SQL注入 / a03 / A03 → A03-SQL注入；
    无法识别 A0x 前缀时原样返回（保留自定义方向名，不误吞）。
    """
    if not name:
        return name
    key = name.strip()[:3].upper()
    return _DIR_BY_PREFIX.get(key, name.strip())


def _get_sub(state, sub_name: str):
    """安全获取 state 的子对象（兼容 dict 和 Pydantic 对象）。"""
    if isinstance(state, dict):
        val = state.get(sub_name, {})
        if isinstance(val, dict):
            return val
        return val  # Pydantic object
    return getattr(state, sub_name, None)


def _normalize_state(state: Any) -> "DeepAgentState":
    """确保 state 的子对象是 Pydantic 模型而非 dict（LangGraph checkpoint 反序列化后可能丢失类型）。"""
    # 如果已经是 Pydantic 对象且子类型正确，直接返回
    if not isinstance(state, dict):
        if (isinstance(state.planner, PlannerContext) and
                isinstance(state.reflector, ReflectorContext) and
                isinstance(state.executor, ExecutorContext)):
            return state
        # 部分子类型被序列化为 dict → 恢复
        if isinstance(state, DeepAgentState):
            if isinstance(state.planner, dict):
                state.planner = PlannerContext(**state.planner)
            if isinstance(state.reflector, dict):
                state.reflector = ReflectorContext(**state.reflector)
            if isinstance(state.executor, dict):
                state.executor = ExecutorContext(**state.executor)
            return state
        return state

    # state 是 dict → 恢复为 Pydantic 对象
    planner_data = state.get("planner", {})
    reflector_data = state.get("reflector", {})
    executor_data = state.get("executor", {})

    if isinstance(planner_data, dict):
        state["planner"] = PlannerContext(**planner_data)
    if isinstance(reflector_data, dict):
        state["reflector"] = ReflectorContext(**reflector_data)
    if isinstance(executor_data, dict):
        state["executor"] = ExecutorContext(**executor_data)

    return DeepAgentState(**state)


class DeepAgentGraph:
    """Deep Agent 状态图"""

    def __init__(
            self,
            llm: BaseChatModel,
            tools: Dict[str, Any],
            max_iterations: int = 50,
            ste_callback: Optional[Callable] = None,
            knowledge_router=None,
    ):
        self.llm = llm
        self.tools = tools
        self.max_iterations = max_iterations
        self.ste_callback = ste_callback  # async callable: (STEExperience) -> None
        self.knowledge_router = knowledge_router

        self.meta_executor = MetaToolExecutor(tools)
        self.guard = AntiAddictionGuard()

        # 会话内已执行任务指纹（工具+参数精确匹配）：执行前硬去重，
        # 同质任务连代码生成/执行都跳过，节省轮次与 LLM token
        self._exec_fingerprints: deque = deque(maxlen=40)
        # 知识检索缓存：同一方向只查一次（_fetch_knowledge_payloads）
        self._kb_cache: Dict[str, str] = {}
        # skill 手册文件内容缓存（secknowledge 静态 read）
        self._skill_cache: Dict[str, str] = {}
        # 证据原文库去重：已入 vault 的证据指纹（前 60 字符），实例级跨轮去重
        self._evidence_seen: Set[str] = set()
        self._evidence_id: int = 0
        # 用户实时纠偏/补充指令（steer）：运行中由 chat_server 追加，Planner 每轮消费
        # （不打断任务，只影响后续轮次的方向与任务生成）
        self.steering: List[str] = []
        self._steering_consumed: int = 0
        self.compressor = ContextCompressor(llm)

        self.graph = self._build_graph()
        self.memory = InMemorySaver()
        self.app = self.graph.compile(checkpointer=self.memory)

    def _build_graph(self) -> StateGraph:
        workflow = StateGraph(DeepAgentState)

        workflow.add_node("planner", self._planner_node)
        workflow.add_node("executors", self._executor_node)
        workflow.add_node("reflector", self._reflector_node)
        workflow.add_node("compressor", self._compressor_node)
        workflow.add_node("summarizer", self._summarizer_node)

        workflow.set_entry_point("planner")
        workflow.add_edge("planner", "executors")
        workflow.add_edge("executors", "reflector")
        workflow.add_conditional_edges(
            "reflector",
            self._should_continue,
            {"continue": "planner", "compress": "compressor", "summarize": "summarizer", "end": END}
        )
        workflow.add_edge("compressor", "planner")
        workflow.add_edge("summarizer", END)

        return workflow

    # ------------------------------------------------------------------
    # 节点
    # ------------------------------------------------------------------

    async def _planner_node(self, state: DeepAgentState) -> DeepAgentState:
        """规划节点 - 让 LLM 生成任务列表"""
        state = _normalize_state(state)
        logger.info("planner_start", round=state.execution_round + 1)

        # ── 第一轮目标分析：根据 URL 特征筛选适用的 OWASP 方向 ──────────
        if state.execution_round == 0 and not state.planner.applicable_directions:
            await self._analyze_target_directions(state)

        summary = self._build_planner_summary(state)

        # ── 知识库 payload 检索（优先用于避免错误 payload）──────────────
        kb_payloads = self._fetch_knowledge_payloads(state.planner.current_vuln_focus or "")
        kb_hint = (
            f"\n知识库推荐 payload（请优先参考，勿自造错误语法）:\n{kb_payloads}\n"
            if kb_payloads else ""
        )

        # ── skill 手册确定性注入：按方向/任务关键词服务端读取对应手册的
        #    payload/绕过片段直接喂给 Planner（不再依赖 LLM 自觉 cat，
        #    解决"知识库未生效"：payload 永远在提示词里）──────────────────
        _last_desc = " ".join(
            str((r.get("task") or {}).get("description", ""))[:200]
            for r in (state.current_results or [])[:8]
            if isinstance(r, dict)
        )
        _last_desc += " " + " ".join(
            str((t or {}).get("description", ""))[:200]
            for t in (state.current_tasks or [])[:8]
            if isinstance(t, dict)
        )
        skill_hint = self._fetch_skill_payloads(
            state.planner.current_vuln_focus or "",
            _last_desc,
        )

        # ── 利用链进度：跨轮要素沉淀，多步利用的下一跳必须基于已有要素 ──
        chain_hint = ""
        if state.planner.chain_notes:
            chain_hint = (
                "\n━━━ 利用链进度（多步利用必须基于这些已有要素继续构造下一跳，"
                "禁止从头重新探测）━━━\n"
                + "\n".join(f"  · {c}" for c in state.planner.chain_notes[-8:])
                + "\n"
            )

        # ── 组合利用工作台：资产面板 + 未破门槛 + 证据原文库（每轮先盘点 ──
        asset_hint = ""
        _ws_lines: List[str] = []
        if state.planner.assets:
            _ws_lines.append("【攻击资产面板——已到手的牌，本轮必须利用】")
            for a in state.planner.assets[-12:]:
                _ev = str(a.get("evidence", ""))[:140].replace("\n", " ")
                _ws_lines.append(
                    f"· [{a.get('kind')}] {str(a.get('desc'))[:110]}"
                    + (f" | 原文: {_ev}" if _ev else "")
                )
        if state.planner.blockers:
            _ws_lines.append("【未破门槛——本轮必须为每一项安排至少一个突破尝试任务】")
            for b in state.planner.blockers[-6:]:
                _ws_lines.append(f"· {str(b.get('desc'))[:150]}")
        if state.planner.evidence_vault:
            _ws_lines.append("【证据原文库——任务 description 可引用证据ID，如\"基于证据 E7 构造\"】")
            for e in state.planner.evidence_vault[-12:]:
                _head = str(e.get("content", ""))[:70].replace("\n", " ")
                _ws_lines.append(f"· E{e.get('id')} [{e.get('kind')}] {_head}")
        if _ws_lines:
            asset_hint = (
                "\n━━━ 组合利用工作台（生成任务前必须先盘点："
                "已确认漏洞的产物必须作为其他方向任务的输入，构造多漏洞联动利用链）━━━\n"
                + "\n".join(_ws_lines) + "\n"
            )

        # ── 上一轮反思建议的下一跳候选（优先采纳）──────────────
        next_hops_hint = ""
        _sns = (state.planner.latest_reflection or {}).get("suggested_next_steps") or []
        if isinstance(_sns, list) and _sns:
            next_hops_hint = (
                "\n━━━ 上轮反思建议的下一跳候选（优先采纳，除非有更强理由）━━━\n"
                + "\n".join(f"  · {str(s)[:160]}" for s in _sns[:3]) + "\n"
            )

        # ── 用户实时纠偏/补充（steer）：运行中追加的指令，本轮必须纳入 ──
        steering_hint = ""
        if self._steering_consumed < len(self.steering):
            _steers = self.steering[self._steering_consumed:]
            self._steering_consumed = len(self.steering)
            steering_hint = (
                "\n⚠️⚠️ 【用户实时指令——最高优先级，本轮任务必须体现】⚠️⚠️\n"
                + "\n".join(f"  · {str(s)[:300]}" for s in _steers[-3:]) + "\n"
            )

        # ── 回显相同警告 + 防沉迷历史（由 executor 节点记录）────────────
        same_output_warnings = [
            r.get("same_output_warning") for r in (state.current_results or [])
            if r.get("same_output_warning")
        ]
        anti_triggered_count = sum(
            1 for r in (state.current_results or [])
            if r.get("anti_addiction_triggered")
        )
        same_output_hint = ""
        if same_output_warnings:
            same_output_hint = (
                f"\n⚠️ 上轮 {len(same_output_warnings)} 个任务回显与历史完全相同"
                f"——当前 payload 已无效，必须换用完全不同的测试角度或参数！\n"
            )
        if anti_triggered_count > 0:
            same_output_hint += (
                f"⚠️ 上轮 {anti_triggered_count} 个任务因防沉迷被拦截"
                f"（与历史过于相似），绝对禁止重复同一思路！\n"
            )
        # ── 无效重复任务清单（Planner 直接可见，禁止再生成相同/微变体）────
        _dup_tasks = [
            r for r in (state.current_results or [])
            if r.get("same_output_warning") or r.get("anti_addiction_triggered")
        ][:6]
        _dup_brief = ""
        if _dup_tasks:
            _dup_lines = []
            for r in _dup_tasks:
                t = r.get("task") or {}
                _dup_lines.append(
                    f"· {t.get('tool', '?')} {json.dumps(t.get('arguments', {}), ensure_ascii=False)[:90]}"
                )
            _dup_brief = (
                "\n⚠️ 上轮无效/重复任务（绝不允许再生成相同或微变体——必须换工具、换参数或换注入角度）:\n"
                + "\n".join(_dup_lines) + "\n"
            )

        _TOOL_DESCRIPTIONS = {
            "browser_navigate":     "导航到已知URL（禁止搜索引擎）",
            "browser_execute_js":   "执行页面JS",
            "browser_get_content":  "获取页面HTML",
            "browser_screenshot":   "页面截图",
            "execute_python":       "执行Python（httpx请求/数据处理）",
            "execute_shell":        "执行Shell命令",
            "proxy_list_traffic":   "代理流量列表",
            "proxy_get_flow":       "流量详情",
            "proxy_clear_traffic":  "清空流量",
            "proxy_replay_flow":    "重放流量",
            "knowledge_search":     "搜索知识库",
            "knowledge_get_detail": "知识库详情",
            "knowledge_save":       "保存知识库",
        }
        tool_desc_lines = "\n".join(
            f"  - {name}: {_TOOL_DESCRIPTIONS.get(name, '(no description)')}"
            for name in self.tools.keys()
        )

        # 已确认漏洞摘要
        confirmed_summary = json.dumps(
            [{"vuln": v.get("vuln_type"), "proof": v.get("proof_brief")}
             for v in state.planner.confirmed_vulns],
            ensure_ascii=False
        ) if state.planner.confirmed_vulns else "无"

        # 已尝试 payload 记录（最近 5 条，避免重复）
        tried_payloads_hint = ""
        if state.planner.tried_payloads:
            recent = [p[:40] for p in state.planner.tried_payloads[-5:]]
            tried_payloads_hint = f"\n已尝试（禁止重复）: {recent}\n"

        # 强制切换方向指令
        pivot_instruction = ""
        if state.planner.force_pivot:
            stalled = state.planner.current_vuln_focus or "当前方向"
            done_dirs = list(set(state.planner.stalled_directions + state.planner.completed_directions))
            all_top10 = list(_OWASP_DIRECTIONS)
            remaining = [d for d in all_top10 if not any(d[:3] in done for done in done_dirs)]
            pivot_instruction = f"""
⚠️ 【强制切换方向】「{stalled}」已完成或停滞。禁止重复: {done_dirs}。剩余方向: {remaining}。立即切换到第一个剩余方向。
"""

        # 截断 rejected_strategies，只保留最近 5 条
        _rejected_brief = dict(list(state.planner.rejected_strategies.items())[-5:])

        # 如果已经有确认的漏洞，调整策略以探索其他方向
        has_confirmed_vulns = len(state.planner.confirmed_vulns) > 0
        exploration_guidance = ""
        if has_confirmed_vulns:
            exploration_guidance = f"已确认 {len(state.planner.confirmed_vulns)} 个漏洞，优先探索其他未测试的 OWASP 方向，避免重复已确认方向。"

        # ── 计划驱动：总轮数 / 规划模式 / 当前测试文档 ─────────────────
        _plan_total = state.planner.total_rounds or self.max_iterations
        _is_final_round = (state.execution_round + 1) >= _plan_total
        if state.execution_round == 0:
            _plan_mode = "init"
        elif _is_final_round:
            _plan_mode = "final"
        else:
            _plan_mode = "update"
        _test_plan_str = (
            json.dumps(state.planner.test_plan, ensure_ascii=False)[:4000]
            if state.planner.test_plan else "（尚未生成，本轮 init 模式必须创建）"
        )
        # 文档用例进度统计 + 上轮 Reflector 轮数建议（动态轮数决策依据）
        _plan_progress = "（文档未生成）"
        if state.planner.test_plan:
            _pp = {"pending": 0, "done": 0, "found": 0, "failed": 0, "other": 0}
            for _d in state.planner.test_plan.get("directions", []):
                for _c in _d.get("cases", []):
                    _st = str(_c.get("status", "pending"))
                    _pp[_st if _st in _pp else "other"] += 1
            _plan_progress = (f"pending={_pp['pending']} done={_pp['done']} "
                              f"found={_pp['found']} failed={_pp['failed']}")
        _rs = state.planner.latest_reflection.get("rounds_suggestion") if state.planner.latest_reflection else None
        _rounds_suggestion_str = (
            f"{_rs.get('action', 'keep')}（{str(_rs.get('reason', ''))[:80]}）"
            if isinstance(_rs, dict) else "无"
        )

        # 会话历史前缀（enriched_goal 中【当前目标】之前的部分）：各处提示词里的
        # _real_goal 会剥离历史，但历史是同会话跨问题记忆的唯一来源，必须显式喂给
        # Planner，否则第二次提问会像第一次一样从零规划。
        _session_hist = _history_of_goal(state.current_goal)
        session_ctx = (
            f"\n━━━ 会话记忆（此前对话的目标与结论，制定计划前必须先理解，避免重复已完成的测试）━━━\n{_session_hist}\n"
            if _session_hist else ""
        )

        _JSON_TEMPLATE = f"""输出JSON（必须严格遵循，只输出JSON）:
{{
    "plan_mode": "init | update | final",
    "total_rounds": 6,
    "rounds_adjust": 0,
    "test_plan": {{"objective": "目标一句话", "directions": [{{"direction": "A03-SQL注入", "cases": [{{"id": "A03-1", "desc": "用例说明+payload要点", "status": "pending"}}]}}]}},
    "test_analysis": {{"response_pattern": "上轮响应差异", "failure_reason": "失效原因", "new_angles": ["角度1", "角度2"]}},
    "tasks": [{{"tool": "工具名", "arguments": {{"参数": "值"}}, "description": "测试值 + 预期观测点"}}],
    "reasoning": "综合判断",
    "vuln_focus": "当前 OWASP 方向（如 A03-SQL注入）",
    "tried_summary": "本轮测试摘要"
}}
字段说明: plan_mode=当前模式({_plan_mode}); total_rounds 仅 init 填写(2-{self.max_iterations}轮，规划总思考轮数，仅为参考基线); rounds_adjust=轮数增减申请(-2~+2整数，默认0，须基于轮数建议与文档进展，reasoning 中说明理由); test_plan 在 init/update 必须输出【完整文档】，final 可省略; 其余字段每轮必填。"""

        prompt = f"""你是一名安全评估工程师，对授权目标执行安全合规性检查。

{_JSON_TEMPLATE}

━━━ 目标 ━━━
当前目标: {_real_goal(state.current_goal)}
{session_ctx}
执行轮次: {state.execution_round + 1} / 共 {_plan_total} 轮
本次规划模式: {_plan_mode}
{exploration_guidance}

━━━ 测试文档（计划驱动主线）━━━
当前文档: {_test_plan_str}
文档进度: {_plan_progress}
总轮数基线: {_plan_total}（已执行 {state.execution_round} 轮，剩余 {_plan_total - state.execution_round} 轮）
上轮轮数建议: {_rounds_suggestion_str}
模式要求（强制）:
  · init（第一轮）: 先生成完整测试文档——对每个适用方向列出至少3个用例（id=方向缩写-序号，desc=测试点+payload要点，status 固定 pending），并确定 total_rounds（2-{self.max_iterations} 轮内，按目标复杂度建议 4-8 轮）。tasks 必须从文档第一批用例生成，不得偏离文档。
  · update（中间轮）: 必须输出修订后的【完整】test_plan——将上轮已执行用例的 status 更新为 done/found/failed（found=确认漏洞，需在 desc 标注证据摘要），允许新增用例（新 id 按方向顺延），禁止删除已有用例。tasks 继续执行文档中 status=pending 且价值最高的用例。首轮 total_rounds 仅为参考基线：结合文档进度与上轮轮数建议，通过 rounds_adjust（-2~+2）动态增减总轮数（进展显著/pending 充足→正值；连续无发现/剩余用例低价值→负值），调整理由写入 reasoning。
  · final（最后一轮）: 只输出收尾验证 tasks——聚焦文档中最可能有突破的 pending 用例与 found 用例的深挖确认；test_plan 可省略。本轮结束后系统自动进入总结节点生成最终报告。

━━━ 状态 ━━━
历史摘要: {summary}
已确认漏洞: {confirmed_summary}
当前方向: {state.planner.current_vuln_focus or "从A01开始"}
已完成: {state.planner.completed_directions}
已停滞: {state.planner.stalled_directions}
被拒策略: {json.dumps(_rejected_brief, ensure_ascii=False)[:100]}
{"历史经验: " + "; ".join(state.planner.long_term_goals[:3]) if state.planner.long_term_goals else ""}
{_dup_brief}{tried_payloads_hint}{same_output_hint}{kb_hint}{skill_hint}{chain_hint}{asset_hint}{next_hops_hint}{steering_hint}{pivot_instruction}

━━━ OWASP Top10（逐一测试，3轮无果换方向）━━━
{state.planner.applicable_directions or 'A01-访问控制 | A02-加密失败 | A03-SQL注入 | A04-不安全设计 | A05-安全配置错误 | A06-已知漏洞组件 | A07-身份认证失败 | A08-完整性失败 | A09-日志缺失 | A10-SSRF'}
{"（已排除不适用方向，优先测试列出的方向）" if state.planner.applicable_directions else ""}

━━━ 可用工具 ━━━
{tool_desc_lines}

━━━ 侦察操作手册（静态文档，按需用 execute_shell 读取）━━━
侦察需求（端口扫描/目录爆破/指纹/空间测绘/JS分析/鉴权绕过）优先读取对应手册获取命令模板，再用 execute_shell/execute_python 执行；手册内含可直接复制的命令与参数组合，按目标特征选择：
  端口扫描(nmap):              cat "{_RECON_PLAYBOOK_DIR}/01-port-scan.md"
  目录/文件爆破(gobuster/ffuf): cat "{_RECON_PLAYBOOK_DIR}/02-directory-scan.md"
  智能字典扫描:                 cat "{_RECON_PLAYBOOK_DIR}/03-smart-directory-scan.md"
  Web 指纹识别:                 cat "{_RECON_PLAYBOOK_DIR}/04-fingerprint.md"
  空间测绘(FOFA/Quake):         cat "{_RECON_PLAYBOOK_DIR}/05-cyberspace-search.md"
  JS 端点/敏感信息:             cat "{_RECON_PLAYBOOK_DIR}/06-analyze-js.md"
  鉴权绕过 Fuzz:                cat "{_RECON_PLAYBOOK_DIR}/07-fuzz-auth-bypass.md"

━━━ 漏洞知识库（SKILL.md 是主要参考/查询笔记，禁止凭印象编造 payload）━━━
定位流程（构造任何 Payload/绕过前强制执行）:
  1. 先查询 SKILL.md 的"场景导航索引"定位对应 reference 文件:  grep -n "<漏洞关键词>" "{_SECKNOWLEDGE_DIR}/SKILL.md"
  2. 再用 execute_shell 按需加载该 reference 对应章节取实战 Payload/绕过/方法论:  cat "{_SECKNOWLEDGE_DIR}/references/<文件>"（大文件如 testing-methodology.md 589 行 / web-logic-auth.md 582 行先 grep 定位章节再局部读取）
  3. 之后才允许 execute_python/execute_shell 执行测试任务，任务 description 注明引用的 文件:章节
按漏洞类型速查（与 SKILL.md 索引一致，直接 cat 的文件名）:
  Web注入:  SQL注入=web-sqli.md  XSS=web-xss.md  RCE=web-rce.md  XXE=web-xxe.md  反序列化=web-deser.md
  Web文件:  文件上传=web-upload.md  路径遍历=web-traversal.md  信息泄露=web-leak.md  SSRF/配置=web-ssrf-misc.md
  Web业务:  越权/支付/重置/逻辑=web-logic-auth.md  CORS/GraphQL/HTTP走私=web-modern-protocols.md  供应链/云/容器=web-deployment-security.md
  AI应用:  Prompt注入=ai-app-prompt-1.md/-2.md  MCP攻击=ai-app-mcp.md  Agent/CoT=ai-app-agent-cot-1.md/-2.md
  AI模型:  越狱=ai-model-jailbreak.md  幻觉=ai-model-hallucination.md  模型提取=ai-model-extraction.md
  AI数据/身份/基座:  数据窃取/RAG投毒=ai-data-app-1.md/-2.md  角色逃逸/Agent伪造=ai-identity-app-1.md/-2.md  沙箱逃逸=ai-baseline-escape.md
  方法论:  L1-L4/GAARM173/OWASP映射=testing-methodology.md  GAARM风险矩阵=gaarm-risk-matrix.md  智能体威胁矩阵=claw-agent-threat-matrix.md
引用铁律（源自 SKILL.md 行为准则，违反即失败）:
  ① Payload/CVE 必须能追溯到 reference 具体章节，追溯不到的一律标注 "UNABLE TO CITE"，禁止编造；
  ② 结论必须区分"假设（需验证）"与"已确认（证据:…）"，只有带确定性证据的才可写入 confirmed_vulns/findings；

━━━ 规划原则（强制执行）━━━
1. 【分析】test_analysis 必须说明：上轮响应差异、失效原因、≥3种新角度
2. 【覆盖】每轮5-8个任务，不同技术手法，每个description含具体测试值+预期观测点
3. 【代码】execute_python/execute_shell ≤8行，示例: import httpx; r=httpx.post('URL',data={{'p':'1 OR 1=1'}},timeout=10,verify=False); print(r.status_code,r.text[:3000])
4. 【变换】发现过滤后输出≥3种变换方案（大小写/注释/编码/等价函数/切换注入类型）
5. 【深挖】SQL注入确认后必须提取数据（库/表/字段/flag），使用完整查询
6. 【文档】test_plan 是全程主线: init 生成 → update 修订增补 → tasks 必须与文档用例对应，found 用例的漏洞证据以 desc 记录，最终报告以文档为准
7. 【组合】生成任务前必须先盘点"组合利用工作台"：资产面板中已确认漏洞的产物（源码/凭据/文件读能力/注入原语）必须成为本轮其他方向任务的输入，构造多漏洞联动利用链（例: 文件包含读源码→源码泄露过滤逻辑→构造绕过→反序列化RCE），禁止各方向孤立测试、禁止丢弃已到手资产重新盲测
8. 【续接】未破门槛列表中的每一项，本轮 tasks 都必须包含至少一个针对它的突破尝试；引用证据原文时在 description 写"基于证据 E{id}"（证据ID见组合利用工作台）"""

        try:
            content = await _llm_invoke_with_retry(self.llm, prompt)
            plan = _extract_json(content)
            if plan and plan.get("tasks"):
                state.current_tasks = plan.get("tasks")

                # ── 计划驱动：总轮数与测试文档维护 ────────────────────────
                if state.execution_round == 0:
                    # 首轮：确定总思考轮数（提前规划，后续按此推进）
                    # 强制至少 3 轮，避免 LLM 保守设 2 轮导致只跑一轮就收尾
                    tr = plan.get("total_rounds")
                    if isinstance(tr, int):
                        tr = max(3, min(self.max_iterations, tr))
                    else:
                        tr = min(self.max_iterations, 8)
                    state.planner.total_rounds = tr
                    logger.info("plan_total_rounds_set", total=tr)

                    # 首轮生成的测试文档用例必须全是 pending，防止 LLM 误标为 done 触发提前收尾
                    tp = plan.get("test_plan")
                    if isinstance(tp, dict):
                        for _d in tp.get("directions", []):
                            for _c in _d.get("cases", []):
                                _c["status"] = "pending"

                # 测试文档：init 生成 / update 修订（完整覆盖式更新）
                tp = plan.get("test_plan")
                if isinstance(tp, dict) and tp.get("directions"):
                    state.planner.test_plan = tp
                    _n_cases = sum(len(d.get("cases", [])) for d in tp.get("directions", []))
                    logger.info("test_plan_updated",
                                round=state.execution_round + 1, directions=len(tp["directions"]), cases=_n_cases)

                # 动态轮数调整：Planner 基于文档进度 + Reflector 建议决策
                # clamp: 单次 ≤±2，总轮数 ∈ [max(3, 当前轮+1), max_iterations]。
                # 下界为"当前轮+1"而非"+2"：旧实现 +2 会把"最后一轮"永远推到未来
                # （负调整也一样被抬升），计划轮数永不耗尽，只能跑满 max_iterations 收场。
                _adj = plan.get("rounds_adjust")
                if state.execution_round > 0 and isinstance(_adj, (int, float)) and int(_adj) != 0:
                    _adj = max(-2, min(2, int(_adj)))
                    _cur_total = state.planner.total_rounds or self.max_iterations
                    _new_total = max(max(3, state.execution_round + 1),
                                     min(self.max_iterations, _cur_total + _adj))
                    if _new_total != _cur_total:
                        state.planner.total_rounds = _new_total
                        logger.info("plan_rounds_adjusted",
                                    old=_cur_total, new=_new_total, adjust=_adj)
                    else:
                        logger.info("plan_rounds_adjust_clamped", old=_cur_total, adjust=_adj)

                state.planner.previous_plan = {
                    "round": state.execution_round,
                    "tasks": state.current_tasks,
                }
                state.planner.planning_history.append({
                    "round": state.execution_round,
                    "tasks": state.current_tasks,
                    "reasoning": plan.get("reasoning", ""),
                })

                # 记录本轮 payload 摘要（避免重复）
                payload_summary = plan.get("tried_summary")
                if payload_summary:
                    state.planner.tried_payloads.append(payload_summary)
                    if len(state.planner.tried_payloads) > 50:
                        state.planner.tried_payloads = state.planner.tried_payloads[-50:]

                # 更新当前漏洞方向
                new_focus = plan.get("vuln_focus")
                if new_focus:
                    new_focus = _norm_dir(new_focus)
                    if (state.planner.force_pivot
                            and state.planner.current_vuln_focus
                            and new_focus != state.planner.current_vuln_focus):
                        # 仅当旧方向不是已完成方向时，才归入停滞列表
                        old_focus = state.planner.current_vuln_focus
                        if (old_focus not in state.planner.completed_directions
                                and old_focus not in state.planner.stalled_directions):
                            state.planner.stalled_directions.append(old_focus)
                        state.planner.tried_payloads = []
                    elif new_focus != state.planner.current_vuln_focus:
                        # 方向自然切换，清空 payload 记录
                        state.planner.tried_payloads = []
                    state.planner.current_vuln_focus = new_focus
                state.planner.force_pivot = False
            else:
                reason = "解析失败" if plan is None else "空任务列表"
                logger.warning("planner_invalid_output", reason=reason, content=content[:200])
                # 解析失败或空列表时重试，避免因无任务导致循环提前结束
                state.current_tasks = await self._planner_retry(state)
        except Exception as e:
            logger.error("planner_failed", error=str(e))
            state.current_tasks = await self._planner_retry(state)

        return state

    async def _planner_retry(self, state: DeepAgentState) -> list:
        """规划解析失败时的兜底：先尝试带约束的 LLM 重试，仍失败则用模板任务。"""
        focus = state.planner.current_vuln_focus or "A01-访问控制"
        url_match = re.search(r'https?://[^\s\u4e00-\u9fff]+', state.current_goal)
        target_url = url_match.group(0).rstrip('.,;') if url_match else "http://target"

        # 提取上一轮失败的错误摘要，避免重试时犯同样错误
        recent_errors = ""
        if state.current_results:
            errs = [str(r.get("error", ""))[:80] for r in state.current_results if r.get("error") and not r.get("success")]
            if errs:
                recent_errors = f"上轮失败: {'; '.join(set(errs))[:150]}"

        # 解析失败兜底：用精简约束 prompt 让 LLM 真正生成 3 个不同任务
        # （不预填完整答案，否则 LLM 原样回吐模板、调用纯属浪费；此处只给
        # 带 <> 占位符的 schema，由 LLM 按 focus + 上轮失败原因生成代码）
        retry_prompt = (
            f"你是安全测试工程师。目标URL={target_url}，当前OWASP方向={focus}。\n"
            f"{recent_errors}\n"
            f"针对该方向生成3个HTTP测试任务（tasks数组含3个对象），必须使用不同payload/参数，"
            f"每个task的code≤8行内联Python(httpx)。根据上轮失败原因变换手法，禁止重复。\n"
            f"严格只输出JSON（无markdown无解释），结构：\n"
            f'{{"tasks":[{{"tool":"execute_python",'
            f'"arguments":{{"code":"<≤8行httpx代码>"}},'
            f'"description":"<测试值+预期观测点>"}}],'
            f'"reasoning":"规划重试","vuln_focus":"{focus}","tried_summary":"retry"}}'
        )
        try:
            content = await _llm_invoke_with_retry(self.llm, retry_prompt)
            plan = _extract_json(content)
            if plan and plan.get("tasks"):
                logger.info("planner_retry_llm_success", tasks=len(plan["tasks"]))
                return plan["tasks"]
        except Exception as e:
            logger.error("planner_retry_llm_failed", error=str(e))

        # LLM 重试也失败 → 直接用模板任务，不再调 LLM
        logger.warning("planner_using_template_task", focus=focus, target=target_url)
        return [
            {
                "tool": "execute_python",
                "arguments": {
                    "code": (
                        f"import httpx\n"
                        f"r=httpx.get('{target_url}',timeout=10,verify=False)\n"
                        f"print(r.status_code,r.text[:3000])"
                    )
                },
                "description": f"模板兜底：GET {target_url}（规划解析失败，轮次 {state.execution_round}）",
            }
        ]

    async def _executor_node(self, state: DeepAgentState) -> DeepAgentState:
        """执行节点 - 依赖排序后并行执行任务。

        并行策略：
        - 预检阶段串行（guard 防沉迷 + 指纹硬去重，保证检查逻辑顺序一致）
        - 执行阶段：无状态工具（execute_python/knowledge_*）并发（信号量 3）；
          有状态工具（execute_shell/browser_*/proxy_*）共享会话，串行队列。
        - 一轮内 ≥2 个任务回显相同 → 强制 pivot，避免同质任务烧轮次。
        """
        state = _normalize_state(state)
        logger.info("executor_start", task_count=len(state.current_tasks))

        # ── 依赖排序：有 depends_on 的任务排在依赖之后 ──────────────────
        ordered_tasks = self._topo_sort_tasks(state.current_tasks)

        # ── 预检阶段（串行）：防沉迷 + 指纹硬去重 ────────────────────────
        pending: List[Dict[str, Any]] = []
        results: List[Dict[str, Any]] = []
        for task in ordered_tasks:
            # 硬去重：工具+参数精确指纹与会话内历史一致 → 直接跳过（连执行都省）
            fp = f"{task.get('tool')}_{json.dumps(task.get('arguments', {}), sort_keys=True)}"
            if fp in self._exec_fingerprints:
                results.append({
                    "task": task,
                    "success": False,
                    "error": f"重复任务已跳过（工具+参数与历史完全一致: {fp[:80]}）",
                    "skipped_duplicate": True,
                })
                logger.warning("duplicate_task_skipped", tool=task.get("tool"), fp=fp[:60])
                continue

            is_looping, warning = self.guard.check_and_record(task)
            if is_looping:
                results.append({
                    "task": task,
                    "success": False,
                    "error": warning,
                    "anti_addiction_triggered": True,
                })
                # 强制触发 pivot，避免 planner 继续同方向
                state.planner.force_pivot = True
                logger.warning("anti_addiction_triggered", tool=task.get("tool"), warning=warning[:80])
                continue

            self._exec_fingerprints.append(fp)
            pending.append(task)

        # ── 执行阶段（并行）──
        # 无状态可并发工具；其他（shell/browser/proxy 共享会话）串行
        _PARALLEL_TOOLS = {"execute_python", "knowledge_search", "knowledge_get_detail", "knowledge_save"}
        # 各工具的超时上限（秒）：快失败避免单任务拖死整轮
        _TOOL_TIMEOUTS = {
            "execute_python": 150, "execute_shell": 90, "browser_navigate": 120,
            "browser_execute_js": 60, "browser_get_content": 60, "browser_screenshot": 60,
            "knowledge_search": 45, "knowledge_get_detail": 45, "knowledge_save": 45,
        }
        _sem = asyncio.Semaphore(3)
        _serial_lock = asyncio.Lock()

        async def run_one(task: Dict[str, Any]) -> Dict[str, Any]:
            tool = str(task.get("tool") or "")
            timeout = _TOOL_TIMEOUTS.get(tool, self.meta_executor.timeout)
            if tool in _PARALLEL_TOOLS:
                async with _sem:
                    try:
                        result = await asyncio.wait_for(self.meta_executor.execute(task), timeout=timeout)
                    except asyncio.TimeoutError:
                        result = {"success": False, "error": f"任务超时（>{timeout}s）"}
            else:
                async with _serial_lock:
                    try:
                        result = await asyncio.wait_for(self.meta_executor.execute(task), timeout=timeout)
                    except asyncio.TimeoutError:
                        result = {"success": False, "error": f"任务超时（>{timeout}s）"}
            result["task"] = task

            # ── 回显相同检测 ──────────────────────────────────────────────
            output_text = ""
            out = result.get("output")
            if isinstance(out, dict):
                output_text = str(out.get("stdout") or out.get("result") or out.get("data") or "")
            elif isinstance(out, str):
                output_text = out
            if output_text and self.guard.record_output(output_text):
                result["same_output_warning"] = (
                    f"【关键反馈】你的 {tool} 命令产生了与之前完全相同的输出，说明当前测试无效。"
                    "必须彻底改变方法：更换不同的参数、使用不同的工具或从另一个角度进行测试。"
                    "重复相同操作不会得到新结果。"
                )
                logger.warning("same_output_detected", tool=tool)
            return result

        if pending:
            exec_results = await asyncio.gather(*(run_one(t) for t in pending))
            results.extend(exec_results)

        # ── 同质化硬信号：一轮 ≥2 个相同回显 → 强制换向 ──────────────────
        same_out_count = sum(1 for r in results if r.get("same_output_warning"))
        if same_out_count >= 2:
            state.planner.force_pivot = True
            logger.warning("same_output_force_pivot", count=same_out_count)

        state.current_results = results
        state.executor.add_results(results)  # 自动限制上限 + 更新 last_result

        return state

    async def _reflector_node(self, state: DeepAgentState) -> DeepAgentState:
        """反思节点 - LLM 分析结果，判断目标完成度，触发压缩"""
        state = _normalize_state(state)
        logger.info("reflector_start", result_count=len(state.current_results))

        failures = [r for r in state.current_results if not r.get("success")]

        # 记录失败模式 / 触发 veto
        for failure in failures:
            error = failure.get("error", "")
            if error:
                state.reflector.record_failure(error)

        if failures and len(failures) > len(state.current_tasks) // 2:
            state.veto_triggered = True
            for failure in failures:
                tool = failure.get("task", {}).get("tool", "unknown")
                state.planner.rejected_strategies[tool] = failure.get("error", "执行失败")

        # LLM 反思
        if state.current_results:
            # 检查是否已经有确认的漏洞，如果有则减少重复测试
            has_confirmed_vulns = len(state.planner.confirmed_vulns) > 0

            reflection = await self._generate_reflection(state, has_confirmed_vulns)
            state.reflector.add_reflection(reflection)
            state.planner.latest_reflection = reflection

            # ── 利用链进度沉淀：关键发现 + 确认证据写入 chain_notes，
            #    供下一轮 Planner 基于已有要素继续构造多步利用──────
            _chain_new: List[str] = []
            if reflection.get("finding_level") == "confirmed" and reflection.get("confirmed_vuln"):
                cv = reflection["confirmed_vuln"]
                _chain_new.append(
                    f"[R{state.execution_round + 1}] 确认 {str(cv.get('vuln_type', ''))[:40]}: "
                    f"{str(cv.get('proof_brief', ''))[:120]} | payload: {str(cv.get('payload', ''))[:120]}"
                )
            for f in (reflection.get("key_findings") or [])[:4]:
                _chain_new.append(f"[R{state.execution_round + 1}] {str(f)[:150]}")
            if _chain_new:
                state.planner.chain_notes = (state.planner.chain_notes + _chain_new)[-16:]

            # ── 攻击资产面板结构化更新（LLM 提取，服务端按 kind+desc 去重合并；
            #    evidence 保留原文，禁止复述 → 下一轮可精确复用）─────────
            _round_no = state.execution_round + 1
            _a_keys = {f"{str(a.get('kind'))}|{str(a.get('desc'))[:60]}" for a in state.planner.assets}
            for a in (reflection.get("asset_updates") or [])[:6]:
                if not isinstance(a, dict) or not a.get("desc"):
                    continue
                _k = f"{str(a.get('kind'))}|{str(a.get('desc'))[:60]}"
                if _k in _a_keys:
                    continue
                a["round"] = _round_no
                a["evidence"] = str(a.get("evidence") or "")[:250]
                state.planner.assets.append(a)
                _a_keys.add(_k)
            state.planner.assets = state.planner.assets[-24:]

            # ── 未破门槛更新：新门槛入列、已突破的移出 ─────────────────
            _solved = {str(s)[:80] for s in (reflection.get("blockers_solved") or [])}
            if _solved:
                state.planner.blockers = [
                    b for b in state.planner.blockers
                    if str(b.get("desc"))[:80] not in _solved
                ]
            _b_keys = {str(b.get("desc"))[:80] for b in state.planner.blockers}
            for b in (reflection.get("blocker_updates") or [])[:4]:
                if not isinstance(b, dict) or not b.get("desc"):
                    continue
                if str(b.get("desc"))[:80] in _b_keys:
                    continue
                b["round"] = _round_no
                b["evidence"] = str(b.get("evidence") or "")[:250]
                state.planner.blockers.append(b)
                _b_keys.add(str(b.get("desc"))[:80])
            state.planner.blockers = state.planner.blockers[-8:]

            # ── 证据原文库自动提取（服务端，非 LLM 复述；复用智能截断保留
            #    错误码/源码片段等诊断原文，防止摘要丢细节）─────────────
            _new_ev = self._extract_evidence(state.current_results, _round_no)
            if _new_ev:
                state.planner.evidence_vault = (state.planner.evidence_vault + _new_ev)[-24:]

            # 确认漏洞 → 写入 confirmed_vulns，并标记方向完成、触发 pivot
            confirmed_vuln = reflection.get("confirmed_vuln")
            if confirmed_vuln and reflection.get("finding_level") == "confirmed":
                confirmed_vuln["round"] = state.execution_round
                if confirmed_vuln.get("vuln_type"):
                    confirmed_vuln["vuln_type"] = _norm_dir(confirmed_vuln["vuln_type"])
                existing_types = {v.get("vuln_type") for v in state.planner.confirmed_vulns}
                if confirmed_vuln.get("vuln_type") not in existing_types:
                    state.planner.confirmed_vulns.append(confirmed_vuln)
                    logger.info(
                        "confirmed_vuln_added",
                        vuln_type=confirmed_vuln.get("vuln_type"),
                        proof=confirmed_vuln.get("proof_brief"),
                    )
                    # 自动将已确认漏洞写入知识库，供后续目标测试参考
                    self._save_vuln_to_knowledge(confirmed_vuln)
                # 将当前方向标记为已完成，自动推进到下一个 Top10 方向
                current_focus = state.planner.current_vuln_focus
                if current_focus and current_focus not in state.planner.completed_directions:
                    state.planner.completed_directions.append(current_focus)
                    logger.info("direction_completed", focus=current_focus)
                # 触发 pivot 继续测下一个方向（除非 goal_achieved）
                if not reflection.get("goal_achieved"):
                    state.planner.force_pivot = True
                    state.reflector.stall_counter = 0  # 重置停滞计数

            # 目标已完成 → 标记退出（首轮不可能完成，强制忽略 LLM 的误判）
            if reflection.get("goal_achieved") and state.execution_round >= 1:
                state.should_continue = False
                logger.info("goal_achieved", round=state.execution_round)
            else:
                reflection["goal_achieved"] = False

            # 停滞检测：只有 confirmed 才算有新发现
            # stall_threshold 随 max_iterations 自动缩放，轮次少时切换更快
            stall_threshold = max(3, self.max_iterations // 6)

            # 如果已经有确认的漏洞，降低停滞阈值以更快切换
            if has_confirmed_vulns:
                stall_threshold = max(2, stall_threshold // 2)

            has_new_finding = (reflection.get("finding_level") == "confirmed")
            should_pivot = state.reflector.tick_stall(
                has_new_finding, state.planner.current_vuln_focus,
                stall_threshold=stall_threshold,
            )
            if should_pivot and not reflection.get("goal_achieved") and not state.planner.force_pivot:
                state.planner.force_pivot = True
                logger.warning(
                    "stall_detected_force_pivot",
                    focus=state.planner.current_vuln_focus,
                    stall_counter=state.reflector.stall_counter,
                    stall_threshold=stall_threshold,
                )

            # 提取 STE 经验
            successful = [r for r in state.current_results if r.get("success")]
            if successful:
                ste = await self._extract_ste_experience(state, successful[0])
                if ste:
                    state.reflector.persistent_insights.append(ste)
                    if self.ste_callback:
                        try:
                            await self.ste_callback(ste)
                        except Exception as e:
                            logger.warning("ste_callback_failed", error=str(e))

        state.execution_round += 1

        # 检查是否需要压缩上下文
        lc_messages = self._state_to_messages(state)
        if self.compressor.should_compress(lc_messages, state.execution_round):
            state.compression_needed = True

        return state

    async def _compressor_node(self, state: DeepAgentState) -> DeepAgentState:
        """压缩节点 - 压缩历史消息，保留关键上下文"""
        state = _normalize_state(state)
        logger.info("compressor_start")

        messages = self._state_to_messages(state)
        context = {
            "reflector": {
                "persistent_insights": [
                    i.model_dump() for i in state.reflector.persistent_insights[-3:]
                ]
            }
        }

        compressed = await self.compressor.compress(messages, context)
        state.messages = self._messages_to_dicts(compressed)
        state.compression_needed = False

        return state

    async def _summarizer_node(self, state: DeepAgentState) -> DeepAgentState:
        """收尾节点 - 在轮次结束前调用 LLM 生成完整测试总结报告，结果存入 state.final_report。"""
        state = _normalize_state(state)
        logger.info("summarizer_start", round=state.execution_round,
                    confirmed=len(state.planner.confirmed_vulns))

        # 已确认漏洞详情（限 1500 字符）
        confirmed_detail = json.dumps(
            state.planner.confirmed_vulns, ensure_ascii=False, indent=2
        )[:1500] if state.planner.confirmed_vulns else "无"

        # 汇总历史关键发现（最近 10 轮，每条限 100 字符，带证据级别前缀，
        # 防止 LLM 把 suspected 发现自行升级为"已确认"写入报告）
        all_findings: List[str] = []
        _level_label = {"confirmed": "已确认", "suspected": "疑似", "no_finding": "无发现"}
        for r in state.reflector.reflection_log[-10:]:
            _lv = _level_label.get(r.get("finding_level"), "未定级")
            for f in (r.get("key_findings") or []):
                all_findings.append(f"[{_lv}] {str(f)[:100]}")
            if r.get("finding_level") == "confirmed" and r.get("summary"):
                all_findings.append(f"[已确认] {r['summary'][:100]}")
        findings_text = "\n".join(f"  · {f}" for f in all_findings[-20:])[:1200] or "无"

        # STE 经验（最近 5 条）
        ste_text = "\n".join(
            f"  · {s.strategy}" for s in state.reflector.persistent_insights[-5:]
        )[:400] or "无"

        # 测试文档用例统计（计划驱动主线：按方向汇总状态，列出 found 用例）
        _plan_summary = "无"
        if state.planner.test_plan:
            _lines = []
            for d in state.planner.test_plan.get("directions", []):
                cases = d.get("cases", [])
                _stat: Dict[str, int] = {}
                for c in cases:
                    _st = str(c.get("status", "pending"))
                    _stat[_st] = _stat.get(_st, 0) + 1
                _stat_str = " ".join(f"[{k}×{v}]" for k, v in _stat.items())
                _lines.append(f"  · {d.get('direction', '?')}: {len(cases)} 用例 {_stat_str}")
                for c in cases:
                    if str(c.get("status")) == "found":
                        _lines.append(f"      - {c.get('id')}: {str(c.get('desc', ''))[:80]}")
            _plan_summary = ("\n".join(_lines)[:1500] or "无")

        # 如果已经有确认的漏洞，调整提示词以加快报告生成
        has_confirmed_vulns = len(state.planner.confirmed_vulns) > 0
        urgency_hint = ""
        if has_confirmed_vulns:
            urgency_hint = f"""
注意：已经发现了 {len(state.planner.confirmed_vulns)} 个确认的漏洞。现在需要快速生成总结报告，重点突出：
1. 已确认的漏洞及其风险等级
2. 重要的安全建议
3. 后续的修复建议
"""

        prompt = f"""你是一名专业渗透测试工程师，请对以下测试过程生成最终总结报告（中文，供甲方阅读）。

测试目标: {_real_goal(state.current_goal)}
执行轮次: {state.execution_round} 轮（计划 {state.planner.total_rounds or "未设置"} 轮，若与实际不一致请在报告中说明动态调整情况）
已完成方向: {state.planner.completed_directions}
已停滞方向: {state.planner.stalled_directions}
{urgency_hint}

━━━ 测试文档用例统计（用例状态: pending未执行/done已执行/found确认漏洞/failed失败）━━━
{_plan_summary}

━━━ 已确认漏洞 ━━━
{confirmed_detail}

━━━ 历史关键发现（每条已标注证据级别）━━━
{findings_text}

━━━ 可复用经验 ━━━
{ste_text}

━━━ 证据分级铁律（违反即不合格，必须重写）━━━
报告只能使用上方已给出的证据，严禁推断、编造 payload 或证据：
· [已确认] 仅限"已确认漏洞"区块中列出的条目（有 payload + 可复现证据）。
  若该区块为"无"，报告中不允许出现任何[已确认]漏洞，禁止把疑似升级为确认。
· [疑似] 来自"历史关键发现"中标注 [疑似] 的条目，必须写明证据不足的原因与建议验证方法。
· [无发现] 的条目不得作为漏洞写入任何章节。

请按以下结构输出（纯文本，无需JSON）：

## 一、漏洞总览
（仅[已确认]漏洞，按风险等级排列。若"已确认漏洞"区块为"无"，本节必须写"未发现达到确认标准的漏洞"，不得列出具体漏洞）

## 二、漏洞详情
（仅[已确认]漏洞：类型 / 证据 / 利用方式 / payload）

## 三、疑似风险
（全部[疑似]级发现：附上已有线索、证据不足的原因、建议验证方法）

## 四、未覆盖范围
（未完成测试的 OWASP 方向及原因）

## 五、修复建议
（[已确认]漏洞给具体修复方案；[疑似]给进一步验证建议）

## 六、测试结论
（一句话总结安全态势，必须与上方分级一致）"""


        try:
            report = await _llm_invoke_with_retry(self.llm, prompt)
            state.final_report = report
            logger.info("summarizer_done", report_len=len(report))
        except Exception as e:
            logger.error("summarizer_failed", error=str(e))
            state.final_report = self._build_fallback_report(state)

        return state

    def _build_fallback_report(self, state: DeepAgentState) -> str:
        """LLM 调用失败时的纯文本兜底报告（从状态数据直接构建，不调用 LLM）。"""
        lines = [
            "# 渗透测试总结报告（自动生成）",
            f"目标: {_real_goal(state.current_goal)}",
            f"执行轮次: {state.execution_round}",
        ]

        # 已确认漏洞
        if state.planner.confirmed_vulns:
            lines.append(f"已确认漏洞数: {len(state.planner.confirmed_vulns)}")

        lines += ["", "## 已确认漏洞"]
        if state.planner.confirmed_vulns:
            for v in state.planner.confirmed_vulns:
                lines.append(f"- [{v.get('vuln_type')}] {v.get('proof_brief')}")
                if v.get("payload"):
                    lines.append(f"  payload: {v.get('payload')}")
                if v.get("proof_detail"):
                    lines.append(f"  证据: {v.get('proof_detail')[:200]}")
        else:
            lines.append("- 未发现确认漏洞")

        # 从 executor 历史中提取测试过的工具和结果
        exec_history = state.executor.execution_history if hasattr(state.executor, "execution_history") else []
        if exec_history:
            lines += ["", "## 执行历史摘要"]
            tool_stats: Dict[str, int] = {}
            success_count = 0
            for entry in exec_history:
                if isinstance(entry, dict):
                    task = entry.get("task", {})
                    tool = task.get("tool", "unknown")
                    tool_stats[tool] = tool_stats.get(tool, 0) + 1
                    if entry.get("success"):
                        success_count += 1
            lines.append(f"- 总任务数: {len(exec_history)}，成功: {success_count}，失败: {len(exec_history) - success_count}")
            lines.append(f"- 工具分布: {dict(sorted(tool_stats.items(), key=lambda x: -x[1]))}")

        # 从 executor 最近结果中提取 stdout/stderr/error 关键线索
        if state.executor.last_result:
            lr = state.executor.last_result
            last_lines = []
            if isinstance(lr, dict):
                for key in ("stdout", "result", "data", "error"):
                    val = lr.get(key)
                    if val:
                        last_lines.append(f"{key}: {str(val)[:300]}")
            if last_lines:
                lines += ["", "## 最新结果"]
                lines.extend(f"- {l}" for l in last_lines)

        lines += ["", "## 测试方向覆盖"]
        lines.append(f"- 已完成: {state.planner.completed_directions or '无'}")
        lines.append(f"- 已停滞: {state.planner.stalled_directions or '无'}")

        # 关键发现（从 reflector 日志中提取，最近 5 轮，带证据级别前缀）
        key_findings = []
        _level_label_fb = {"confirmed": "已确认", "suspected": "疑似", "no_finding": "无发现"}
        for r in state.reflector.reflection_log[-5:]:
            _lv = _level_label_fb.get(r.get("finding_level"), "未定级")
            for f in (r.get("key_findings") or []):
                key_findings.append(f"[{_lv}] {f}")
        if key_findings:
            lines += ["", "## 关键发现（含证据级别）"]
            for f in key_findings[-10:]:
                lines.append(f"- {f}")

        # STE 经验
        if state.reflector.persistent_insights:
            lines += ["", "## 可复用经验"]
            for s in state.reflector.persistent_insights[-3:]:
                lines.append(f"- {s.strategy}")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # 路由
    # ------------------------------------------------------------------

    def _should_continue(self, state: DeepAgentState) -> Literal["continue", "compress", "summarize", "end"]:
        state = _normalize_state(state)
        _plan_total = state.planner.total_rounds or self.max_iterations

        # 轮数耗尽（计划总轮数 或 max_iterations 硬上限）→ 一律进入 summarizer 生成最终报告。
        # 原实现 max_iterations 分支返回 "end" 静默退出、吞掉总结（summarizer 自身有兜底
        # 报告且异常不抛出，"end" 兜底路径只会导致无总结收场）。
        # state.execution_round 在 reflector 节点末尾已 +1，表示"下一轮索引"，
        # 因此用 >= 判断，确保实际执行 _plan_total 轮（而非提前一轮）。
        if state.execution_round >= min(_plan_total, self.max_iterations):
            logger.info("plan_rounds_exhausted_to_summarize",
                        round=state.execution_round, total=_plan_total,
                        max_iter=self.max_iterations)
            return "summarize"

        # 目标达成 或 剩余最后一轮 → 收尾总结
        if not state.should_continue:
            logger.info("goal_achieved_to_summarize")
            return "summarize"

        # 计划驱动：测试文档全部用例达到终态（无 pending）→ 提前收尾
        # 仅当用例总数 ≥3 时启用，防止 LLM 忘记给用例导致空文档误触发
        _tp = state.planner.test_plan
        if _tp and isinstance(_tp.get("directions"), list):
            _all_cases = [c for d in _tp["directions"] for c in d.get("cases", [])]
            if len(_all_cases) >= 3 and all(str(c.get("status", "pending")) != "pending" for c in _all_cases):
                logger.info("test_plan_completed_to_summarize", round=state.execution_round,
                            cases=len(_all_cases))
                return "summarize"

        if state.compression_needed:
            return "compress"

        if state.veto_triggered:
            state.veto_triggered = False
            return "continue"

        return "continue"

    # ------------------------------------------------------------------
    # LLM 辅助方法
    # ------------------------------------------------------------------

    async def _generate_reflection(self, state: DeepAgentState, has_confirmed_vulns: bool = False) -> Dict[str, Any]:
        """调用 LLM 生成反思，判断目标是否达成。"""
        success_results = [r for r in state.current_results if r.get("success")]
        failed_results = [r for r in state.current_results if not r.get("success")]

        # 只取最近 3 条结果，每条限 1500 字符，附带诊断元数据
        def _brief(results, key, max_len=1500, max_items=3):
            out = []
            for r in results[:max_items]:
                raw_val = r.get(key, "")
                task = r.get("task", {})
                task_desc = task.get("description", "")[:80]
                tool = task.get("tool", "")

                # 诊断元数据：执行时间、状态码、输出长度
                meta = {}
                if isinstance(raw_val, dict):
                    et = raw_val.get("execution_time")
                    if et:
                        meta["exec_time"] = f"{et:.1f}s"
                    sc = raw_val.get("status_code")
                    if sc:
                        meta["status_code"] = str(sc)
                    resp_len = len(raw_val.get("stdout", "") or raw_val.get("content", "") or "")
                    if resp_len:
                        meta["resp_len"] = str(resp_len)

                if isinstance(raw_val, dict):
                    if "image_note" in raw_val:
                        val = raw_val["image_note"]
                    elif "content" in raw_val:
                        val = raw_val.get("content", "")[:max_len]
                    else:
                        stdout  = raw_val.get("stdout")  or ""
                        stderr  = raw_val.get("stderr")  or ""
                        error   = raw_val.get("error")   or ""
                        result_ = raw_val.get("result")  or ""
                        data    = raw_val.get("data")    or ""
                        if stdout:
                            val = stdout[:max_len]
                        elif result_:
                            val = str(result_)[:max_len]
                        elif data:
                            val = str(data)[:max_len]
                        elif stderr:
                            val = stderr[:max_len]
                        elif error:
                            val = f"[error] {error[:max_len]}"
                        else:
                            parts = []
                            for k, v in raw_val.items():
                                if k in ("image_base64",):
                                    continue
                                parts.append(f"{k}={str(v)[:100]}")
                            val = "; ".join(parts)[:max_len]
                else:
                    val = str(raw_val)[:max_len]

                entry = {"tool": tool, "task": task_desc, key: val}
                if meta:
                    entry["meta"] = " | ".join(f"{k}={v}" for k, v in meta.items())
                out.append(entry)
            return out

        # 从 enriched_goal 提取纯目标文本（去掉会话历史前缀）
        real_goal = _real_goal(state.current_goal)

        # 如果已经有确认的漏洞，调整提示词以加快收敛
        additional_guidance = ""
        if has_confirmed_vulns:
            additional_guidance = """
注意：已经发现了确认的漏洞，现在应该：
1. 优先探索其他类型的漏洞（A01-A10的其他方向）
2. 如果当前方向已确认漏洞，应尽快切换到新方向
3. 避免在已确认漏洞的方向上进行过多重复测试
"""

        prompt = f"""你是一名严谨的渗透测试工程师，深度分析本轮测试结果，提取有价值的发现。

目标: {real_goal}
执行轮次: {state.execution_round}
当前漏洞方向: {state.planner.current_vuln_focus or "未指定"}
已完成方向: {state.planner.completed_directions}
已停滞方向: {state.planner.stalled_directions}
已确认漏洞数: {len(state.planner.confirmed_vulns)}

{additional_guidance}

成功({len(success_results)}):
{json.dumps(_brief(success_results, "output", max_len=3000, max_items=8), ensure_ascii=False, indent=2)}

失败({len(failed_results)}):
{json.dumps(_brief(failed_results, "error", max_len=800, max_items=8), ensure_ascii=False, indent=2)}

注意：每条结果包含 tool（工具名）、meta（执行时间/状态码/响应长度等诊断信息），请结合这些元数据分析失败原因。

━━━ 漏洞证据判断标准（严格执行）━━━
confirmed（已确认）— 必须同时满足：
  · 有明确的技术证据（报错含 SQL 关键词 / SLEEP 延迟≥5s / 成功提取数据库数据 /
    未授权访问到真实敏感内容 / SSRF 收到外联回调 / JWT alg:none 被接受）
  · 证据与 payload 有直接因果关系，可复现

suspected（疑似）— 有迹象但缺乏确定性证据：
  · 响应有差异但未获取实质数据
  · 存在注入入口但被过滤，尚未成功提取
  ⚠️ suspected 不算完成，下一轮必须继续深挖获取确定性证据

no_finding — 结果为空、无响应差异、工具失败
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

判断规则：
1. confirmed 漏洞 → has_new_finding=true，填写 confirmed_vuln 详情
2. suspected → has_new_finding=false，在 next_direction 中说明需要继续的具体方向，并在 next_payloads 中给出3个具体可执行的 payload 变体
3. no_finding → has_new_finding=false，next_payloads 给出换方向的思路或下一种注入类型
4. ⚠️ goal_achieved 触发条件（缺一不可）：
   - 所有适用方向（A01-A10 中未被预筛排除的不适用方向）均已被思考过
   - 每个适用方向要么有 confirmed 证据，要么已被确认无漏洞（stalled 或 completed）
   - 未完成（适用）方向数 = 0
   - ⛔ 仅找到一个漏洞不能触发 goal_achieved：必须把所有适用方向都覆盖完（confirmed 或 stalled/completed），单点确认不构成测试完成
5. 【轮数建议】rounds_suggestion 基于本轮进展评估总轮数是否需要调整：
   - extend：confirmed 漏洞需深挖提取 / 当前方向刚出现有效响应且 pending 用例充足
   - shrink：连续无发现且被拒策略堆积 / 剩余 pending 均为低价值重复
   - keep：进展正常，按既定轮数推进
6. 【组合利用沉淀】资产面板/门槛/下一跳是跨轮组合利用的关键，必须如实填写：
   - asset_updates：本轮新获得且未来可利用的资产（获取到的源码/接口/参数/凭据/cookie/
     可用的注入原语/文件读原语/已识别的过滤规则等），desc 一句话说清"这是什么牌"，
     evidence 必须粘贴结果原文片段（不要复述）
   - blocker_updates：本轮遇到但未突破的门槛（过滤/权限/二次校验），下一轮必须继续攻
   - blockers_solved：本轮已突破的门槛（与 blocker_updates 的 desc 对应）
   - suggested_next_steps：基于已有资产的组合利用下一跳候选（如"用已读到的源码中
     X 函数的过滤缺陷，构造 Y 绕过读取 flag.php"），供 Planner 优先采纳

请以 JSON 格式输出:
{{
    "summary": "本轮测试摘要（必须含：状态码/响应长度/关键响应片段/延迟时间，不要只写结论）",
    "goal_achieved": false,
    "has_new_finding": false,
    "finding_level": "confirmed | suspected | no_finding",
    "rounds_suggestion": {{"action": "extend | shrink | keep", "reason": "调整理由（一句话）"}},
    "confirmed_vuln": {{
        "vuln_type": "漏洞类型（如 A03-SQL注入）",
        "proof_brief": "证据一句话（如：SLEEP(5) 触发 5.2s 延迟，确认时间盲注）",
        "proof_detail": "完整证据（响应片段/报错内容/数据/延迟时间）",
        "payload": "使用的 payload"
    }},
    "key_findings": ["发现要点1（含具体状态码/响应长度/片段）", "要点2"],
    "next_direction": "下一步方向（suspected时必须说明：哪个参数/位置/注入类型还未测）",
    "next_payloads": ["具体 payload 变体1", "具体 payload 变体2", "具体 payload 变体3"],
    "asset_updates": [{{"kind": "endpoint|param|source-code|credential|cookie|filter-rule|injection-primitive|file-read-primitive|other", "desc": "一句话", "evidence": "结果原文片段"}}],
    "blocker_updates": [{{"desc": "一句话", "evidence": "结果原文片段"}}],
    "blockers_solved": ["已突破门槛的 desc"],
    "suggested_next_steps": ["下一跳候选1", "下一跳候选2"]
}}"""

        try:
            # 判定类调用使用低温：漏洞证据判定需要稳定可复现，避免同样证据一次 confirmed 一次 no_finding
            content = await _llm_invoke_with_retry(self.llm, prompt, temperature=0.2)
            data = _extract_json(content) or {}
        except Exception as e:
            logger.error("reflection_llm_failed", error=str(e))
            data = {}

        # ── 字段校验：LLM 返回的 finding_level 必须是枚举值之一 ──
        _VALID_LEVELS = {"confirmed", "suspected", "no_finding"}
        raw_level = data.get("finding_level", "")
        if raw_level not in _VALID_LEVELS:
            if raw_level:
                logger.warning("reflection_invalid_level", level=raw_level, fallback="no_finding")
            data["finding_level"] = "no_finding"

        # ── 代码校验 goal_achieved：LLM 不可信，必须满足以下条件才真正结束 ──
        _ALL_DIRECTIONS = {"A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"}
        _done_dirs = set(state.planner.completed_directions) | set(state.planner.stalled_directions)
        _covered = {d[:3] for d in _done_dirs}
        # 目标校验集 = 预筛后的适用方向（applicable_directions）；若未预筛则默认全 10。
        # 否则被预筛排除的不适用方向永远不进 completed/stalled，issubset 恒 False，
        # goal_achieved 永不触发、agent 只能跑到 max_iter。
        _applicable = state.planner.applicable_directions
        _required = {d[:3] for d in _applicable} if _applicable else _ALL_DIRECTIONS
        _goal_achieved_safe = _required.issubset(_covered)
        # 如果 LLM 说完成但条件不满足，强制设为 False
        if data.get("goal_achieved") and not _goal_achieved_safe:
            logger.info("goal_achieved_blocked_by_check",
                        covered=list(_covered),
                        remaining=list(_required - _covered))
            data["goal_achieved"] = False

        return {
            "round": state.execution_round,
            "success_count": len(success_results),
            "failure_count": len(failed_results),
            "summary": data.get(
                "summary",
                f"执行了 {len(state.current_tasks)} 个任务，成功 {len(success_results)} 个",
            ),
            "goal_achieved": data.get("goal_achieved", False),
            "has_new_finding": data.get("has_new_finding", False),
            "finding_level": data.get("finding_level", "no_finding"),
            "confirmed_vuln": data.get("confirmed_vuln"),
            "key_findings": data.get("key_findings", []),
            "next_direction": data.get("next_direction"),
            "next_payloads": data.get("next_payloads", []),
            # 动态轮数建议（透传给下一轮 Planner 决策参考）
            "rounds_suggestion": data.get("rounds_suggestion") if isinstance(data.get("rounds_suggestion"), dict) else None,
            # 组合利用：结构化资产/门槛/下一跳（透传给状态沉淀逻辑）
            "asset_updates": data.get("asset_updates", []) if isinstance(data.get("asset_updates"), list) else [],
            "blocker_updates": data.get("blocker_updates", []) if isinstance(data.get("blocker_updates"), list) else [],
            "blockers_solved": data.get("blockers_solved", []) if isinstance(data.get("blockers_solved"), list) else [],
            "suggested_next_steps": data.get("suggested_next_steps", []) if isinstance(data.get("suggested_next_steps"), list) else [],
        }

    async def _extract_ste_experience(
            self,
            state: DeepAgentState,
            successful_result: Dict[str, Any],
    ) -> Optional[STEExperience]:
        """调用 LLM 从成功执行中提取 STE 经验。"""
        task = successful_result.get("task", {})
        output = str(successful_result.get("output", ""))[:500]

        prompt = f"""从以下成功的工具执行中提取可复用的 STE（Strategy-Tactics-Example）经验。

目标: {_real_goal(state.current_goal, max_len=200)}
工具: {task.get("tool")}
参数: {json.dumps(task.get("arguments", {}), ensure_ascii=False)}
描述: {task.get("description", "")}
输出: {output}

请以 JSON 格式输出:
{{
    "strategy": "高层次战略原则（一句话）",
    "tactics": ["战术步骤1", "步骤2"],
    "example": "简短具体示例",
    "applicable_scenarios": ["适用场景标签1", "标签2"]
}}"""

        try:
            content = await _llm_invoke_with_retry(self.llm, prompt)
            data = _extract_json(content)
            if not data:
                return None
            return STEExperience(
                strategy=data.get("strategy", "使用工具完成任务"),
                tactics=data.get("tactics", [f"调用 {task.get('tool')}"]),
                example=data.get("example", f"成功调用 {task.get('tool')}"),
                applicable_scenarios=data.get("applicable_scenarios", []),
            )
        except Exception as e:
            logger.error("ste_extraction_failed", error=str(e))
            return None

    # ------------------------------------------------------------------
    # 工具方法
    # ------------------------------------------------------------------

    async def _analyze_target_directions(self, state: DeepAgentState) -> None:
        """第一轮启动时，快速分析 URL 特征，筛选适用的 OWASP Top10 方向。"""
        url_match = re.search(r'https?://[^\s\u4e00-\u9fff]+', state.current_goal)
        target_url = url_match.group(0) if url_match else ""

        _all = list(_OWASP_DIRECTIONS)
        excluded = set()

        # 规则引擎先行：根据 URL 特征快速排除明显不适用的方向
        has_login = any(kw in state.current_goal for kw in ["login", "signin", "登录", "认证", "auth", "password"])
        if not has_login and target_url:
            parsed = target_url.split("/")[-1].lower()
            if not any(kw in parsed for kw in ["login", "signin", "auth", "admin", "user", "account"]):
                excluded.add("A07-身份认证失败")

        remaining = [d for d in _all if d not in excluded]

        if excluded:
            # LLM 快速确认排除是否合理
            prompt = f"""分析以下目标，判断是否需要排除任何 OWASP 测试方向。
目标: {state.current_goal[:200]}
URL: {target_url}
可能排除: {list(excluded)}
如果排除合理，输出"确认"；如果需要额外保留某方向，输出需保留的方向编号。只输出结果。"""
            try:
                result = await _llm_invoke_with_retry(self.llm, prompt, temperature=0.2)
                if "确认" in result:
                    state.planner.applicable_directions = remaining
                else:
                    state.planner.applicable_directions = _all
            except Exception:
                state.planner.applicable_directions = remaining
        else:
            state.planner.applicable_directions = _all

        # ── 加载跨会话历史经验（从知识库持久化数据恢复）───────────────
        await self._load_session_context(state, target_url)

    async def _load_session_context(self, state: DeepAgentState, target_url: str = "") -> None:
        """从知识库加载历史经验和漏洞记录，注入到 planner context。
        根据目标特征（技术栈/框架/路径/目标描述）智能检索相关经验，而非直接搜索 URL。
        """
        if not self.knowledge_router:
            return
        try:
            router = self.knowledge_router
            exp_count = router.get_experience_count()
            vuln_count = router.get_vuln_count()
            if exp_count == 0 and vuln_count == 0:
                return

            # ── 提取目标特征，构建智能搜索 query ──────────────────
            search_queries = self._extract_target_features(state.current_goal, target_url)

            # 加载历史 STE 经验（按特征多轮搜索，取最相关的 5 条）
            all_exp = []
            for query in search_queries:
                experiences = router.load_experience_for_target(query, limit=3)
                all_exp.extend(experiences)
            # 去重 + 截断
            seen_ids = set()
            unique_exp = []
            for exp in all_exp:
                eid = exp.get("id")
                if eid and eid not in seen_ids:
                    seen_ids.add(eid)
                    unique_exp.append(exp)

            if unique_exp:
                for exp in unique_exp[:5]:
                    content = exp.get("content", "")
                    meta = exp.get("metadata", {})
                    strategy = meta.get("strategy", "") or content[:80]
                    tags = meta.get("tags", "")
                    entry = f"历史经验: {strategy}"
                    if tags:
                        entry += f" [标签: {tags}]"
                    state.planner.long_term_goals.append(entry)
                if len(state.planner.long_term_goals) > 10:
                    state.planner.long_term_goals = state.planner.long_term_goals[-10:]

            # 加载历史确认漏洞（按特征搜索）
            all_vulns = []
            for query in search_queries:
                vulns = router.load_vulns_for_target(query, limit=3)
                all_vulns.extend(vulns)
            seen_vulns = set()
            unique_vulns = []
            for v in all_vulns:
                vid = v.get("id")
                if vid and vid not in seen_vulns:
                    seen_vulns.add(vid)
                    unique_vulns.append(v)

            if unique_vulns:
                logger.info("cross_session_loaded", experiences=len(unique_exp),
                           vulns=len(unique_vulns), queries=search_queries)
        except Exception as e:
            logger.warning("load_session_context_failed", error=str(e))

    def _extract_target_features(self, goal: str, url: str = "") -> list:
        """从目标描述和 URL 中提取多维度搜索特征，用于知识库智能检索。"""
        queries = []

        # 1. URL 特征：域名、路径关键词
        if url:
            domain = url.split("/")[2] if "://" in url else url.split("/")[0]
            # 去掉协议和端口
            domain = domain.split(":")[0]
            path = "/".join(url.split("/")[3:])
            queries.append(domain)
            if path:
                # 从路径提取关键词（如 login, admin, api, upload）
                path_keywords = [p for p in path.lower().split("/") if len(p) > 2]
                if path_keywords:
                    queries.append(" ".join(path_keywords))

        # 2. 目标描述中的技术栈关键词
        tech_patterns = [
            r'(\w+(?:CMS|Java|PHP|Node\.js|Spring|Django|Flask|WordPress|React|Vue|Nginx|Apache|MySQL|PostgreSQL|Redis|MongoDB|Docker|K8s))',
            r'(JSP|ASP|ASPX|PHP|Python|Java|Node)',
        ]
        import re
        for pat in tech_patterns:
            matches = re.findall(pat, goal, re.IGNORECASE)
            queries.extend(matches)

        # 3. 业务场景关键词（登录/注册/支付/上传/管理后台等）
        biz_keywords = [kw for kw in re.findall(r'(登录|注册|支付|上传|下载|管理后台|admin|login|api|接口|用户|表单|搜索|导出)', goal)]
        if biz_keywords:
            queries.append(" ".join(biz_keywords))

        # 4. 兜底：完整 goal
        queries.append(goal[:150])

        # 去重 + 限制
        seen = set()
        unique = []
        for q in queries:
            q = q.strip()
            if q and q not in seen:
                seen.add(q)
                unique.append(q)
        return unique[:6]  # 最多 6 个特征 query

    def _topo_sort_tasks(self, tasks: list) -> list:
        """任务拓扑排序：支持 depends_on 字段（1-based 索引）。"""
        # 无依赖的任务直接按原顺序，有依赖的排在依赖之后
        independent = []
        dependent = []
        for task in tasks:
            if task.get("depends_on"):
                dependent.append(task)
            else:
                independent.append(task)
        return independent + dependent

    def _build_planner_summary(self, state: DeepAgentState) -> str:
        summary = []

        # ── 上一轮实际执行结果（含关键响应片段，让 LLM 看到服务端真实返回）──
        if state.current_results:
            result_lines = []
            for r in state.current_results[:4]:
                task_desc = r.get("task", {}).get("description", "")[:50]
                if r.get("success"):
                    out = r.get("output", {})
                    if isinstance(out, dict):
                        text = (out.get("stdout") or out.get("result") or
                                out.get("data") or out.get("content") or "")
                    else:
                        text = str(out)
                    # 优先截取含关键字的片段
                    text = str(text)
                    snippet = text[:150]
                    result_lines.append(f"  ✓ {task_desc} → {snippet}")
                else:
                    err = str(r.get("error", ""))[:100]
                    warn = r.get("same_output_warning", "")
                    extra = f" [{warn}]" if warn else ""
                    result_lines.append(f"  ✗ {task_desc} → {err}{extra}")
            summary.append("上一轮结果:\n" + "\n".join(result_lines))

        # ── 最新反思（含具体下一步建议）──────────────────────────────────
        if state.planner.latest_reflection:
            refl = state.planner.latest_reflection
            summary.append(f"反思({refl.get('finding_level','?')}): {refl.get('summary','')[:120]}")
            if refl.get("key_findings"):
                summary.append(f"关键发现: {refl['key_findings'][:3]}")
            if refl.get("next_direction"):
                summary.append(f"下一步: {refl['next_direction']}")
            if refl.get("next_payloads"):
                summary.append(f"建议payload: {refl['next_payloads'][:3]}")

        # ── 上上轮反思（帮助 LLM 看出趋势）──────────────────────────────
        if len(state.reflector.reflection_log) >= 2:
            prev = state.reflector.reflection_log[-2]
            summary.append(f"上上轮({prev.get('finding_level','?')}): {prev.get('summary','')[:120]}")

        if state.planner.confirmed_vulns:
            types = [v.get("vuln_type") for v in state.planner.confirmed_vulns]
            summary.append(f"已确认漏洞: {types}")

        if state.planner.completed_directions:
            summary.append(f"已完成方向: {state.planner.completed_directions}")

        if state.reflector.persistent_insights:
            recent_insights = state.reflector.persistent_insights[-3:]
            insight_lines = [f"  · {s.strategy} | 场景: {s.applicable_scenarios[:3]}" for s in recent_insights]
            summary.append(f"可复用经验:\n" + "\n".join(insight_lines))

        return "\n".join(summary) if summary else "无历史"

    def _state_to_messages(self, state: DeepAgentState) -> List:
        from langchain_core.messages import HumanMessage, AIMessage, SystemMessage

        messages = [SystemMessage(content="You are a capable Deep Agent.")]
        for msg in state.messages:
            role = msg.get("role", "")
            content = msg.get("content", "")
            if role == "user":
                messages.append(HumanMessage(content=content))
            elif role == "assistant":
                messages.append(AIMessage(content=content))
        return messages

    def _messages_to_dicts(self, messages: List) -> List[Dict[str, Any]]:
        result = []
        for msg in messages:
            role = "system"
            if hasattr(msg, "type"):
                if msg.type == "human":
                    role = "user"
                elif msg.type == "ai":
                    role = "assistant"
            content = msg.content if hasattr(msg, "content") else str(msg)
            result.append({"role": role, "content": content})
        return result

    def _save_vuln_to_knowledge(self, vuln: Dict[str, Any]) -> None:
        """将已确认漏洞自动写入知识库，供未来类似目标参考。
        存储目标特征（域名/路径/技术栈），便于后续智能检索匹配。
        """
        if not self.knowledge_router:
            return
        try:
            content = (
                f"漏洞类型: {vuln.get('vuln_type', '')}\n"
                f"证据: {vuln.get('proof_detail', vuln.get('proof_brief', ''))}\n"
                f"Payload: {vuln.get('payload', '')}\n"
                f"轮次: {vuln.get('round', '')}"
            )
            # 提取目标特征作为元数据，便于后续按特征检索
            target_features = self._extract_target_features(
                vuln.get("target", ""), vuln.get("url", "")
            )
            doc_id = self.knowledge_router.save(
                content=content,
                title=f"已确认: {vuln.get('vuln_type', '')} - {vuln.get('proof_brief', '')[:60]}",
                category="general",
                tags=["confirmed_vuln", vuln.get("vuln_type", "")] + target_features[:3],
                extra_meta={
                    "vuln_type": vuln.get("vuln_type", ""),
                    "payload": vuln.get("payload", ""),
                    "features": " ".join(target_features),
                },
            )
            if doc_id:
                logger.info("vuln_saved_to_knowledge", doc_id=doc_id, vuln_type=vuln.get("vuln_type"))
        except Exception as e:
            logger.warning("vuln_save_to_knowledge_failed", error=str(e))

    # ------------------------------------------------------------------

    def _fetch_knowledge_payloads(self, vuln_focus: str) -> str:
        """多路检索知识库：按方向+目标特征查静态 payload + 动态经验 + Nuclei CVE + 历史漏洞，合并去重后返回。

        会话内缓存：同一方向前缀只检索一次（每轮 Planner 都会调用本方法，
        重复 chroma 检索浪费 2-4 秒 × 4 分类，缓存后仅首轮付出成本）。
        """
        if not self.knowledge_router or not vuln_focus:
            return ""
        cache_key = vuln_focus.strip()[:3]
        if cache_key in self._kb_cache:
            return self._kb_cache[cache_key]
        _FOCUS_QUERY = {
            "A01": "access control bypass unauthorized IDOR privilege escalation",
            "A02": "weak encryption TLS plaintext sensitive data",
            "A03": "SQL injection union select sleep error based blind",
            "A04": "insecure design business logic flaw negative price",
            "A05": "security misconfiguration .env .git phpinfo actuator debug",
            "A06": "CVE exploit known vulnerability component version",
            "A07": "authentication bypass weak password brute force token",
            "A08": "JWT none algorithm HMAC deserialization gadget",
            "A09": "log injection audit bypass",
            "A10": "SSRF internal metadata 169.254 dnslog ceye",
        }
        key = vuln_focus[:3]
        base_query = _FOCUS_QUERY.get(key, vuln_focus)
        try:
            all_results = []
            # 1. 静态 payload（按方向关键词搜索）
            static = self.knowledge_router.search(base_query, category="payloads", limit=2)
            all_results.extend(static)

            # 2. Nuclei CVE 模板（A06 方向优先）
            if key == "A06":
                cve_results = self.knowledge_router.search(base_query, category="nuclei", limit=3)
                all_results.extend(cve_results)

            # 3. 动态经验：按 vuln_focus + 方向特征搜索
            exp = self.knowledge_router.search(vuln_focus, category="experience", limit=2)
            all_results.extend(exp)

            # 4. 历史确认漏洞：按方向关键词搜索
            vulns = self.knowledge_router.search(base_query, category="general", limit=2)
            all_results.extend(vulns)

            # 去重 + 截断
            seen = set()
            unique = []
            for r in all_results:
                sig = (r.get("id") or "")[:32] + (r.get("content", "") or "")[:40]
                if sig and sig not in seen:
                    seen.add(sig)
                    unique.append(r)

            lines = []
            for r in unique[:4]:
                content = (r.get("content") or "")[:160]
                title = (r.get("title") or "")[:40]
                if content:
                    tag = r.get("type", r.get("category", ""))
                    lines.append(f"· [{tag}] {title}: {content}")
            result = "\n".join(lines)[:500]
            self._kb_cache[cache_key] = result
            if len(self._kb_cache) > 12:
                self._kb_cache.pop(next(iter(self._kb_cache)))
            return result
        except Exception:
            return ""

    # ── secknowledge 手册确定性注入（静态文件按需读，不进 ChromaDB）────
    def _pick_skill_files(self, vuln_focus: str, task_desc: str) -> List[str]:
        """按当前方向 + 任务描述关键词确定要注入的 skill 手册文件名。"""
        files: List[str] = []
        if vuln_focus:
            f = _SKILL_BY_DIR.get(vuln_focus.strip()[:3])
            if f and f not in files:
                files.append(f)
        low = (task_desc or "").lower()
        for pattern, f in _SKILL_KEYWORD_FILES:
            if re.search(pattern, low) and f not in files:
                files.append(f)
        return files[:2]

    def _read_skill_snippet(self, filename: str, max_chars: int = 1000) -> str:
        """读取 secknowledge 手册并提取 payload/绕过相关片段（带内容缓存）。

        大文件不整读：优先定位 Payload/Bypass/POC 章节，取其后 max_chars 字符；
        找不到则取文件头部，保证注入内容高密度可执行。
        """
        if filename in self._skill_cache:
            return self._skill_cache[filename]
        path = os.path.join(_SECKNOWLEDGE_DIR, "references", filename)
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception as e:
            logger.warning("skill_file_read_failed", file=filename, error=str(e))
            self._skill_cache[filename] = ""
            return ""
        if not content:
            self._skill_cache[filename] = ""
            return ""
        # 定位高价值章节：Payload / Bypass / POC / 利用
        m = re.search(
            r"^#{1,4}\s*[^\n]*(payload|绕过|bypass|poc|利用|exploit)[^\n]*$",
            content, re.IGNORECASE | re.MULTILINE,
        )
        start = m.start() if m else 0
        snippet = content[start:start + max_chars * 3]  # 章节后 3 倍窗口
        snippet = snippet[:max_chars * 2]              # 实际输出最多 2 倍
        # 去掉空行压缩，保留 markdown 结构
        snippet = re.sub(r"\n{3,}", "\n\n", snippet).strip()
        snippet = snippet[:max_chars]
        self._skill_cache[filename] = snippet
        return snippet

    def _fetch_skill_payloads(self, vuln_focus: str, task_desc: str) -> str:
        """确定性注入 skill 手册精选片段到 Planner 提示词。"""
        files = self._pick_skill_files(vuln_focus or "", task_desc or "")
        if not files:
            return ""
        parts = []
        for f in files:
            snip = self._read_skill_snippet(f)
            if snip:
                parts.append(f"—— 《{f}》 ——\n{snip}")
        if not parts:
            return ""
        return (
            "\n━━━ 渗透 skill 手册精选（已注入，直接使用其中 payload/绕过，无需再 cat 读取）━━━\n"
            + "\n\n".join(parts) + "\n"
        )[:2400]

    _EVIDENCE_SOURCE_PAT = re.compile(
        r"<\?php|class\s+\w+|function\s+\w+|def\s+\w+|preg_match"
        r"|file_get_contents|unserialize|SELECT\s|UNION\s|flag\{|token|session"
        r"|cookie|authorization|base64_decode|system\s*\(|eval\s*\(",
        re.IGNORECASE,
    )

    def _extract_evidence(self, results: List[Dict[str, Any]], round_no: int) -> List[Dict[str, Any]]:
        """服务端自动提取本轮执行结果中的高价值证据原文（防摘要丢细节）。

        复用 meta_executor 的漏洞关键词智能截断，保留错误码/源码片段/
        响应差异等诊断原文；实例级去重（前 60 字符指纹）防跨轮重复。
        仅收录"有信号"的输出：命中漏洞关键词或源码特征的较长输出。
        """
        from .mcp.executors.meta_executor import _VULN_KEYWORDS, _smart_trim

        evs: List[Dict[str, Any]] = []
        for r in results or []:
            out = r.get("output") or r.get("stdout") or r.get("result") or ""
            if isinstance(out, dict):
                out = json.dumps(out, ensure_ascii=False)
            text = str(out)
            if len(text) < 40 or len(text) > 20000:
                continue
            low = text.lower()
            has_signal = any(kw in low for kw in _VULN_KEYWORDS) \
                or bool(self._EVIDENCE_SOURCE_PAT.search(text))
            if not has_signal:
                continue
            fp = text[:60]
            if fp in self._evidence_seen:
                continue
            self._evidence_seen.add(fp)
            self._evidence_id += 1
            kind = "source" if self._EVIDENCE_SOURCE_PAT.search(text) else "response"
            evs.append({
                "id": self._evidence_id,
                "kind": kind,
                "content": _smart_trim(text, 500),
                "round": round_no,
            })
        return evs

    # ------------------------------------------------------------------
    # 入口
    # ------------------------------------------------------------------

    async def run(self, goal: str, thread_id: str = "default") -> Dict[str, Any]:
        # PER 循环每轮消耗 3 步（planner/executor/reflector），LangGraph 默认 recursion_limit=25
        # 只够约 8 轮，max_iterations 较大时必须显式放大，否则抛 GRAPH_RECURSION_LIMIT 错误
        config = {
            "configurable": {"thread_id": thread_id},
            "recursion_limit": max(40, self.max_iterations * 3 + 15),
        }
        initial_state = DeepAgentState(
            current_goal=goal,
            messages=[{"role": "user", "content": goal}],
        )

        final_state = None
        async for event in self.app.astream(initial_state, config):
            for node_name, state in event.items():
                logger.debug("node_completed", node=node_name)
                final_state = state

        return final_state
