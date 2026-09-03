#!/usr/bin/env python3
"""
DeepAgent 聊天服务器

启动:
    cd /path/to/langGraph
    python deepagent/chat_server.py
    python deepagent/chat_server.py --port 8888 --debug

访问:
    http://localhost:8000
"""

import argparse
import asyncio
import json
import logging as _logging
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

# ── 路径 ──────────────────────────────────────────────────────────────────────
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

# Windows 控制台默认 GBK，structlog 输出 emoji/特殊符号会 UnicodeEncodeError，
# 导致 agent 节点崩溃。方案：配置 structlog 同时写文件（UTF-8）和控制台（replace 容错）。
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent / ".env", override=True)
except ImportError:
    pass

os.environ["ANONYMIZED_TELEMETRY"] = "false"
_logging.getLogger("chromadb.telemetry.product.posthog").setLevel(_logging.CRITICAL)

import structlog
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

logger = structlog.get_logger(__name__)

# ── 全局组件（启动时初始化一次，所有会话共享）────────────────────────────────
_llm = None
_executors: Optional[Dict[str, Any]] = None
_config: Optional[Dict[str, Any]] = None

# ── 会话记忆：session_id -> 对话历史列表 [{"goal", "summary", "findings"}]
_session_memory: Dict[str, list] = {}

# ── 会话记忆磁盘持久化：服务重启后仍能恢复"同窗口对话的记忆"──────────────
_CHAT_STATE_DIR = Path(__file__).parent / ".chat_state"
_SESSION_MEMORY_FILE = _CHAT_STATE_DIR / "session_memory.json"


def _load_session_memory() -> None:
    """启动时从磁盘恢复会话记忆（服务重启/崩溃后继续可用）。"""
    try:
        if _SESSION_MEMORY_FILE.exists():
            data = json.loads(_SESSION_MEMORY_FILE.read_text(encoding="utf-8"))
            for k, v in (data or {}).items():
                if isinstance(v, list):
                    _session_memory[str(k)] = [t for t in v if isinstance(t, dict)][-10:]
    except Exception as e:
        logger.warning("session_memory_load_failed", error=str(e))


def _save_session_memory() -> None:
    try:
        _CHAT_STATE_DIR.mkdir(parents=True, exist_ok=True)
        _SESSION_MEMORY_FILE.write_text(
            json.dumps(_session_memory, ensure_ascii=False, indent=1), encoding="utf-8"
        )
    except Exception as e:
        logger.warning("session_memory_save_failed", error=str(e))


def _append_session_memory(session_id: str, goal: str, summary: str, findings: list, attack_state: Optional[dict] = None) -> None:
    """任务完成后记账：写入内存 + 磁盘，供同会话的下一轮提问携带记忆。

    attack_state: 本轮任务的结构化战果（确认漏洞/资产面板/未破门槛等），
    让下一轮提问"结合上次测试结果"而非仅凭摘要文本从零开始。
    """
    mem = _session_memory.setdefault(session_id, [])
    turn = {
        "goal": goal,
        "summary": summary or f"（第 {len(mem) + 1} 轮任务已完成）",
        "findings": findings,
    }
    if attack_state:
        turn["attack_state"] = attack_state
    mem.append(turn)
    # 最多保留最近 10 轮
    if len(mem) > 10:
        _session_memory[session_id] = mem[-10:]
    _save_session_memory()


_load_session_memory()

# ── 正在运行的任务：session_id -> asyncio.Task（用于打断）
_running_tasks: Dict[str, asyncio.Task] = {}

# ── 正在运行的 agent 实例：session_id -> DeepAgent（用于运行时注入 steer 纠偏指令）
_running_agents: Dict[str, Any] = {}

# ── 协作式停止标志：session_id -> asyncio.Event（打断时置位，_run_agent 在
#    每个流事件处检查并主动退出，配合 task.cancel() 双保险）
_session_stops: Dict[str, asyncio.Event] = {}

# ── 会话级事件广播（解决"刷新后任务进度丢失/重连后卡住"）───────────────────
#   _session_events: session_id -> 累积的进度事件列表（start/progress/test_plan/done）
#   _session_subs:   session_id -> set[WebSocket]（该会话当前所有活跃连接）
# 设计：agent 进度事件广播到会话的所有连接并写入缓冲；新连接建立时回放缓冲，
#       WebSocket 断开不再 cancel 任务，任务继续跑完、结果留痕。
_session_events: Dict[str, list] = {}
_session_subs: Dict[str, set] = {}

_EVENT_HISTORY_MAX = 600  # 历史事件上限，超出滚动保留（防止长任务内存膨胀）


async def _broadcast(session_id: str, event: dict) -> None:
    """将事件广播给该会话所有活跃连接，并写入 session 级缓冲供新连接回放。"""
    payload = json.dumps(event, ensure_ascii=False)
    buf = _session_events.setdefault(session_id, [])
    buf.append(event)
    if len(buf) > _EVENT_HISTORY_MAX:
        _session_events[session_id] = buf[-_EVENT_HISTORY_MAX // 2:]

    for ws in list(_session_subs.get(session_id, ())):
        try:
            await ws.send_text(payload)
        except Exception:
            _session_subs.get(session_id, set()).discard(ws)


# ──────────────────────────────────────────────────────────────────────────────
# 组件构建
# ──────────────────────────────────────────────────────────────────────────────

def _build_llm():
    """从环境变量构建 LangChain Chat 模型（按 LLM_PROVIDER 选 Anthropic / OpenAI 兼容）。

    与 run_agent.py 的 _build_llm 保持一致：
      Provider → LLM_PROVIDER（默认 anthropic；openai 覆盖所有 OpenAI 兼容端点）
      API Key  → LLM_API_KEY > ANTHROPIC_API_KEY > ANTHROPIC_AUTH_TOKEN
      Base URL → LLM_BASE_URL > ANTHROPIC_BASE_URL（支持中转代理）
    """
    def _clean(val: str) -> str:
        return (val or "").strip().strip("'\"")

    provider  = (_clean(os.getenv("LLM_PROVIDER", "anthropic")) or "anthropic").lower()
    api_key   = _clean(os.getenv("LLM_API_KEY", "")) or _clean(os.getenv("ANTHROPIC_API_KEY", "")) or _clean(os.getenv("ANTHROPIC_AUTH_TOKEN", ""))
    base_url  = _clean(os.getenv("LLM_BASE_URL", "")) or _clean(os.getenv("ANTHROPIC_BASE_URL", ""))
    model     = os.getenv("LLM_MODEL",       "claude-sonnet-4-6")
    temp      = float(os.getenv("LLM_TEMPERATURE", "0.7"))
    max_tok   = int(os.getenv("LLM_MAX_TOKENS",    "25000"))
    streaming = os.getenv("LLM_STREAMING", "true").lower() in ("1", "true", "yes")

    if provider == "openai":
        # OpenAI 兼容端点：OpenAI 本家 + DeepSeek/Qwen/GLM/Kimi/Yi/MiniMax/Doubao/Baichuan/Gemini/xAI
        from langchain_openai import ChatOpenAI
        if not base_url:
            base_url = "https://api.openai.com/v1"
        return ChatOpenAI(
            model=model,
            api_key=api_key,
            base_url=base_url,
            temperature=temp,
            max_tokens=max_tok,
            streaming=streaming,
            timeout=120,
        )

    # 默认 anthropic（原生 Anthropic SDK）
    from langchain_anthropic import ChatAnthropic
    if not base_url:
        base_url = "https://api.anthropic.com"
    return ChatAnthropic(
        model=model,
        anthropic_api_key=api_key,
        anthropic_api_url=base_url,
        temperature=temp,
        max_tokens=max_tok,
        streaming=streaming,
        timeout=120,
    )


def _build_tools(executors: dict) -> dict:
    py = executors["python"]
    sh = executors["terminal"]
    br = executors["browser"]
    px = executors["proxy"]
    kn = executors["knowledge"]

    return {
        "execute_python":       py.execute,
        "execute_shell":        sh.execute,
        "browser_navigate":     br.navigate,
        "browser_execute_js":   br.execute_js,
        "browser_get_content":  br.get_content,
        "browser_screenshot":   br.screenshot,
        "proxy_list_traffic":   px.list_traffic,
        "proxy_get_flow":       px.get_flow,
        "proxy_clear_traffic":  px.clear_traffic,
        "proxy_replay_flow":    px.replay_flow,
        "knowledge_search":     kn.search,
        "knowledge_get_detail": kn.get_detail,
        "knowledge_save":       kn.save,
    }


async def _init_components():
    global _llm, _executors, _config

    from deepagent.mcp.config import load_config
    from deepagent.mcp.executors import (
        PythonExecutor, TerminalExecutor, BrowserExecutor,
        ProxyExecutor, KnowledgeExecutor,
    )

    _config = load_config()
    _llm = _build_llm()
    _executors = {
        "python":      PythonExecutor(_config["python"]),
        "terminal":    TerminalExecutor(_config["terminal"]),
        "browser":     BrowserExecutor(_config["browser"]),
        "proxy":       ProxyExecutor(_config["proxy"]),
        "knowledge":   KnowledgeExecutor(_config["knowledge"]),
    }
    logger.info("components_initialized")


def _make_agent(max_iterations: int = 50):
    from deepagent.agent import DeepAgent

    knowledge_router = None
    try:
        knowledge_router = _executors["knowledge"]._get_router()
    except Exception:
        pass

    return DeepAgent(
        llm=_llm,
        tools=_build_tools(_executors),
        max_iterations=max_iterations,
        mcp_config=_config,
        knowledge_router=knowledge_router,
    )


# ──────────────────────────────────────────────────────────────────────────────
# FastAPI App
# ──────────────────────────────────────────────────────────────────────────────

from contextlib import asynccontextmanager


@asynccontextmanager
async def lifespan(app: FastAPI):
    await _init_components()
    logger.info("deepagent_chat_ready", url="http://localhost:8000")
    yield
    if _executors:
        try:
            await _executors["browser"].close()
        except Exception:
            pass
        try:
            _executors["proxy"].stop()
        except Exception:
            pass


app = FastAPI(title="DeepAgent Chat", docs_url="/docs", redoc_url="/redoc", lifespan=lifespan)

# Serve static files
_CHAT_HTML = Path(__file__).parent / "chat.html"


@app.get("/")
async def index():
    return HTMLResponse(_CHAT_HTML.read_text(encoding="utf-8"))


@app.get("/health")
async def health_check():
    """Health check endpoint to verify the server is running."""
    return {"status": "healthy", "timestamp": time.time()}


@app.websocket("/ws/{session_id}")
async def websocket_endpoint(websocket: WebSocket, session_id: str):
    await websocket.accept()
    logger.info("ws_connected", session_id=session_id)

    # 会话级广播：agent 进度事件发到该会话所有连接，并写入缓冲
    async def send(data: dict):
        await _broadcast(session_id, data)

    # ── 连接建立：先告知前端本会话是否有事件缓冲，再回放历史 ────────────
    #   has_history=true  → 前端清空界面，等待随后回放的事件重建（运行中刷新场景）
    #   has_history=false → 服务重启、无缓冲，前端回退到本地 localStorage 快照
    history_buf = _session_events.get(session_id, [])
    try:
        await websocket.send_text(json.dumps(
            {"type": "session_state", "has_history": bool(history_buf)}, ensure_ascii=False
        ))
        for ev in history_buf:
            await websocket.send_text(json.dumps(ev, ensure_ascii=False))
    except Exception:
        # 回放过程中连接断开则直接结束
        return

    # 回放完成后加入订阅者，开始接收实时广播
    _session_subs.setdefault(session_id, set()).add(websocket)

    try:
        while True:
            raw = await websocket.receive_text()
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                await send({"type": "error", "message": "消息格式错误（需 JSON）"})
                continue

            # ── 心跳保活：pong 只回给当前连接，不广播、不缓冲 ──────
            if msg.get("type") == "ping":
                try:
                    await websocket.send_text(json.dumps({"type": "pong"}, ensure_ascii=False))
                except Exception:
                    break
                continue

            # ── 打断请求 ──────────────────────────────────────
            if msg.get("type") == "interrupt":
                task = _running_tasks.get(session_id)
                if task and not task.done():
                    # 双保险：协作式停止标志（让 astream 循环主动退出）+ 强制 cancel
                    stop = _session_stops.get(session_id)
                    if stop:
                        stop.set()
                    task.cancel()
                    logger.info("task_interrupted", session_id=session_id)
                    # 最多等 2 秒确认任务退出，避免 interrupted 之后旧任务事件继续涌入
                    for _ in range(20):
                        if task.done():
                            break
                        await asyncio.sleep(0.1)
                    await send({"type": "interrupted", "message": "已打断"})
                else:
                    await send({"type": "interrupted", "message": "无正在运行的任务"})
                continue

            # ── 清除会话记忆 ──────────────────────────────────
            if msg.get("type") == "clear_memory":
                _session_memory.pop(session_id, None)
                await send({"type": "memory_cleared"})
                continue

            # ── 实时纠偏/补充信息（steer）：不打断任务，注入后续轮次 ──
            if msg.get("type") == "steer":
                _steer = (msg.get("content") or "").strip()
                if not _steer:
                    await send({"type": "error", "message": "补充内容不能为空"})
                    continue
                _agent = _running_agents.get(session_id)
                _task = _running_tasks.get(session_id)
                if _agent and _task and not _task.done():
                    _agent.graph.steering.append(_steer)
                    logger.info("steer_injected", session_id=session_id, content=_steer[:60])
                    await send({"type": "steer_ack", "content": _steer})
                else:
                    await send({"type": "error", "message": "当前没有运行中的任务，请直接输入问题"})
                continue

            goal = (msg.get("goal") or "").strip()
            if not goal:
                await send({"type": "error", "message": "目标不能为空"})
                continue

            # ── 意图分流：知识查询走快速问答，测试走 agent 流程 ──
            _intent = _classify_intent(goal)
            if _intent["intent"] == "query":
                logger.info("query_dispatch", session_id=session_id, goal=goal[:60],
                            confidence=_intent["confidence"])
                await _answer_query(session_id, goal, send)
                continue

            # 防并发：同会话同时只允许一个 agent 任务，避免两个任务共享 executor
            # 交叉污染、事件混流（旧 bug：打断失效时旧任务继续跑 + 新任务并发）
            _prev = _running_tasks.get(session_id)
            if _prev and not _prev.done():
                await send({"type": "error", "message": "已有任务在运行中，请先打断或等待完成"})
                continue

            thread_id = (msg.get("thread_id") or "").strip() or session_id
            max_iter  = min(int(msg.get("max_iterations", 10)), 50)  # Increased max iterations

            # 构建携带历史记忆的完整 goal
            history = _session_memory.get(session_id, [])
            enriched_goal = _build_goal_with_memory(goal, history)

            # 新任务开始：清空本会话事件缓冲，避免刷新重连回放时旧任务的
            # progress/done 事件混入新任务流（→ 前端旧轮卡片与新卡片交错、
            # 两份总结报告）。任务互斥已保证此刻无旧任务在跑。
            _session_events[session_id] = []
            logger.info("task_start", session_id=session_id, goal=goal[:80])
            await send({"type": "start", "goal": goal})

            # 在独立 Task 中运行 agent；主循环【不 await】——继续处理 receive，
            # 打断/新消息可即时响应（旧实现阻塞在 await agent_task 上，interrupt
            # 消息排队到任务结束才被处理，打断形同虚设）
            stop = asyncio.Event()
            _session_stops[session_id] = stop
            agent_task = asyncio.ensure_future(
                _run_agent(session_id, goal, enriched_goal, thread_id, max_iter, send, stop)
            )
            _running_tasks[session_id] = agent_task

            def _on_agent_done(t: asyncio.Task, sid: str = session_id):
                _running_tasks.pop(sid, None)
                _running_agents.pop(sid, None)
                _session_stops.pop(sid, None)
                # 取出异常避免 "exception was never retrieved"（内部已处理并广播 error）
                if not t.cancelled() and t.exception():
                    logger.error("agent_task_crashed", session_id=sid,
                                 error=str(t.exception()))
            agent_task.add_done_callback(_on_agent_done)

    except WebSocketDisconnect:
        logger.info("ws_disconnected", session_id=session_id)
    except Exception as e:
        logger.error("ws_error", session_id=session_id, error=str(e))
    finally:
        # 连接断开仅移除订阅，不取消运行中的任务（任务继续跑完，结果缓冲供新连接回放）
        _session_subs.get(session_id, set()).discard(websocket)


def _build_goal_with_memory(goal: str, history: list) -> str:
    """将历史对话摘要 + 最近一次结构化战果拼接到当前 goal 前，让 agent 感知上下文。

    除逐轮摘要外，额外注入"上次测试战果"（确认漏洞/资产面板/未破门槛），
    使 agent 能站在上次测试结果基础上继续或纠偏，而非仅凭摘要从零开始。
    """
    if not history:
        return goal
    lines = ["【本次会话历史记录（请结合上下文理解当前目标）】"]
    for i, turn in enumerate(history, 1):
        lines.append(f"第{i}次提问 目标: {turn['goal']}")
        if turn.get("summary"):
            lines.append(f"第{i}次提问 收尾概括: {turn['summary'][:500]}")
        if turn.get("findings"):
            lines.append(f"第{i}次提问 发现: {'; '.join(str(f) for f in turn['findings'][:5])}")

    # 最近一次携带结构化战果的任务：作为"上次战果"紧贴当前目标注入
    _last_attack = None
    for turn in reversed(history):
        if turn.get("attack_state"):
            _last_attack = turn["attack_state"]
            break
    if _last_attack:
        _as = _last_attack
        _battle_lines = []
        for v in (_as.get("confirmed_vulns") or [])[:5]:
            _battle_lines.append(
                f"  · 已确认[{v.get('vuln_type')}]: {str(v.get('proof_brief', ''))[:80]}"
                + (f" payload={str(v.get('payload', ''))[:80]}" if v.get('payload') else "")
            )
        for a in (_as.get("assets") or [])[:10]:
            _battle_lines.append(f"  · 资产[{a.get('kind')}]: {str(a.get('desc'))[:90]}")
        for b in (_as.get("blockers") or [])[:5]:
            _battle_lines.append(f"  · 未破门槛: {str(b.get('desc'))[:120]}")
        if _battle_lines:
            lines.append("【上次测试战果（本轮必须结合继续，禁止重复已确认内容）】")
            lines.extend(_battle_lines)
    lines.append(f"\n【当前目标】{goal}")
    return "\n".join(lines)


# ── 意图分类：测试(query 之外的 agent 流程) vs 知识查询(query 走快速问答) ────
_TEST_INTENT_WORDS = (
    "测试", "渗透", "挖洞", "利用", "审计", "扫描", "打靶", "攻击", "复现",
    "pentest", "exploit", "recon", "漏洞挖掘", "测一下", "帮我测", "检测漏洞",
    "getshell", "get flag", "拿flag",
)
_QUERY_INTENT_WORDS = (
    "是什么", "原理", "介绍", "讲解", "说明", "怎么防御", "如何防护", "如何修复",
    "查询", "检索", "查一下", "知识", "区别", "定义", "概念", "有哪些", "分类",
    "方法", "流程",
)
_URL_RE = re.compile(r"https?://|(\d{1,3}\.){3}\d{1,3}(:\d{1,5})?")


def _classify_intent(goal: str) -> dict:
    """判定用户本轮输入是『测试』还是『知识查询』（规则优先，低置信度交给前端追问）。"""
    g = (goal or "").strip()
    low = g.lower()
    has_target = bool(_URL_RE.search(g)) or "```" in g or "/flag" in low or "flag" in low
    has_test_word = any(w in low for w in _TEST_INTENT_WORDS)
    has_query_word = any(w in g for w in _QUERY_INTENT_WORDS)

    if has_target and has_query_word and not has_test_word:
        return {"intent": "query", "confidence": "medium",
                "reason": "含目标但为查询/理解类问句"}
    if has_target:
        return {"intent": "test", "confidence": "high", "reason": "检测到测试目标"}
    if has_test_word:
        return {"intent": "test", "confidence": "medium", "reason": "检测到测试意图动词"}
    if has_query_word:
        return {"intent": "query", "confidence": "high", "reason": "检测到查询/概念类问句"}
    return {"intent": "query", "confidence": "low", "reason": "无明确目标与意图，默认按知识问答处理"}


async def _answer_query(session_id: str, goal: str, send) -> None:
    """知识问答路径：检索知识库 + LLM 生成带引用答案，不启动 PER 测试循环。"""
    _session_events[session_id] = []
    await send({"type": "start", "goal": goal})

    kb_ctx = ""
    try:
        _res = await _executors["knowledge"].search(goal, limit=5)
        for r in (_res.get("results") or [])[:5]:
            if isinstance(r, dict):
                _title = r.get("title") or r.get("id") or r.get("name") or ""
                _snip = r.get("snippet") or r.get("content") or r.get("text") or ""
                kb_ctx += f"- {_title}: {str(_snip)[:300]}\n"
    except Exception as e:
        logger.warning("query_kb_search_failed", error=str(e))

    prompt = (
        "你是安全知识助手。请用中文简洁回答用户问题，可结合下方知识库检索结果；"
        "若检索为空则基于通用安全知识回答并在不确定处注明，禁止编造 CVE/payload 细节。\n"
        f"用户问题: {goal}\n\n知识库检索结果:\n{kb_ctx or '（无）'}\n\n"
        "请直接回答，控制在 3 个要点以内。"
    )
    try:
        answer = await _llm.ainvoke(prompt)
        text = answer.content if hasattr(answer, "content") else str(answer)
    except Exception as e:
        logger.error("query_llm_failed", error=str(e))
        text = f"（回答生成失败：{e}）"
    await send({"type": "done", "summary": (text or "").strip(),
                "key_findings": [], "final_report": None})
    _append_session_memory(session_id, goal, (text or "").strip()[:300], [])


async def _run_agent(
    session_id: str,
    clean_goal: str,
    enriched_goal: str,
    thread_id: str,
    max_iter: int,
    send,
    stop: asyncio.Event,
) -> tuple[str, list, dict]:
    """执行 agent 流，流式推送进度，返回 (summary, findings, attack_state)。

    clean_goal   用户本轮原始目标（写会话记忆用，不含历史前缀）；
    enriched_goal 拼接了会话历史的完整目标（喂给 agent 图用）；
    stop         协作式停止标志——打断时置位，本函数在每个流事件处
                 检查并主动退出（不发送 done，interrupted 由打断方发送）。
    attack_state 本轮结构化战果（确认漏洞/资产面板/未破门槛），供会话记忆复用。
    """
    agent = _make_agent(max_iterations=max_iter)
    _running_agents[session_id] = agent   # 注册，供 steer 消息运行时注入纠偏指令
    last_summary = ""
    last_key_findings: list = []
    last_final_report: str | None = None
    last_state = None
    interrupted = False

    try:
        async for event in agent.stream(enriched_goal, thread_id=thread_id):
            if stop.is_set():
                interrupted = True
                logger.info("agent_stopped_by_flag", session_id=session_id)
                break
            for node_name, state in event.items():
                last_state = state
                # 总结报告：在 summarizer 事件里直接捕获，不依赖"最后一个事件"
                # （LangGraph 部分版本不产出末端节点事件，仅靠 last_state 会丢报告）
                if node_name == "summarizer":
                    _fr = _sget(state, "final_report", None)
                    if _fr:
                        last_final_report = _fr

                round_   = _sget(state, "execution_round", 0)
                tasks    = _extract_tasks(state)
                results  = _extract_results(state)
                summary, key_findings, next_direction, finding_level, next_payloads, confirmed_vulns = _extract_reflection(node_name, state)
                reasoning = _extract_planner_reasoning(state) if node_name == "planner" else ""
                should_continue = _sget(state, "should_continue", True)

                # 提取当前 vuln_focus
                vuln_focus = ""
                planner_raw = _sget(state, "planner")
                if planner_raw:
                    if isinstance(planner_raw, dict):
                        vuln_focus = planner_raw.get("current_vuln_focus", "") or ""
                    else:
                        vuln_focus = getattr(planner_raw, "current_vuln_focus", "") or ""

                if summary:
                    last_summary = summary
                    last_key_findings = key_findings

                await send({
                    "type":             "progress",
                    "node":             node_name,
                    "round":            round_,
                    "tasks":            tasks,
                    "results":          results,
                    "summary":          summary,
                    "key_findings":     key_findings,
                    "next_direction":   next_direction,
                    "reasoning":        reasoning,
                    "should_continue":  should_continue,
                    "vuln_focus":       vuln_focus,
                    "finding_level":    finding_level,
                    "next_payloads":    next_payloads,
                    "confirmed_vulns":  confirmed_vulns,
                })

                # 测试文档推送：planner 生成/修订 test_plan 后单独发事件供前端展示
                # （首轮为完整文档；中间轮为修订版，前端原地更新同一卡片）
                if node_name == "planner":
                    tp_raw = planner_raw
                    tp_dict = None
                    total_rounds = None
                    if tp_raw:
                        if isinstance(tp_raw, dict):
                            tp_dict = tp_raw.get("test_plan")
                            total_rounds = tp_raw.get("total_rounds")
                        else:
                            tp_dict = getattr(tp_raw, "test_plan", None)
                            total_rounds = getattr(tp_raw, "total_rounds", None)
                    if isinstance(tp_dict, dict) and tp_dict.get("directions"):
                        await send({
                            "type":         "test_plan",
                            "round":        round_,
                            "total_rounds": total_rounds,
                            "plan":         tp_dict,
                        })

        # 打断（协作式退出）：不发 done（interrupted 已由打断方发送）、不写记忆
        if interrupted:
            return last_summary, last_key_findings, {}

        if not last_summary and last_state is not None:
            last_summary = _extract_last_ai_message(last_state)

        # 兜底：从 checkpointer 直接取最终状态（应对末端节点事件缺失/状态回环等边界）
        if not last_final_report:
            try:
                snap = agent.graph.app.get_state({"configurable": {"thread_id": thread_id}})
                if snap and snap.values:
                    _v = snap.values
                    _fr = _v.get("final_report") if isinstance(_v, dict) else getattr(_v, "final_report", None)
                    if _fr:
                        last_final_report = _fr
            except Exception as e:
                logger.warning("final_report_get_state_failed", error=str(e))

        await send({
            "type":         "done",
            "summary":      last_summary,
            "key_findings": last_key_findings,
            "final_report": last_final_report,
        })

        # 会话记忆：任务真正完成后立即记账（写在 _run_agent 内，WebSocket 断开也不丢）
        # 额外保存结构化战果，让同会话下一轮提问"结合上次测试结果"
        attack_state = _extract_attack_state(last_state) if last_state else {}
        # 收尾概括：优先用 summarizer 生成的最终报告（含结论/证据/利用链），
        # 而非仅反射节点的零散 summary——这才是"本次提问的收尾概括"
        _summary_for_mem = (last_final_report or last_summary or "").strip()
        _append_session_memory(session_id, clean_goal, _summary_for_mem, last_key_findings, attack_state)

        logger.info("task_done", session_id=session_id,
                    report_len=len(last_final_report or ""))
        return last_summary, last_key_findings, attack_state
    except asyncio.CancelledError:
        # 强制 cancel（打断的第二层保险）：不发 done、不写记忆，由打断方发 interrupted
        logger.info("agent_task_cancelled", session_id=session_id)
        raise
    except Exception as e:
        _err = str(e)
        # WebSocket 断开导致的异常不向前端报错（连接已断，报了也收不到）
        if "websocket" in _err.lower() or "asgi" in _err.lower():
            logger.warning("agent_stream_ws_disconnected", session_id=session_id, error=_err[:100])
        else:
            logger.error("agent_stream_error", session_id=session_id, error=_err)
            await send({
                "type": "error",
                "message": f"Agent执行错误: {_err}"
            })
        return "", [], {}


# ──────────────────────────────────────────────────────────────────────────────
# 状态提取辅助函数
# ──────────────────────────────────────────────────────────────────────────────

def _sget(state, key, default=None):
    if isinstance(state, dict):
        return state.get(key, default)
    return getattr(state, key, default)


def _extract_attack_state(state) -> dict:
    """从最终状态提取结构化战果（确认漏洞/资产面板/未破门槛），供会话记忆复用。"""
    planner = _sget(state, "planner") or {}

    def _g(key):
        if isinstance(planner, dict):
            return planner.get(key) or []
        return getattr(planner, key, None) or []

    ev_vault = _g("evidence_vault")
    return {
        "confirmed_vulns": _g("confirmed_vulns")[:5],
        "assets": _g("assets")[:12],
        "blockers": _g("blockers")[:6],
        # 证据原文库只存 id/kind 目录（原文过长不便入库，跨轮引用靠摘要+确认漏洞）
        "evidence_vault": [
            {"id": e.get("id"), "kind": e.get("kind")}
            for e in ev_vault[-6:] if isinstance(e, dict)
        ],
    }


def _extract_last_ai_message(state) -> str:
    try:
        msgs = _sget(state, "messages", []) or []
        for msg in reversed(msgs):
            if isinstance(msg, dict):
                role    = msg.get("role", "")
                content = msg.get("content", "")
            else:
                role    = str(getattr(msg, "type", "") or getattr(msg, "role", ""))
                content = getattr(msg, "content", "") or ""
            if not content or not isinstance(content, str):
                continue
            if "ai" in role.lower() or "assistant" in role.lower():
                return content.strip()
    except Exception:
        pass
    return ""


def _extract_tasks(state) -> list:
    """Extract tasks with FULL arguments for frontend display."""
    raw = _sget(state, "current_tasks", []) or []
    return [
        {
            "tool":        t.get("tool", ""),
            "description": t.get("description", ""),
            "arguments":   t.get("arguments", {}),
        }
        for t in raw
    ]


def _extract_results(state) -> list:
    """Extract results with output preview and metadata for frontend display."""
    raw = _sget(state, "current_results", []) or []
    out = []

    for r in raw:
        output = r.get("output") or r.get("stdout") or r.get("result") or ""
        output_preview = ""
        meta = {}

        if isinstance(output, dict):
            if "image_base64" in output:
                img_b64 = output["image_base64"]
                size_kb = len(img_b64) * 3 // 4 // 1024
                output_preview = f"[截图完成] URL={output.get('url', '')}，图像约 {size_kb}KB"
                meta["type"] = "screenshot"
            elif "image_note" in output:
                output_preview = output["image_note"]
            else:
                stdout = output.get("stdout") or ""
                stderr = output.get("stderr") or ""
                error  = output.get("error") or ""
                content = output.get("content") or ""
                result_ = output.get("result") or ""
                data    = output.get("data") or ""

                # 诊断元数据
                et = output.get("execution_time")
                if et:
                    meta["execution_time"] = f"{et:.1f}s"
                sc = output.get("status_code")
                if sc:
                    meta["status_code"] = str(sc)
                resp_len = len(stdout or content or result_ or data or "")
                if resp_len:
                    meta["resp_len"] = str(resp_len)

                # 输出预览
                if stdout:
                    output_preview = stdout[:800]
                elif content:
                    output_preview = content[:800]
                elif result_:
                    output_preview = str(result_)[:800]
                elif data:
                    output_preview = str(data)[:800]
                elif stderr:
                    output_preview = f"[stderr]\n{stderr[:800]}"
                elif error:
                    output_preview = f"[error] {error[:800]}"

                if r.get("same_output_warning"):
                    meta["same_output"] = True
        elif isinstance(output, str):
            output_preview = output[:800]

        tool = r.get("tool") or r.get("task", {}).get("tool", "")
        out.append({
            "tool":           tool,
            "success":        r.get("success", False),
            "summary":        f"工具执行: {tool}",
            "output_preview": output_preview,
            "meta":           meta,
        })

    return out


def _extract_planner_reasoning(state) -> str:
    planner_raw = _sget(state, "planner")
    if planner_raw is None:
        return ""
    if isinstance(planner_raw, dict):
        history = planner_raw.get("planning_history", [])
    else:
        history = getattr(planner_raw, "planning_history", [])
    if history:
        return history[-1].get("reasoning", "") or ""
    return ""


def _extract_reflection(node_name: str, state) -> tuple[str, list, str, str, list, list]:
    if node_name != "reflector":
        return "", [], "", "", [], []

    reflector_raw = _sget(state, "reflector")
    if reflector_raw is None:
        return "", [], "", "", [], []

    if isinstance(reflector_raw, dict):
        log = reflector_raw.get("reflection_log", [])
    else:
        log = getattr(reflector_raw, "reflection_log", [])

    if not log:
        return "", [], "", "", [], []

    last = log[-1]
    if isinstance(last, dict):
        summary        = last.get("summary", "")
        key_findings   = last.get("key_findings", [])
        next_direction = last.get("next_direction", "") or ""
        finding_level  = last.get("finding_level", "no_finding")
        next_payloads  = last.get("next_payloads", [])
    else:
        summary        = getattr(last, "summary", "")
        key_findings   = getattr(last, "key_findings", [])
        next_direction = getattr(last, "next_direction", "") or ""
        finding_level  = getattr(last, "finding_level", "no_finding")
        next_payloads  = getattr(last, "next_payloads", [])

    # 确认的漏洞列表
    confirmed_vulns = []
    planner_raw = _sget(state, "planner")
    if planner_raw:
        if isinstance(planner_raw, dict):
            confirmed_vulns = planner_raw.get("confirmed_vulns", [])
        else:
            confirmed_vulns = getattr(planner_raw, "confirmed_vulns", [])

    return summary, key_findings, next_direction, finding_level, next_payloads, confirmed_vulns


# ──────────────────────────────────────────────────────────────────────────────
# 入口
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    parser = argparse.ArgumentParser(description="DeepAgent 聊天服务器")
    parser.add_argument("--host",  default="0.0.0.0", help="监听地址")
    parser.add_argument("--port",  type=int, default=8000, help="端口号")
    parser.add_argument("--debug", action="store_true", help="调试模式（热重载）")
    args = parser.parse_args()

    # 日志双输出：控制台（容错编码）+ 文件（UTF-8 完整保留，供诊断）
    _log_dir = Path(__file__).parent / ".logs"
    _log_dir.mkdir(parents=True, exist_ok=True)
    _log_file = _log_dir / "chat_server.log"
    _log_handler_file = _logging.FileHandler(_log_file, encoding="utf-8")
    _log_handler_file.setFormatter(_logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    _log_handler_console = _logging.StreamHandler()
    _log_handler_console.setFormatter(_logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    # 控制台在 Windows GBK 下用 replace 容错，避免 UnicodeEncodeError 崩溃整个 agent
    if sys.platform == "win32":
        _log_handler_console.setStream(open(sys.stderr.fileno(), mode="w", encoding="utf-8", errors="replace", closefd=False))

    _root_logger = _logging.getLogger()
    _root_logger.handlers.clear()
    _root_logger.addHandler(_log_handler_file)
    _root_logger.addHandler(_log_handler_console)
    _root_logger.setLevel(_logging.DEBUG if args.debug else _logging.INFO)

    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="%H:%M:%S"),
            structlog.dev.ConsoleRenderer(colors=False),
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    print(f"\n  DeepAgent Chat Server")
    print(f"  http://{args.host}:{args.port}\n")

    uvicorn.run(
        "deepagent.chat_server:app",
        host=args.host,
        port=args.port,
        reload=args.debug,
        log_level="debug" if args.debug else "info",
    )
