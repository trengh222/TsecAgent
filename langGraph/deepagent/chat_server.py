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
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

# ── 路径 ──────────────────────────────────────────────────────────────────────
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

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

# ── 正在运行的任务：session_id -> asyncio.Task（用于打断）
_running_tasks: Dict[str, asyncio.Task] = {}


# ──────────────────────────────────────────────────────────────────────────────
# 组件构建
# ──────────────────────────────────────────────────────────────────────────────

def _build_llm():
    from langchain_anthropic import ChatAnthropic

    def _clean(val: str) -> str:
        return (val or "").strip().strip("'\"")

    api_key  = _clean(os.getenv("ANTHROPIC_API_KEY", "")) or _clean(os.getenv("ANTHROPIC_AUTH_TOKEN", ""))
    base_url = _clean(os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com")) or "https://api.anthropic.com"
    model    = os.getenv("LLM_MODEL", "claude-sonnet-4-6")
    temp     = float(os.getenv("LLM_TEMPERATURE", "0.7"))
    max_tok  = int(os.getenv("LLM_MAX_TOKENS", "25000"))
    streaming = os.getenv("LLM_STREAMING", "false").lower() in ("1", "true", "yes")

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

    async def send(data: dict):
        try:
            await websocket.send_text(json.dumps(data, ensure_ascii=False))
        except Exception as e:
            logger.error("websocket_send_failed", session_id=session_id, error=str(e))
            raise

    try:
        while True:
            raw = await websocket.receive_text()
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                await send({"type": "error", "message": "消息格式错误（需 JSON）"})
                continue

            # ── 打断请求 ──────────────────────────────────────
            if msg.get("type") == "interrupt":
                task = _running_tasks.get(session_id)
                if task and not task.done():
                    task.cancel()
                    logger.info("task_interrupted", session_id=session_id)
                    await send({"type": "interrupted", "message": "已打断"})
                else:
                    await send({"type": "interrupted", "message": "无正在运行的任务"})
                continue

            # ── 清除会话记忆 ──────────────────────────────────
            if msg.get("type") == "clear_memory":
                _session_memory.pop(session_id, None)
                await send({"type": "memory_cleared"})
                continue

            goal = (msg.get("goal") or "").strip()
            if not goal:
                await send({"type": "error", "message": "目标不能为空"})
                continue

            thread_id = (msg.get("thread_id") or "").strip() or session_id
            max_iter  = min(int(msg.get("max_iterations", 10)), 50)  # Increased max iterations

            # 构建携带历史记忆的完整 goal
            history = _session_memory.get(session_id, [])
            enriched_goal = _build_goal_with_memory(goal, history)

            logger.info("task_start", session_id=session_id, goal=goal[:80])
            await send({"type": "start", "goal": goal})

            # 在独立 Task 中运行 agent，以便打断
            agent_task = asyncio.ensure_future(
                _run_agent(session_id, enriched_goal, thread_id, max_iter, send)
            )
            _running_tasks[session_id] = agent_task

            try:
                summary, findings = await agent_task
                # 保存到会话记忆（无论 summary 是否为空，都保存以保证记忆连贯性）
                mem = _session_memory.setdefault(session_id, [])
                mem.append({
                    "goal": goal,
                    "summary": summary or f"（第 {len(mem)+1} 轮任务已完成）",
                    "findings": findings,
                })
                # 最多保留最近 10 轮
                if len(mem) > 10:
                    _session_memory[session_id] = mem[-10:]
            except asyncio.CancelledError:
                # 打断：interrupted 消息已由 interrupt 处理块发送，这里不重复发 done
                logger.info("task_cancelled", session_id=session_id)
            except Exception as e:
                logger.error("task_error", session_id=session_id, error=str(e))
                await send({"type": "error", "message": str(e)})
            finally:
                _running_tasks.pop(session_id, None)

    except WebSocketDisconnect:
        logger.info("ws_disconnected", session_id=session_id)
        task = _running_tasks.pop(session_id, None)
        if task and not task.done():
            task.cancel()
    except Exception as e:
        logger.error("ws_error", session_id=session_id, error=str(e))
        try:
            await send({"type": "error", "message": str(e)})
        except Exception:
            pass


def _build_goal_with_memory(goal: str, history: list) -> str:
    """将历史对话摘要拼接到当前 goal 前，让 agent 感知上下文。"""
    if not history:
        return goal
    lines = ["【本次会话历史记录（请结合上下文理解当前目标）】"]
    for i, turn in enumerate(history, 1):
        lines.append(f"第{i}轮 目标: {turn['goal']}")
        if turn.get("summary"):
            lines.append(f"第{i}轮 结论: {turn['summary'][:300]}")
        if turn.get("findings"):
            lines.append(f"第{i}轮 发现: {'; '.join(str(f) for f in turn['findings'][:5])}")
    lines.append(f"\n【当前目标】{goal}")
    return "\n".join(lines)


async def _run_agent(
    session_id: str,
    enriched_goal: str,
    thread_id: str,
    max_iter: int,
    send,
) -> tuple[str, list]:
    """执行 agent 流，流式推送进度，返回 (summary, findings)。"""
    agent = _make_agent(max_iterations=max_iter)
    last_summary = ""
    last_key_findings: list = []
    last_final_report: str | None = None
    last_state = None

    try:
        async for event in agent.stream(enriched_goal, thread_id=thread_id):
            for node_name, state in event.items():
                last_state = state
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

        if not last_summary and last_state is not None:
            last_summary = _extract_last_ai_message(last_state)

        if last_state is not None:
            last_final_report = _sget(last_state, "final_report", None)

        await send({
            "type":         "done",
            "summary":      last_summary,
            "key_findings": last_key_findings,
            "final_report": last_final_report,
        })
        logger.info("task_done", session_id=session_id)
        return last_summary, last_key_findings
    except Exception as e:
        logger.error("agent_stream_error", session_id=session_id, error=str(e))
        await send({
            "type": "error",
            "message": f"Agent执行错误: {str(e)}"
        })
        return "", []


# ──────────────────────────────────────────────────────────────────────────────
# 状态提取辅助函数
# ──────────────────────────────────────────────────────────────────────────────

def _sget(state, key, default=None):
    if isinstance(state, dict):
        return state.get(key, default)
    return getattr(state, key, default)


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

    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="%H:%M:%S"),
            structlog.dev.ConsoleRenderer(colors=True),
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
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
