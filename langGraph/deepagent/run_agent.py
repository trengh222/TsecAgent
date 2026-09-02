#!/usr/bin/env python3
"""
DeepAgent 启动脚本

用法:
    python run_agent.py --goal "对 http://target.com 进行渗透测试"
    python run_agent.py --goal "..." --thread-id pentest_01
    python run_agent.py --check              # 仅健康检查，不执行任务
    python run_agent.py --stream --goal "..." # 流式输出每轮节点状态
    python run_agent.py --max-iter 20 --goal "..."

健康检查说明:
    [✓] OK   — 组件正常
    [!] WARN — 可选组件不可用，任务仍可运行
    [✗] FAIL — 关键组件故障，阻断启动
    [?] SKIP — 依赖未安装，跳过
"""

import argparse
import asyncio
import os
import platform
import sys
import time

# Windows GBK 控制台兼容：健康检查输出含 ✓/✗ 等符号，强制 UTF-8 输出避免 UnicodeEncodeError
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# 将 deepagent 的父目录（langGraph/）加入 sys.path，使 `import deepagent` 可用
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 优先加载 .env（override=True：.env 中的值覆盖系统环境变量，避免残留旧配置干扰）
try:
    from dotenv import load_dotenv
    _env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    load_dotenv(_env_path, override=True)
except ImportError:
    pass  # python-dotenv 未安装时直接使用系统环境变量

# 关闭 ChromaDB 匿名遥测：
#   1. 环境变量方式（chromadb 0.4 及以下读取）
os.environ["ANONYMIZED_TELEMETRY"] = "false"
#   2. 直接静默 posthog logger（版本不兼容时的兜底，不依赖 chromadb 内部逻辑）
import logging as _logging
_logging.getLogger("chromadb.telemetry.product.posthog").setLevel(_logging.CRITICAL)

import structlog

# ──────────────────────────────────────────────────────────────
# 健康检查数据结构
# ──────────────────────────────────────────────────────────────

class _Status:
    OK   = "OK  "
    WARN = "WARN"
    FAIL = "FAIL"
    SKIP = "SKIP"


class CheckResult:
    def __init__(
        self,
        status: str,
        name: str,
        detail: str = "",
        elapsed: float = 0.0,
        critical: bool = False,
    ):
        self.status   = status
        self.name     = name
        self.detail   = detail
        self.elapsed  = elapsed
        self.critical = critical   # FAIL 时是否阻断启动

    def __str__(self) -> str:
        icons = {
            _Status.OK:   "✓",
            _Status.WARN: "!",
            _Status.FAIL: "✗",
            _Status.SKIP: "?",
        }
        icon    = icons.get(self.status.strip(), "?")
        ms_str  = f" ({self.elapsed * 1000:.0f}ms)" if self.elapsed > 0.01 else ""
        name_w  = f"{self.name:<26}"
        detail  = f"  {self.detail}" if self.detail else ""
        return f"  [{icon}] {name_w} {self.status.strip()}{ms_str}{detail}"


# ──────────────────────────────────────────────────────────────
# LLM 构建
# ──────────────────────────────────────────────────────────────

def _build_llm():
    """从环境变量构建 LangChain Chat 模型（按 LLM_PROVIDER 选 Anthropic / OpenAI 兼容）。

    优先级:
      Provider → LLM_PROVIDER（默认 anthropic；openai 覆盖所有 OpenAI 兼容端点）
      API Key  → LLM_API_KEY > ANTHROPIC_API_KEY > ANTHROPIC_AUTH_TOKEN
      Base URL → LLM_BASE_URL > ANTHROPIC_BASE_URL（支持中转代理）
    """
    # strip() + 去掉可能由 linter 加入的引号
    def _clean(val: str) -> str:
        return (val or "").strip().strip("'\"")

    provider  = (_clean(os.getenv("LLM_PROVIDER", "anthropic")) or "anthropic").lower()
    api_key   = _clean(os.getenv("LLM_API_KEY", "")) or _clean(os.getenv("ANTHROPIC_API_KEY", "")) or _clean(os.getenv("ANTHROPIC_AUTH_TOKEN", ""))
    base_url  = _clean(os.getenv("LLM_BASE_URL", "")) or _clean(os.getenv("ANTHROPIC_BASE_URL", ""))
    model     = os.getenv("LLM_MODEL",       "claude-sonnet-4-6")
    temp      = float(os.getenv("LLM_TEMPERATURE", "0.7"))
    max_tok   = int(os.getenv("LLM_MAX_TOKENS",    "25000"))
    streaming  = os.getenv("LLM_STREAMING", "true").lower() in ("1", "true", "yes")

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
        ), model

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
    ), model


# ──────────────────────────────────────────────────────────────
# 各组件健康检查
# ──────────────────────────────────────────────────────────────

async def _check_llm(llm) -> CheckResult:
    t = time.monotonic()
    try:
        resp = await asyncio.wait_for(
            llm.ainvoke("Reply with one word: OK"),
            timeout=60,
        )
        # 兼容新版本返回 dict 和旧版本返回 AIMessage
        if isinstance(resp, dict):
            content = resp.get("content", str(resp))
        else:
            content = resp.content if hasattr(resp, "content") else str(resp)
        # content 可能是 list[dict]（Anthropic API 返回格式）
        if isinstance(content, list):
            content = " ".join(
                item.get("text", "") for item in content if isinstance(item, dict) and item.get("type") == "text"
            ) or str(content)
        content = str(content).strip()[:40]
        return CheckResult(_Status.OK, "LLM", content, time.monotonic() - t, critical=True)
    except asyncio.TimeoutError:
        return CheckResult(_Status.FAIL, "LLM", "请求超时（>60s），检查 LLM_BASE_URL / 网络", time.monotonic() - t, critical=True)
    except Exception as e:
        return CheckResult(_Status.FAIL, "LLM", str(e)[:70], time.monotonic() - t, critical=True)


async def _check_python(executor) -> CheckResult:
    t = time.monotonic()
    try:
        r = await asyncio.wait_for(
            executor.execute("import sys; print(f'Python {sys.version_info.major}.{sys.version_info.minor}')", timeout=10),
            timeout=12,
        )
        elapsed = time.monotonic() - t
        if r.get("success"):
            return CheckResult(_Status.OK, "Python Executor", r.get("output", "").strip(), elapsed, critical=True)
        return CheckResult(_Status.FAIL, "Python Executor", r.get("error", "")[:60], elapsed, critical=True)
    except Exception as e:
        return CheckResult(_Status.FAIL, "Python Executor", str(e)[:60], time.monotonic() - t, critical=True)


async def _check_terminal(executor) -> CheckResult:
    t = time.monotonic()
    try:
        if sys.platform == "win32":
            # Windows PowerShell 无 uname，系统信息本地获取，会话只做冒烟
            r = await asyncio.wait_for(
                executor.execute("$PSVersionTable.PSVersion.Major", timeout=15),
                timeout=18,
            )
            sysinfo = f"Windows {platform.machine()}"
        else:
            r = await asyncio.wait_for(
                executor.execute("echo $(uname -s) $(uname -m)", timeout=10),
                timeout=12,
            )
            sysinfo = ""
        elapsed = time.monotonic() - t
        if r.get("success"):
            out = (r.get("stdout", r.get("output", "")) or "").strip()
            detail = sysinfo if not out or out.startswith("PS>") else f"{sysinfo} PS {out}".strip()
            return CheckResult(_Status.OK, "Terminal Executor", detail[:40], elapsed, critical=True)
        return CheckResult(_Status.FAIL, "Terminal Executor", r.get("error", "")[:60], elapsed, critical=True)
    except Exception as e:
        return CheckResult(_Status.FAIL, "Terminal Executor", str(e)[:60], time.monotonic() - t, critical=True)


async def _check_browser(_executor) -> CheckResult:
    t = time.monotonic()
    try:
        from playwright.async_api import async_playwright  # noqa: F401
        return CheckResult(_Status.OK, "Browser (Playwright)", "已安装，按需启动", time.monotonic() - t)
    except ImportError:
        return CheckResult(
            _Status.SKIP, "Browser (Playwright)",
            "pip install playwright && playwright install chromium",
            time.monotonic() - t,
        )
    except Exception as e:
        return CheckResult(_Status.WARN, "Browser (Playwright)", str(e)[:60], time.monotonic() - t)


async def _check_proxy(executor) -> CheckResult:
    t = time.monotonic()
    try:
        r = await asyncio.wait_for(executor.list_traffic(limit=1), timeout=5)
        elapsed = time.monotonic() - t
        if r.get("success"):
            return CheckResult(_Status.OK, "Proxy (mitmproxy)", f"已连接 {executor.host}:{executor.proxy_port}", elapsed)
        raise RuntimeError("not running")
    except Exception:
        elapsed = time.monotonic() - t
        auto = executor.config.get("auto_start", False)
        hint = "已配置自动启动" if auto else f"手动启动: mitmdump --listen-port {executor.proxy_port} --web-port {executor.api_port} --ssl-insecure -q"
        return CheckResult(_Status.WARN, "Proxy (mitmproxy)", hint, elapsed)


async def _check_knowledge(executor) -> CheckResult:
    t = time.monotonic()
    try:
        r = await asyncio.wait_for(executor.search("test", limit=1), timeout=15)
        elapsed = time.monotonic() - t
        if r.get("success") is not False:
            return CheckResult(_Status.OK, "Knowledge (ChromaDB)", "已就绪", elapsed)
        return CheckResult(_Status.WARN, "Knowledge (ChromaDB)", r.get("error", "")[:60], elapsed)
    except Exception as e:
        return CheckResult(_Status.WARN, "Knowledge (ChromaDB)", str(e)[:60], time.monotonic() - t)


async def _check_recon() -> CheckResult:
    t = time.monotonic()
    import shutil
    tools_ok   = [t_ for t_ in ("nmap",) if shutil.which(t_)]
    tools_dir  = [t_ for t_ in ("gobuster", "ffuf") if shutil.which(t_)]
    elapsed    = time.monotonic() - t

    found_all  = tools_ok + tools_dir
    if tools_ok and tools_dir:
        return CheckResult(_Status.OK, "Recon Tools", f"已安装: {', '.join(found_all)}", elapsed)
    if found_all:
        missing = ([] if tools_ok else ["nmap"]) + ([] if tools_dir else ["gobuster/ffuf"])
        return CheckResult(_Status.WARN, "Recon Tools", f"已安装: {', '.join(found_all)}  缺少: {', '.join(missing)}", elapsed)
    return CheckResult(_Status.WARN, "Recon Tools", "nmap / gobuster / ffuf 均未安装（apt install nmap gobuster）", elapsed)


async def run_all_checks(executors: dict, llm) -> list[CheckResult]:
    """并发执行所有健康检查，返回有序结果列表。"""
    results = await asyncio.gather(
        _check_llm(llm),
        _check_python(executors["python"]),
        _check_terminal(executors["terminal"]),
        _check_browser(executors["browser"]),
        _check_proxy(executors["proxy"]),
        _check_knowledge(executors["knowledge"]),
        _check_recon(),
        return_exceptions=True,
    )
    out = []
    names = ["LLM", "Python Executor", "Terminal Executor",
             "Browser", "Proxy", "Knowledge", "Recon"]
    for i, r in enumerate(results):
        if isinstance(r, BaseException):
            out.append(CheckResult(_Status.FAIL, names[i], str(r)[:70]))
        else:
            out.append(r)
    return out


# ──────────────────────────────────────────────────────────────
# 工具字典构建
# ──────────────────────────────────────────────────────────────

def _build_tools(executors: dict) -> dict:
    """将执行器方法映射为 DeepAgent 工具字典。"""
    py = executors["python"]
    sh = executors["terminal"]
    br = executors["browser"]
    px = executors["proxy"]
    kn = executors["knowledge"]

    return {
        # Python 沙箱
        "execute_python":       py.execute,
        # Shell 终端（持久 session）
        "execute_shell":        sh.execute,
        # 浏览器自动化
        "browser_navigate":     br.navigate,
        "browser_execute_js":   br.execute_js,
        "browser_get_content":  br.get_content,
        "browser_screenshot":   br.screenshot,
        # 代理流量分析
        "proxy_list_traffic":   px.list_traffic,
        "proxy_get_flow":       px.get_flow,
        "proxy_clear_traffic":  px.clear_traffic,
        "proxy_replay_flow":    px.replay_flow,
        # 知识库
        "knowledge_search":     kn.search,
        "knowledge_get_detail": kn.get_detail,
        "knowledge_save":       kn.save,
    }


# ──────────────────────────────────────────────────────────────
# 主函数
# ──────────────────────────────────────────────────────────────

async def main() -> None:
    parser = argparse.ArgumentParser(
        description="DeepAgent 渗透测试 AI Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--goal",      type=str,  help="任务目标描述（不提供则进入交互输入）")
    parser.add_argument("--thread-id", type=str,  default="default", help="会话 ID，用于多任务隔离，默认 default")
    parser.add_argument("--check",     action="store_true", help="仅执行健康检查，不启动 Agent")
    parser.add_argument("--stream",    action="store_true", help="流式输出，逐节点打印状态（默认关）")
    parser.add_argument("--max-iter",  type=int,  default=50, help="最大迭代轮次，默认 50")
    parser.add_argument("--debug",     action="store_true", help="启用 DEBUG 日志")
    args = parser.parse_args()

    # ── 日志配置 ────────────────────────────────────────────
    import logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        level=log_level,
        stream=sys.stderr,
    )
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="%H:%M:%S"),
            structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty()),
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # ── Banner ────────────────────────────────────────────────
    print("=" * 62)
    print("  DeepAgent  —  渗透测试 AI Agent")
    print("  PER 架构 (Planner → Executor → Reflector)")
    print("=" * 62)

    # ── 加载配置 ─────────────────────────────────────────────
    from deepagent.mcp.config import load_config
    config = load_config()

    # ── 构建 LLM ─────────────────────────────────────────────
    try:
        llm, model_name = _build_llm()
    except Exception as e:
        print(f"\n[✗] LLM 构建失败: {e}")
        print("    请检查 .env 中 LLM_PROVIDER / LLM_API_KEY（或 ANTHROPIC_API_KEY）/ LLM_BASE_URL")
        sys.exit(1)

    _provider = (os.getenv("LLM_PROVIDER") or "anthropic").strip().lower() or "anthropic"
    _base_url = os.getenv("LLM_BASE_URL") or os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com")
    _key = os.getenv("LLM_API_KEY") or os.getenv("ANTHROPIC_API_KEY") or os.getenv("ANTHROPIC_AUTH_TOKEN") or ""
    _key_masked = (_key[:6] + "***" + _key[-4:]) if len(_key) > 12 else ("***" if _key else "未设置")
    print(f"\n  Provider: {_provider}")
    print(f"  模型   : {model_name}")
    print(f"  接入点 : {_base_url}")
    print(f"  Key    : {_key_masked}")
    print(f"  代理   : {config['proxy'].get('caido_url') or '未启用'}")
    print(f"  知识库 : {config['knowledge']['chroma_path']}")
    print(f"  线程ID : {args.thread_id}  最大轮次: {args.max_iter}")

    # ── 初始化执行器 ─────────────────────────────────────────
    from deepagent.mcp.executors import (
        PythonExecutor, TerminalExecutor, BrowserExecutor,
        ProxyExecutor,    KnowledgeExecutor,
    )
    executors = {
        "python":    PythonExecutor(config["python"]),
        "terminal":  TerminalExecutor(config["terminal"]),
        "browser":   BrowserExecutor(config["browser"]),
        "proxy":     ProxyExecutor(config["proxy"]),
        "knowledge": KnowledgeExecutor(config["knowledge"]),
    }

    # ── 健康检查 ─────────────────────────────────────────────
    print("\n  健康检查 ...")
    t0 = time.monotonic()
    check_results = await run_all_checks(executors, llm)
    check_elapsed = time.monotonic() - t0

    print()
    critical_fail = False
    for r in check_results:
        print(str(r))
        if r.status.strip() == "FAIL" and r.critical:
            critical_fail = True

    print(f"\n  检查耗时 {check_elapsed:.1f}s")

    if critical_fail:
        print("\n[✗] 关键组件检查失败，请根据上方提示修复后重试。")
        sys.exit(1)

    warn_count = sum(1 for r in check_results if r.status.strip() == "WARN")
    if warn_count:
        print(f"  [{warn_count} 个可选组件不可用，不影响核心功能]")

    if args.check:
        print("\n  --check 模式：健康检查完成，退出。")
        return

    # ── 获取任务目标 ─────────────────────────────────────────
    goal = args.goal
    if not goal:
        print("\n  请输入任务目标（Ctrl+C 退出）:")
        try:
            goal = input("  Goal > ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n  已取消。")
            return
        if not goal:
            print("  [✗] 目标不能为空。")
            return

    print("\n" + "=" * 62)
    print(f"  目标: {goal}")
    print("=" * 62 + "\n")

    # ── 初始化 KnowledgeRouter（用于 STE 经验回写）───────────
    knowledge_router = None
    try:
        knowledge_router = executors["knowledge"]._get_router()
    except Exception:
        pass   # 可选，失败不阻断

    # ── 构建并运行 Agent ─────────────────────────────────────
    from deepagent.agent import DeepAgent

    agent = DeepAgent(
        llm=llm,
        tools=_build_tools(executors),
        max_iterations=args.max_iter,
        mcp_config=config,
        knowledge_router=knowledge_router,
    )

    try:
        if args.stream:
            # 流式模式：每个节点完成后立即打印
            async for event in agent.stream(goal, thread_id=args.thread_id):
                for node_name, state in event.items():
                    ts    = time.strftime("%H:%M:%S")
                    round_ = getattr(state, "execution_round", "?")
                    tasks  = getattr(state, "current_tasks",  [])
                    print(f"  [{ts}] ▶ {node_name:<12} round={round_}  tasks={len(tasks)}")
        else:
            # 批量模式：等待最终结果
            result = await agent.run(goal, thread_id=args.thread_id)

            print("\n" + "=" * 62)
            if result.get("success"):
                state  = result.get("state") or {}
                rounds = state.get("execution_round", "?")
                print(f"  ✓ 任务完成  共执行 {rounds} 轮")

                # 优先打印收尾总结报告
                final_report = state.get("final_report")
                if final_report:
                    print("\n" + "=" * 62)
                    print("  【测试总结报告】")
                    print("=" * 62)
                    print(final_report)
                else:
                    # 无总结报告时回退到最后一次反思摘要
                    reflector   = state.get("reflector") or {}
                    reflections = reflector.get("reflection_log", [])
                    if reflections:
                        last = reflections[-1]
                        print(f"\n  摘要: {last.get('summary', '')}")
                        findings = last.get("key_findings", [])
                        if findings:
                            print("  关键发现:")
                            for f in findings[:5]:
                                print(f"    · {f}")
            else:
                print(f"  ✗ 任务失败: {result.get('error')}")
            print("=" * 62)

    except KeyboardInterrupt:
        print("\n\n  已中断。")
    finally:
        # 释放浏览器资源
        try:
            await executors["browser"].close()
        except Exception:
            pass
        # 停止托管的 mitmproxy（若为 auto_start 模式）
        try:
            executors["proxy"].stop()
        except Exception:
            pass


if __name__ == "__main__":
    asyncio.run(main())
