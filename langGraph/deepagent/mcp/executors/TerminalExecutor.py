# src/mcp/executors/TerminalExecutor.py
"""
终端命令执行器（跨平台）

平台后端自动选择：
  Windows:
    powershell 模式（推荐）：长驻 PowerShell 进程管理持久会话。
      Agent 通过 send_keys → get_output 模式与终端交互，
      保留 CWD / $env: 环境变量，只收到命令输出结果。
    直接模式（fallback）：一次性 `powershell -Command` 执行。
  Linux / macOS:
    tmux 模式（推荐）：通过 tmux 会话管理终端。
    直接模式（fallback）：tmux 不可用时使用 asyncio subprocess 一次性执行。
"""

import asyncio
import collections
import os
import shlex
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from typing import Optional, Dict

import structlog

logger = structlog.get_logger(__name__)

_SENTINEL_PREFIX = "DEEPAGENT_DONE_"

_IS_WINDOWS = sys.platform == "win32"

# Windows 沙箱默认工作目录（避免在用户主目录执行命令）
_SANDBOX_DIR = os.path.join(tempfile.gettempdir(), "tsecagent-sandbox")


def default_workdir() -> str:
    """返回平台默认工作目录，并确保其存在。"""
    if _IS_WINDOWS:
        try:
            os.makedirs(_SANDBOX_DIR, exist_ok=True)
        except OSError:
            pass
        return _SANDBOX_DIR
    return "/tmp"


def _ps_quote(s: str) -> str:
    """PowerShell 单引号字面量转义（'' 表示 '）。"""
    return "'" + s.replace("'", "''") + "'"


# ─────────────────────────────────────────────────────────────────────────────
# 后端可用性检查
# ─────────────────────────────────────────────────────────────────────────────

def _check_tmux() -> bool:
    """检查系统是否安装了 tmux。"""
    try:
        r = subprocess.run(["tmux", "-V"], capture_output=True, timeout=3)
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def _check_powershell() -> bool:
    """检查 Windows PowerShell 是否可用。"""
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive",
             "-Command", "$PSVersionTable.PSVersion.Major"],
            capture_output=True, text=True, timeout=20,
        )
        return r.returncode == 0 and r.stdout.strip().isdigit()
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


# ─────────────────────────────────────────────────────────────────────────────
# TmuxSession — tmux 会话管理器（Linux / macOS）
# ─────────────────────────────────────────────────────────────────────────────

class TmuxSession:
    """基于 tmux 的终端会话管理器。

    Agent 通过 new_session → send_keys → get_output 模式与终端交互，
    不直接接触底层 shell 进程，只收到窗格输出结果。

    所有操作均使用同步子进程调用（tmux CLI），在异步上下文中可安全调用，
    因为 tmux 命令本身执行极快（<10ms）。
    """

    def new_session(self) -> str:
        """创建新的 tmux 会话，返回 session_id。

        会话名称格式：da_{8位随机hex}，例如 da_3f7a9c12。
        """
        session_id = f"da_{uuid.uuid4().hex[:8]}"
        subprocess.run(
            ["tmux", "new-session", "-d", "-s", session_id, "-x", "220", "-y", "50"],
            check=True,
            capture_output=True,
        )
        logger.info("tmux_session_created", session_id=session_id)
        return session_id

    def send_keys(self, session_id: str, keys: str, enter: bool = True) -> None:
        """向指定 tmux 会话发送按键/命令。

        Args:
            session_id: new_session() 返回的会话 ID
            keys:       要发送的文本（命令字符串）
            enter:      是否在末尾追加 Enter 键，默认 True
        """
        cmd = ["tmux", "send-keys", "-t", session_id, keys]
        if enter:
            cmd.append("Enter")
        subprocess.run(cmd, check=True, capture_output=True)

    def clear_pane(self, session_id: str) -> None:
        """清空窗格可见内容与滚动历史，防止上条命令输出残留到本次采集。

        顺序至关重要：
          1. 先 ``send-keys C-l``（Ctrl-L）：shell 把可见内容推入滚动历史，
             提示符重绘到窗格顶部；
          2. 再 ``clear-history``：清空刚才被推入的滚动历史。
        若顺序颠倒，clear-history 先清空后 C-l 又会把旧可见内容推回滚动历史。
        """
        subprocess.run(["tmux", "send-keys", "-t", session_id, "C-l"],
                       capture_output=True)
        subprocess.run(["tmux", "clear-history", "-t", session_id],
                       capture_output=True)

    def interrupt(self, session_id: str) -> None:
        """发送 Ctrl-C 中断当前运行的命令（shell 自身仍可继续使用）。"""
        subprocess.run(["tmux", "send-keys", "-t", session_id, "C-c"],
                       capture_output=True)

    def get_output(self, session_id: str, history_lines: int = 500) -> str:
        """捕获 tmux 窗格的当前可视输出（含滚动历史）。

        Args:
            session_id:    会话 ID
            history_lines: 向上捕获的历史行数，默认 500

        Returns:
            窗格输出文本（含 ANSI 转义码）
        """
        result = subprocess.run(
            ["tmux", "capture-pane", "-t", session_id, "-p", "-e",
             "-S", str(-history_lines)],
            capture_output=True,
            text=True,
            errors="replace",
        )
        return result.stdout

    def kill_session(self, session_id: str) -> None:
        """销毁 tmux 会话，释放资源。"""
        subprocess.run(
            ["tmux", "kill-session", "-t", session_id],
            capture_output=True,
        )
        logger.debug("tmux_session_killed", session_id=session_id)

    def session_exists(self, session_id: str) -> bool:
        """检查指定 tmux 会话是否存在。"""
        r = subprocess.run(
            ["tmux", "has-session", "-t", session_id],
            capture_output=True,
        )
        return r.returncode == 0

    def list_sessions(self) -> list:
        """列出所有由 DeepAgent 创建的 tmux 会话。"""
        result = subprocess.run(
            ["tmux", "list-sessions", "-F", "#{session_name}"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            return []
        return [s for s in result.stdout.splitlines() if s.startswith("da_")]


# ─────────────────────────────────────────────────────────────────────────────
# PowerShellSession — Windows 长驻 PowerShell 会话管理器
# ─────────────────────────────────────────────────────────────────────────────

class _PSReader(threading.Thread):
    """后台线程：持续读取 PowerShell 进程 stdout 到环形缓冲。"""

    def __init__(self, proc: subprocess.Popen):
        super().__init__(daemon=True)
        self.proc = proc
        self.lines: collections.deque = collections.deque(maxlen=500)
        self.dead = False

    def run(self) -> None:
        try:
            for line in self.proc.stdout:
                self.lines.append(line.rstrip("\r\n"))
        except Exception:
            pass
        self.dead = True


class PowerShellSession:
    """基于长驻 PowerShell 进程的终端会话管理器（Windows）。

    以 `powershell -NoProfile -NoExit -Command -` 启动 REPL 进程，
    通过 stdin 写入命令、后台线程读取 stdout 到环形缓冲（模拟 tmux
    的 capture-pane 历史）。会话内 CWD / $env: 变量跨调用保留。

    语义差异说明（相对 bash）：
    - 退出码使用 $LASTEXITCODE，仅对外部命令（exe/cmdlet 调用外部程序）
      更新；纯 cmdlet 失败不会改变它。渗透场景中 execute_shell 绝大多数
      调用外部工具，语义与 bash $? 一致。
    """

    def __init__(self):
        # session_id → {"proc": Popen, "reader": _PSReader}
        self._procs: Dict[str, dict] = {}

    def new_session(self) -> str:
        """创建新的 PowerShell 会话，返回 session_id。"""
        session_id = f"da_{uuid.uuid4().hex[:8]}"
        proc = subprocess.Popen(
            ["powershell", "-NoProfile", "-NoExit", "-Command", "-"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,   # 合并 stderr（与 tmux 混屏语义一致）
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
        )
        reader = _PSReader(proc)
        reader.start()
        self._procs[session_id] = {"proc": proc, "reader": reader}
        # 首条命令强制 UTF-8，避免中文输出乱码
        self.send_keys(
            session_id,
            "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; $OutputEncoding=[System.Text.Encoding]::UTF8",
            enter=True,
        )
        logger.info("powershell_session_created", session_id=session_id,
                    pid=proc.pid)
        return session_id

    def send_keys(self, session_id: str, keys: str, enter: bool = True) -> None:
        """向指定会话写入命令行。"""
        entry = self._procs.get(session_id)
        if not entry or entry["proc"].stdin is None or entry["proc"].stdin.closed:
            raise RuntimeError(f"PowerShell session {session_id} not available")
        entry["proc"].stdin.write(keys + ("\n" if enter else ""))
        entry["proc"].stdin.flush()

    def get_output(self, session_id: str, history_lines: int = 500) -> str:
        """返回会话输出缓冲快照（最近 history_lines 行）。"""
        entry = self._procs.get(session_id)
        if not entry:
            return ""
        lines = list(entry["reader"].lines)
        if history_lines and len(lines) > history_lines:
            lines = lines[-history_lines:]
        return "\n".join(lines)

    def mark_consumed(self, session_id: str) -> None:
        """清空已解析的输出缓冲，防止上一次的哨兵行泄漏到下一次结果。"""
        entry = self._procs.get(session_id)
        if entry:
            entry["reader"].lines.clear()

    def kill_session(self, session_id: str) -> None:
        """销毁会话：杀整个进程树并关闭 stdin。"""
        entry = self._procs.pop(session_id, None)
        if not entry:
            return
        proc = entry["proc"]
        try:
            if _IS_WINDOWS:
                subprocess.run(
                    ["taskkill", "/T", "/F", "/PID", str(proc.pid)],
                    capture_output=True, timeout=10,
                )
            else:
                proc.terminate()
        except Exception:
            pass
        try:
            if proc.stdin and not proc.stdin.closed:
                proc.stdin.close()
        except Exception:
            pass
        logger.debug("powershell_session_killed", session_id=session_id)

    def session_exists(self, session_id: str) -> bool:
        """检查指定会话进程是否存活。"""
        entry = self._procs.get(session_id)
        if not entry:
            return False
        return entry["proc"].poll() is None and not entry["reader"].dead

    def list_sessions(self) -> list:
        """列出当前活跃的会话 ID。"""
        return [sid for sid in self._procs if self.session_exists(sid)]


# ─────────────────────────────────────────────────────────────────────────────
# TerminalExecutor — Agent 工具接口
# ─────────────────────────────────────────────────────────────────────────────

class TerminalExecutor:
    """终端命令执行器

    平台后端自动选择：
    - Linux/macOS：tmux 模式（推荐）→ 直接模式 fallback
    - Windows：powershell 模式（推荐）→ 直接模式 fallback
    支持持久会话（跨调用保留 CWD / 环境变量）和一次性执行。
    """

    def __init__(self, config: dict = None):
        self.config = config or {}
        # 持久会话映射：逻辑 session_id → 后端 session_id
        self._persistent: Dict[str, str] = {}
        self._persistent_lock = asyncio.Lock()

        if _IS_WINDOWS:
            self._backend = "powershell" if _check_powershell() else "direct"
        else:
            self._backend = "tmux" if _check_tmux() else "direct"

        if self._backend == "tmux":
            self.terminal = TmuxSession()
            logger.info("terminal_executor_ready", mode="tmux")
        elif self._backend == "powershell":
            self.terminal = PowerShellSession()
            logger.info("terminal_executor_ready", mode="powershell")
        else:
            self.terminal = None
            logger.warning(
                "terminal_backend_direct",
                hint="持久会话不可用，退化为一次性执行模式",
            )

    # ------------------------------------------------------------------
    # 公开工具方法（Agent 调用入口）
    # ------------------------------------------------------------------

    async def execute(
        self,
        command: str,
        working_dir: str = None,
        timeout: int = 60,
        session_id: Optional[str] = None,
    ) -> dict:
        """执行 Shell 命令并返回结果。

        持久会话模式下：
          1. 创建会话 / 复用持久会话
          2. 发送命令（附哨兵标记）
          3. 轮询输出直到哨兵出现或超时
          4. 解析退出码并返回输出

        Args:
            command:    Shell 命令字符串
            working_dir: 工作目录；None 时从 config["default_dir"] 读取，
                         兜底为平台沙箱目录（Windows: %TEMP%\\tsecagent-sandbox，
                         POSIX: /tmp）
            timeout:    最大等待秒数，默认 60
            session_id: 持久会话 ID（可选）；提供时跨调用保留 CWD / env 状态

        Returns:
            {"success": bool, "stdout": str, "stderr": str, "exit_code": int}
        """
        if not working_dir or not os.path.isdir(working_dir):
            # 配置目录无效（如跨平台拷贝的 /home/daytona）时回退到平台沙箱目录
            working_dir = self.config.get("default_dir") or default_workdir()
        if not os.path.isdir(working_dir):
            working_dir = default_workdir()

        if self._backend == "tmux":
            return await self._execute_tmux(command, working_dir, timeout, session_id)
        if self._backend == "powershell":
            return await self._execute_powershell(command, working_dir, timeout, session_id)
        return await self._execute_subprocess(command, working_dir, timeout)

    async def delete_session(self, session_id: str) -> bool:
        """关闭并销毁指定持久会话。"""
        async with self._persistent_lock:
            backend_sid = self._persistent.pop(session_id, None)
            if backend_sid and self.terminal is not None:
                self.terminal.kill_session(backend_sid)
                return True
        return False

    def list_sessions(self) -> list:
        """列出当前活跃的持久会话 ID 列表。"""
        if self.terminal is not None:
            return self.terminal.list_sessions()
        return []

    # ------------------------------------------------------------------
    # 内部实现 — 持久会话管理（tmux / powershell 共用逻辑）
    # ------------------------------------------------------------------

    async def _get_or_create_session(
        self, logical_id: str, working_dir: str
    ) -> str:
        """获取或新建与逻辑 ID 绑定的后端会话（锁内线程安全）。"""
        async with self._persistent_lock:
            backend_sid = self._persistent.get(logical_id)
            if backend_sid and self.terminal.session_exists(backend_sid):
                return backend_sid
            backend_sid = self.terminal.new_session()
            if self._backend == "tmux":
                self.terminal.send_keys(
                    session_id=backend_sid,
                    keys=f"cd {shlex.quote(working_dir)}",
                    enter=True,
                )
            else:
                self.terminal.send_keys(
                    session_id=backend_sid,
                    keys=f"Set-Location -LiteralPath {_ps_quote(working_dir)}",
                    enter=True,
                )
            await asyncio.sleep(0.3)
            # 丢弃初始化输出（PowerShell 的 UTF-8 设置/cd 回显、tmux 的 cd 回显），
            # 防止首次命令 stdout 被这些残留污染。tmux 无 mark_consumed 方法时为空操作，
            # 其残留由 _execute_tmux 中的 clear_pane 负责清理。
            self._mark_consumed(backend_sid)
            self._persistent[logical_id] = backend_sid
            return backend_sid

    # ------------------------------------------------------------------
    # 内部实现 — tmux 模式（Linux/macOS）
    # ------------------------------------------------------------------

    async def _execute_tmux(
        self,
        command: str,
        working_dir: str,
        timeout: int,
        session_id: Optional[str],
    ) -> dict:
        """通过 tmux 执行命令，使用哨兵标记检测完成。"""
        one_shot = session_id is None

        # 获取/创建会话
        if one_shot:
            sid = self.terminal.new_session()
            self.terminal.send_keys(
                session_id=sid,
                keys=f"cd {shlex.quote(working_dir)}",
                enter=True,
            )
            await asyncio.sleep(0.2)
        else:
            sid = await self._get_or_create_session(session_id, working_dir)

        try:
            # 发送命令，末尾附哨兵 + 退出码
            sentinel = f"{_SENTINEL_PREFIX}{uuid.uuid4().hex[:8]}"
            # T-3 修复：清空窗格历史，保证 capture-pane 只采集本次命令输出
            self.terminal.clear_pane(sid)
            self.terminal.send_keys(
                session_id=sid,
                keys=f"{command}; echo {sentinel}:$?",
                enter=True,
            )
            return await self._poll_sentinel(sid, sentinel, timeout, bash=True)
        except Exception as e:
            logger.error("tmux_execute_error", error=str(e))
            return {
                "success": False,
                "error": str(e),
                "stdout": "",
                "stderr": "",
                "exit_code": -1,
            }
        finally:
            if one_shot:
                self.terminal.kill_session(sid)

    # ------------------------------------------------------------------
    # 内部实现 — powershell 模式（Windows）
    # ------------------------------------------------------------------

    async def _execute_powershell(
        self,
        command: str,
        working_dir: str,
        timeout: int,
        session_id: Optional[str],
    ) -> dict:
        """通过长驻 PowerShell 会话执行命令，使用哨兵标记检测完成。

        一次性执行（session_id=None）直接走直接模式，避免为单条命令
        额外创建/销毁常驻进程。
        """
        if session_id is None:
            return await self._execute_subprocess(command, working_dir, timeout)

        sid = await self._get_or_create_session(session_id, working_dir)

        try:
            # 发送命令，末尾附哨兵 + 退出码（$LASTEXITCODE 仅对外部命令更新）
            sentinel = f"{_SENTINEL_PREFIX}{uuid.uuid4().hex[:8]}"
            self.terminal.send_keys(
                session_id=sid,
                keys=f'{command}; Write-Host "{sentinel}:$LASTEXITCODE"',
                enter=True,
            )
            return await self._poll_sentinel(sid, sentinel, timeout, bash=False)
        except Exception as e:
            logger.error("powershell_execute_error", error=str(e))
            return {
                "success": False,
                "error": str(e),
                "stdout": "",
                "stderr": "",
                "exit_code": -1,
            }

    async def _poll_sentinel(
        self, sid: str, sentinel: str, timeout: int, bash: bool
    ) -> dict:
        """轮询会话输出直到哨兵出现或超时，解析退出码并清理输出。

        bash=True  时哨兵格式为 `{sentinel}:$?`；
        bash=False 时哨兵格式为 `{sentinel}:$LASTEXITCODE`（Write-Host 输出）。
        """
        deadline = time.monotonic() + timeout
        output = ""
        while time.monotonic() < deadline:
            await asyncio.sleep(0.5)
            output = self.terminal.get_output(sid)
            if sentinel in output:
                break
        else:
            # T-2 修复：超时后必须中断正在运行的命令，否则其输出会串台到下一次调用，
            # 且 tmux/PowerShell 会话长期占用资源。中断后 mark_consumed 清理已采集输出。
            self._interrupt_session(sid)
            self._mark_consumed(sid)
            return {
                "success": False,
                "error": f"Command timed out after {timeout}s",
                "stdout": output,
                "stderr": "",
                "exit_code": -1,
            }

        # 解析退出码和清理输出
        exit_code = 0
        result_lines = []
        for line in output.splitlines():
            if sentinel in line:
                try:
                    exit_code = int(line.strip().rsplit(":", 1)[1])
                except (IndexError, ValueError):
                    pass
                break
            result_lines.append(line)

        stdout = "\n".join(result_lines).strip()
        self._mark_consumed(sid)
        return {
            "success": exit_code == 0,
            "stdout": stdout,
            "stderr": "",
            "exit_code": exit_code,
        }

    def _mark_consumed(self, sid: str) -> None:
        """丢弃已解析的会话输出（PowerShellSession 专用，tmux 全量捕获无需处理）。"""
        if hasattr(self.terminal, "mark_consumed"):
            self.terminal.mark_consumed(sid)

    def _interrupt_session(self, sid: str) -> None:
        """中断会话中正在运行的命令（超时路径调用）。

        - tmux：发送 C-c，shell 自身继续可用（保留 CWD / 环境变量）。
        - powershell：管道 stdin 无法可靠传递 Ctrl-C 控制信号（cmdlet 与
          外部子进程仍会运行），故直接 ``taskkill /T /F`` 销毁进程树——
          连带终止挂起的 nmap/gobuster 等子进程——并清除逻辑映射，
          下次 _get_or_create_session 检测到 session_exists 失败即重建。
          CWD 会丢失，但超时场景下可接受。
        """
        if self.terminal is None:
            return
        if self._backend == "powershell":
            try:
                self.terminal.kill_session(sid)
            except Exception as e:
                logger.warning("interrupt_kill_failed", sid=sid, error=str(e))
            # 清除逻辑映射，使下次调用重建会话
            stale = [k for k, v in self._persistent.items() if v == sid]
            for k in stale:
                self._persistent.pop(k, None)
        elif hasattr(self.terminal, "interrupt"):
            try:
                self.terminal.interrupt(sid)
            except Exception as e:
                logger.warning("interrupt_session_failed", sid=sid, error=str(e))

    # ------------------------------------------------------------------
    # 内部实现 — 直接模式（fallback，跨平台）
    # ------------------------------------------------------------------

    async def _execute_subprocess(
        self, command: str, working_dir: str, timeout: int
    ) -> dict:
        """直接模式：一次性执行。

        - Windows: `powershell -Command <command>`，用 cwd 参数切目录，
          语法与 powershell 持久会话一致。
        - POSIX:   `cd <dir> && <command>` 走默认 shell（原逻辑不变）。
        """
        try:
            if _IS_WINDOWS:
                # PowerShell 5.1 的 -Command 不会把外部命令退出码传播给进程
                # 退出码，需显式 exit $LASTEXITCODE 才能让 returncode 透传
                wrapped = f"& {{ {command}\nexit $LASTEXITCODE }}"
                process = await asyncio.create_subprocess_exec(
                    "powershell", "-NoProfile", "-NonInteractive",
                    "-Command", wrapped,
                    cwd=working_dir,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            else:
                full_command = f"cd {shlex.quote(working_dir)} && {command}"
                process = await asyncio.create_subprocess_shell(
                    full_command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=timeout
                )
                return {
                    "success": process.returncode == 0,
                    "stdout": stdout.decode("utf-8", errors="replace"),
                    "stderr": stderr.decode("utf-8", errors="replace"),
                    "exit_code": process.returncode,
                }
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return {
                    "success": False,
                    "error": f"Command timed out after {timeout}s",
                    "stdout": "",
                    "stderr": "",
                    "exit_code": -1,
                }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "stdout": "",
                "stderr": "",
                "exit_code": -1,
            }
