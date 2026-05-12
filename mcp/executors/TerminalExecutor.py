# src/mcp/executors/TerminalExecutor.py
"""
终端命令执行器

双模式运行：
  tmux 模式（推荐）：通过 tmux 会话管理终端。
    Agent 通过 send_keys → get_output 模式与终端交互，
    不直接接触 shell 进程，只收到命令输出结果。

  直接模式（fallback）：tmux 不可用时使用 asyncio subprocess 一次性执行。
"""

import asyncio
import shlex
import subprocess
import time
import uuid
from typing import Optional, Dict

import structlog

logger = structlog.get_logger(__name__)

_SENTINEL_PREFIX = "DEEPAGENT_DONE_"


# ─────────────────────────────────────────────────────────────────────────────
# tmux 可用性检查
# ─────────────────────────────────────────────────────────────────────────────

def _check_tmux() -> bool:
    """检查系统是否安装了 tmux。"""
    try:
        r = subprocess.run(["tmux", "-V"], capture_output=True, timeout=3)
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


# ─────────────────────────────────────────────────────────────────────────────
# TmuxSession — tmux 会话管理器
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
# TerminalExecutor — Agent 工具接口
# ─────────────────────────────────────────────────────────────────────────────

class TerminalExecutor:
    """终端命令执行器

    双模式运行：
    - tmux 模式（推荐）：通过 TmuxSession 管理终端会话。
      支持持久会话（跨调用保留 CWD / 环境变量）和一次性执行。
    - 直接模式（fallback）：tmux 不可用时使用 asyncio subprocess。
    """

    def __init__(self, config: dict = None):
        self.config = config or {}
        self._tmux_ok = _check_tmux()
        # 持久会话映射：逻辑 session_id → tmux session_id
        self._persistent: Dict[str, str] = {}
        self._persistent_lock = asyncio.Lock()

        if self._tmux_ok:
            self.terminal = TmuxSession()
            logger.info("terminal_executor_ready", mode="tmux")
        else:
            self.terminal = None
            logger.warning(
                "tmux_not_found",
                hint="建议安装 tmux：brew install tmux / apt install tmux",
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

        tmux 模式下（推荐）：
          1. 创建 tmux 会话 / 复用持久会话
          2. send_keys 发送命令（附哨兵标记）
          3. 轮询 get_output 直到哨兵出现或超时
          4. 解析退出码并返回输出

        Args:
            command:    Shell 命令字符串
            working_dir: 工作目录；None 时从 config["default_dir"] 读取，兜底 /tmp
            timeout:    最大等待秒数，默认 60
            session_id: 持久会话 ID（可选）；提供时跨调用保留 CWD / env 状态

        Returns:
            {"success": bool, "stdout": str, "stderr": str, "exit_code": int}
        """
        if working_dir is None:
            working_dir = self.config.get("default_dir", "/tmp")

        if self._tmux_ok:
            return await self._execute_tmux(command, working_dir, timeout, session_id)
        return await self._execute_subprocess(command, working_dir, timeout)

    async def delete_session(self, session_id: str) -> bool:
        """关闭并销毁指定持久会话。"""
        async with self._persistent_lock:
            tmux_sid = self._persistent.pop(session_id, None)
            if tmux_sid and self._tmux_ok:
                self.terminal.kill_session(tmux_sid)
                return True
        return False

    def list_sessions(self) -> list:
        """列出当前活跃的持久会话 ID 列表。"""
        if self._tmux_ok:
            return self.terminal.list_sessions()
        return []

    # ------------------------------------------------------------------
    # 内部实现 — tmux 模式
    # ------------------------------------------------------------------

    async def _get_or_create_tmux_session(
        self, logical_id: str, working_dir: str
    ) -> str:
        """获取或新建与逻辑 ID 绑定的 tmux 会话（线程安全）。"""
        async with self._persistent_lock:
            tmux_sid = self._persistent.get(logical_id)
            if tmux_sid and self.terminal.session_exists(tmux_sid):
                return tmux_sid
            # 创建新会话并 cd 到工作目录
            tmux_sid = self.terminal.new_session()
            self.terminal.send_keys(
                session_id=tmux_sid,
                keys=f"cd {shlex.quote(working_dir)}",
                enter=True,
            )
            await asyncio.sleep(0.3)
            self._persistent[logical_id] = tmux_sid
            return tmux_sid

    async def _execute_tmux(
        self,
        command: str,
        working_dir: str,
        timeout: int,
        session_id: Optional[str],
    ) -> dict:
        """通过 tmux 执行命令，使用哨兵标记检测完成。

        执行流程（与规格一致）：
          session_id = self.terminal.new_session()
          self.terminal.send_keys(session_id=session_id, keys=command, enter=True)
          # 轮询替代 sleep(2)，可靠等待哨兵出现
          output = self.terminal.get_output(session_id)
        """
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
            sid = await self._get_or_create_tmux_session(session_id, working_dir)

        try:
            # 发送命令，末尾附哨兵 + 退出码
            sentinel = f"{_SENTINEL_PREFIX}{uuid.uuid4().hex[:8]}"
            self.terminal.send_keys(
                session_id=sid,
                keys=f"{command}; echo {sentinel}:$?",
                enter=True,
            )

            # 轮询等待哨兵出现
            deadline = time.monotonic() + timeout
            output = ""
            while time.monotonic() < deadline:
                await asyncio.sleep(0.5)
                output = self.terminal.get_output(sid)
                if sentinel in output:
                    break
            else:
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
            return {
                "success": exit_code == 0,
                "stdout": stdout,
                "stderr": "",
                "exit_code": exit_code,
            }

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
    # 内部实现 — 直接模式（fallback）
    # ------------------------------------------------------------------

    async def _execute_subprocess(
        self, command: str, working_dir: str, timeout: int
    ) -> dict:
        """直接模式：asyncio subprocess 一次性执行（tmux 不可用时使用）。"""
        full_command = f"cd {shlex.quote(working_dir)} && {command}"
        try:
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
