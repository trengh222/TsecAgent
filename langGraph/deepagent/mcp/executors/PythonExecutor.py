# src/mcp/executors/PythonExecutor.py
"""
Python 代码执行器 - 安全测试 AI Agent 专用环境

安全测试需求：
- 允许执行渗透测试相关操作（端口扫描、漏洞检测等）
- 提供安全可控的沙箱环境
- 限制系统破坏性操作
- 记录所有敏感操作审计日志
- 支持网络请求和扫描
- 防止逃逸和提权
"""

import asyncio
import sys
import time
import traceback
import threading
import ast
import hashlib
import json
from io import StringIO
from typing import Optional, Dict, Any, List, Set, Callable
from pathlib import Path
from datetime import datetime
from collections import defaultdict
import structlog
try:
    import resource  # Unix-only：用于 CPU/内存 rlimit，Windows 上不存在
except ImportError:
    resource = None
import signal
import functools
import os

logger = structlog.get_logger(__name__)

# 执行限制
_MAX_OUTPUT = 10 * 1024 * 1024  # 10 MB（安全测试可能输出较多）
_MAX_MEMORY_MB = 1024  # 1GB 内存（扫描可能需要较大内存）
_MAX_CPU_TIME = 300  # 5分钟CPU时间
_MAX_NETWORK_CONNECTIONS = 100  # 最大并发连接数

# 审计日志级别
AUDIT_INFO = "info"
AUDIT_WARNING = "warning"
AUDIT_ALERT = "alert"

# 允许的安全测试模块（完整保留渗透测试能力）
_PENTEST_MODULES: Set[str] = {
    # 网络扫描与攻击
    "socket", "socketserver", "ssl", "asyncio", "aiohttp", "requests",
    "urllib", "urllib3", "httpx", "scapy", "nmap", "python_nmap",

    # 漏洞利用
    "exploit", "pwnlib", "pwntools", "metasploit", "rpyc",

    # 密码学与编码
    "hashlib", "base64", "binascii", "cryptography", "Crypto",
    "hmac", "secrets", "random", "time", "datetime",

    # 数据处理
    "json", "xml", "yaml", "csv", "re", "struct",

    # 系统信息（受限）
    "platform", "sys", "os", "subprocess", "psutil",

    # Web 测试
    "selenium", "playwright", "beautifulsoup4", "lxml",
    "scrapy", "mechanize",

    # 数据库测试
    "sqlite3", "pymysql", "psycopg2", "redis",

    # 二进制分析
    "pefile", "elf", "capstone", "unicorn",

    # 模糊测试
    "afl", "radamsa", "pythonfuzz",

    # AI/ML 辅助
    "numpy", "pandas", "scikit-learn", "tensorflow", "torch",

    # 工具库
    "colorama", "tqdm", "rich", "click",
}

# 危险操作黑名单（可能破坏系统或逃逸沙箱）
_DANGEROUS_OPERATIONS = {
    "os": [
        "system", "popen", "execl", "execv", "fork", "kill",
        "remove", "rmdir", "unlink", "chmod", "chown",
        "mkfifo", "mknod", "rename",
    ],
    "subprocess": [
        "Popen", "call", "run", "check_output", "check_call",
        "getoutput", "getstatusoutput",
    ],
    "shutil": [
        "rmtree", "move", "copy", "copytree", "make_archive",
    ],
    "pathlib": [
        "unlink", "rmdir", "chmod", "rename",
    ],
    "__builtins__": [
        "exec", "eval", "compile", "__import__", "open",
    ],
    "sys": [
        "setrecursionlimit", "settrace", "setprofile",
        "addaudithook", "breakpointhook",
    ],
    "ctypes": [
        "cdll", "windll", "oledll", "pydll",
    ],
    "resource": [
        "setrlimit",  # 防止修改资源限制
    ],
    "signal": [
        "signal", "kill",  # 防止发送信号
    ],
}

# 允许的路径（白名单）
_ALLOWED_PATHS = [
    Path("/tmp"),  # 临时文件
    Path("/var/tmp"),  # 临时文件
    Path.cwd() / "output",  # 输出目录
    Path.cwd() / "logs",  # 日志目录
    Path.cwd() / "reports",  # 报告目录
    Path.cwd() / "screenshots",  # 截图目录
]

# 审计日志存储
_AUDIT_LOG: List[Dict[str, Any]] = []
_AUDIT_LOCK = threading.Lock()


class AuditLogger:
    """安全测试审计日志"""

    @staticmethod
    def log(level: str, action: str, details: Dict[str, Any],
            session_id: Optional[str] = None):
        """记录审计日志"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "level": level,
            "action": action,
            "details": details,
            "session_id": session_id,
        }

        with _AUDIT_LOCK:
            _AUDIT_LOG.append(entry)
            # 保留最近10000条日志
            if len(_AUDIT_LOG) > 10000:
                _AUDIT_LOG.pop(0)

        # 发送到结构化日志
        logger.warning("security_audit", **entry)

        # 高危操作立即警告
        if level == AUDIT_ALERT:
            logger.error("HIGH_RISK_OPERATION", **entry)


class SecurityError(Exception):
    """安全违规异常"""
    pass


class _OutputBuffer:
    """线程安全的输出缓冲区"""

    def __init__(self, limit: int = _MAX_OUTPUT):
        self._buf = StringIO()
        self._limit = limit
        self._lock = threading.Lock()
        self._truncated = False

    def write(self, text: str) -> None:
        with self._lock:
            used = self._buf.tell()
            if used >= self._limit:
                self._truncated = True
                return
            remaining = self._limit - used
            self._buf.write(text[:remaining])
            if len(text) > remaining:
                self._truncated = True

    def flush(self) -> None:
        pass

    def getvalue(self) -> str:
        val = self._buf.getvalue()
        if self._truncated:
            val += f"\n[输出已截断，限制 {self._limit // 1024 // 1024}MB]"
        return val

    def clear(self) -> None:
        with self._lock:
            self._buf.seek(0)
            self._buf.truncate(0)
            self._truncated = False


class _SandboxImporter:
    """沙箱导入器 - 控制模块导入权限"""

    def __init__(self, allowed_modules: Set[str], audit_callback: Optional[Callable] = None):
        self._allowed = allowed_modules
        self._imported = {}
        self._lock = threading.Lock()
        self._audit = audit_callback

    def import_module(self, name: str, *args, **kwargs):
        """安全导入模块"""
        # 记录导入行为
        if self._audit:
            self._audit(AUDIT_INFO, "module_import", {"module": name})

        # 检查白名单
        base_module = name.split('.')[0]
        if base_module not in self._allowed:
            # 安全测试需要的一些动态导入处理
            if base_module in ["pkg_resources", "setuptools", "pip"]:
                raise ImportError(f"模块 '{name}' 不允许导入（包管理工具）")

            # 允许某些子模块的特殊情况
            allowed_exceptions = {
                "sqlite3": "sqlite3",
                "xml.etree": "xml",
                "xml.dom": "xml",
            }

            if name not in allowed_exceptions:
                raise ImportError(
                    f"模块 '{name}' 不在白名单中。"
                    f"如需使用，请联系管理员添加。"
                )

        # 缓存已导入模块
        with self._lock:
            if name in self._imported:
                return self._imported[name]

        try:
            module = __import__(name, *args, **kwargs)
            with self._lock:
                self._imported[name] = module
            return module
        except ImportError as e:
            raise ImportError(f"导入模块 '{name}' 失败: {str(e)}")


class _SafeSys:
    """安全的 sys 模块（审计危险调用）"""

    def __init__(self, out: _OutputBuffer, err: _OutputBuffer, audit_callback: Callable):
        self.stdout = out
        self.stderr = err
        self.version = sys.version
        self.version_info = sys.version_info
        self.platform = sys.platform
        self.maxsize = sys.maxsize
        self.argv = []
        self.path = []
        self._audit = audit_callback

    def exit(self, code=0):
        self._audit(AUDIT_INFO, "sys_exit", {"code": code})
        raise SystemExit(code)

    def __getattr__(self, name):
        dangerous = ["setrecursionlimit", "settrace", "setprofile",
                     "addaudithook", "breakpointhook"]
        if name in dangerous:
            self._audit(AUDIT_ALERT, f"dangerous_sys_{name}", {})
            raise SecurityError(f"sys.{name} 被禁止")
        raise AttributeError(f"'SafeSys' has no attribute '{name}'")


class _SafeOS:
    """安全的 os 模块包装器（审计和限制危险操作）"""

    def __init__(self, audit_callback: Callable):
        self._real_os = os
        self._audit = audit_callback
        self.name = os.name
        self.path = os.path

    def __getattr__(self, name):
        # 检查危险函数
        if name in _DANGEROUS_OPERATIONS.get("os", []):
            self._audit(AUDIT_ALERT, f"blocked_os_{name}", {"function": name})
            raise SecurityError(f"os.{name} 被禁止（潜在危险操作）")

        # 允许的安全函数
        safe_functions = ["getenv", "environ", "getcwd", "listdir", "access",
                          "stat", "path", "sep", "linesep"]

        if name in safe_functions or name.startswith("_"):
            attr = getattr(self._real_os, name)
            self._audit(AUDIT_INFO, f"os_{name}", {"function": name})
            return attr

        # 其他函数需要明确允许
        self._audit(AUDIT_WARNING, f"unverified_os_{name}", {"function": name})
        raise SecurityError(f"os.{name} 需要明确授权才能使用")

    def getcwd(self):
        return self._real_os.getcwd()

    def listdir(self, path):
        # 限制目录访问
        if not self._is_safe_path(path):
            raise SecurityError(f"不允许访问目录: {path}")
        return self._real_os.listdir(path)

    def _is_safe_path(self, path):
        """检查路径是否安全"""
        try:
            resolved = Path(path).resolve()
            for allowed in _ALLOWED_PATHS:
                if resolved == allowed or allowed in resolved.parents:
                    return True
            return False
        except Exception:
            return False


class _SafeSubprocess:
    """安全的 subprocess 模块（仅允许只读命令）"""

    ALLOWED_COMMANDS = {
        "ping", "nslookup", "dig", "host",  # DNS查询
        "curl", "wget",  # 网络请求
        "whois",  # WHOIS查询
        "nmap", "masscan", "zmap",  # 端口扫描（需预装）
        "gobuster", "ffuf", "dirb",  # 目录扫描
        "sqlmap", "nikto",  # 漏洞扫描
        "python3", "python",  # Python脚本
        "openssl",  # SSL工具
        "traceroute", "mtr",  # 路由追踪
    }

    def __init__(self, audit_callback: Callable):
        self._audit = audit_callback

    def run(self, args, **kwargs):
        """限制的命令执行"""
        if isinstance(args, str):
            cmd = args.split()[0]
        else:
            cmd = args[0] if args else ""

        cmd_base = Path(cmd).name

        if cmd_base not in self.ALLOWED_COMMANDS:
            self._audit(AUDIT_ALERT, "blocked_command", {"command": cmd})
            raise SecurityError(f"命令 '{cmd}' 不允许执行")

        self._audit(AUDIT_INFO, "allowed_command", {"command": cmd})

        # 添加超时和输出限制
        kwargs.setdefault("timeout", 60)
        kwargs.setdefault("capture_output", True)
        kwargs.setdefault("text", True)

        return self._real_run(args, **kwargs)

    def _real_run(self, args, **kwargs):
        """实际执行"""
        import subprocess
        return subprocess.run(args, **kwargs)

    Popen = run
    call = run
    check_output = run


class _SafeSocket:
    """socket.socket 包装器：受控 close() 维护连接计数。

    直接对 socket 实例赋值 ``sock.close = ...`` 会抛 AttributeError
    （内置 socket 类型无 __dict__，属性只读），故改用组合 + __getattr__
    委托其余属性/方法，仅覆盖 close() 注入计数逻辑。
    """

    def __init__(self, sock, on_close: Callable[[], None]):
        self._sock = sock
        self._on_close = on_close
        self._released = False

    def __getattr__(self, name):
        # settimeout / connect / recv / send / fileno / getpeername 等全部委托
        return getattr(self._sock, name)

    def close(self):
        try:
            self._sock.close()
        finally:
            # 防御重复 close 导致计数归零越界
            if not self._released:
                self._released = True
                self._on_close()


class _SafeNetwork:
    """安全的网络操作（防止拒绝服务和攻击）"""

    def __init__(self, audit_callback: Callable):
        self._audit = audit_callback
        self._connections = 0
        self._lock = threading.Lock()

    def create_socket(self, *args, **kwargs):
        """创建受限的 socket"""
        import socket

        self._audit(AUDIT_INFO, "socket_created", {})

        with self._lock:
            if self._connections >= _MAX_NETWORK_CONNECTIONS:
                raise SecurityError(f"超过最大连接数限制: {_MAX_NETWORK_CONNECTIONS}")
            self._connections += 1

        sock = socket.socket(*args, **kwargs)
        # 设置超时防止阻塞
        sock.settimeout(30)

        def release():
            with self._lock:
                # 防御性下限，避免重复 close 导致负数
                self._connections = max(0, self._connections - 1)

        # 包装为 _SafeSocket：socket 内置类型不可赋值属性，必须用包装类
        return _SafeSocket(sock, release)


class PythonExecutor:
    """Python 代码执行器 - 安全测试专用版本"""

    def __init__(self, config: dict = None):
        self.config = config or {}

        # 配置参数
        self.allowed_modules = set(self.config.get("allowed_modules", _PENTEST_MODULES))
        self.max_output = self.config.get("max_output", _MAX_OUTPUT)
        self.max_memory_mb = self.config.get("max_memory_mb", _MAX_MEMORY_MB)
        self.max_cpu_time = self.config.get("max_cpu_time", _MAX_CPU_TIME)
        self.enable_audit = self.config.get("enable_audit", True)
        self.enable_network = self.config.get("enable_network", True)
        self.enable_filesystem = self.config.get("enable_filesystem", False)

        # 执行器状态
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self._session_lock = threading.Lock()

        # 创建安全组件
        self._audit = AuditLogger().log if self.enable_audit else lambda *args, **kwargs: None
        self._importer = _SandboxImporter(self.allowed_modules, self._audit)
        self._safe_os = _SafeOS(self._audit) if self.enable_filesystem else None
        self._safe_subprocess = _SafeSubprocess(self._audit)
        self._safe_network = _SafeNetwork(self._audit) if self.enable_network else None

        # 统计信息
        self.stats = {
            "total_executions": 0,
            "successful": 0,
            "failed": 0,
            "security_blocks": 0,
            "total_time": 0.0,
        }

        logger.info("python_executor_initialized",
                    modules_count=len(self.allowed_modules),
                    audit_enabled=self.enable_audit,
                    network_enabled=self.enable_network,
                    filesystem_enabled=self.enable_filesystem)

    # ------------------------------------------------------------------
    # 代码安全检查
    # ------------------------------------------------------------------

    def validate_security(self, code: str) -> Dict[str, Any]:
        """深度安全验证代码"""
        warnings = []
        errors = []
        imports = []

        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            return {
                "safe": False,
                "errors": [f"语法错误: {e}"],
                "warnings": [],
                "imports": []
            }

        # AST 分析
        for node in ast.walk(tree):
            # 检查导入
            if isinstance(node, ast.Import):
                for alias in node.names:
                    module = alias.name
                    imports.append(module)

                    if module.split('.')[0] not in self.allowed_modules:
                        errors.append(f"禁止导入模块: {module}")

            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                imports.append(module)

                if module and module.split('.')[0] not in self.allowed_modules:
                    errors.append(f"禁止导入模块: {module}")

            # 检查危险函数调用
            elif isinstance(node, ast.Call):
                # 检查 eval/exec
                if isinstance(node.func, ast.Name):
                    if node.func.id in ["eval", "exec", "compile"]:
                        errors.append(f"禁止使用 {node.func.id}()")

                # 检查危险方法
                elif isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name):
                        obj = node.func.value.id
                        method = node.func.attr

                        # 检查危险 API
                        dangerous_pairs = [
                            ("os", ["system", "popen", "remove"]),
                            ("subprocess", ["Popen", "call", "run"]),
                            ("socket", ["bind", "listen"]),
                        ]

                        for dangerous_obj, methods in dangerous_pairs:
                            if obj == dangerous_obj and method in methods:
                                if method in ["bind", "listen"]:
                                    warnings.append(f"网络监听操作: {obj}.{method}()（可能需要额外权限）")
                                else:
                                    errors.append(f"禁止使用: {obj}.{method}()")

            # 检查无限循环
            elif isinstance(node, ast.While):
                if isinstance(node.test, ast.Constant) and node.test.value is True:
                    warnings.append("检测到 while True 循环，请确保有退出条件")

        return {
            "safe": len(errors) == 0,
            "errors": errors,
            "warnings": warnings,
            "imports": imports
        }

    # ------------------------------------------------------------------
    # 会话管理
    # ------------------------------------------------------------------

    def _create_safe_globals(self, session_id: Optional[str] = None) -> Dict[str, Any]:
        """创建安全的全局命名空间"""
        safe_globals = {
            "__builtins__": self._get_safe_builtins(safe_import=self._importer.import_module),
            "__name__": "__main__",
            "__doc__": None,
        }

        if self._safe_os:
            safe_globals["os"] = self._safe_os

        safe_globals["subprocess"] = self._safe_subprocess

        if self._safe_network:
            # 注入安全的 socket
            import socket
            safe_globals["socket"] = self._safe_network.create_socket

        # 注入辅助工具
        safe_globals["print"] = lambda *args, **kwargs: None  # 会被覆盖
        safe_globals["_audit_log"] = self._audit

        # 注入常用常量
        safe_globals["ALLOWED_MODULES"] = list(self.allowed_modules)

        return safe_globals

    def _get_safe_builtins(self, safe_import=None) -> Dict[str, Any]:
        """获取安全的 builtins"""
        safe_builtins = {}

        dangerous = ["exec", "eval", "compile", "open", "input",
                     "breakpoint", "help", "exit", "quit"]

        builtins_dict = __builtins__ if isinstance(__builtins__, dict) else __builtins__.__dict__
        for name, obj in builtins_dict.items():
            if name not in dangerous:
                safe_builtins[name] = obj

        # 添加安全的文件操作
        safe_builtins["open"] = self._safe_open

        # 注入安全的 __import__
        if safe_import:
            safe_builtins["__import__"] = safe_import

        return safe_builtins

    def _safe_open(self, file: str, mode: str = "r", **kwargs):
        """安全的文件打开函数"""
        # 审计文件访问
        self._audit(AUDIT_INFO, "file_access", {"path": file, "mode": mode})

        # 检查模式
        if any(m in mode for m in ["w", "a", "+", "x"]):
            raise SecurityError(f"文件写入模式不被允许: {mode}")

        # 检查路径
        file_path = Path(file).resolve()
        allowed = False

        for allowed_path in _ALLOWED_PATHS:
            if file_path == allowed_path or allowed_path in file_path.parents:
                allowed = True
                break

        if not allowed:
            raise SecurityError(f"不允许访问路径: {file}")

        # 限制文件大小
        if file_path.exists() and file_path.stat().st_size > _MAX_OUTPUT:
            raise SecurityError(f"文件过大: {file_path.stat().st_size} 字节")

        return open(file, mode, **kwargs)

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """获取会话"""
        with self._session_lock:
            return self.sessions.get(session_id)

    def create_session(self, session_id: str) -> str:
        """创建新会话"""
        with self._session_lock:
            if session_id not in self.sessions:
                self.sessions[session_id] = self._create_safe_globals(session_id)
                self._audit(AUDIT_INFO, "session_created", {"session_id": session_id})
            return session_id

    def delete_session(self, session_id: str) -> bool:
        """删除会话"""
        with self._session_lock:
            if session_id in self.sessions:
                del self.sessions[session_id]
                self._audit(AUDIT_INFO, "session_deleted", {"session_id": session_id})
                return True
            return False

    def list_sessions(self) -> List[str]:
        with self._session_lock:
            return list(self.sessions.keys())

    # ------------------------------------------------------------------
    # 执行核心
    # ------------------------------------------------------------------

    async def execute(
            self,
            code: str,
            timeout: int = 120,
            session_id: Optional[str] = None,
            validate: bool = True,
    ) -> Dict[str, Any]:
        """执行 Python 代码

        Args:
            code: Python 代码
            timeout: 超时秒数
            session_id: 会话ID（共享状态）
            validate: 是否进行安全验证
        """
        start_time = time.monotonic()

        # 更新统计
        self.stats["total_executions"] += 1

        # 安全验证
        if validate:
            security_check = self.validate_security(code)
            if not security_check["safe"]:
                self.stats["security_blocks"] += 1
                self._audit(AUDIT_ALERT, "security_block",
                            {"errors": security_check["errors"]})

                return {
                    "success": False,
                    "error": "安全验证失败",
                    "details": security_check["errors"],
                    "warnings": security_check["warnings"],
                    "stdout": "",
                    "stderr": "",
                    "execution_time": 0.0,
                }

        # 准备执行环境
        buf_out = _OutputBuffer(self.max_output)
        buf_err = _OutputBuffer(self.max_output)

        try:
            # 获取或创建会话
            if session_id:
                with self._session_lock:
                    if session_id not in self.sessions:
                        self.sessions[session_id] = self._create_safe_globals(session_id)
                    exec_globals = self.sessions[session_id]
            else:
                exec_globals = self._create_safe_globals()

            # 注入输出捕获
            exec_globals["sys"] = _SafeSys(buf_out, buf_err, self._audit)
            exec_globals["print"] = self._make_print(buf_out, buf_err)
            exec_globals["__session_id__"] = session_id

            # 记录执行审计
            code_hash = hashlib.sha256(code.encode()).hexdigest()[:16]
            self._audit(AUDIT_INFO, "code_execution",
                        {"session_id": session_id, "code_hash": code_hash,
                         "code_length": len(code)})

            # 设置资源限制（macOS 默认 RLIMIT_CPU soft limit 可能远超 hard limit，
            # 此时 setrlimit 会失败，静默跳过即可，不影响安全性）
            if resource is not None and hasattr(resource, "setrlimit"):
                try:
                    resource.setrlimit(resource.RLIMIT_CPU, (self.max_cpu_time, self.max_cpu_time))
                    memory_bytes = self.max_memory_mb * 1024 * 1024
                    resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
                except (ValueError, OSError) as e:
                    err_str = str(e)
                    if "current limit exceeds maximum" not in err_str and "exceeds maximum" not in err_str:
                        logger.warning("setrlimit_failed", error=err_str)
                except Exception as e:
                    logger.warning("setrlimit_failed", error=str(e))

            # 执行代码
            loop = asyncio.get_running_loop()
            error_tb = await asyncio.wait_for(
                loop.run_in_executor(None, self._run_code, code, exec_globals),
                timeout=timeout
            )

            elapsed = round(time.monotonic() - start_time, 4)

            # 更新统计
            if error_tb is None:
                self.stats["successful"] += 1
            else:
                self.stats["failed"] += 1
            self.stats["total_time"] += elapsed

            result = {
                "success": error_tb is None,
                "stdout": buf_out.getvalue(),
                "stderr": buf_err.getvalue(),
                "execution_time": elapsed,
            }

            if error_tb:
                # 限制 traceback 长度，避免日志过长
                truncated_tb = (error_tb[:3000] + "\n[truncated]") if len(error_tb) > 3000 else error_tb
                result["error"] = truncated_tb
                result["traceback"] = truncated_tb
                self._audit(AUDIT_WARNING, "execution_error",
                            {"session_id": session_id, "error": error_tb.splitlines()[-1] if error_tb.splitlines() else "unknown error"})

            return result

        except asyncio.TimeoutError:
            elapsed = round(time.monotonic() - start_time, 4)
            self.stats["failed"] += 1

            self._audit(AUDIT_WARNING, "execution_timeout",
                        {"session_id": session_id, "timeout": timeout})

            return {
                "success": False,
                "error": f"执行超时 ({timeout} 秒)",
                "stdout": buf_out.getvalue(),
                "stderr": buf_err.getvalue(),
                "execution_time": elapsed,
            }

        except SecurityError as e:
            elapsed = round(time.monotonic() - start_time, 4)
            self.stats["failed"] += 1
            self.stats["security_blocks"] += 1

            self._audit(AUDIT_ALERT, "security_violation",
                        {"session_id": session_id, "error": str(e)})

            return {
                "success": False,
                "error": f"安全违规: {str(e)}",
                "stdout": buf_out.getvalue(),
                "stderr": buf_err.getvalue(),
                "execution_time": elapsed,
            }

        except Exception as e:
            elapsed = round(time.monotonic() - start_time, 4)
            self.stats["failed"] += 1

            logger.error("execution_error", error=str(e), session_id=session_id)

            return {
                "success": False,
                "error": str(e),
                "stdout": buf_out.getvalue(),
                "stderr": buf_err.getvalue(),
                "execution_time": elapsed,
            }

    @staticmethod
    def _run_code(code: str, exec_globals: dict) -> Optional[str]:
        """在线程中执行代码"""
        try:
            compiled = compile(code, "<security_test>", "exec")
            exec(compiled, exec_globals)
            return None
        except SystemExit:
            return None
        except MemoryError:
            return "内存不足错误"
        except RecursionError:
            return "递归深度超限"
        except Exception:
            return traceback.format_exc()

    @staticmethod
    def _make_print(out: _OutputBuffer, err: _OutputBuffer):
        """安全的 print 函数"""

        def _print(*args, sep=" ", end="\n", file=None, flush=False):
            text = sep.join(str(a) for a in args) + end
            if file is None or file is sys.stdout:
                out.write(text)
            elif file is sys.stderr:
                err.write(text)
            else:
                try:
                    file.write(text)
                except Exception:
                    err.write("警告: 自定义文件对象写入失败\n")

        return _print

    # ------------------------------------------------------------------
    # 辅助功能
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        stats = self.stats.copy()
        stats["active_sessions"] = len(self.sessions)
        stats["total_audit_logs"] = len(_AUDIT_LOG)

        if stats["total_executions"] > 0:
            stats["success_rate"] = stats["successful"] / stats["total_executions"]
        else:
            stats["success_rate"] = 0.0

        return stats

    def get_audit_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        """获取审计日志"""
        with _AUDIT_LOCK:
            return _AUDIT_LOG[-limit:]

    def clear_audit_logs(self):
        """清空审计日志"""
        with _AUDIT_LOCK:
            _AUDIT_LOG.clear()