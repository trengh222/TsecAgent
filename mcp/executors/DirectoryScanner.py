# src/mcp/executors/DirectoryScanner.py
"""
目录扫描器 - 封装 gobuster / ffuf

依赖：gobuster 或 ffuf（二选一）
  apt install gobuster
  go install github.com/ffuf/ffuf/v2@latest

wordlist 关键字：
  "common"    → /usr/share/wordlists/dirb/common.txt
  "big"       → /usr/share/wordlists/dirb/big.txt
  "api"       → /usr/share/seclists/Discovery/Web-Content/api/objects.txt
  "webshell"  → 本地 webshell 路径字典
  "java"      → 本地 Java 文件路径字典
  "java_path" → 本地 Java 路径/文件字典（含路径穿越）
  "jndi"      → 本地 JNDI 注入 payload 字典
  "ssti"      → 本地 SSTI payload 字典
  "sql"       → 本地 SQL 注入字典
  "angular"   → 本地 AngularJS 字典
  "cloud"     → 本地云服务路径字典
  "parameter" → 本地 URL 参数字典
  "viewstate" → 本地 ASP.NET ViewState 字典
  "username"  → 本地用户名字典
  "password"  → 本地密码字典
  绝对路径    → 直接使用
"""

import asyncio
import os
import re
import shutil
import time
from typing import Optional

import structlog

logger = structlog.get_logger(__name__)

# 本地 Dictionary 目录（相对于本文件：../../knowledge/reference/Dictionary/）
_DICT_BASE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "knowledge", "reference", "Dictionary",
)


def _d(filename: str) -> str:
    """返回本地字典绝对路径。"""
    return os.path.join(_DICT_BASE, filename)


_BUILTIN_WORDLIST = [
    "admin", "login", "index", "index.php", "index.html",
    "wp-admin", "wp-login.php", "config", "backup", "api",
    "upload", "uploads", "static", "assets", "js", "css",
    "robots.txt", "sitemap.xml", ".git", ".env",
]

_WORDLIST_MAP = {
    # ── 系统通用词表 ──────────────────────────────────────────────────────────
    "common": [
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/dirbuster/wordlists/directory-list-2.3-small.txt",
    ],
    "big": [
        "/usr/share/seclists/Discovery/Web-Content/big.txt",
        "/usr/share/wordlists/dirb/big.txt",
        "/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt",
    ],
    "api": [
        "/usr/share/seclists/Discovery/Web-Content/api/objects.txt",
        "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt",
    ],
    # ── 本地技术专项字典 ──────────────────────────────────────────────────────
    "webshell":  [_d("webshell.txt")],
    "java":      [_d("Java_file.txt")],
    "java_path": [_d("Java_path_file.txt")],
    "jndi":      [_d("JNDI.txt")],
    "ssti":      [_d("SSTI.txt")],
    "sql":       [_d("SQL字典.txt")],
    "angular":   [_d("AngularJS.txt")],
    "cloud":     [_d("CloudService.txt")],
    "parameter": [_d("parameter.txt")],
    "viewstate": [_d("ViewState.txt")],
    "username":  [_d("username.txt")],
    "cn_username": [_d("CN_username3000.txt")],
    "password":  [_d("password.txt")],
}


def _resolve_wordlist(keyword: str) -> Optional[str]:
    if os.path.isabs(keyword):
        return keyword if os.path.isfile(keyword) else None
    for path in _WORDLIST_MAP.get(keyword, []):
        if os.path.isfile(path):
            return path
    return None


async def _run_cmd(cmd: list[str], timeout: int = 600) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return proc.returncode, stdout.decode(errors="replace"), stderr.decode(errors="replace")
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        return -1, "", f"Command timed out after {timeout}s"


def _parse_gobuster(output: str) -> list[dict]:
    found   = []
    pattern = re.compile(r"^(/\S+)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?")
    for line in output.splitlines():
        m = pattern.match(line.strip())
        if m:
            found.append({
                "path":   m.group(1),
                "status": int(m.group(2)),
                "size":   int(m.group(3)) if m.group(3) else None,
            })
    return found


def _parse_ffuf(output: str) -> list[dict]:
    found = []
    for line in output.splitlines():
        line = line.strip()
        if line:
            found.append({"path": "/" + line.split("/")[-1], "url": line})
    return found


class DirectoryScanner:
    """Web 目录扫描器（gobuster 优先，次选 ffuf）。"""

    def __init__(self, config: dict = None):
        self.config = config or {}

    @staticmethod
    def _which(tool: str) -> Optional[str]:
        return shutil.which(tool)

    async def scan(
        self,
        url: str,
        wordlist: str = "common",
        threads: int = 10,
    ) -> dict:
        """扫描目标 URL 的目录和文件。

        Args:
            url:      目标 URL（如 http://target.com）
            wordlist: "common" / "big" / "api" / 绝对路径
            threads:  并发线程数

        Returns:
            {"success", "url", "tool",
             "found": [{"path","status","size"}],
             "total", "elapsed", "output"}
        """
        wordlist_path = _resolve_wordlist(wordlist)
        tool = self._which("gobuster") or self._which("ffuf")
        if not tool:
            return {"success": False,
                    "error": "gobuster / ffuf 均未安装，"
                             "请执行: apt install gobuster 或 go install github.com/ffuf/ffuf/v2@latest"}

        tmp_path = None
        if not wordlist_path:
            import tempfile, os
            tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
            tmp.write("\n".join(_BUILTIN_WORDLIST))
            tmp.close()
            wordlist_path = tmp_path = tmp.name
            logger.warning("wordlist_not_found_using_builtin", keyword=wordlist)

        try:
            if "gobuster" in tool:
                return await self._gobuster(url, wordlist_path, threads)
            return await self._ffuf(url, wordlist_path, threads)
        finally:
            if tmp_path:
                import os
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

    async def _gobuster(self, url: str, wordlist: str, threads: int) -> dict:
        start = time.monotonic()
        cmd = [
            self._which("gobuster"), "dir",
            "-u", url, "-w", wordlist,
            "-t", str(threads), "--no-progress", "-q", "-o", "-",
        ]
        logger.info("directory_scan_gobuster", url=url)
        rc, stdout, stderr = await _run_cmd(cmd)
        found = _parse_gobuster(stdout)
        return {
            "success": rc != -1, "tool": "gobuster", "url": url,
            "found": found, "total": len(found),
            "elapsed": round(time.monotonic() - start, 2),
            "output": stdout[:3000],
        }

    async def _ffuf(self, url: str, wordlist: str, threads: int) -> dict:
        start = time.monotonic()
        cmd = [
            self._which("ffuf"),
            "-u", url.rstrip("/") + "/FUZZ",
            "-w", wordlist,
            "-t", str(threads),
            "-mc", "200,201,204,301,302,307,401,403,405",
            "-sf", "-s",
        ]
        logger.info("directory_scan_ffuf", url=url)
        rc, stdout, stderr = await _run_cmd(cmd)
        found = _parse_ffuf(stdout)
        return {
            "success": rc != -1, "tool": "ffuf", "url": url,
            "found": found, "total": len(found),
            "elapsed": round(time.monotonic() - start, 2),
            "output": stdout[:3000],
        }
