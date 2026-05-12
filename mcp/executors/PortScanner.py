# src/mcp/executors/PortScanner.py
"""
端口扫描器 - 封装 nmap

依赖：nmap（apt install nmap 或 brew install nmap）
"""

import asyncio
import shutil
import time
from typing import Optional

import structlog

logger = structlog.get_logger(__name__)


async def _run_cmd(cmd: list[str], timeout: int = 300) -> tuple[int, str, str]:
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


def _parse_nmap_grepable(output: str) -> list[dict]:
    """解析 nmap -oG 输出，提取开放端口列表。

    示例行：
      Host: 192.168.1.1 ()  Ports: 22/open/tcp//ssh//OpenSSH 8.9/, 80/open/tcp//http//nginx/
    """
    ports = []
    for line in output.splitlines():
        if not line.startswith("Host:"):
            continue
        idx = line.find("Ports:")
        if idx == -1:
            continue
        for entry in line[idx + 6:].strip().split(","):
            parts = entry.strip().split("/")
            if len(parts) >= 3 and parts[1] == "open":
                ports.append({
                    "port":    int(parts[0]),
                    "proto":   parts[2],
                    "service": parts[4] if len(parts) > 4 else "",
                    "version": parts[6] if len(parts) > 6 else "",
                })
    return ports


class PortScanner:
    """nmap 端口扫描器。"""

    def __init__(self, config: dict = None):
        self.config = config or {}

    @staticmethod
    def _which(tool: str) -> Optional[str]:
        return shutil.which(tool)

    async def scan(
        self,
        target: str,
        ports: str = "1-65535",
        timeout: int = 300,
    ) -> dict:
        """对目标执行 nmap 端口扫描。

        Args:
            target:  目标 IP 或主机名
            ports:   "1-1000" / "80,443,8080" / "-"（全端口）
            timeout: 超时秒数

        Returns:
            {"success", "target", "ports_range",
             "open_ports": [{"port","proto","service","version"}],
             "open_count", "elapsed", "output"}
        """
        nmap = self._which("nmap")
        if not nmap:
            return {"success": False, "error": "nmap 未安装: apt install nmap 或 brew install nmap"}

        start = time.monotonic()
        cmd = [
            nmap, "-T4", "-p", ports, "--open",
            "-sV", "--version-intensity", "3",
            "-oG", "-",
            target,
        ]
        logger.info("port_scan_start", target=target, ports=ports)
        rc, stdout, stderr = await _run_cmd(cmd, timeout)
        elapsed = round(time.monotonic() - start, 2)

        if rc == -1:
            return {"success": False, "error": stderr, "target": target}

        open_ports = _parse_nmap_grepable(stdout)
        logger.info("port_scan_done", target=target, open_count=len(open_ports), elapsed=elapsed)
        return {
            "success":     True,
            "target":      target,
            "ports_range": ports,
            "open_ports":  open_ports,
            "open_count":  len(open_ports),
            "elapsed":     elapsed,
            "output":      stdout[:3000],
        }
