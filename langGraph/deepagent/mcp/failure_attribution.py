# src/mcp/failure_attribution.py
from typing import Dict, Any, Optional
from enum import Enum
import structlog

logger = structlog.get_logger(__name__)


class AttributionLevel(Enum):
    L0_OBSERVATION = "L0"  # 观察层 - 原始输出
    L1_TOOL_FAILURE = "L1"  # 工具层 - 工具执行失败
    L2_PREREQUISITE = "L2"  # 前提层 - 前提条件失败
    L3_ENVIRONMENT = "L3"  # 环境层 - 环境阻断
    L4_HYPOTHESIS = "L4"  # 假设层 - 假设被证伪
    L5_STRATEGY = "L5"  # 战略层 - 战略缺陷


class FailureAttributor:
    """失败归因器 - L0-L5 递进归因"""

    def __init__(self):
        self.failure_counts = {}  # 记录失败模式计数

    def attribute(
            self,
            tool_name: str,
            arguments: Dict,
            error: str,
            output: str = ""
    ) -> Dict[str, Any]:
        """执行失败归因

        Returns:
            归因结果字典
        """
        error_lower = error.lower()

        # L1: 工具执行失败
        l1_result = self._check_l1_tool_failure(error_lower, tool_name)
        if l1_result:
            return l1_result

        # L2: 前提条件失败
        l2_result = self._check_l2_prerequisite_failure(error_lower, output)
        if l2_result:
            return l2_result

        # L3: 环境因素
        l3_result = self._check_l3_environment(error_lower)
        if l3_result:
            return l3_result

        # L4: 假设被证伪（需要多次失败）
        failure_key = f"{tool_name}:{str(arguments)}"
        self.failure_counts[failure_key] = self.failure_counts.get(failure_key, 0) + 1

        if self.failure_counts[failure_key] >= 3:
            l4_result = self._check_l4_hypothesis(tool_name, arguments, error_lower)
            if l4_result:
                # 检查是否需要升级到 L5
                if self._check_l5_strategy(tool_name):
                    return {
                        "level": AttributionLevel.L5_STRATEGY.value,
                        "reason": f"多次 L4 失败形成模式，建议调整战略",
                        "failed_attempts": self.failure_counts[failure_key],
                        "suggestion": "考虑完全不同的攻击路径"
                    }
                return l4_result

        # 默认返回 L0 观察层
        return {
            "level": AttributionLevel.L0_OBSERVATION.value,
            "reason": f"工具返回原始输出: {error[:100]}",
            "raw_output": output[:200] if output else error[:200]
        }

    def _check_l1_tool_failure(self, error_lower: str, tool_name: str) -> Optional[Dict]:
        """L1: 工具执行失败"""
        l1_patterns = [
            ("command not found", "命令不存在，工具可能未安装"),
            ("permission denied", "权限不足"),
            ("connection refused", "连接被拒绝"),
            ("no such file", "文件不存在"),
        ]

        for pattern, reason in l1_patterns:
            if pattern in error_lower:
                return {
                    "level": AttributionLevel.L1_TOOL_FAILURE.value,
                    "reason": reason,
                    "tool": tool_name,
                    "suggestion": f"检查 {tool_name} 是否已安装，或使用绝对路径"
                }
        return None

    def _check_l2_prerequisite_failure(self, error_lower: str, output: str) -> Optional[Dict]:
        """L2: 前提条件失败"""
        l2_patterns = [
            ("session expired", "会话已过期，需要重新认证"),
            ("authentication", "认证失败，凭证可能无效"),
            ("login required", "需要登录"),
            ("not authenticated", "未认证"),
            ("invalid token", "令牌无效"),
        ]

        for pattern, reason in l2_patterns:
            if pattern in error_lower or pattern in output.lower():
                return {
                    "level": AttributionLevel.L2_PREREQUISITE.value,
                    "reason": reason,
                    "suggestion": "重新获取有效的认证凭证"
                }
        return None

    def _check_l3_environment(self, error_lower: str) -> Optional[Dict]:
        """L3: 环境阻断"""
        l3_patterns = [
            ("waf", "可能被 WAF 拦截"),
            ("blocked", "请求被防火墙阻断"),
            ("rate limit", "触发速率限制"),
            ("too many requests", "请求过于频繁"),
            ("timeout", "网络超时"),
            ("cloudflare", "Cloudflare 防护"),
        ]

        for pattern, reason in l3_patterns:
            if pattern in error_lower:
                return {
                    "level": AttributionLevel.L3_ENVIRONMENT.value,
                    "reason": reason,
                    "suggestion": "降低请求频率、更换 IP、或使用代理绕过"
                }
        return None

    def _check_l4_hypothesis(self, tool_name: str, arguments: Dict, error_lower: str) -> Dict:
        """L4: 假设被证伪"""
        return {
            "level": AttributionLevel.L4_HYPOTHESIS.value,
            "reason": f"当前假设（使用 {tool_name} 参数 {arguments}）经过多次尝试被证伪",
            "suggestion": "调整参数或更换攻击思路",
            "failed_attempts": self.failure_counts.get(f"{tool_name}:{str(arguments)}", 0)
        }

    def _check_l5_strategy(self, tool_name: str) -> bool:
        """L5: 检查是否应该升级到战略层"""
        # 统计该工具的所有失败次数
        total_failures = sum(
            count for key, count in self.failure_counts.items()
            if key.startswith(tool_name)
        )
        return total_failures >= 10