# src/agent/guardrails.py
import json
from collections import deque
from difflib import SequenceMatcher
from typing import Deque, Optional, Tuple


class CommandHistory:
    """滑动窗口命令历史，使用 deque 保证 O(1) 追加和弹出。"""

    def __init__(self, max_length: int = 20):
        self.commands: Deque[str] = deque(maxlen=max_length)

    def add(self, command: str) -> None:
        self.commands.append(command)

    def last(self) -> Optional[str]:
        return self.commands[-1] if self.commands else None

    def contains_similar(self, command: str, threshold: float) -> bool:
        """检查历史窗口中是否已有高度相似的命令（不仅限于最后一条）。"""
        for hist_cmd in self.commands:
            if SequenceMatcher(None, command, hist_cmd).ratio() >= threshold:
                return True
        return False


class AntiAddictionGuard:
    def __init__(self, similarity_threshold: float = 0.85, max_similar_count: int = 5):
        self.threshold = similarity_threshold
        self.max_count = max_similar_count  # 连续相似命令超过此数即触发
        self.history = CommandHistory(max_length=20)
        self.similar_count = 0
        # 用于记录 output 签名，检测回显相同的情况
        self._output_signatures: Deque[str] = deque(maxlen=10)
        self._same_output_count: int = 0

    def check_and_record(self, task: dict) -> Tuple[bool, Optional[str]]:
        """检查是否陷入循环，并记录命令。

        Returns:
            (is_looping, warning_message)
        """
        command = f"{task.get('tool')}_{json.dumps(task.get('arguments', {}), sort_keys=True)}"
        last_cmd = self.history.last()

        if last_cmd:
            similarity = SequenceMatcher(None, command, last_cmd).ratio()
            if similarity >= self.threshold:
                self.similar_count += 1
                if self.similar_count >= self.max_count:
                    self.similar_count = 0
                    warning = (
                        f"⚠️ 防沉迷触发：连续 {self.max_count} 次发送高度相似命令（相似度≥{self.threshold:.0%}），"
                        f"当前工具: {task.get('tool')}。请立即换用不同的 payload 或切换测试方向，禁止重复同一思路。"
                    )
                    self.history.add(command)
                    return True, warning
            else:
                self.similar_count = 0

        # 即使不与最后一条相似，也检查在整个窗口内是否出现过（防止 ABAB 型循环）
        if self.history.contains_similar(command, threshold=0.92):
            self.similar_count += 1
            if self.similar_count >= self.max_count * 2:
                self.similar_count = 0
                warning = (
                    f"⚠️ 防沉迷触发：在最近历史中检测到重复命令（工具: {task.get('tool')}），"
                    f"请切换新的测试角度或方向。"
                )
                self.history.add(command)
                return True, warning

        self.history.add(command)
        return False, None

    def record_output(self, output_text: str) -> bool:
        """记录执行输出的签名，检测回显相同的情况。

        Returns:
            True 表示输出与之前相同（需要切换策略）
        """
        # 取前 200 字符作为签名，忽略空白
        sig = output_text.strip()[:200] if output_text else ""
        if not sig:
            return False

        if sig in self._output_signatures:
            self._same_output_count += 1
            if self._same_output_count >= 2:
                self._same_output_count = 0
                return True
        else:
            self._same_output_count = 0
            self._output_signatures.append(sig)
        return False
