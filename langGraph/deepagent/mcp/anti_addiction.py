
from difflib import SequenceMatcher
from typing import List, Dict, Any, Optional, Tuple
import json
from dataclasses import dataclass, field


@dataclass
class CommandHistory:
    """滑动窗口命令历史"""
    commands: List[str] = field(default_factory=list)
    max_length: int = 18

    def add(self, command: str) -> None:
        self.commands.append(command)
        if len(self.commands) > self.max_length:
            self.commands.pop(0)

    def last(self) -> Optional[str]:
        return self.commands[-1] if self.commands else None


class AntiAddictionGuard:
    """防沉迷守卫 - 防止循环执行"""

    def __init__(
            self,
            similarity_threshold: float = 0.85,
            max_similar_count: int = 10,
            min_cmd_length: int = 10
    ):
        self.threshold = similarity_threshold
        self.max_count = max_similar_count
        self.min_cmd_length = min_cmd_length
        self.history = CommandHistory(max_length=max_similar_count)
        self.similar_count = 0

    def _normalize_command(self, task: Dict[str, Any]) -> str:
        """标准化命令用于比较"""
        tool = task.get("tool", "")
        args = task.get("arguments", {})
        args_str = json.dumps(args, sort_keys=True)
        return f"{tool}:{args_str}"

    def _is_too_short(self, cmd: str) -> bool:
        return len(cmd) < self.min_cmd_length

    def check_and_record(self, task: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """检查是否陷入循环

        Returns:
            (is_looping, warning_message)
        """
        current_cmd = self._normalize_command(task)

        if self._is_too_short(current_cmd):
            self.history.add(current_cmd)
            return False, None

        last_cmd = self.history.last()

        if last_cmd:
            similarity = SequenceMatcher(None, current_cmd, last_cmd).ratio()

            if similarity >= self.threshold:
                self.similar_count += 1
                if self.similar_count >= self.max_count:
                    self.similar_count = 0
                    warning = self._generate_warning(task, similarity)
                    self.history.add(current_cmd)
                    return True, warning
            else:
                self.similar_count = 0

        self.history.add(current_cmd)
        return False, None

    def _generate_warning(self, task: Dict[str, Any], similarity: float) -> str:
        """生成防沉迷警告"""
        return f"""
⚠️ 检测到可能陷入循环（连续 {self.max_count} 次相似命令，相似度 {similarity:.2%}）

当前任务: {task.get('tool')}({task.get('arguments', {})})

请先思考以下问题来重新制定计划：
1. 我的核心假设是什么？
2. 过去 {self.max_count} 次的尝试，是否证明了这个假设是错误的？
3. 除了当前的方法，还有哪些其他的可能性？
4. 是否有更高效的方式（如批量处理、自动化脚本）？
"""