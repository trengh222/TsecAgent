"""持久化上下文对象 - 对抗灾难性遗忘"""

from pydantic import BaseModel, Field, ConfigDict
from typing import List, Dict, Any, Optional
from datetime import datetime

_MAX_EXECUTION_HISTORY = 200
_MAX_REFLECTION_LOG = 100
_MAX_FAILURE_PATTERNS = 500


class STEExperience(BaseModel):
    """Strategy-Tactics-Example 经验结构"""
    strategy: str
    tactics: List[str]
    example: str
    applicable_scenarios: List[str]
    created_at: datetime = Field(default_factory=datetime.now)


class PlannerContext(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    planning_history: List[Dict[str, Any]] = Field(default_factory=list)
    rejected_strategies: Dict[str, str] = Field(default_factory=dict)
    long_term_goals: List[str] = Field(default_factory=list)
    latest_reflection: Optional[Dict[str, Any]] = None
    previous_plan: Optional[Dict[str, Any]] = None

    # 渗透测试方向追踪
    current_vuln_focus: Optional[str] = None          # 当前正在测试的漏洞/方向
    stalled_directions: List[str] = Field(default_factory=list)  # 已判定无进展的方向
    force_pivot: bool = False                          # 反思器触发：强制切换方向

    # OWASP Top10 测试队列与结果
    top10_queue: List[str] = Field(default_factory=list)   # 待测方向（按优先级排列）
    confirmed_vulns: List[Dict[str, Any]] = Field(default_factory=list)   # 已确认漏洞（有确定性证据）
    suspected_vulns: List[Dict[str, Any]] = Field(default_factory=list)   # 疑似漏洞（证据不足，不上报）

    # 已完成的方向（confirmed 后标记为完成，自动推进到下一个方向）
    completed_directions: List[str] = Field(default_factory=list)

    # 当前方向的已尝试 payload 记录（避免重复，供 LLM 参考）
    tried_payloads: List[str] = Field(default_factory=list)   # 已尝试的 payload 摘要

    # 目标分析：根据 URL 特征筛选出的适用方向（为空表示全部方向适用）
    applicable_directions: Optional[List[str]] = None


class ReflectorContext(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    reflection_log: List[Dict[str, Any]] = Field(default_factory=list)
    validated_patterns: List[Dict[str, Any]] = Field(default_factory=list)
    persistent_insights: List[STEExperience] = Field(default_factory=list)
    failure_patterns: Dict[str, int] = Field(default_factory=dict)

    # 停滞检测：连续无实质进展的轮次计数
    stall_counter: int = 0
    last_focus: Optional[str] = None   # 上一轮记录的 vuln_focus，用于检测方向是否切换

    def add_reflection(self, reflection: Dict[str, Any]) -> None:
        """追加反思记录，超出上限时丢弃最旧的。"""
        self.reflection_log.append(reflection)
        if len(self.reflection_log) > _MAX_REFLECTION_LOG:
            self.reflection_log = self.reflection_log[-_MAX_REFLECTION_LOG:]

    def record_failure(self, error: str) -> None:
        """累计失败模式，超出上限时清理低频条目。"""
        self.failure_patterns[error] = self.failure_patterns.get(error, 0) + 1
        if len(self.failure_patterns) > _MAX_FAILURE_PATTERNS:
            # 保留出现次数最多的一半
            sorted_items = sorted(self.failure_patterns.items(), key=lambda x: x[1], reverse=True)
            self.failure_patterns = dict(sorted_items[: _MAX_FAILURE_PATTERNS // 2])

    def tick_stall(self, has_new_finding: bool, current_focus: Optional[str],
                   stall_threshold: int = 8) -> bool:
        """更新停滞计数器，返回是否应触发 pivot。

        - 方向切换后重置计数器
        - 有新发现时重置计数器
        - 连续 stall_threshold 轮无新发现且方向未变 → 触发 pivot
        """
        if current_focus != self.last_focus:
            self.stall_counter = 0
            self.last_focus = current_focus
            return False
        if has_new_finding:
            self.stall_counter = 0
            return False
        self.stall_counter += 1
        return self.stall_counter >= stall_threshold


class ExecutorContext(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    execution_history: List[Dict[str, Any]] = Field(default_factory=list)
    last_result: Optional[Dict[str, Any]] = None
    # session_id -> {"type": "python"|"shell", "created_at": float}
    active_sessions: Dict[str, Any] = Field(default_factory=dict)

    def add_results(self, results: List[Dict[str, Any]]) -> None:
        """追加执行结果，超出上限时丢弃最旧的。"""
        self.execution_history.extend(results)
        if len(self.execution_history) > _MAX_EXECUTION_HISTORY:
            self.execution_history = self.execution_history[-_MAX_EXECUTION_HISTORY:]
        if results:
            self.last_result = results[-1]

    def register_session(self, session_id: str, session_type: str) -> None:
        import time
        self.active_sessions[session_id] = {
            "type": session_type,
            "created_at": time.time(),
        }

    def remove_session(self, session_id: str) -> None:
        self.active_sessions.pop(session_id, None)


class DeepAgentState(BaseModel):
    """LangGraph 状态对象"""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    messages: List[Dict[str, Any]] = Field(default_factory=list)
    current_goal: str = ""
    execution_round: int = 0

    planner: PlannerContext = Field(default_factory=PlannerContext)
    reflector: ReflectorContext = Field(default_factory=ReflectorContext)
    executor: ExecutorContext = Field(default_factory=ExecutorContext)

    current_tasks: List[Dict[str, Any]] = Field(default_factory=list)
    current_results: List[Dict[str, Any]] = Field(default_factory=list)

    should_continue: bool = True
    veto_triggered: bool = False
    compression_needed: bool = False
    final_report: Optional[str] = None  # 收尾节点生成的总结报告
