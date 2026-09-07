"""独立角色 Agent（形态 D 多 Agent 架构）。

把"判定权"与"报告权"从主流程解耦为独立角色：
- VerifierAgent（裁决者）：证伪陪审团（多路多数裁定）+ Finding 机器校验 + 复现协议。
  设计铁律（借鉴 xz.aliyun 漏洞挖掘 Agent 规范）：模型只当"提出者"，绝不当"裁决者"，
  确认候选必须经独立证伪者角色攻击，SURVIVED 才可进入 confirmed_vulns。
- ReporterAgent（报告者）：最终总结报告生成 + 无 LLM 兜底报告。

每个角色有独立身份与独立 LLM 配置（env 覆盖：LLM_<前缀>_MODEL/API_KEY/BASE_URL/
TEMPERATURE，缺省回退全局 LLM_*），由 AgentOrchestrator 装配与统计。

循环依赖规避：本模块顶部不 import graph；_llm_invoke_with_retry / _extract_json /
_real_goal / _smart_trim 均在方法体内惰性 import（运行时 graph 已加载，安全）。

角色 system 提示说明：现有证伪/报告 prompt 均为单条 user 消息且含"唯一事实来源"
等语义，改为 system+user 双消息会改变 prompt 语义并可能引发回归，因此角色身份只作
元数据保留，不强制注入 messages。
"""

import asyncio
import json
import os
import re
from typing import Any, Dict, List, Literal, Optional

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger(__name__)

# ── Finding 机器校验关卡（借鉴文章 §7：结构不完整/证据为空的候选在进入
#    下一阶段前被机器拒绝；置信度分级 L1/L2 才按漏洞上报）──────────────
# L1 = 实质性证据（数据回显/副作用延迟/外联回调/报错原文等）；L2 = 确认但仅响应差异/指纹级
_HARD_EVIDENCE_RE = re.compile(
    r"flag\{|sleep|延迟|外联|dnslog|ceye|回显|webshell|sql syntax|error in your sql"
    r"|unclosed quotation|phpmyadmin|databases|information_schema|/etc/passwd"
    r"|管理员|admin 密码|select .{0,40}from|union select|os-shell|rce|命令执行成功",
    re.IGNORECASE,
)


def _hard_signal(text: str) -> Optional[str]:
    """提取文本中命中的硬证据信号（无则返回 None），用于复现比对。"""
    m = _HARD_EVIDENCE_RE.search(str(text or ""))
    return m.group(0) if m else None


# ──────────────────────────────────────────────────────────────────────────────
# 契约模型
# ──────────────────────────────────────────────────────────────────────────────

class RoleLLMConfig(BaseModel):
    """独立角色 LLM 配置：仅覆盖非空值，缺省回退全局 LLM_*。"""
    model: str = ""
    api_key: str = ""
    base_url: str = ""
    temperature: Optional[float] = None   # None = 跟随调用点/全局 LLM_TEMPERATURE

    @classmethod
    def from_env(cls, prefix: str) -> "RoleLLMConfig":
        def _c(v: Optional[str]) -> str:
            return (v or "").strip().strip("'\"")

        def _f(v: Optional[str]) -> Optional[float]:
            try:
                return float(v) if v else None
            except (TypeError, ValueError):
                return None

        return cls(
            model=_c(os.getenv(f"LLM_{prefix}_MODEL", "")),
            api_key=_c(os.getenv(f"LLM_{prefix}_API_KEY", "")),
            base_url=_c(os.getenv(f"LLM_{prefix}_BASE_URL", "")),
            temperature=_f(os.getenv(f"LLM_{prefix}_TEMPERATURE")),
        )


class RoleStats(BaseModel):
    """角色调用统计（进程级，不进 LangGraph checkpoint）。"""
    calls: int = 0
    errors: int = 0
    last_error: str = ""


class RefuteVote(BaseModel):
    """证伪单路结果。"""
    verdict: Literal["SURVIVED", "REFUTED"]
    rebuttal: str = ""
    survived_checks: List[str] = Field(default_factory=list)
    refuted_check: str = ""


class RefuteResult(BaseModel):
    """多路证伪多数裁定结果。"""
    verdict: Literal["SURVIVED", "REFUTED"]
    rebuttal: str = ""
    votes: Dict[str, int] = Field(default_factory=dict)    # {"survived","refuted","paths"}
    survived_checks: List[str] = Field(default_factory=list)
    refuted_check: str = ""


class MachineCheckResult(BaseModel):
    """Finding 机器校验结果（字段完备性 + SURVIVED 关卡 + L1/L2 定级）。"""
    passed: bool
    level: Literal["L1", "L2", "L4"] = "L4"
    problems: List[str] = Field(default_factory=list)


class EvidenceCard(BaseModel):
    """结构化证据卡（source/sink/flow/reachability + 证伪记录）。"""
    source: str = ""
    sink: str = ""
    flow: str = ""
    reachability: str = ""
    refutation: Optional[RefuteResult] = None


class VerdictResult(BaseModel):
    """VerifierAgent 统一对外判定。

    语义约定（与 graph.py 旧确认链逐路径等价）：
    - verdict=REFUTED：证伪者多数裁定驳回（machine_check 为 None）
    - verdict=SURVIVED 且 machine_check.passed=False：机器校验驳回
    - verdict=SURVIVED 且 machine_check.passed=True：confidence_level 定级 L1/L2，
      L1 无复现证据的自动降级（L1→L2）由调用方回写 _cand 时执行
    """
    verdict: Literal["SURVIVED", "REFUTED"]
    refutation: Optional[RefuteResult] = None
    machine_check: Optional[MachineCheckResult] = None
    confidence_level: Optional[Literal["L1", "L2"]] = None
    evidence_card: EvidenceCard = Field(default_factory=EvidenceCard)
    poc: Dict[str, Any] = Field(default_factory=dict)


# ──────────────────────────────────────────────────────────────────────────────
# 角色 Agent
# ──────────────────────────────────────────────────────────────────────────────

class RoleAgent:
    """独立角色 Agent 基类：身份 + 独立 LLM 配置 + 调用统计。"""

    def __init__(self, name: str, llm: Any = None, config: Optional[RoleLLMConfig] = None):
        self.name = name
        self.config = config or RoleLLMConfig()
        self._llm = llm      # _llm_invoke_with_retry 实际忽略它（env 驱动），仅占位
        self.stats = RoleStats()

    async def _invoke(self, prompt: str, temperature: Optional[float] = None) -> str:
        """以本角色配置调用 LLM（惰性 import 规避循环依赖）。"""
        from .graph import _llm_invoke_with_retry

        self.stats.calls += 1
        temp = self.config.temperature if self.config.temperature is not None else temperature
        try:
            return await _llm_invoke_with_retry(
                self._llm, prompt, temperature=temp,
                model=self.config.model or None,
                api_key=self.config.api_key or None,
                base_url=self.config.base_url or None,
            )
        except Exception as e:
            self.stats.errors += 1
            self.stats.last_error = str(e)[:120]
            raise


class VerifierAgent(RoleAgent):
    """裁决者：对抗式证伪 + 机器校验 + 复现协议（判定权独立于提出者）。"""

    REFUTER_PROMPT = """你是一名对抗式**证伪者**（Red-Team Refuter）。你的唯一目标是【推翻】下面的候选漏洞，而不是证实它。默认立场是有罪推定：只要有一个检查项存疑、无法从原始执行输出逐字锚定，就必须判 REFUTED。

候选漏洞:
- 漏洞类型: {vuln_type}
- 声称证据: {proof_brief}
- 完整证据: {proof_detail}
- 使用 payload: {payload}

本轮原始执行结果（唯一事实来源，禁止凭空补充）:
{results_context}

逐项攻击以下四点（找出一条即可推翻）:
① source 不可控: 输入是否真的来自攻击者面？响应差异是否可能来自其它缘由（缓存/正常页面/网络抖动）？
② sink 未到 / 已被 sanitize: payload 是否真的到达危险操作？是否存在被忽略的过滤、校验、权限拦截？
③ 证据与 payload 无因果: 声称的证据与 payload 之间是否有直接因果？是否只有响应差异而无实质数据/副作用（如延迟/外联/报错回显）？
④ 幻觉锚定失败: 声称证据的每个关键片段能否回读到原始执行输出原文？任何"凭印象"的描述都是证伪点。

严格只输出 JSON:
{{"verdict": "SURVIVED | REFUTED", "rebuttal": "一句话结论", "survived_checks": ["数量不限，可空数组"], "refuted_check": "被推翻的检查项及依据（REFUTED 时必填，SURVIVED 填空字符串）"}}

铁律: 只有四项全部通过、证据可回读原文时才允许 SURVIVED；REFUTED 时必须给出具体的推翻依据。"""

    def __init__(self, meta_executor: Any = None, llm: Any = None):
        super().__init__("verifier", llm=llm, config=RoleLLMConfig.from_env("VERIFIER"))
        self.meta_executor = meta_executor
        # 多路证伪者并行路数（多数裁定）：可用环境变量 REFUTER_PATHS 覆盖
        try:
            self.default_paths = int(os.environ.get("REFUTER_PATHS", "3") or 3)
        except ValueError:
            self.default_paths = 3
            logger.warning("refuter_paths_invalid_env", fallback=3)
        self.default_paths = max(1, min(self.default_paths, 5))
        if self.config.temperature is not None:
            logger.info("verifier_temp_override", note="覆盖多路温度轮转(0.1/0.25/0.4)，建议不设置该变量")

    # ── 机器校验 ──────────────────────────────────────────────────────────

    def validate_finding(self, vuln: Dict[str, Any]) -> MachineCheckResult:
        """对候选 Finding 做机器可判定的硬校验。

        机器只做无歧义裁判（字段完备性 + SURVIVED 关卡），绝不做智能推断：
        - 必填字段缺失/过短 → 驳回（passed=False）
        - 未经 Refuter SURVIVED → 驳回
        - 通过后按证据强度定级：硬证据（数据/副作用/报错原文）→ L1，否则 L2
        """
        problems: List[str] = []
        if not str(vuln.get("vuln_type") or "").strip():
            problems.append("vuln_type 缺失")
        if len(str(vuln.get("proof_brief") or "").strip()) < 8:
            problems.append("proof_brief 缺失或过短(<8字符)")
        if len(str(vuln.get("proof_detail") or "").strip()) < 20:
            problems.append("proof_detail 缺失或过短(<20字符)")
        if not str(vuln.get("payload") or "").strip():
            problems.append("payload 缺失")
        verdict = (vuln.get("refute") or {}).get("verdict")
        if verdict != "SURVIVED":
            problems.append(f"未经对抗验证 SURVIVED（当前 verdict={verdict or '无'}）")
        if problems:
            return MachineCheckResult(passed=False, level="L4", problems=problems)
        txt = f"{vuln.get('proof_detail', '')} {vuln.get('proof_brief', '')}"
        if _HARD_EVIDENCE_RE.search(txt):
            return MachineCheckResult(passed=True, level="L1")
        return MachineCheckResult(passed=True, level="L2")

    # ── 对抗式证伪 ────────────────────────────────────────────────────────

    async def refute_candidate(self, vuln: Dict[str, Any], results: List[Dict[str, Any]],
                               temperature: float = 0.1) -> RefuteVote:
        """对抗式验证：独立证伪者角色试图推翻候选漏洞（单路）。

        保守策略（证明负担在确认方）：Refuter 调用失败/输出非法时一律判 REFUTED，
        宁可漏报降级，不放幻觉误报进 confirmed_vulns。
        temperature 用于多路裁定时制造视角差异（默认 0.1 最稳定）。
        """
        from .mcp.executors.meta_executor import _smart_trim

        # 原始执行结果作为唯一事实来源：锚定证据、防幻觉
        _ctx_lines: List[str] = []
        for r in (results or [])[:10]:
            t = r.get("task") or {}
            desc = str(t.get("description", ""))[:80]
            out = r.get("output") or r.get("stdout") or r.get("result") or ""
            if isinstance(out, dict):
                out = json.dumps(out, ensure_ascii=False)
            status = "成功" if r.get("success") else f"失败: {str(r.get('error', ''))[:80]}"
            _ctx_lines.append(f"- [{status}] {desc}\n  {_smart_trim(str(out), 250)}")

        prompt = self.REFUTER_PROMPT.format(
            vuln_type=str(vuln.get("vuln_type", "")),
            proof_brief=str(vuln.get("proof_brief", "")),
            proof_detail=str(vuln.get("proof_detail", ""))[:600],
            payload=str(vuln.get("payload", ""))[:300],
            results_context="\n".join(_ctx_lines) or "（无原始执行输出——这本身即是证伪点）",
        )
        try:
            from .graph import _extract_json
            # 证伪判定需要最稳定的低温，避免同样证据两次判决不一致
            content = await self._invoke(prompt, temperature=temperature)
            data = _extract_json(content) or {}
            verdict = str(data.get("verdict", "")).strip().upper()
            if verdict not in ("SURVIVED", "REFUTED"):
                logger.warning("refuter_invalid_verdict", raw=str(data.get("verdict"))[:40])
                return RefuteVote(verdict="REFUTED", rebuttal="证伪者输出非法，按保守策略证伪",
                                  refuted_check="verdict 解析失败")
            return RefuteVote(
                verdict=verdict,  # type: ignore[arg-type]
                rebuttal=str(data.get("rebuttal", ""))[:200],
                survived_checks=data.get("survived_checks", []) if isinstance(data.get("survived_checks"), list) else [],
                refuted_check=str(data.get("refuted_check", ""))[:300],
            )
        except Exception as e:
            logger.warning("refuter_llm_failed", error=str(e))
            return RefuteVote(verdict="REFUTED",
                              rebuttal=f"证伪者调用失败（{str(e)[:80]}），按保守策略证伪",
                              refuted_check="调用异常")

    async def refute_majority(self, vuln: Dict[str, Any], results: List[Dict[str, Any]],
                              paths: Optional[int] = None) -> RefuteResult:
        """多路证伪者并行 + 多数裁定（文章 §11）。

        - 并行 paths 路证伪（温度 0.1/0.25/0.4 轮转制造视角差异）
        - 调用失败/输出非法的那一路按保守策略计 REFUTED（证明负担在确认方）
        - 返回附 votes 计数与各路线索合并
        """
        n = paths or self.default_paths
        if n <= 1:
            v = await self.refute_candidate(vuln, results)
            return RefuteResult(verdict=v.verdict, rebuttal=v.rebuttal,
                                votes={"survived": 1 if v.verdict == "SURVIVED" else 0,
                                       "refuted": 0 if v.verdict == "SURVIVED" else 1,
                                       "paths": 1},
                                survived_checks=v.survived_checks, refuted_check=v.refuted_check)
        temps = [0.1, 0.25, 0.4]
        gathered = await asyncio.gather(
            *(self.refute_candidate(vuln, results, temperature=temps[i % len(temps)])
              for i in range(n)),
            return_exceptions=True,
        )
        voted = [r for r in gathered if isinstance(r, RefuteVote)]
        survived = sum(1 for r in voted if r.verdict == "SURVIVED")
        refuted = n - survived   # 异常/非法输出均计 REFUTED（保守）

        survived_checks: List[str] = []
        refuted_checks: List[str] = []
        rebuttals: List[str] = []
        for r in voted:
            if r.rebuttal:
                rebuttals.append(r.rebuttal[:120])
            if r.verdict == "SURVIVED":
                for c in r.survived_checks:
                    survived_checks.append(str(c)[:80])
            else:
                if r.refuted_check:
                    refuted_checks.append(r.refuted_check[:150])
        verdict = "SURVIVED" if survived > refuted else "REFUTED"
        logger.info(
            "refuter_majority_vote",
            survived=survived, refuted=refuted, verdict=verdict,
        )
        return RefuteResult(
            verdict=verdict,  # type: ignore[arg-type]
            votes={"survived": survived, "refuted": refuted, "paths": n},
            rebuttal="；".join(dict.fromkeys(rebuttals))[:300],
            survived_checks=list(dict.fromkeys(survived_checks))[:6],
            refuted_check=" | ".join(dict.fromkeys(refuted_checks))[:300],
        )

    async def reproduce_finding(self, vuln: Dict[str, Any],
                                results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """复现协议：重放产生该候选的执行代码，比对原始与新输出的关键特征。

        黑盒场景的"PoC 复现"= 同一 payload 的代码独立重放一次，验证关键证据可重现：
        - 原始输出含硬证据信号 → 复现输出必须命中同一信号
        - 无硬信号 → 最长公共片段 ≥ 25 字符视为一致
        找不到可复现代码/执行失败 → reproduced=False（文章规则：L1 无复现 → 降 L2，
        由调用方执行降级）。
        """
        import difflib
        payload = str(vuln.get("payload") or "").strip()

        def _norm(s: str) -> str:
            # 归一化比对：去空白 + 去反斜杠（容忍 code 里 '\\'' 转义与空格排版差异）
            return s.replace(" ", "").replace("\\", "")

        repro: Optional[Dict[str, Any]] = None
        for r in (results or []):
            if not r.get("success"):
                continue
            task = r.get("task") or {}
            code = task.get("code") or (task.get("arguments") or {}).get("code") or ""
            if not code:
                continue
            if payload and _norm(payload[:20]) in _norm(code):
                repro = {"code": code, "original": r.get("output")}
                break
        if not repro:
            return {"reproduced": False, "reason": "本轮结果中找不到含该 payload 的可复现代码"}

        try:
            if self.meta_executor is None:
                raise RuntimeError("meta_executor 未注入")
            res = await asyncio.wait_for(
                self.meta_executor.execute({
                    "tool": "execute_python",
                    "arguments": {"code": repro["code"]},
                    "description": f"复现验证: {payload[:40]}",
                }),
                timeout=60,
            )
            new_out = res.get("output") or res.get("stdout") or res.get("result") or ""
            if isinstance(new_out, dict):
                new_out = json.dumps(new_out, ensure_ascii=False)
        except Exception as e:
            return {"reproduced": False, "reason": f"复现执行失败: {str(e)[:80]}"}

        orig_out = repro["original"]
        if isinstance(orig_out, dict):
            orig_out = json.dumps(orig_out, ensure_ascii=False)
        o, n = str(orig_out)[:2000], str(new_out)[:2000]

        sig = _hard_signal(o)
        if sig:
            ok = sig in n
            reason = f"硬证据信号[{sig[:40]}] {'复现命中' if ok else '复现输出未命中'}"
        else:
            sm = difflib.SequenceMatcher(None, o, n)
            m = sm.find_longest_match(0, len(o), 0, len(n))
            ok = m.size >= 25
            reason = f"最长公共片段 {m.size} 字符（阈值25）"
        return {"reproduced": bool(ok), "reason": reason, "attempt_output": n[:120]}

    # ── 统一判定入口 ──────────────────────────────────────────────────────

    async def evaluate(self, vuln: Dict[str, Any],
                       results: List[Dict[str, Any]]) -> VerdictResult:
        """确认链编排：证伪陪审团 → 机器校验 → 复现协议。

        - 证伪 REFUTED → 直接驳回（machine_check=None）
        - 证伪 SURVIVED 但机器校验不过 → 驳回（machine_check.passed=False）
        - 双关通过 → confidence_level 按机器定级 L1/L2（L1 无复现的降级由调用方回写）
        """
        refutation = await self.refute_majority(vuln, results)
        evidence = EvidenceCard(refutation=refutation,
                                source=str(vuln.get("proof_detail", ""))[:600])
        if refutation.verdict == "REFUTED":
            return VerdictResult(verdict="REFUTED", refutation=refutation,
                                 evidence_card=evidence)

        # 机器校验需看到 SURVIVED 印记：用副本注入，避免污染调用方 _cand
        _check_vuln = dict(vuln)
        _check_vuln["refute"] = {"verdict": "SURVIVED"}
        mc = self.validate_finding(_check_vuln)
        if not mc.passed:
            return VerdictResult(verdict="SURVIVED", refutation=refutation,
                                 machine_check=mc, evidence_card=evidence)

        poc = await self.reproduce_finding(vuln, results)
        level: Literal["L1", "L2"] = mc.level  # type: ignore[assignment]
        return VerdictResult(verdict="SURVIVED", refutation=refutation, machine_check=mc,
                             confidence_level=level, evidence_card=evidence, poc=poc)


class ReporterAgent(RoleAgent):
    """报告者：最终总结报告生成 + 无 LLM 兜底。"""

    def __init__(self, llm: Any = None):
        super().__init__("reporter", llm=llm, config=RoleLLMConfig.from_env("REPORTER"))

    async def generate_report(self, state: Any) -> str:
        """生成最终报告；LLM 失败时回退纯文本兜底报告。"""
        prompt = self._build_prompt(state)
        try:
            report = await self._invoke(prompt)
            logger.info("summarizer_done", report_len=len(report))
            return report
        except Exception as e:
            logger.error("summarizer_failed", error=str(e))
            return self.build_fallback_report(state)

    def _build_prompt(self, state: Any) -> str:
        from .graph import _real_goal

        # 已确认漏洞详情（限 1500 字符）
        confirmed_detail = json.dumps(
            state.planner.confirmed_vulns, ensure_ascii=False, indent=2
        )[:1500] if state.planner.confirmed_vulns else "无"

        # 汇总历史关键发现（最近 10 轮，每条限 100 字符，带证据级别前缀，
        # 防止 LLM 把 suspected 发现自行升级为"已确认"写入报告）
        all_findings: List[str] = []
        _level_label = {"confirmed": "已确认", "suspected": "疑似", "no_finding": "无发现"}
        for r in state.reflector.reflection_log[-10:]:
            _lv = _level_label.get(r.get("finding_level"), "未定级")
            for f in (r.get("key_findings") or []):
                all_findings.append(f"[{_lv}] {str(f)[:100]}")
            if r.get("finding_level") == "confirmed" and r.get("summary"):
                all_findings.append(f"[已确认] {r['summary'][:100]}")
        findings_text = "\n".join(f"  · {f}" for f in all_findings[-20:])[:1200] or "无"

        # STE 经验（最近 5 条）
        ste_text = "\n".join(
            f"  · {s.strategy}" for s in state.reflector.persistent_insights[-5:]
        )[:400] or "无"

        # 测试文档用例统计（计划驱动主线：按方向汇总状态，列出 found 用例）
        _plan_summary = "无"
        if state.planner.test_plan:
            _lines = []
            for d in state.planner.test_plan.get("directions", []):
                cases = d.get("cases", [])
                _stat: Dict[str, int] = {}
                for c in cases:
                    _st = str(c.get("status", "pending"))
                    _stat[_st] = _stat.get(_st, 0) + 1
                _stat_str = " ".join(f"[{k}×{v}]" for k, v in _stat.items())
                _lines.append(f"  · {d.get('direction', '?')}: {len(cases)} 用例 {_stat_str}")
                for c in cases:
                    if str(c.get("status")) == "found":
                        _lines.append(f"      - {c.get('id')}: {str(c.get('desc', ''))[:80]}")
            _plan_summary = ("\n".join(_lines)[:1500] or "无")

        # 如果已经有确认的漏洞，调整提示词以加快报告生成
        has_confirmed_vulns = len(state.planner.confirmed_vulns) > 0
        urgency_hint = ""
        if has_confirmed_vulns:
            urgency_hint = f"""
注意：已经发现了 {len(state.planner.confirmed_vulns)} 个确认的漏洞。现在需要快速生成总结报告，重点突出：
1. 已确认的漏洞及其风险等级
2. 重要的安全建议
3. 后续的修复建议
"""

        return f"""你是一名专业渗透测试工程师，请对以下测试过程生成最终总结报告（中文，供甲方阅读）。

测试目标: {_real_goal(state.current_goal)}
执行轮次: {state.execution_round} 轮（计划 {state.planner.total_rounds or "未设置"} 轮，若与实际不一致请在报告中说明动态调整情况）
已完成方向: {state.planner.completed_directions}
已停滞方向: {state.planner.stalled_directions}
{urgency_hint}

━━━ 测试文档用例统计（用例状态: pending未执行/done已执行/found确认漏洞/failed失败）━━━
{_plan_summary}

━━━ 已确认漏洞 ━━━
{confirmed_detail}

━━━ 历史关键发现（每条已标注证据级别）━━━
{findings_text}

━━━ 可复用经验 ━━━
{ste_text}

━━━ 证据分级铁律（违反即不合格，必须重写）━━━
报告只能使用上方已给出的证据，严禁推断、编造 payload 或证据：
· [已确认] 仅限"已确认漏洞"区块中列出的条目（有 payload + 可复现证据）。
  若该区块为"无"，报告中不允许出现任何[已确认]漏洞，禁止把疑似升级为确认。
· [疑似] 来自"历史关键发现"中标注 [疑似] 的条目，必须写明证据不足的原因与建议验证方法。
· [无发现] 的条目不得作为漏洞写入任何章节。

请按以下结构输出（纯文本，无需JSON）：

## 一、漏洞总览
（仅[已确认]漏洞，按风险等级排列。若"已确认漏洞"区块为"无"，本节必须写"未发现达到确认标准的漏洞"，不得列出具体漏洞）

## 二、漏洞详情
（仅[已确认]漏洞：类型 / 证据 / 利用方式 / payload）

## 三、疑似风险
（全部[疑似]级发现：附上已有线索、证据不足的原因、建议验证方法）

## 四、未覆盖范围
（未完成测试的 OWASP 方向及原因）

## 五、修复建议
（[已确认]漏洞给具体修复方案；[疑似]给进一步验证建议）

## 六、测试结论
（一句话总结安全态势，必须与上方分级一致）"""

    def build_fallback_report(self, state: Any) -> str:
        """LLM 调用失败时的纯文本兜底报告（从状态数据直接构建，不调用 LLM）。"""
        from .graph import _real_goal

        lines = [
            "# 渗透测试总结报告（自动生成）",
            f"目标: {_real_goal(state.current_goal)}",
            f"执行轮次: {state.execution_round}",
        ]

        # 已确认漏洞
        if state.planner.confirmed_vulns:
            lines.append(f"已确认漏洞数: {len(state.planner.confirmed_vulns)}")

        lines += ["", "## 已确认漏洞"]
        if state.planner.confirmed_vulns:
            for v in state.planner.confirmed_vulns:
                lines.append(f"- [{v.get('vuln_type')}] {v.get('proof_brief')}")
                if v.get("payload"):
                    lines.append(f"  payload: {v.get('payload')}")
                if v.get("proof_detail"):
                    lines.append(f"  证据: {v.get('proof_detail')[:200]}")
        else:
            lines.append("- 未发现确认漏洞")

        # 从 executor 历史中提取测试过的工具和结果
        exec_history = state.executor.execution_history if hasattr(state.executor, "execution_history") else []
        if exec_history:
            lines += ["", "## 执行历史摘要"]
            tool_stats: Dict[str, int] = {}
            success_count = 0
            for entry in exec_history:
                if isinstance(entry, dict):
                    task = entry.get("task", {})
                    tool = task.get("tool", "unknown")
                    tool_stats[tool] = tool_stats.get(tool, 0) + 1
                    if entry.get("success"):
                        success_count += 1
            lines.append(f"- 总任务数: {len(exec_history)}，成功: {success_count}，失败: {len(exec_history) - success_count}")
            lines.append(f"- 工具分布: {dict(sorted(tool_stats.items(), key=lambda x: -x[1]))}")

        # 从 executor 最近结果中提取 stdout/stderr/error 关键线索
        if state.executor.last_result:
            lr = state.executor.last_result
            last_lines = []
            if isinstance(lr, dict):
                for key in ("stdout", "result", "data", "error"):
                    val = lr.get(key)
                    if val:
                        last_lines.append(f"{key}: {str(val)[:300]}")
            if last_lines:
                lines += ["", "## 最新结果"]
                lines.extend(f"- {l}" for l in last_lines)

        lines += ["", "## 测试方向覆盖"]
        lines.append(f"- 已完成: {state.planner.completed_directions or '无'}")
        lines.append(f"- 已停滞: {state.planner.stalled_directions or '无'}")

        # 关键发现（从 reflector 日志中提取，最近 5 轮，带证据级别前缀）
        key_findings = []
        _level_label_fb = {"confirmed": "已确认", "suspected": "疑似", "no_finding": "无发现"}
        for r in state.reflector.reflection_log[-5:]:
            _lv = _level_label_fb.get(r.get("finding_level"), "未定级")
            for f in (r.get("key_findings") or []):
                key_findings.append(f"[{_lv}] {f}")
        if key_findings:
            lines += ["", "## 关键发现（含证据级别）"]
            for f in key_findings[-10:]:
                lines.append(f"- {f}")

        # STE 经验
        if state.reflector.persistent_insights:
            lines += ["", "## 可复用经验"]
            for s in state.reflector.persistent_insights[-3:]:
                lines.append(f"- {s.strategy}")

        return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────────────────
# 编排器
# ──────────────────────────────────────────────────────────────────────────────

class AgentOrchestrator:
    """多 Agent 编排器：装配角色实例、聚合统计。

    当前角色：verifier（裁决）、reporter（报告）。Planner/Finder 仍由主图承担，
    后续增补新角色时在此扩展。
    """

    def __init__(self, llm: Any = None, meta_executor: Any = None):
        self.verifier = VerifierAgent(meta_executor=meta_executor, llm=llm)
        self.reporter = ReporterAgent(llm=llm)

    @property
    def roles(self) -> List[RoleAgent]:
        return [self.verifier, self.reporter]

    def stats(self) -> Dict[str, Any]:
        """聚合各角色调用统计（供日志/健康诊断使用）。"""
        return {role.name: role.stats.model_dump() for role in self.roles}