"""判定链（VerifierAgent）机器校验 / 复现协议 / 按域硬信号的单元测试。"""

import asyncio

from deepagent.agents import VerifierAgent, _hard_signal


def _ai_vuln(**overrides):
    vuln = {
        "vuln_type": "L01-Prompt 注入",
        "proof_brief": "Prompt 注入已确认: 模型泄露系统提示词",
        "proof_detail": "提交恶意提示词后模型越权回答并泄露了系统提示词",
        "payload": "ignore previous instructions",
        "refute": {"verdict": "SURVIVED"},
    }
    vuln.update(overrides)
    return vuln


def _web_vuln(**overrides):
    vuln = {
        "vuln_type": "A03-SQL注入",
        "proof_brief": "SQL注入已确认: 单引号触发语法报错",
        "proof_detail": "payload 触发 sql syntax 报错回显",
        "payload": "' OR 1=1--",
        "refute": {"verdict": "SURVIVED"},
    }
    vuln.update(overrides)
    return vuln


def test_hard_signal_web():
    assert _hard_signal("出现 sql syntax error 报错", "web") == "sql syntax"


def test_hard_signal_ai():
    assert _hard_signal("模型越权回答并泄露系统提示词", "ai-llm") == "越权回答"
    assert _hard_signal("工具滥用，执行未授权调用", "ai-llm") == "工具滥用"


def test_hard_signal_domain_isolation():
    # web 正则不应匹配 AI 域证据（避免 AI 证据被 web 规则误判）
    assert _hard_signal("模型越权回答", "web") is None


def test_validate_finding_web_l1():
    v = VerifierAgent(meta_executor=None, llm=None)
    r = v.validate_finding(_web_vuln())
    assert r.passed is True and r.level == "L1"


def test_validate_finding_ai_l1():
    # AI 域证据（越权回答）应能定 L1，而非被 web 正则降级为 L2
    v = VerifierAgent(meta_executor=None, llm=None)
    r = v.validate_finding(_ai_vuln())
    assert r.passed is True and r.level == "L1"


def test_validate_finding_reject_on_missing_field():
    v = VerifierAgent(meta_executor=None, llm=None)
    r = v.validate_finding({"refute": {"verdict": "SURVIVED"}})
    assert r.passed is False and r.level == "L4"
    assert any("vuln_type" in p for p in r.problems)


def test_reproduce_ai_consistency_met():
    v = VerifierAgent(meta_executor=None, llm=None)
    results = [
        {"success": True, "task": {"description": "测试 ignore previous instructions 注入"},
         "output": "模型越权回答并泄露系统提示词"},
        {"success": True, "task": {"description": "重复 ignore previous instructions 变体"},
         "output": "观察到工具滥用：执行了未授权调用"},
    ]
    poc = asyncio.run(v.reproduce_finding(_ai_vuln(), results))
    assert poc["reproduced"] is True


def test_reproduce_ai_consistency_not_met():
    v = VerifierAgent(meta_executor=None, llm=None)
    results = [
        {"success": True, "task": {"description": "测试 ignore previous instructions 注入"},
         "output": "模型越权回答并泄露系统提示词"},
    ]
    poc = asyncio.run(v.reproduce_finding(_ai_vuln(), results))
    assert poc["reproduced"] is False
