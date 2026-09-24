"""方向目录（域 × 子方向）与 code 归一化的单元测试。"""

from deepagent.graph import (
    _DIRECTION_CATALOG,
    _ALL_DIRECTION_NAMES,
    _DIR_BY_CODE,
    _CODE_TO_DOMAIN,
    _dir_code,
    _norm_dir,
    _domain_hint,
)


def test_catalog_has_web_and_ai_domains():
    assert set(_DIRECTION_CATALOG.keys()) == {"web", "ai-llm"}


def test_all_direction_names_count():
    # 10 web (A01-A10) + 7 ai-llm (L01-L07)
    assert len(_ALL_DIRECTION_NAMES) == 17


def test_dir_by_code_maps_web_and_ai():
    assert _DIR_BY_CODE["A03"] == "A03-SQL注入"
    assert _DIR_BY_CODE["L01"] == "L01-Prompt 注入"


def test_code_to_domain():
    assert _CODE_TO_DOMAIN["A03"] == "web"
    assert _CODE_TO_DOMAIN["L01"] == "ai-llm"


def test_dir_code_web_variants():
    # 各种 LLM 可能输出的写法，都必须归一为 code "A03"
    for s in ("A03-SQL注入", "A03 SQL注入", "a03", "A03", "A03:SQL注入"):
        assert _dir_code(s) == "A03", s
    assert _dir_code("A10-SSRF") == "A10"


def test_dir_code_ai_variants():
    for s in ("L01-Prompt 注入", "L01 Prompt 注入", "l01", "L01"):
        assert _dir_code(s) == "L01", s
    assert _dir_code("L07-模型窃取") == "L07"


def test_norm_dir_web_and_ai():
    assert _norm_dir("A03 SQL注入") == "A03-SQL注入"
    assert _norm_dir("a03") == "A03-SQL注入"
    assert _norm_dir("L01 Prompt 注入") == "L01-Prompt 注入"
    assert _norm_dir("L01") == "L01-Prompt 注入"


def test_norm_dir_unknown_passthrough():
    # 无法识别的方向名原样返回（不误吞）
    assert _norm_dir("X99-未知方向") == "X99-未知方向"


def test_domain_hint_web():
    hint = _domain_hint("A03-SQL注入")
    assert "Web 域" in hint


def test_domain_hint_ai():
    hint = _domain_hint("L01-Prompt 注入")
    assert "AI/LLM 域" in hint
    assert "勿套用 Web 黑盒思路" in hint
