"""源码情报强制衔接（信息收集 → 利用）的单元测试。

修复背景：反序列化题盲猜类名（GWHT/Yasuo/Yongen）烧光轮次却未先把
源码解析成结构化情报。验证 _extract_source_intel 的确定性提取、
防误判与跨轮去重。
"""

from deepagent.graph import DeepAgentGraph


def _mk_graph():
    # 跳过 __init__（LLM 初始化），只测纯解析逻辑
    g = DeepAgentGraph.__new__(DeepAgentGraph)
    g._source_intel_seen = set()
    return g


PHP_SRC = """<?php
class GWHT {
    public $username;
    protected $password;
    public function __construct($a) { $this->username = $a; }
    function upload($file) { file_get_contents($file); }
    public function __toString() { return $this->username; }
}
class Yasuo {
    public $name;
    private $age;
    public function __sleep() { return ['name']; }
}
"""


def test_extracts_classes_magics_dangers():
    g = _mk_graph()
    intel = g._extract_source_intel([{"output": PHP_SRC}], 1)
    assert len(intel) == 1
    it = intel[0]
    assert it["kind"] == "source-code-analysis"
    assert "GWHT" in it["classes"] and "Yasuo" in it["classes"]
    assert "__tostring" in it["magic_methods"]
    assert "__construct" in it["magic_methods"]
    assert "file_get_contents" in it["dangers"]
    assert "username" in it["properties"] and "name" in it["properties"]
    assert it["domain"] == "web"          # PHP 特征 → web 域
    assert "禁止盲猜类名" in it["desc"]     # 强制下一轮基于已解析结构


def test_blind_guess_payload_not_extracted():
    g = _mk_graph()
    # 盲猜输出：无 "class X {/:" 类定义语法，不应产情报
    out = ('trying payload O:4:"GWHT":3:{...} ... '
           "trying class Yasuo ... 200 len=1024 ... maybe class Yongen")
    assert g._extract_source_intel([{"output": out}], 1) == []


def test_dollar_property_not_misclassified():
    g = _mk_graph()
    # $className 属性引用不应被误判为类定义（负向后行断言挡掉 $/\w 前缀）
    out = 'public $className = "GWHT"; echo $className;'
    assert g._extract_source_intel([{"output": out}], 1) == []


def test_single_bare_class_ignored():
    g = _mk_graph()
    # 单一类且无魔术方法/危险调用 → 面太窄（可能是翻到 class 字样），不产情报
    out = "class Foo { private $x; }"
    assert g._extract_source_intel([{"output": out}], 1) == []


def test_instance_level_dedup():
    g = _mk_graph()
    r = [{"output": PHP_SRC}]
    assert len(g._extract_source_intel(r, 1)) == 1
    assert g._extract_source_intel(r, 2) == []   # 同份源码跨轮不重复入面板


def test_reads_stdout_field():
    g = _mk_graph()
    intel = g._extract_source_intel([{"stdout": PHP_SRC}], 3)
    assert intel and intel[0]["round"] == 3
    assert "evidence" in intel[0] and intel[0]["evidence"]   # 原文锚定非空