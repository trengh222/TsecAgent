"""skill 引用文件与 SKILL.md 一致性校验的单元测试。"""

import os
from types import SimpleNamespace

from deepagent.graph import (
    _SECKNOWLEDGE_DIR,
    _CTF_WEB_DIR,
    _skill_referenced_files,
    _validate_skill_index_consistency,
    DeepAgentGraph,
)


def test_referenced_files_cover_three_groups():
    refs = _skill_referenced_files()
    web = {f for f in refs if f.startswith("web-")}
    ai = {f for f in refs if f.startswith("ai-")}
    ctf = {f for f in refs if f.startswith("ctf-web/")}
    assert web, "应包含 secknowledge web 手册"
    assert ai, "应包含 secknowledge ai 手册"
    assert ctf, "应包含 ctf-web 手册"


def test_secknowledge_files_present_in_skill_md():
    refs = _skill_referenced_files()
    text = _read(_SECKNOWLEDGE_DIR, "SKILL.md")
    sec = {f for f in refs if not f.startswith("ctf-web/")}
    missing = sorted(f for f in sec if f not in text)
    assert not missing, f"secknowledge 文件未在 SKILL.md 出现: {missing}"


def test_ctf_files_present_in_skill_md():
    refs = _skill_referenced_files()
    text = _read(_CTF_WEB_DIR, "SKILL.md")
    ctf = {f[len("ctf-web/"):] for f in refs if f.startswith("ctf-web/")}
    missing = sorted(f for f in ctf if f not in text)
    assert not missing, f"ctf-web 文件未在 SKILL.md 出现: {missing}"


def test_validate_skill_index_consistency_runs():
    # 仅验证不抛异常（无漂移时静默；漂移时打 warning 不阻断）
    _validate_skill_index_consistency()


def test_read_skill_snippet_ctf_path_resolution():
    # ctf-web 文件带 "ctf-web/" 前缀，应解析到平铺目录（非 references/ 子目录）
    fake = SimpleNamespace(_skill_cache={})
    snippet = DeepAgentGraph._read_skill_snippet(fake, "ctf-web/sql-injection.md")
    assert len(snippet) > 0
    assert "SQL" in snippet or "sql" in snippet.lower()


def _read(dir_path: str, filename: str) -> str:
    with open(os.path.join(dir_path, filename), encoding="utf-8", errors="ignore") as f:
        return f.read()
