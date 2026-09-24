"""字典库（E:\\notebook\\字典 / WORDLIST_DIR 覆盖）集成的单元测试。"""

import pytest

from deepagent import graph


def test_wordlist_dir_env_override(monkeypatch, tmp_path):
    d = tmp_path / "dicts"
    d.mkdir()
    (d / "a.txt").write_text("x\ny\nz\n", encoding="utf-8")
    monkeypatch.setenv("WORDLIST_DIR", str(d))
    graph._wordlist_catalog.cache_clear()
    try:
        assert graph._wordlist_dir() == str(d)
        assert graph._wordlist_catalog() == ["a.txt(3行)"]
    finally:
        graph._wordlist_catalog.cache_clear()


def test_wordlist_missing_dir_returns_none(monkeypatch):
    monkeypatch.setenv("WORDLIST_DIR", r"Z:\no\such\dir")
    graph._wordlist_catalog.cache_clear()
    try:
        assert graph._wordlist_dir() is None
        assert graph._wordlist_catalog() == []
    finally:
        graph._wordlist_catalog.cache_clear()


def test_wordlist_catalog_local_if_present():
    # 仅当本机存在用户常用字典目录时校验内容（CI/其他机器自动跳过）
    wd = graph._wordlist_dir()
    if not wd:
        pytest.skip("用户字典库目录不存在")
    cats = graph._wordlist_catalog()
    names = "；".join(cats)
    assert "3-5w.txt" in names          # 大目录字典
    assert "passwd-EN-Top10000.txt" in names  # 弱口令
    assert "springboot.txt" in names


def test_ffuf_wordlist_builtins_fallback(monkeypatch, tmp_path):
    # 字典库缺失时，_build_ffuf_wordlist 回退内置高频路径（不依赖外部目录）
    from deepagent import chat_server
    monkeypatch.setenv("WORDLIST_DIR", r"Z:\no\such\dir")
    p = tmp_path / "w.txt"
    assert chat_server._build_ffuf_wordlist(str(p)) is True
    lines = p.read_text(encoding="utf-8").splitlines()
    assert "admin" in lines and ".git" in lines and "robots.txt" in lines
    assert len(lines) >= 40