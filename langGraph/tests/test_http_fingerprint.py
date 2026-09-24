"""响应指纹回传（HTTP fingerprint）的单元测试。

验证 PythonExecutor 沙箱内 httpx/requests 响应指纹的捕获与回传，
这是 Reflector 做响应差异对比（修复"盲发请求"）的基础。
"""

from types import SimpleNamespace

from deepagent.mcp.executors.PythonExecutor import (
    _HttpFingerprintCollector,
    _FingerprintingHttpProxy,
)


def _resp(status=200, body="hello flag", length=None):
    content = body.encode() if length is None else b"x" * length
    return SimpleNamespace(status_code=status, content=content, text=body)


def test_collector_record_and_list():
    col = _HttpFingerprintCollector()
    col.record("http://t/a", 200, 505, "hello flag")
    col.record("http://t/b", 404, 0, "")
    fps = col.to_list()
    assert len(fps) == 2
    assert fps[0]["status"] == 200
    assert fps[0]["length"] == 505
    assert fps[0]["snippet"] == "hello flag"
    assert fps[1]["status"] == 404


def test_collector_max_entries_cap():
    col = _HttpFingerprintCollector(max_entries=3)
    for i in range(10):
        col.record(f"http://t/{i}", 200, 1, "x")
    assert len(col.to_list()) == 3


def test_proxy_captures_get_and_post():
    col = _HttpFingerprintCollector()
    m = SimpleNamespace(
        get=lambda url, **kw: _resp(200, "hello flag"),
        post=lambda url, **kw: _resp(404, "nf"),
    )
    proxy = _FingerprintingHttpProxy(m, lambda: col)
    proxy.get("http://t/flag.php")
    proxy.post("http://t/login")
    fps = col.to_list()
    assert len(fps) == 2
    assert fps[0]["url"] == "http://t/flag.php"
    assert fps[0]["length"] == 10  # len("hello flag")
    assert fps[1]["status"] == 404


def test_proxy_transparent_forwarding():
    # 未拦截的属性（如 Client）经 __getattr__ 透明转发到真实模块
    col = _HttpFingerprintCollector()
    m = SimpleNamespace(Client="client", get=lambda url, **kw: _resp())
    proxy = _FingerprintingHttpProxy(m, lambda: col)
    assert proxy.Client == "client"
    assert proxy.get("http://t/x").status_code == 200


def test_proxy_no_collector_silent():
    # 无 collector 时（未 set_collector），包装静默不报错、正常返回响应
    m = SimpleNamespace(get=lambda url, **kw: _resp())
    proxy = _FingerprintingHttpProxy(m, lambda: None)
    resp = proxy.get("http://t/x")
    assert resp.status_code == 200


def test_proxy_capture_uses_length_from_content():
    # length 应来自响应 content 字节长度，而非文本长度
    col = _HttpFingerprintCollector()
    m = SimpleNamespace(get=lambda url, **kw: _resp(200, "x", length=505))
    proxy = _FingerprintingHttpProxy(m, lambda: col)
    proxy.get("http://t/x")
    assert col.to_list()[0]["length"] == 505
