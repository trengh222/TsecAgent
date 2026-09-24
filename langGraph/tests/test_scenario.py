"""场景方法论速查（横向视角）的单元测试。"""

from deepagent.graph import _scenario_hint, _scenario_hits, _load_scenarios


def test_cheatsheet_has_core_scenarios():
    scenarios = _load_scenarios()
    names = [name for _, name, _, _ in scenarios]
    assert "登录/认证" in names
    assert "API 接口" in names
    assert "文件上传" in names
    assert len(scenarios) >= 14  # 覆盖高频入口


def test_new_scenarios_detected():
    cases = {
        "注册流程": "测试 http://target.com/register 注册功能",
        "评论/留言": "测试 http://target.com/comment 评论",
        "文件下载/读取": "测试 http://target.com/download 下载",
        "后台管理": "测试 http://target.com/admin 后台",
        "文件包含": "测试 http://target.com/index.php?page=1 文件包含",
    }
    for scene, goal in cases.items():
        assert scene in _scenario_hint(goal, [], ""), f"{scene} 未识别: {goal}"


def test_cheatsheet_entries_have_files():
    # 每个场景条目都带关联手册（files 字段非空），供 payload 注入
    for _pat, name, _angles, files in _load_scenarios():
        assert files, f"场景 {name} 缺少关联手册"


def test_scenario_hits_returns_files():
    hits = _scenario_hits("测试 http://target.com/login 登录", [], "")
    assert hits
    name, angles, files = hits[0]
    assert name == "登录/认证"
    assert "web-logic-auth.md" in files  # 登录框应关联认证手册（弱口令等）
    assert "web-sqli.md" in files       # 登录框应关联 SQL 注入手册


def test_login_scenario_detected():
    h = _scenario_hint("对 http://target.com/login 进行渗透测试", [], "")
    assert "登录/认证" in h
    assert "弱口令爆破" in h  # 登录框场景应包含弱口令（非仅 SQL 注入）
    assert "SQL 注入" in h


def test_api_scenario_detected_via_entrypoint():
    h = _scenario_hint("渗透测试 http://target.com",
                       [{"url": "/api/user/1", "params": ["id"]}], "")
    assert "API 接口" in h


def test_upload_scenario_detected():
    h = _scenario_hint("测试 http://target.com/upload 上传功能", [], "")
    assert "文件上传" in h


def test_multiple_scenarios_capped_at_two():
    h = _scenario_hint("测试 login 和 api 接口",
                       [{"url": "/api/login", "params": ["username", "password"]}], "")
    assert h.count("◆ 场景") <= 2


def test_no_scenario_returns_empty():
    assert _scenario_hint("对 http://target.com 进行渗透测试", [], "") == ""
