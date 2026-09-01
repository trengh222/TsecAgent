# 网络空间测绘 Playbook

替代 MCP 工具 `recon_cyberspace_search`。用 `execute_python` + httpx 调 FOFA/Quake API。
封装工具的固定 schema 限制了 FOFA 复杂语法表达，改用脚本自由构造查询。

## 依赖
- httpx：`pip install httpx`
- FOFA：`.env` 设 `FOFA_EMAIL` / `FOFA_API_KEY`
- Quake：`.env` 设 `QUAKE_TOKEN`

## FOFA
```python
import base64, httpx, os
email, key = os.getenv("FOFA_EMAIL"), os.getenv("FOFA_API_KEY")
if not email or not key:
    print("FOFA 未配置")
else:
    q = 'domain="example.com" && status_code="200"'
    params = {
        "email": email, "key": key,
        "qbase64": base64.b64encode(q.encode()).decode(),
        "fields": "ip,port,domain,title,protocol,country",
        "size": 100, "page": 1,
    }
    r = httpx.get("https://fofa.info/api/v1/search/all",
                  params=params, verify=False, timeout=30)
    data = r.json()
    print("total:", data.get("size"))
    for row in data.get("results", []):
        print(row)
```

## Quake
```python
import httpx, os
token = os.getenv("QUAKE_TOKEN")
if not token:
    print("Quake 未配置")
else:
    r = httpx.post("https://quake.360.net/api/v3/search/quake_service",
        headers={"X-QuakeToken": token},
        json={"query": 'domain:"example.com"', "start": 0, "size": 100},
        timeout=30)
    data = r.json()
    for item in data.get("data", []):
        svc = item.get("service", {})
        print(item.get("ip"), svc.get("port"), svc.get("name"))
```

## FOFA 语法速查
| 语法 | 含义 |
|---|---|
| `domain="x.com"` | 域名 |
| `ip="1.2.3.4"` | IP |
| `port="8080"` | 端口 |
| `title="后台"` | 网页标题 |
| `body="登录"` | 正文 |
| `header="Set-Cookie"` | 响应头 |
| `icon_hash="xxx"` | favicon hash |
| `&&` / `\|\|` | 与 / 或 |
| `status_code="200"` | 状态码 |

## 判读
- results 列表的 ip/port/domain 用于后续端口扫描与目录爆破
- 注意 size 上限（FOFA 100/页，需翻 page）；Quake size 上限 100

## 注意
- API key 缺失时脚本返回提示，对应 A05 配置错误方向另查
- 企业代理环境 `verify=False` 跳过自签证书
