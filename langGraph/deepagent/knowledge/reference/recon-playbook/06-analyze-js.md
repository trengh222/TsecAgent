# JS 端点/敏感信息提取 Playbook

替代 MCP 工具 `recon_analyze_js`。用 `execute_python` 拉 JS 后正则提取。

## 依赖
- requests（或 httpx）

## 脚本
```python
import re, requests
from urllib.parse import urljoin

base = "https://target"
html = requests.get(base, verify=False, timeout=15).text

# 提取页面引用的 JS 文件 URL
js_files = re.findall(r'<script[^>]+src="([^"]+\.js)"', html)

endpoints = set()
secrets = []
for js in js_files[:10]:
    jsu = js if js.startswith("http") else urljoin(base, js)
    try:
        content = requests.get(jsu, verify=False, timeout=15).text
    except Exception as e:
        print("fetch fail:", jsu, e)
        continue
    # API 端点
    endpoints.update(re.findall(r'["\'`](/api/[^\s"\'`]+)["\'`]', content))
    endpoints.update(re.findall(r'["\'`](/v\d+/[^\s"\'`]+)["\'`]', content))
    # 敏感信息
    for pat in [r'token["\']?\s*[:=]\s*["\']([^"\'\s]{8,})',
                r'apikey["\']?\s*[:=]\s*["\']([^"\'\s]+)',
                r'api_key["\']?\s*[:=]\s*["\']([^"\'\s]+)',
                r'secret["\']?\s*[:=]\s*["\']([^"\'\s]{8,})',
                r'password["\']?\s*[:=]\s*["\']([^"\'\s]{4,})']:
        secrets.extend(re.findall(pat, content, re.I))
    # 内网地址
    internal = re.findall(
        r'(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})',
        content)

print("endpoints:", sorted(endpoints))
print("secrets:", secrets)
print("internal:", internal)
```

## 提取目标
| 类别 | 说明 |
|---|---|
| API 端点 | `/api/...`、`/v1/...`，用于后续目录爆破/鉴权测试 |
| Token / Key | `token`、`jwt`、`apikey`、`secret` |
| 凭证 | `password`、`passwd` |
| 内网地址 | 10.x / 192.168.x / 172.16-31.x，可能暴露内网拓扑 |
| 云端点 | `amazonaws.com`、`aliyuncs.com`、`oss` |

## 判读
- 端点用于后续目录爆破 / 鉴权绕过测试
- 敏感信息直接报告（可能即漏洞，对应 A02 加密失败 / A05 配置错误）
- 内网地址用于 SSRF（A10）方向构造 payload
