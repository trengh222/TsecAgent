# Web 指纹识别 Playbook

替代 MCP 工具 `recon_fingerprint`。

## 依赖
- webtech（`pip install webtech`）或仅 curl（兜底）

## 方式一：execute_python + webtech（推荐）
```python
import webtech
wt = webtech.WebTech(options={"json": True})
report = wt.start_from_url("https://target")
techs = []
for t in report.get("tech", []):
    name = t.get("name", "")
    ver = t.get("version", "")
    techs.append(f"{name} {ver}".strip() if ver else name)
print("technologies:", techs)
```

## 方式二：execute_shell + curl（无依赖兜底）
```bash
curl -sI https://target -k | grep -iE "server|powered-by|x-aspnet|set-cookie"
curl -s https://target -k | grep -ioE "wp-content|joomla|drupal|laravel|django|spring|bootstrap|jquery|vue\.js|react\.production|ng-version|cloudflare|nginx|apache"
```

## 特征签名速查
| 技术 | 特征 |
|---|---|
| WordPress | `wp-content`、`wp-includes`、`wp-json` |
| Drupal | `drupal.js`、`Drupal.settings` |
| Joomla | `joomla`、`/components/` |
| Laravel | `laravel_session`、`csrf-token` |
| Spring | `X-Application-Context`、`Whitelabel Error Page` |
| Django | `csrfmiddlewaretoken` |
| React | `react.production`、`data-reactroot` |
| Vue.js | `vue.js`、`__vue__` |
| Angular | `ng-version`、`ng-app` |
| jQuery | `jquery`、`$.fn` |
| Cloudflare | `cf-ray`、`server: cloudflare` |
| Nginx | `server: nginx` |
| Apache | `server: apache` |

## 判读
- Server 头 + body 特征双确认更可靠
- 指纹结果驱动 [03-smart-directory-scan.md](03-smart-directory-scan.md) 选词表
- 指纹结果驱动 A06（已知漏洞组件）匹配 nuclei 模板
