# 智能字典目录扫描 Playbook

替代 MCP 工具 `recon_smart_directory_scan`。
核心思路：先识别技术栈，再按栈选最优词表，最后 ffuf 执行。

## 流程
1. 指纹识别（见 [04-fingerprint.md](04-fingerprint.md)）获取 technologies
2. 按下表选词表
3. 用 `execute_shell` 跑 ffuf

## 技术栈 → 词表映射
| 技术栈 | 推荐词表（按优先级） |
|---|---|
| Java / Tomcat / Spring / Struts | java, java_path, webshell, jndi |
| PHP / Laravel | webshell, common |
| ASP.NET / IIS | webshell, viewstate, common |
| Django / Flask | ssti, common |
| Angular | angular, common |
| WordPress / Drupal / Joomla | common, webshell |
| Cloudflare / Nginx / Apache | common, webshell |
| 未识别 | webshell, common |

## 执行（选定词表后）
```bash
ffuf -u https://target/FUZZ -w java.txt -t 30 -mc 200,301,403 -o result.json
```
多词表可分次跑，或用多 `-w` 占位符组合：
```bash
ffuf -u https://target/FUZZ -w common.txt -w /tmp/extra.txt:FUZZ2 -mc 200,301
```

## 判读
同 [02-directory-scan.md](02-directory-scan.md)，重点关注 webshell 字典命中的可执行文件路径
（可能直接是 webshell 或上传点，对应 A05 配置错误 / A01 访问控制）。

## 注意
- 词表文件在仓库 `langGraph/data/wordlists/`，若不在 PATH 用绝对路径
- 若指纹识别失败，默认 `webshell, common` 兜底
