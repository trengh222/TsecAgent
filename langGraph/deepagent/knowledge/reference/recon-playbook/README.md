# Recon Playbook（侦察行动手册）

本目录收录渗透侦察阶段的操作手册，用于替代专项 MCP 侦察工具（`recon_*`）。
Agent 通过 `execute_shell` / `execute_python` 通用执行器 + 本手册的命令模板完成侦察，
不再占用工具面、恢复参数自由度。

## 手册索引

| 文件 | 主题 | 执行器 | 依赖 |
|---|---|---|---|
| [01-port-scan.md](01-port-scan.md) | 端口扫描 | execute_shell | nmap |
| [02-directory-scan.md](02-directory-scan.md) | 目录/文件爆破 | execute_shell | gobuster/ffuf |
| [03-smart-directory-scan.md](03-smart-directory-scan.md) | 按技术栈智能选字典 | execute_shell | ffuf |
| [04-fingerprint.md](04-fingerprint.md) | Web 指纹识别 | execute_python/shell | webtech/curl |
| [05-cyberspace-search.md](05-cyberspace-search.md) | FOFA/Quake 空间测绘 | execute_python | httpx + API key |
| [06-analyze-js.md](06-analyze-js.md) | JS 端点/敏感信息提取 | execute_python | requests |
| [07-fuzz-auth-bypass.md](07-fuzz-auth-bypass.md) | 鉴权绕过 Fuzz | execute_python | requests |

## 检索与使用

Agent 在侦察阶段可通过 `knowledge_search` 工具按主题词检索本手册，例如：

```
knowledge_search(query="port scan nmap")
knowledge_search(query="directory scan ffuf")
knowledge_search(query="auth bypass fuzz")
```

命中后按手册中的命令模板，用 `execute_shell` / `execute_python` 执行。

> **接入说明**：本手册需导入知识库后才能被 `knowledge_search` 命中。导入方式见仓库
> `knowledge/import_static_knowledge.py`，可按 `category="PayloadsAllTheThings"` 或新增
> 类别导入 OpenViking / ChromaDB。在导入前，agent 仍可通过文件读取直接使用本手册。

## 设计原则

- 每个 playbook 给出**可直接复制的命令/代码模板**，agent 据此用通用执行器落地
- 参数按场景分组，agent 按目标特征自由选择（不再受封装工具的固定 schema 限制）
- 替代原 `recon_*` 专项 MCP 工具，释放工具面、恢复参数自由度
