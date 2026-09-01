# TsecAgent

自主渗透测试 AI Agent，基于 LangGraph 实现 **Planner → Executor → Reflector (PER)** 循环架构。

支持国内外主流 LLM（Anthropic / OpenAI 兼容端点：DeepSeek、通义千问、GLM、Kimi 等），Windows / Linux 双平台运行。

## 架构

```
┌──────────────────────────────────────────────────────────────┐
│                        Planner (LLM)                        │
│   目标分析 → 方向筛选 → 策略规划 → 任务生成                    │
└──────────────┬───────────────────────────────────────────────┘
               │ 任务列表
┌──────────────▼───────────────────────────────────────────────┐
│                     Executors (MCP Tools)                     │
│  execute_python │ execute_shell │ browser_* │ proxy_* │     │
│  knowledge_*   （侦察命令经 execute_shell + playbook 执行）    │
└──────────────┬───────────────────────────────────────────────┘
               │ 执行结果
┌──────────────▼───────────────────────────────────────────────┐
│                     Reflector (LLM)                           │
│   证据判断 → 停滞检测 → 经验提取 → 方向切换 → 压缩上下文        │
└──────────────┬───────────────────────────────────────────────┘
               │ 决策：continue / compress / summarize / end
               ▼
```

## 特性

### 渗透测试流程

- **OWASP Top 10 逐一测试**：A01-A10 方向按优先级自动推进，3 轮无果自动切换；方向名统一归一化（`_norm_dir`），杜绝 LLM 输出格式漂移导致的重复测试
- **目标分析**：根据 URL 特征（域名/路径/技术栈/业务场景）筛选适用方向，`goal_achieved` 按"所有适用方向覆盖完"动态判定
- **漏洞证据分级**：confirmed / suspected / no_finding 三级判定标准，代码校验 goal_achieved，不信任 LLM 主观判断
- **自动报告生成**：测试完成后自动生成完整渗透测试报告

### 三层知识体系

| 层 | 知识源 | 加载方式 |
|----|--------|----------|
| 漏洞方法论 | `knowledge/reference/secknowledge-skill/`（Web SQLi/XSS/RCE/反序列化 + AI 安全等 48 篇） | 漏洞类型路由表 + 按需懒加载（`grep`-then-read），不入向量库 |
| 侦察模板 | `knowledge/reference/recon-playbook/`（端口/目录扫描、指纹、JS 分析、鉴权绕过等 7 篇） | Executor 按需读取，经 `execute_shell` 执行其中命令模板 |
| 动态经验 | ChromaDB（STE 经验 + 确认漏洞回写）+ OpenViking（可选） | 特征检索：从目标 URL 提取域名/路径/技术栈关键词多维度检索 |

- **自动回写**：确认漏洞自动写入知识库，STE 经验自动持久化，跨会话加载

### 多 Provider LLM

通过 `LLM_PROVIDER` 环境变量切换，双路径调用（原生 SDK 隔离）：

- `anthropic`：原生 Anthropic SDK（Claude 系列）
- `openai`：OpenAI 兼容端点，覆盖 **DeepSeek、通义千问、智谱 GLM、Kimi、零一 Yi、MiniMax、豆包、百川、Gemini、xAI Grok** 等国内外模型

预设清单见 `deepagent/.env.example`，切换只需改 4 个环境变量。

### 安全与可靠性

- **防沉迷机制**：检测循环任务和相似输出，自动触发方向切换
- **L0-L5 渐进式失败归因**：从工具级到策略级的系统性故障分析
- **上下文压缩**：LLM 驱动的对话历史摘要，保留关键经验防止灾难性遗忘
- **沙箱加固**：`_SafeSocket` 套接字包装（防连接泄漏）、Python 代码沙箱、命令超时强制中断（PowerShell `taskkill` / tmux `C-c`）与历史清理（防输出串台）

## 快速开始

### 环境要求

- Python 3.12+
- 任一 LLM API Key（Anthropic，或 DeepSeek/Qwen/GLM 等 OpenAI 兼容 Key）
- [Caido](https://caido.io/)（可选，用于浏览器流量捕获和流量重放）
- OpenViking（可选，用于静态知识库）

### 安装

```bash
cd langGraph
pip install -r requirements.txt

# 配置
cp deepagent/.env.example deepagent/.env
# 编辑 .env：至少配置 LLM_PROVIDER / LLM_API_KEY（及兼容端点时的 LLM_BASE_URL / LLM_MODEL）
```

**LLM 配置示例**（详见 `.env.example` 内置 12 个国内外 Provider 预设）：

```ini
# Anthropic（默认）
LLM_PROVIDER=anthropic
LLM_API_KEY=sk-ant-xxxx

# DeepSeek（OpenAI 兼容端点）
LLM_PROVIDER=openai
LLM_API_KEY=sk-你的deepseek密钥
LLM_BASE_URL=https://api.deepseek.com/v1
LLM_MODEL=deepseek-chat
```

### 启动 Web UI

```bash
python deepagent/chat_server.py          # 默认 8000 端口
python deepagent/chat_server.py --port 8888 --debug  # 自定义端口 + 热重载
```

访问 http://localhost:8000

### CLI 模式

```bash
python deepagent/run_agent.py --goal "对 http://target.com 进行渗透测试"
python deepagent/run_agent.py --stream --goal "..." --max-iter 20
python deepagent/run_agent.py --check    # 仅组件健康检查
```

### Windows 支持

项目原生支持 Windows 运行（终端后端自动切换为长驻 PowerShell 会话，保留 CWD 与环境变量），详见 [WINDOWS_MIGRATION.md](WINDOWS_MIGRATION.md)：

```powershell
# 安全工具（可选，按需安装）
winget install Insecure.Nmap           # 端口扫描（需勾选 Npcap）
scoop install gobuster ffuf            # 目录扫描

# 词表已随仓库分发在 langGraph/data/wordlists/，无需额外安装
# 默认工作目录自动使用 %TEMP%\tsecagent-sandbox（建议在 .env 中设为专用目录）
```

## 工具集

MCP 工具面共 13 个，聚焦通用执行能力；侦察动作由 Agent 读取 playbook 后经 `execute_shell` 组合原生安全工具（nmap/gobuster/ffuf 等）完成：

| 工具 | 描述 |
|------|------|
| `execute_python` | Python 代码执行（httpx 请求/数据处理，`_SafeSocket` 沙箱加固） |
| `execute_shell` | Shell 命令执行（持久化会话；侦察 playbook 的命令模板经此执行） |
| `browser_navigate` | 浏览器导航 |
| `browser_execute_js` | 执行页面 JavaScript |
| `browser_get_content` | 获取页面 HTML |
| `browser_screenshot` | 页面截图 |
| `proxy_list_traffic` | 列出代理流量 |
| `proxy_get_flow` | 流量详情 |
| `proxy_clear_traffic` | 清空流量 |
| `proxy_replay_flow` | 重放流量 |
| `knowledge_search` | 搜索知识库 |
| `knowledge_get_detail` | 知识库详情 |
| `knowledge_save` | 保存知识 |

## 目录结构

```
langGraph/
├── requirements.txt          # 依赖清单
└── deepagent/
    ├── agent.py              # DeepAgent 主类，PER 循环入口
    ├── graph.py              # LangGraph StateGraph（Planner/Executor/Reflector 节点）
    ├── context.py            # Pydantic 状态模型（DeepAgentState / PlannerContext 等）
    ├── memory.py             # 上下文压缩器（LLM 驱动）
    ├── guard.py              # 防沉迷守卫（循环/重复检测）
    ├── chat_server.py        # FastAPI WebSocket 聊天服务器
    ├── chat.html             # 前端 UI（Round Card 时间线布局）
    ├── run_agent.py          # CLI 入口（含组件健康检查、多 Provider LLM 构建）
    ├── run_server.py         # MCP stdio 服务器入口
    ├── .env.example          # 环境变量模板（含 12 个国内外 Provider 预设）
    ├── mcp/                  # MCP 工具层
    │   ├── config.py         # 配置加载器
    │   ├── anti_addiction.py # 防沉迷检测
    │   ├── failure_attribution.py  # 失败归因分析
    │   ├── mcp_ser.py        # MCP stdio 服务器（13 工具注册）
    │   └── executors/
    │       ├── PythonExecutor.py    # Python 沙箱（_SafeSocket 加固）
    │       ├── TerminalExecutor.py  # Shell 会话（PowerShell REPL / tmux 双后端）
    │       ├── BrowserExecutor.py   # Playwright 浏览器
    │       ├── ProxyExecutor.py     # Caido 代理
    │       ├── KnowledgeExecutor.py # 知识库
    │       └── meta_executor.py     # 超时/重试/结果标准化
    └── knowledge/            # 知识库系统
        ├── router.py         # 知识路由器（secknowledge 漏洞类型路由表）
        ├── viking.py         # OpenViking 静态后端
        ├── import_knowledge.py   # 知识库导入工具（语义切割）
        └── reference/
            ├── secknowledge-skill/   # 漏洞方法论 skill（懒加载，随仓库分发）
            ├── recon-playbook/       # 侦察命令模板（7 篇，随仓库分发）
            ├── PayloadsAllTheThings/ # 以下第三方大库不入仓库，需 --clone-all 下载
            ├── HowToHunt/
            ├── hacktricks/
            ├── wstg/
            ├── nuclei-templates/
            └── Dictionary/
```

## 知识库导入

`secknowledge-skill` 与 `recon-playbook` 已随仓库分发，开箱即用。第三方大体积知识库（合计数百 MB）**不入仓库**，按需下载导入：

```bash
# 下载缺失的远程仓库
python deepagent/knowledge/import_knowledge.py --clone-all

# 单独导入
python deepagent/knowledge/import_knowledge.py --nuclei      # Nuclei CVE 模板
python deepagent/knowledge/import_knowledge.py --dictionary   # 攻击词表
python deepagent/knowledge/import_knowledge.py --wstg         # OWASP WSTG
python deepagent/knowledge/import_knowledge.py --hacktricks   # HackTricks

# 导入全部可用知识
python deepagent/knowledge/import_knowledge.py --all
```

## 环境变量

见 `deepagent/.env.example`，主要配置：

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `LLM_PROVIDER` | LLM Provider：`anthropic` / `openai`（OpenAI 兼容） | anthropic |
| `LLM_API_KEY` | 通用 API Key（缺省回退 `ANTHROPIC_API_KEY`） | - |
| `LLM_BASE_URL` | 兼容端点地址（缺省回退 `ANTHROPIC_BASE_URL`） | 按 provider 自动 |
| `LLM_MODEL` | 模型名称 | claude-sonnet-4-6 |
| `ANTHROPIC_API_KEY` | Anthropic API Key（向后兼容） | - |
| `BROWSER_HEADLESS` | 浏览器无头模式 | true |
| `PROXY_CAIDO_URL` | Caido 代理地址 | http://127.0.0.1:8080 |
| `TERMINAL_DEFAULT_DIR` | 终端默认工作目录 | Windows: `%TEMP%\tsecagent-sandbox` |
| `CHROMA_PATH` | ChromaDB 持久化路径 | ./data/chroma |

## License

本项目仅供安全研究和授权渗透测试使用。
