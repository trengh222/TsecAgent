# TsecAgent

自主渗透测试 AI Agent，基于 LangGraph 实现 **Planner → Executor → Reflector (PER)** 循环架构。

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
│  recon_* │ knowledge_* │ http_search                           │
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

- **OWASP Top 10 逐一测试**：A01-A10 方向按优先级自动推进，3 轮无果自动切换
- **目标分析**：根据 URL 特征（域名/路径/技术栈/业务场景）筛选适用方向
- **漏洞证据分级**：confirmed / suspected / no_finding 三级判定标准，代码校验 goal_achieved
- **自动报告生成**：测试完成后自动生成完整渗透测试报告

### 智能知识库

双后端知识路由（OpenViking 静态 + ChromaDB 动态）：

| 知识源 | 内容 | 条目数 |
|--------|------|--------|
| PayloadsAllTheThings | Web 漏洞 Payload | 89 文件 |
| HowToHunt | 挖洞方法论 | 141 文件 |
| HackTricks | 渗透测试百科全书 | 9,703 块 |
| OWASP WSTG | 官方测试指南 | 1,269 块 |
| Nuclei Templates | CVE 检测模板 | 2,723 块 |
| Dictionary | 攻击词表 | 594 块 |
| ChromaDB 动态 | STE 经验 + 确认漏洞 | 运行时积累 |

- **特征检索**：从目标 URL 提取域名/路径/技术栈/业务场景关键词，多维度智能检索
- **自动回写**：确认漏洞自动写入知识库，STE 经验自动持久化，跨会话加载

### 安全与可靠性

- **防沉迷机制**：检测循环任务和相似输出，自动触发方向切换
- **L0-L5 渐进式失败归因**：从工具级到策略级的系统性故障分析
- **上下文压缩**：LLM 驱动的对话历史摘要，保留关键经验防止灾难性遗忘
- **LLM 输出校验**：goal_achieved 代码级验证，不信任 LLM 的主观判断

## 快速开始

### 环境要求

- Python 3.12+
- Anthropic API Key（或兼容代理）
- [Caido](https://caido.io/)（可选，用于浏览器流量捕获和流量重放）
- OpenViking（可选，用于静态知识库）

### 安装

```bash
cd langGraph
pip install -r requirements.txt

# 配置
cp deepagent/.env.example deepagent/.env
# 编辑 .env 填入 ANTHROPIC_API_KEY
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
```

## 工具集

| 工具 | 描述 |
|------|------|
| `execute_python` | Python 代码执行（httpx 请求/数据处理） |
| `execute_shell` | Shell 命令执行（持久化会话） |
| `browser_navigate` | 浏览器导航 |
| `browser_execute_js` | 执行页面 JavaScript |
| `browser_get_content` | 获取页面 HTML |
| `browser_screenshot` | 页面截图 |
| `proxy_list_traffic` | 列出代理流量 |
| `proxy_get_flow` | 流量详情 |
| `proxy_clear_traffic` | 清空流量 |
| `proxy_replay_flow` | 重放流量 |
| `recon_port_scan` | nmap 端口扫描 |
| `recon_directory_scan` | gobuster/ffuf 目录扫描 |
| `recon_fingerprint` | Web 指纹识别 |
| `recon_cyberspace_search` | FOFA/Quake 测绘 |
| `recon_analyze_js` | JS 文件分析 |
| `recon_fuzz_auth_bypass` | 鉴权绕过 Fuzz |
| `recon_workflow` | 一键侦察工作流 |
| `knowledge_search` | 搜索知识库 |
| `knowledge_get_detail` | 知识库详情 |
| `knowledge_save` | 保存知识 |
| `http_search` | HTTP 轻量搜索 |

## 目录结构

```
langGraph/
├── deepagent/
│   ├── agent.py              # DeepAgent 主类，PER 循环入口
│   ├── graph.py              # LangGraph StateGraph（Planner/Executor/Reflector 节点）
│   ├── context.py            # Pydantic 状态模型（DeepAgentState / PlannerContext 等）
│   ├── memory.py             # 上下文压缩器（LLM 驱动）
│   ├── guard.py              # 防沉迷守卫（循环/重复检测）
│   ├── tool.py               # 工具定义
│   ├── main.py               # 主入口
│   ├── chat_server.py        # FastAPI WebSocket 聊天服务器
│   ├── chat.html             # 前端 UI（Round Card 时间线布局）
│   ├── run_agent.py          # CLI 入口
│   ├── .env                  # 环境变量配置
│   ├── mcp/                  # MCP 工具层
│   │   ├── config.py         # 配置加载器
│   │   ├── anti_addiction.py # 防沉迷检测
│   │   ├── failure_attribution.py  # 失败归因分析
│   │   ├── mcp_ser.py        # MCP stdio 服务器
│   │   └── executors/        # 10+ 执行器
│   │       ├── PythonExecutor.py    # Python 沙箱
│   │       ├── TerminalExecutor.py  # Shell 会话
│   │       ├── BrowserExecutor.py   # Playwright 浏览器
│   │       ├── ProxyExecutor.py     # Caido 代理
│   │       ├── ReconExecutor.py     # 侦察工具集
│   │       ├── KnowledgeExecutor.py # 知识库
│   │       ├── HttpSearchExecutor.py
│   │       ├── meta_executor.py     # 超时/重试/结果标准化
│   │       ├── AuthBypassFuzzer.py  # 鉴权绕过
│   │       ├── DirectoryScanner.py  # 目录扫描
│   │       ├── JSAnalyzer.py        # JS 分析
│   │       └── PortScanner.py       # 端口扫描
│   └── knowledge/            # 知识库系统
│       ├── router.py         # 知识路由器（别名/路由/合并搜索）
│       ├── viking.py         # OpenViking 静态后端
│       ├── import_knowledge.py   # 知识库导入工具（语义切割）
│       └── reference/        # 静态知识源
│           ├── PayloadsAllTheThings/
│           ├── HowToHunt/
│           ├── HackTricks/
│           ├── wstg/
│           ├── nuclei-templates/
│           └── Dictionary/
├── demo.py                   # LangGraph 演示脚本
├── test.py                   # OpenViking 初始化测试
└── read.md                   # 架构图文档
```

## 知识库导入

```bash
# 导入全部可用知识
python deepagent/knowledge/import_knowledge.py --all

# 单独导入
python deepagent/knowledge/import_knowledge.py --nuclei      # Nuclei CVE 模板
python deepagent/knowledge/import_knowledge.py --dictionary   # 攻击词表
python deepagent/knowledge/import_knowledge.py --wstg         # OWASP WSTG
python deepagent/knowledge/import_knowledge.py --hacktricks   # HackTricks

# 下载缺失的远程仓库
python deepagent/knowledge/import_knowledge.py --clone-all
```

## 环境变量

见 `deepagent/.env`，主要配置：

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `ANTHROPIC_API_KEY` | Anthropic API Key | - |
| `ANTHROPIC_BASE_URL` | API 代理地址 | https://api.anthropic.com |
| `LLM_MODEL` | 模型名称 | claude-sonnet-4-6 |
| `BROWSER_HEADLESS` | 浏览器无头模式 | true |
| `PROXY_CAIDO_URL` | Caido 代理地址 | http://127.0.0.1:8080 |
| `CHROMA_PATH` | ChromaDB 持久化路径 | ./data/chroma |

## License

本项目仅供安全研究和授权渗透测试使用。
