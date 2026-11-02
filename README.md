# TsecAgent

自主渗透测试 AI Agent，基于 LangGraph 实现 **Planner → Finder → Reflector (PFR)** 循环 + **多 Agent 角色编排**（独立裁决 Agent + 独立报告 Agent），所有漏洞确认必须通过对抗式证伪 + 机器校验 + 复现协议三道关卡。

支持国内外主流 LLM（Anthropic / OpenAI 兼容端点：DeepSeek、通义千问、GLM、Kimi 等），Windows / Linux 双平台运行。

## 架构

```
┌──────────────────────────────────────────────────────────────────┐
│                        Planner (规划角色)                        │
│  威胁建模(§4) → 方向筛选 → 测试文档 → 任务生成                    │
│  提示词注入: 扫描种子/CWE质问清单/知识库payload/组合利用工作台       │
└──────────────┬───────────────────────────────────────────────────┘
               │ 任务列表（depends_on 依赖）
┌──────────────▼───────────────────────────────────────────────────┐
│                      Finder (发现角色, §8)                        │
│  多模态分道并行: python(×3) ∥ shell ∥ browser ∥ proxy             │
│  依赖波次调度 + 指纹硬去重 + 防沉迷守卫                             │
└──────────────┬───────────────────────────────────────────────────┘
               │ 执行结果
┌──────────────▼───────────────────────────────────────────────────┐
│                     Reflector (反思角色)                          │
│  证据判断 → 利用链沉淀 → 停滞检测 → 方向切换 → 压缩判定             │
│      │ 候选漏洞                                                  │
│      ▼                                                           │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  VerifierAgent (独立裁决 Agent)                           │   │
│  │  ① N路证伪者多数裁定 → ② 机器校验 → ③ 复现协议(L1无复现降L2)│   │
│  └──────────┬───────────────────────────────────────────────┘   │
└─────────────┼────────────────────────────────────────────────────┘
              │ 决策：continue / compress / summarize
              ▼
┌──────────────────────────────────────────────────────────────────┐
│  compressor (上下文压缩)          summarizer → ReporterAgent       │
│                                  (独立报告 Agent，含兜底报告)      │
└──────────────────────────────────────────────────────────────────┘
```

## 特性

### 渗透测试流程

- **确定性预扫打底（8 路两波）**：任务开始前机器枚举并行铺底，第一波 nuclei(指纹/敏感文件) + ffuf(目录爆破) + httpx(存活指纹/WAF) + katana(爬虫端点) + subfinder/gau/被动 OSINT(子域/历史 URL/DNS) + naabu(广扫端口)，第二波 dnsx(子域存活解析) + nmap(naabu 命中端口精测)；结果 round-robin 交错去重为 `scan_seeds`（≤30 条）注入 Planner，避免盲目盲测
- **方向空间两层建模**：web（OWASP A01-A10）× ai-llm（L01-L07 提示注入/越狱/MCP 攻击/Agent 滥用/RAG 投毒/沙箱逃逸/模型窃取）17 子方向；按目标域预筛适用方向，域专精提示词切换，跨域产物链式联动（web 凭据 → ai-llm MCP 攻击）
- **场景方法论横向速查**：登录框/API/上传/注册等 14 类入口场景自动识别，注入对应测试角度与 payload 手册（如登录框必带弱口令爆破，不只测 SQL 注入）
- **信息收集 → 利用强制衔接**：沙箱 HTTP 响应指纹（status/length/片段）结构化回传供差异对比；源码结构（类/魔术方法/危险调用）服务端确定性解析入资产面板，反序列化等利用强制基于已解析结构构造，禁止盲猜类名
- **威胁建模层（§4）**：首轮强制产出结构化威胁模型——资产 / 信任边界 / 入口点清单（未认证可达 vs 需认证）/ 反例假设；后续轮按入口点切分攻击面，任务必须标注目标 EP#
- **CWE 模式质问清单（§5.3）**：14 条黑盒漏洞模式（触发特征 / 必证项 / 误报自检 / 检查步骤）按 OWASP 方向路由注入 Planner，命中特征才可提假设、必证项不齐只写疑似
- **全方向覆盖推进**：17 子方向（web A01-A10 + ai-llm L01-L07）按优先级自动推进，3 轮无果自动切换；`goal_achieved` 按"所有适用方向覆盖完"动态判定
- **计划驱动主线**：首轮生成完整测试文档（用例级测试点+payload 要点），中间轮修订增补、动态调整总轮数，报告以文档为准
- **多步利用链**：跨轮沉淀攻击资产面板 / 未破门槛 / 证据原文库，已确认漏洞的产物必须作为其他方向任务的输入，禁止孤立测试
- **自动报告生成**：ReporterAgent 生成中文报告，严格区分 [已确认]/[疑似]/[无发现]，LLM 失败走纯文本兜底

### 对抗式验证（防误报核心）

- **独立裁决 Agent（形态 D 多 Agent）**：VerifierAgent 与 Planner/Finder 隔离，独立 LLM 配置（`LLM_VERIFIER_*`）
- **多路证伪者多数裁定（§11）**：3 路并行证伪（温度 0.1/0.25/0.4 轮转），有罪推定，异常输出一律计 REFUTED
- **Finding 机器校验（§7）**：字段完备性 + SURVIVED 关卡的机器硬校验，四级置信度（L1-L4）仅 L1/L2 上报告
- **复现协议**：重放候选 payload 代码，硬证据信号比对 / 最长公共片段比对，L1 无复现自动降 L2
- **任务同质化三级拦截**：工具+参数指纹硬去重 / 无效任务清单注入 Planner / 一轮 ≥2 相同回显强制换向
- **三级去重防沉迷**：循环任务检测、相似输出检测、方向停滞自动 pivot

### 确定性知识体系

| 层 | 知识源 | 加载方式 |
|----|--------|----------|
| 漏洞方法论 | `knowledge/reference/secknowledge-skill/`（Web SQLi/XSS/RCE/反序列化 + AI 安全等 48 篇） | 漏洞类型路由表 + 按需懒加载（`grep`-then-read），不入向量库 |
| 漏洞模式库 | `knowledge/reference/cwe-patterns/web.yaml`（14 条 CWE 质问清单） | 服务端按方向确定性路由注入 Planner |
| 侦察模板 | `knowledge/reference/recon-playbook/`（端口/目录扫描、指纹、JS 分析、鉴权绕过等 7 篇） | Executor 按需读取，经 `execute_shell` 执行其中命令模板 |
| 场景速查 | `knowledge/reference/scenario-playbook/scenarios.yaml`（14 类入口场景 + 测试角度 + 关联手册） | 服务端正则识别场景，payload 确定性注入 |
| 进阶手册 | `knowledge/reference/ctf-web/`（CTF 实战视角 Web 手法 24 篇） | 关键词路由按需加载，与 secknowledge 互补 |
| 动态经验 | ChromaDB（STE 经验 + 确认漏洞回写）+ OpenViking（可选） | 特征检索：从目标 URL 提取域名/路径/技术栈关键词多维度检索 |

- **知识库确定性注入**：payload/绕过片段由服务端读取后直接注入 Planner 提示词，不依赖 LLM 自觉查阅，杜绝凭印象编造 payload
- **自动回写**：确认漏洞自动写入知识库，STE 经验自动持久化，跨会话加载

### 多 Provider LLM 与角色模型隔离

通过 `LLM_PROVIDER` 环境变量切换，双路径调用（原生 SDK 隔离）：

- `anthropic`：原生 Anthropic SDK（Claude 系列）
- `openai`：OpenAI 兼容端点，覆盖 **DeepSeek、通义千问、智谱 GLM、Kimi、零一 Yi、MiniMax、豆包、百川、Gemini、xAI Grok** 等国内外模型

多 Agent 角色可绑独立模型（缺省回退全局配置）：

- `LLM_VERIFIER_MODEL/API_KEY/BASE_URL`：裁决者（证伪陪审团/机器校验/复现）
- `LLM_REPORTER_MODEL/API_KEY/BASE_URL`：报告者（最终报告）

预设清单见 `deepagent/.env.example`，切换只需改 4 个环境变量。

### 安全与可靠性

- **上下文压缩**：LLM 驱动的对话历史摘要，保留关键经验防止灾难性遗忘；压缩只作用于消息，结构化工作记忆面板天然不丢
- **沙箱加固**：`_SafeSocket` 套接字包装（防连接泄漏）、Python 代码沙箱、命令超时强制中断（PowerShell `taskkill` / tmux `C-c`）与历史清理（防输出串台）
- **会话记忆持久化**：跨服务重启恢复对话上下文；单会话单任务互斥，中断 2 秒内退出

## 快速开始

### 环境要求

- Python 3.12+
- 任一 LLM API Key（Anthropic，或 DeepSeek/Qwen/GLM 等 OpenAI 兼容 Key）
- [Caido](https://caido.io/)（可选，用于浏览器流量捕获和流量重放）
- OpenViking（可选，用于静态知识库）
- 确定性扫描工具（可选，用于 8 路预扫）：二进制不随仓库分发，按 [langGraph/tools/](langGraph/tools/) 下载指南从各官方 release 获取

### 下载预扫工具（可选，8 路预扫需要）

nuclei / ffuf / httpx / katana / subfinder / dnsx / naabu / gau 共 8 个单文件工具，放置到 `langGraph/tools/` 后预扫自动启用（缺失的工具静默跳过，不影响主流程）：

```powershell
cd langGraph\tools
# 从各官方 GitHub Release 下载 windows_amd64 版并解压 exe 到当前目录：
#   nuclei    https://github.com/projectdiscovery/nuclei/releases
#   httpx     https://github.com/projectdiscovery/httpx/releases
#   katana    https://github.com/projectdiscovery/katana/releases
#   subfinder https://github.com/projectdiscovery/subfinder/releases
#   dnsx      https://github.com/projectdiscovery/dnsx/releases
#   naabu     https://github.com/projectdiscovery/naabu/releases
#   ffuf      https://github.com/ffuf/ffuf/releases
#   gau       https://github.com/lc/gau/releases
```

nmap 走系统安装（`NMAP_BIN` 环境变量可指定路径）；nuclei 模板库按需 `python deepagent/knowledge/import_knowledge.py --nuclei` 下载。

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

MCP 工具面共 13 个，聚焦通用执行能力（Python 沙箱 / Shell 会话 / 浏览器 / 代理 / 知识库）；侦察与验证动作由 Agent 读取 playbook 后经 `execute_shell` 组合原生安全工具完成，`langGraph/tools/` 下的确定性引擎自动接入 8 路预扫：

| 引擎 | 预扫分工 |
|------|----------|
| nuclei | 指纹技术栈 + 敏感文件暴露（模板收敛子集，禁全量 CVE 扫描） |
| nmap | naabu 命中端口逐一 `-sV` 服务精测（无果退化 top-100） |
| ffuf | 目录爆破（用户字典库小字典 + 内置高频路径合并） |
| httpx | 存活探测 + status/title/server/tech 指纹 + CDN/WAF 识别 |
| katana | 主动爬虫（深 2 层 + JS 提取，产端点种子） |
| subfinder / gau | 被动子域枚举 / 历史 URL 聚合 |
| dnsx | 子域存活解析（A/AAAA/CNAME） |

爆破字典优先使用本地字典库 `WORDLIST_DIR`（缺省 `E:\notebook\字典`），缺失时自动回退内置小字典。

| 工具 | 描述 |
|------|------|
| `execute_python` | Python 代码执行（httpx 请求/数据处理，`_SafeSocket` 沙箱加固 + HTTP 响应指纹自动采集） |
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
├── tools/                   # 确定性预扫引擎（8 个 exe 不随仓库分发，按 README 下载；含 LICENSE/说明）
├── requirements.txt         # 依赖清单
├── tests/                   # pytest 套件（48 例：方向目录/验证链/skill路由/指纹/源码情报/字典库）
└── deepagent/
    ├── agent.py             # DeepAgent 主类，PFR 循环入口
    ├── graph.py             # LangGraph 状态图（Planner/Finder/Reflector 节点 + 多 Agent 编排器装配）
    ├── agents.py            # 独立角色 Agent（形态 D：VerifierAgent 裁决 / ReporterAgent 报告 / AgentOrchestrator）
    ├── context.py           # Pydantic 状态模型（DeepAgentState / PlannerContext 等）
    ├── memory.py            # 上下文压缩器（LLM 驱动）
    ├── guard.py             # 防沉迷守卫（循环/重复检测）
    ├── chat_server.py       # FastAPI WebSocket 聊天服务器（含 8 路预扫接线）
    ├── chat.html            # 前端 UI（Round Card 时间线布局）
    ├── run_agent.py         # CLI 入口（含组件健康检查、多 Provider LLM 构建）
    ├── run_server.py        # MCP stdio 服务器入口
    ├── .env.example         # 环境变量模板（12 个 Provider 预设 + 角色模型隔离 + fast 模型/字典库）
    ├── mcp/                 # MCP 工具层
    │   ├── config.py        # 配置加载器
    │   ├── anti_addiction.py # 防沉迷检测
    │   ├── failure_attribution.py  # 失败归因分析
    │   ├── mcp_ser.py       # MCP stdio 服务器（13 工具注册）
    │   └── executors/
    │       ├── PythonExecutor.py    # Python 沙箱（_SafeSocket 加固 + HTTP 响应指纹采集）
    │       ├── TerminalExecutor.py  # Shell 会话（PowerShell REPL / tmux 双后端）
    │       ├── BrowserExecutor.py   # Playwright 浏览器
    │       ├── ProxyExecutor.py     # Caido 代理
    │       ├── KnowledgeExecutor.py # 知识库
    │       └── meta_executor.py     # 超时/重试/结果标准化
    └── knowledge/           # 知识库系统
        ├── router.py        # 知识路由器（secknowledge 漏洞类型路由表）
        ├── viking.py        # OpenViking 静态后端
        ├── import_knowledge.py   # 知识库导入工具（语义切割）
        └── reference/
            ├── secknowledge-skill/   # 漏洞方法论 skill（懒加载，随仓库分发）
            ├── cwe-patterns/         # CWE 模式质问清单（YAML，随仓库分发）
            ├── recon-playbook/       # 侦察命令模板（7 篇，随仓库分发）
            ├── scenario-playbook/    # 场景方法论速查（14 场景 YAML，随仓库分发）
            ├── ctf-web/              # CTF 实战视角 Web 进阶手册（24 篇，随仓库分发）
            ├── PayloadsAllTheThings/ # 以下第三方大库不入仓库，需 --clone-all 下载
            ├── HowToHunt/
            ├── hacktricks/
            ├── wstg/
            ├── nuclei-templates/
            └── Dictionary/
```

## 知识库导入

`secknowledge-skill`、`cwe-patterns` 与 `recon-playbook` 已随仓库分发，开箱即用。第三方大体积知识库（合计数百 MB）**不入仓库**，按需下载导入：

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
| `LLM_VERIFIER_MODEL` 等 | 裁决 Agent 模型隔离（证伪/机器校验/复现） | 全局配置 |
| `LLM_REPORTER_MODEL` 等 | 报告 Agent 模型隔离（最终报告） | 全局配置 |
| `LLM_FAST_MODEL` | fast 模型分流（证伪/反思/经验提取等高频低创意调用） | 全局配置 |
| `WORDLIST_DIR` | 本地字典库目录（目录爆破/弱口令爆破优先使用） | `E:\notebook\字典` |
| `REFUTER_PATHS` | 证伪者并行路数（多数裁定） | 3 |
| `ANTHROPIC_API_KEY` | Anthropic API Key（向后兼容） | - |
| `BROWSER_HEADLESS` | 浏览器无头模式 | true |
| `PROXY_CAIDO_URL` | Caido 代理地址 | http://127.0.0.1:8080 |
| `TERMINAL_DEFAULT_DIR` | 终端默认工作目录 | Windows: `%TEMP%\tsecagent-sandbox` |
| `CHROMA_PATH` | ChromaDB 持久化路径 | ./data/chroma |

## License

本项目仅供安全研究和授权渗透测试使用。
