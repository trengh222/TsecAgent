# SecKnowledge - Web与AI安全测试知识技能

📖 [English](README_EN.md)

![version](https://img.shields.io/badge/version-2.2.0-blue)
![license](https://img.shields.io/badge/license-MIT-green)
![references](https://img.shields.io/badge/references-48-orange)

> 一个安全测试专家技能（Agent Skill），将 WooYun 88,636 个真实漏洞案例、先知 5,600+ 篇研究文档、GAARM 173 条 AI 安全风险（5 域）、OWASP LLM/ASI/WSTG 三大框架与 200+ 常用测试用例，浓缩为可按需加载的实战渗透测试知识库——让 AI 助手在安全评估中即时调用系统化的攻防知识。

---

## 为什么需要这个 Skill？

用 AI 助手做安全评估时，模型的通用知识往往不够专业和系统。这个 Skill 让 AI 变成一个**经验丰富的安全测试专家**：

- 给出一个目标，它能系统化地列出攻击面和测试用例
- 遇到 WAF 拦截，它能从 88,636 个真实绕过案例中提供对策
- 测试 AI 应用，它能覆盖 173 条 GAARM 风险（5 域，AISS 2026-06 快照）+ OWASP LLM/Agent Top 10
- 需要 Payload，它能提供经过实战验证的完整速查库

## 知识来源

| 来源 | 规模 | 内容 |
|------|------|------|
| **WooYun 漏洞库** | 88,636 条真实漏洞 | SQL注入、XSS、命令执行、文件上传、逻辑漏洞等实战案例与绕过技巧 |
| **先知安全社区** | 5,600+ 篇安全文档 | L1-L4 安全研究思维金字塔方法论 |
| **GAARM 风险矩阵** | 173 条 AI 安全风险 | 来自 AISS 绿盟大模型安全智链社区，5 安全域×3生命周期（2026-06 快照，含 RAG/记忆投毒、Agent 失控等 23 条增量）|
| **OWASP 三大框架** | LLM Top 10 / Agentic AI Top 10 / WSTG | 2025-2026 最新版合规映射 |

## 覆盖范围

### Web 安全（传统 + 现代）

```
注入攻击        SQL注入 / XSS / 命令执行 / XXE / 反序列化
逻辑漏洞        越权 / 支付篡改 / 密码重置 / 条件竞争
文件安全        文件上传 / 路径遍历 / SSRF / 信息泄露
现代协议        CORS / GraphQL / HTTP走私 / WebSocket / OAuth
部署安全        供应链 / 云服务 / TLS / 容器 / CI/CD
框架安全        指纹识别→CVE匹配→PoC验证 通用方法论
```

### AI 安全（5 大安全域 × 173 条风险）

```
AI应用安全(39)   Prompt注入 / CoT攻击 / MCP投毒 / Agent利用 / 工具链误调用·循环失控(2026)
AI模型安全(46)   越狱 / 幻觉滥用 / 对抗样本 / 模型窃取 / 推理链污染·规划篡改(2026)
AI数据安全(43)   Prompt泄露 / 数据窃取 / 推断攻击 / RAG投毒·记忆投毒(2026)
AI身份安全(26)   角色逃逸 / 权限失控 / Agent伪造 / 会话劫持 / 多Agent协同失控(2026)
AI基座安全(19)   沙箱逃逸 / 容器逃逸 / 供应链 / 拒绝服务
前沿风险         类Claw杀伤链矩阵 / MCP工具投毒 / Agent蠕虫 / Skills注入 / Claude Code CVE
```

### 核心方法论

```
先知 L1-L4       攻击面识别 → 假设验证 → 深度利用 → 防御反推
WooYun 本质公式   漏洞 = 预期行为 - 实际行为 = 开发者假设 ⊕ 攻击者输入
GAARM 矩阵       5安全域 × 3生命周期 = 系统化AI风险覆盖（173 条, 2026-06）
OWASP 映射       LLM01-10 / ASI01-10 / WSTG-* 合规编号
```

## 文件结构

```
SKILL.md                              # 入口：速查卡片 + 决策树 + 导航
references/
├── 【Web 漏洞类型】
│   ├── web-sqli.md                   # SQL 注入（含 SQLMap 速查）(~245 行)
│   ├── web-xss.md                    # XSS 跨站脚本 (~187 行)
│   ├── web-rce.md                    # 命令执行 (~232 行)
│   ├── web-xxe.md                    # XXE 外部实体注入 (~106 行)
│   ├── web-deser.md                  # 反序列化 (~151 行)
│   ├── web-upload.md                 # 文件上传 + Webshell 免杀 (~174 行)
│   ├── web-traversal.md              # 文件遍历/包含 (~145 行)
│   ├── web-leak.md                   # 信息泄露 (~136 行)
│   └── web-ssrf-misc.md              # SSRF + 配置错误 + CMS/URL 附录 (~191 行)
├── 【Web 业务与现代协议】
│   ├── web-logic-auth.md             # 越权/支付/密码重置/逻辑漏洞 (582 行)
│   ├── web-modern-protocols.md       # CORS/GraphQL/HTTP走私/WebSocket/OAuth (348 行)
│   └── web-deployment-security.md    # 供应链/云部署/框架CVE检测 (449 行)
├── 【AI 应用安全 - 应用阶段按风险类别细分 + 部署/训练 + 前沿】
│   ├── ai-app-prompt-1.md            # 应用阶段细分：Prompt 注入/XSS劫持/间接/Memory/蠕虫 (~301 行)
│   ├── ai-app-prompt-2.md            # 应用阶段细分：反向诱导/多模态/对抗编码/关键字混淆/同义词 (~242 行)
│   ├── ai-app-mcp.md                 # 应用阶段细分：MCP 协议攻击 (~261 行)
│   ├── ai-app-agent-cot-1.md         # 应用阶段细分：CoT注入/SSRF探测/代码执行注入 (~177 行)
│   ├── ai-app-agent-cot-2.md         # 应用阶段细分：Agent利用/思维链/查询&环境注入/预期外代码执行 (~365 行)
│   ├── ai-app-deploy.md              # 部署阶段：API/源码 (~154 行)
│   ├── ai-app-train.md               # 训练阶段：第三方组件/插件 (~427 行)
│   └── ai-app-frontier.md            # 前沿：Agent/MCP/Skills 2025-2026 (~121 行)
├── 【AI 模型安全 - 应用阶段按风险大类细分 + 部署/训练】
│   ├── ai-model-jailbreak.md         # 应用阶段细分：越狱 GAARM.0027.x (~404 行)
│   ├── ai-model-hallucination.md     # 应用阶段细分：幻觉 GAARM.0028/0064 (~252 行)
│   ├── ai-model-content-1.md         # 应用阶段细分：非合规内容 偏见/暴力/政治军事 GAARM.0029.x (~315 行)
│   ├── ai-model-content-2.md         # 应用阶段细分：非合规内容 虚假/诱导/非合规输出 GAARM.0029.x (~241 行)
│   ├── ai-model-copyright.md         # 应用阶段细分：版权/商业 GAARM.0030.x (~154 行)
│   ├── ai-model-misuse-1.md          # 应用阶段细分：图片伪造/多模态/恶意代码/意图破坏/数据漂移 (~316 行)
│   ├── ai-model-misuse-2.md          # 应用阶段细分：功能滥用/视频伪造/钓鱼/音频伪造 GAARM.0031.x/0033/0062/0063 (~233 行)
│   ├── ai-model-extraction.md        # 应用阶段细分：对抗样本/模型提取 GAARM.0032.x (~363 行)
│   ├── ai-model-deploy.md            # 部署阶段：文件窃取/参数篡改 (~136 行)
│   └── ai-model-train.md             # 训练阶段：后门/对齐/投毒 (~292 行)
├── 【AI 数据安全 - GAARM 三阶段】
│   ├── ai-data-app-1.md              # 应用阶段：API/隐私/企业/假定场景&角色/元Prompt/关键字/外部源泄露 (~477 行)
│   ├── ai-data-app-2.md              # 应用阶段：成员推断/数据操纵/模型反演/推理API/级联幻觉/训练推导 (~432 行)
│   ├── ai-data-deploy.md             # 部署阶段：备份/传输/存储 (~230 行)
│   ├── ai-data-train-1.md            # 训练阶段：外部数据源/隐私/企业/内部/对话语料投毒 (~263 行)
│   └── ai-data-train-2.md            # 训练阶段：匿名化/机密/投毒/泄露/篡改/预训练偏见 (~333 行)
├── 【AI 身份安全 - GAARM 三阶段】
│   ├── ai-identity-app-1.md          # 应用阶段：Action权限/MCP越权/Prompt劫持/假定逃逸/云凭证/外部源欺骗/多Agent伪造 (~462 行)
│   ├── ai-identity-app-2.md          # 应用阶段：会话劫持/未授权访问/权限管控/模拟对话/角色逃逸/账户劫持&越权/遗忘法 (~450 行)
│   ├── ai-identity-deploy.md         # 部署阶段：未授权访问 (~226 行)
│   └── ai-identity-train.md          # 训练阶段：权限设计 (~148 行)
├── 【AI 基座安全 - GAARM 三阶段 + 实战】
│   ├── ai-baseline-app.md            # 应用阶段：容器逃逸/DoS (~278 行)
│   ├── ai-baseline-deploy-1.md       # 部署阶段：CI&CD/多租户/云平台/不安全配置/向量DB (~290 行)
│   ├── ai-baseline-deploy-2.md       # 部署阶段：容器集群/部署服务/镜像污染/环境隔离/供应链 (~267 行)
│   ├── ai-baseline-train.md          # 训练阶段：开发工具/环境隔离 (~202 行)
│   └── ai-baseline-escape.md         # 容器与沙箱逃逸实战方法论 (~159 行)
├── 【核心索引与方法论】
│   ├── gaarm-risk-matrix.md          # 173条AI风险索引表 (5域×3阶段, AISS 2026-06)
│   ├── claw-agent-threat-matrix.md   # 类Claw智能体威胁矩阵 (杀伤链6阶段×36威胁+39防御+ATLAS式编号)
│   └── testing-methodology.md        # 统一测试方法论 (589 行)
```

> **拆分原则**：
> - AI 类一次拆分按 GAARM 三阶段（应用/部署/训练）
> - AI 应用/模型 应用阶段二次拆分按风险大类（Prompt/MCP/Agent-CoT、越狱/幻觉/内容/版权/滥用/提取）
> - Web 注入/文件类按漏洞子类型（SQLi/XSS/RCE/XXE/Deser/Upload/Traversal/Leak/SSRF）
> - Payload 内联在对应主题文件，不独立成文
> - 全部 48 个 reference 文件 ≤ 1000 行（单次 Read 友好）

**总计**: 48 个 reference 文件 + 1 SKILL.md = 49 个文件 | 最大文件 589 行 | 100% 单次 Read 友好

## 安装

### Claude Code

将本仓库克隆到 Claude Code 的 skills 目录：

```bash
git clone https://github.com/Pa55w0rd/secknowledge-skill.git ~/.claude/skills/secknowledge
```

### Cursor

将本仓库克隆到 Cursor 的 skills 目录：

```bash
git clone https://github.com/Pa55w0rd/secknowledge-skill.git ~/.cursor/skills/secknowledge
```

克隆完成后，AI 会在你进行安全相关操作时自动加载此 Skill。

## 使用示例

### 场景1：Web渗透测试

```
用户: 对 target.com 进行SQL注入测试
AI: [自动加载 SKILL.md → web-sqli.md]
    → 列出高危注入点、数据库指纹识别、WAF绕过技巧、完整利用链
```

### 场景2：AI应用安全评估

```
用户: 测试这个chatbot的Prompt注入防护
AI: [自动加载 SKILL.md → ai-app-prompt-1.md/-2.md / ai-app-mcp.md（按风险类别）]
    → 系统化测试直接注入/间接注入/MCP投毒/Agent利用
```

### 场景3：混合应用攻击链

```
用户: 这个AI应用有文件上传和RAG功能，怎么测试？
AI: [加载跨层攻击链]
    → Web层(文件上传绕过) → AI层(RAG投毒/间接注入) → 组合利用
```

### 场景4：查询特定风险

```
用户: GAARM.0039 是什么风险？
AI: [查阅 gaarm-risk-matrix.md → ai-app-prompt-1.md（GAARM.0039 在应用阶段-Prompt 注入类，Part 1）]
    → 返回完整的攻击概述、案例、风险分析、缓解措施
```

## 触发关键词

以下关键词会自动触发 Skill 加载：

> 漏洞挖掘、渗透测试、安全审计、代码审计、安全评估、红队攻防、CTF、
> SQL注入、XSS、命令执行、文件上传、SSRF、越权、逻辑漏洞、
> Prompt注入、越狱、MCP安全、Agent安全、LLM安全、沙箱逃逸、
> 数据泄露、模型安全、RAG投毒、供应链安全

## 方法论框架

```
用户请求
│
├─ Web应用 ──→ SQL? → [web-sqli.md]   XSS? → [web-xss.md]   RCE? → [web-rce.md]
│              文件上传? → [web-upload.md]   遍历? → [web-traversal.md]
│              业务逻辑? → [web-logic-auth.md]   现代协议? → [web-modern-protocols.md]
│
├─ AI应用 ──→ Prompt 注入 → [ai-app-prompt-1/-2.md]   MCP → [ai-app-mcp.md]   Agent/CoT → [ai-app-agent-cot-1/-2.md]
│              越狱 → [ai-model-jailbreak.md]   幻觉 → [ai-model-hallucination.md]
│              Prompt 泄露/数据窃取 → [ai-data-app-1/-2.md]
│              角色逃逸/权限失控 → [ai-identity-app-1/-2.md]
│
├─ 部署环境 → 供应链/云/框架CVE [web-deployment-security.md]
│
└─ 容器沙箱 → 逃逸/持久化/横向移动 [ai-baseline-escape.md]
```

## 变更日志（Changelog）

### v2.2.0（2026-06-17）— AISS 上游同步 + 类Claw 威胁矩阵

- **GAARM 矩阵同步至 AISS 2026-06 快照**：150→**173 条**、确认 **5 安全域**（非 6；"AI合规治理"非 GAARM 域）；社区改用命名威胁矩阵、不再公开 `GAARM.XXXX` 数字编号（增量条目编号标 `—`，禁止编造）
- **23 条 2026 增量**：Agent 自治/失控（工具链误调用·循环执行失控·自动任务失控）、RAG 与记忆投毒（11 条）、多 Agent 协同、规划与推理链；其中 4 处抓取占位/typo 据上游校正（攻击案例→忠实性幻觉等）
- **新增 `claw-agent-threat-matrix.md`**：类Claw 智能体威胁矩阵（杀伤链 6 阶段 × 36 威胁 + 39 防御 + AISS-ATLAS 式编号），与 GAARM 分类法正交互补
- **选择性回填** 2 高价值簇到 `ai-app-agent-cot-2.md` / `ai-data-app-2.md`（引自公开语料，带 CVE/出处）
- reference 46→**48**；同步 wiki 快照页；抓取法（sitemap + `/api/v1/matrix`，站点为 React SPA）记入 `lessons.md` L-2

### v2.1.1（2026-05-29）— skill-craft 审计修复

- frontmatter 补 `metadata.version`（机读版本门禁，check-version PASS）
- 触发条件新增**现象信号路由表**（"agent 行为异常"/"RAG 返回可疑"/"输出疑似被注入" 等现象优先于关键词路由）
- 与同域 skill 对称 DO-NOT 路由：Mira PI 跑测→mira-pi-tester、自建 wiki→llm-wiki、文章录入→mira-pi-ingest
- 8 个 >500 行 reference 二次拆分到 ≤500（最大 906→589；场景导航索引 / GAARM 矩阵 / OWASP 映射原子同步，零断链）
- 新增 `references/lessons.md` 自我进化记录；本 README 计数同步（38→46，最大 906→589）

### v2.0（2026-05-18）— 结构性重构 + 拆分优化

**SKILL.md 入口升级**:
- 增加 ❗ 标记的 3 条行为准则（Payload 引用 / 假设 vs 已确认 / 授权边界）+ "每次输出前自检"机制
- 新增"依赖链约束"节：Step 2 输入 == Step 1 产出、Step 3 引用 ⊆ Step 2 加载列表、禁止重新搜索
- 流程步骤等式验收：`已引用 + UNABLE TO CITE == 总假设数`
- 每个 Step 补"失败→重试→降级→不允许跳过"三段式失败路径
- 触发条件细化：CTF 短代码片段 + 利用思路 → 本 Skill；完整项目目录 + 系统白盒 → code-audit-skill

**reference 拆分**（12 → 38 个文件）:
- 一次拆分（按 GAARM 三阶段）：5 个 AI 大文件 + 2 个 Web 大文件 → 26 个子文件
- 二次拆分（ai-model-app.md 2231 行）→ 6 个按风险大类（越狱/幻觉/内容/版权/滥用/提取）
- 三次拆分（ai-app-app.md 1318 行）→ 3 个按风险类别（Prompt 注入/MCP/Agent-CoT）
- 最大文件从 2651 → 906 行，**100% reference ≤ 1000 行**
- 删除冗余的 payloads.md，按场景内联到主 reference

**索引重构**:
- gaarm-risk-matrix.md 116 条风险按"GAARM 域 + 阶段 + 编号大类"精细映射到 38 个子文件
- testing-methodology.md OWASP 三框架（LLM01-10 / ASI01-10 / WSTG-*）映射全部对齐新结构
- SKILL.md 场景导航索引：AI 安全按"安全域 × 阶段 × 风险类别"三层导航

### v1.0（初始版本）— 12 个 reference 文件

WooYun 88,636 案例 + 先知 5,600+ 文档 + GAARM 150 风险 + OWASP 三框架 初始融合。

---

## 致谢与参考

本 Skill 的知识体系建立在以下优秀项目和社区之上：

| 项目 | 说明 |
|------|------|
| [WooYun Legacy](https://github.com/tanweai/wooyun-legacy) | 88,636 个真实漏洞案例的 Claude Code Skill，由探微杜渐安全研究团队整理。本项目的 Web 安全知识（注入、文件、逻辑漏洞等）从该漏洞库中提炼 |
| [先知安全研究方法论](https://github.com/tanweai/xianzhi-research) | 从先知社区 5,621 篇安全文档中提炼的 L1-L4 元思考方法论框架。本项目的四层思维模型和跨域攻击链思维源于此 |
| [AISS 绿盟大模型安全智链社区](https://aiss.nsfocus.com/) | 绿盟科技出品的 AI 安全知识库，提供了 GAARM 风险矩阵的 AI 安全风险条目（2026-06 快照 173 条），覆盖 5 大安全域 × 3 生命周期阶段 |
| [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/) | 2025 版 LLM 应用安全 Top 10 风险 |
| [OWASP Agentic AI Security Top 10](https://owasp.org/www-project-agentic-ai-security-initiative/) | 2026 版 AI Agent 安全 Top 10 风险 |
| [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) | v4.2 Web 安全测试指南，WSTG-* 分类标准 |

## 作者

[Pa55w0rd](https://github.com/Pa55w0rd)

## 免责声明

本 Skill 中的所有内容**仅供安全研究与防御参考**。请在获得合法授权后进行安全测试，遵守当地法律法规。知识来源均来自公开的安全社区和标准框架。

## 许可证

MIT License

---

*版本: v2.2.0 (2026-06-17) | 作者: Pa55w0rd | 知识融合: WooYun 88,636案例 × 先知 5,600+文档 × GAARM 173风险（5域） × OWASP LLM/ASI/WSTG × 常用 200+安全测试用例 | 文件结构: 48 个 reference，100% 单次 Read 友好*
