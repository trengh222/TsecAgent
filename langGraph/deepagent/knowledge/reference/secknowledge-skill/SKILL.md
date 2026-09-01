---
name: secknowledge-skill
description: |
  Web+AI 安全测试知识库。融合 WooYun 88,636 案例 + 先知 L1-L4 方法论 + GAARM 173 风险
  + OWASP Top 10 (LLM/ASI/WSTG)。
  TRIGGER when 任务是实战安全测试：渗透测试、漏洞挖掘/利用、红队攻防、安全审计 (SAST/DAST)、
  CTF、AI/LLM 安全测试 (Prompt 注入/越狱/MCP/Agent/沙箱逃逸)。用户明确给出测试目标
  (URL/代码/模型/Agent 架构) 且意图是"测试/审计/挖漏洞/利用"。
  DO NOT trigger:
  - 安全概念讨论（"什么是 XSS"、"SQL 注入原理是什么"）→ 普通问答
  - 非安全性质的 code review / debug / 性能优化 → code-audit-skill 或其他
  - 修复语法错误 / 业务逻辑 bug → 普通编程协助
  - 纯 Web 白盒代码审计（完整项目目录 / Source-Sink 污点分析）→ code-audit-skill
  - 仅引用 CVE 编号查文档 → WebSearch
  - Mira 内置 handbook / preview.mira.day 的 PI 红队跑测（tier/TC-ID/resume）→ mira-pi-tester
  - 用户要构建/维护自己的 markdown 知识库/wiki（本 skill 的"知识库"指内置只读安全语料，非用户可编辑 wiki）→ llm-wiki
  - 把外部 PI/越狱文章录入 Mira 红队体系（产出 handbook TC 卡）→ mira-pi-ingest
  边界细则: CTF 短代码片段 + 利用思路 → 本 Skill；完整项目目录 + 系统白盒审计 → code-audit-skill
metadata:
  version: 2.2.0
---

# Web 和 AI 安全测试知识库

> 知识源: WooYun 88,636 漏洞 × 先知 5,600+ 文档 × GAARM 173 AI 风险（5 域，AISS 2026-06 快照）× OWASP
> 架构: SKILL.md（路由）→ references/（按场景加载）

## 触发条件

**路由优先级：现象信号 > 意图+关键词 > 歧义澄清**。用户常描述的是**问题现象**（"agent 又乱调工具了"），而非任务类型（"做个渗透测试"）。先匹配现象信号，命中则进入对应安全测试路径；未命中再走下方意图+关键词的 AND 组合判断。

**现象信号路由（优先于关键词，命中即进入 AI 安全测试路径）**：

| 现象信号（用户原话风格） | 推断风险 → 路由 reference |
|------------------------|--------------------------|
| "agent 行为异常 / off-policy / 乱调工具 / 工具调用死循环" | Agent 利用/越权 → `ai-app-agent-cot-*.md` + `ai-identity-app-*.md`；若是多 Agent / MCP 系统 → 见 agent-threat-modeling |
| "RAG 返回可疑内容 / 检索结果被污染 / 知识库被投毒" | 间接 Prompt 注入/RAG 投毒 → `ai-app-prompt-*.md`（间接注入小节）+ `ai-data-app-*.md` |
| "输出疑似被注入 / 模型不听系统提示 / 越权回答 / 泄露 system prompt" | 直接/间接 Prompt 注入、角色逃逸、Prompt 泄露 → `ai-app-prompt-*.md` + `ai-identity-app-*.md` + `ai-data-app-*.md` |
| "WAF 误报 / 被过滤 / payload 被拦 / 绕不过内容审核" | WAF/内容过滤/GuardRails 绕过 → `testing-methodology.md §6`（绕过技巧）+ 对应漏洞类型 reference |
| "沙箱里跑出来了 / 容器逃逸 / 隔离失效" | 沙箱/容器逃逸 → `ai-baseline-escape.md` + `ai-baseline-deploy-*.md` |

> 现象信号只把任务**路由**到 AI 安全测试路径，不替代行为准则 §2 的"假设 vs 确认"分级与 §3 的授权边界。仍须按"使用流程"三步走 + 引用 reference。

**触发条件（AND 组合）**：
1. 用户意图是**执行**安全测试（渗透/挖洞/利用/审计） — 非讨论/学习
2. 提供了**具体目标**：URL、接口、代码片段、模型/Agent 架构、MCP 配置 — 非抽象问题
3. 任务**涉及以下领域之一**：
   - Web: SQL 注入/XSS/命令执行/越权/文件上传/SSRF/反序列化/XXE/GraphQL/HTTP 走私
   - AI: Prompt 注入/越狱/MCP 投毒/Agent 滥用/RAG 投毒/沙箱逃逸/模型窃取
   - 绕过: WAF/内容过滤/Guard Rails 绕过

**不触发**（任一命中即路由到他处）：
- 概念讲解："什么是…"、"…原理"、"…怎么防御" → 普通问答
- 非安全代码审查："review 代码质量"、"优化性能" → 普通 code review
- 业务 bug：语法错误、空指针、业务逻辑错误（非安全逻辑）→ 普通 debug
- **深度白盒代码审计**（Source-Sink 污点传播、AST 分析）→ code-audit-skill
- 查 CVE 文档、工具文档 → WebSearch/Context7
- **Mira handbook / preview.mira.day 的 PI 红队跑测**（tier/TC-ID/resume）→ mira-pi-tester
- 用户要**构建/维护自己的 markdown 知识库/wiki**（本 skill 的"知识库"=内置只读安全语料）→ llm-wiki
- 把**外部 PI/越狱文章录入 Mira 红队体系**（产出 handbook TC 卡）→ mira-pi-ingest

**歧义处理**：目标和意图不明时，先问："目标是什么？你希望做渗透测试 / 代码审计 / 还是了解概念？"

## 行为准则（整个会话有效，不因对话长度放松）

1. ❗ **所有 Payload/CVE 编号/风险编号必须引用 reference 文件的具体章节** — 每次输出前自检。未在 reference 中的一律标注 "UNABLE TO CITE"，禁止编造。
2. ❗ **区分"漏洞假设"与"漏洞确认"** — 基于方法论推断的潜在风险 → 标注 `假设（需验证）`；有明确证据的 → 标注 `已确认（证据: …）`。禁止混淆。
3. ❗ **授权边界** — 任何利用步骤输出前必须确认是 CTF/授权渗透/本人环境。无授权上下文只输出分析，不输出可直接武器化的完整 Payload。

## 幻觉防护与来源引用

| 内容类型 | 正确输出 | 禁止输出 |
|---------|---------|---------|
| CVE 编号 | 引用具体 reference 文件和章节，或标 "UNABLE TO CITE — 建议 WebSearch 核实" | 编造 CVE-YYYY-NNNN |
| Payload | 从 `references/web-*.md` 或 `references/ai-*.md` 内 payload 章节引用 | 凭印象写 payload |
| GAARM 风险编号 | 引用 `references/gaarm-risk-matrix.md` | 自造编号 |
| OWASP 条目 | LLM01-10 / ASI01-10 / WSTG-* 引用 `testing-methodology.md §10.x` | 改写编号含义 |
| 工具/命令 | 仅使用在 reference 中出现过的，或明确标注 "通用命令（未在 reference 中核对）" | 伪造工具参数 |
| 无检索结果 | "UNABLE TO ASSESS：reference 未覆盖此场景，建议 WebSearch" | 凭经验推测作为结论 |

**标注分级**：
- `[引用]` — 来自 reference 具体章节（需带 file:section）
- `⚠️ 通用知识` — 未在本 Skill reference 中核对，仅作提示
- `💡 建议` — 方法论推理，非事实声明

## 输出约束

禁止输出：
- 开场白："让我来分析…" / "首先我们需要…" / "根据你的需求…"
- 工具调用描述："我将使用 Read 工具读取 XX"
- 已知信息复述（用户刚说的 URL、目标类型）
- 无来源引用的 Payload 或 CVE 编号
- 未经授权场景下的完整武器化链

输出限制：
- 单次回复 ≤ 3 个层次的建议（避免信息膨胀）
- Payload 示例 ≤ 5 条/漏洞类型（完整列表引用 reference）
- 使用表格/速查格式，禁止长段落叙述

## 工具优先级（本 Skill 自用）

| 操作 | 首选 | 降级条件 | 降级工具 |
|------|------|---------|---------|
| 读 reference | Read | Read 失败 | Bash cat |
| 搜索关键词/CVE | Grep (reference 内) | 连续 2 次未命中 | WebSearch |
| 代码审计目标 | 委派 code-audit-skill | — | — |

单次超时 ≠ 不可用，必须重试 1 次后才能降级。

## 使用流程

**依赖链约束（贯穿三步，强制）**:
- Step 2 输入 == Step 1 的"已定位 reference 列表"，不得新加文件
- Step 3 引用集合 ⊆ Step 2 的"已加载列表"，禁止在 Step 3 重新搜索 reference
- Step 3 Checkpoint 中的引用计数必须能在 Step 2 Checkpoint 中找到对应来源

**Step 1: 目标分类 + reference 定位**
- 判断：Web / AI / Web+AI 混合 / 容器沙箱
- 定位：按"场景导航索引"找到对应 reference 文件，记为列表 `L1`

失败降级:
- 目标信息不足无法分类 → 触发歧义澄清问题，不猜测；不允许默认归类为 "Web+AI 混合"
- 场景导航索引未覆盖该场景 → 标注 "UNABLE TO CITE: 场景 {X} 不在索引内"，列表 `L1` 为空，进入 Step 3 时只能输出方法论级建议

✅ Checkpoint: `Step 1 完成: 目标类型={X}, |L1| == 场景导航索引匹配数 = {N}`

**Step 2: 按需加载 Step 1 定位的 reference（懒加载）**
- 输入: Step 1 产出的列表 `L1`；记本步加载集合为 `L2`，必须满足 `L2 ⊆ L1`
- 每次加载 1 个文件，单次 ≤ 1000 tokens；体量较大的 reference（如 `testing-methodology.md` ~589 行、`web-logic-auth.md` ~582 行）必须用 Read offset/limit 或 Grep 定位后再读。已拆分的双文件（`*-1.md` / `*-2.md`）按场景导航索引的 Part 1/Part 2 子风险归属只加载需要的一半
- 禁止在本步加载未在 `L1` 中的文件

失败降级:
- Read 失败 → 重试 1 次 → 仍失败用 Bash cat → 都失败 → 标注 "UNABLE TO ASSESS: 文件不可读"，从 `L2` 移除该项，不允许跳过到 Step 3
- Grep 无命中 → 标注 "UNABLE TO CITE: {关键词} 未在 {文件} 中检出"
- reference 文件不存在 → 标注断链 + 列入待补 reference 清单，不编造内容

✅ Checkpoint: `Step 2 完成: |L2| == |L1| - 不可读文件数 = {M}, 合计 {X} tokens`

**Step 3: 按方法论输出测试思路（L1→L4）**
- 输入: Step 2 产出的加载集合 `L2`；本步所有引用必须 ⊆ `L2`
- L1 攻击面识别 → L2 假设构建 → L3 深度利用 → L4 防御反推
- 每条结论必须引用 `L2` 中某文件的具体 section/行号；无依据 → 标注 "UNABLE TO CITE" 并停止该假设线
- 禁止重新搜索：本步发现需要新 reference → 回到 Step 1 重新定位，而不是直接 Read/Grep

✅ Checkpoint: `Step 3 完成: 输出 N 条假设, 其中 已引用 M 条 + UNABLE TO CITE K 条 == N (等式验收)`

**全流程交叉验证**:
- [ ] Step 3 引用的所有文件 ∈ Step 2 的 `L2`（grep 验证）
- [ ] 已引用条数 + UNABLE TO CITE 条数 == 总假设条数

## 场景导航索引

> 每行指向对应 reference。详细 Payload/案例/方法论全部在 reference 中，本 SKILL.md 不再展开。

### 核心方法论

| 场景 | reference |
|------|----------|
| L1-L4 思维金字塔 + WooYun 漏洞公式 + GAARM 映射 | `references/testing-methodology.md` |
| OWASP Top 10 映射（LLM/ASI/WSTG）| `testing-methodology.md §10.1-10.3` |
| GAARM 173 条风险编号（5 域 × 3 阶段，含 2026 增量）| `references/gaarm-risk-matrix.md` |
| 类Claw 智能体威胁矩阵（杀伤链 6 阶段 × 36 威胁 + 39 防御，攻防对照 + ATLAS 式编号）| `references/claw-agent-threat-matrix.md` |

### Web 安全（按漏洞类型）

| 场景 | reference |
|------|----------|
| SQL 注入（含 SQLMap 速查）| `references/web-sqli.md` |
| XSS 跨站脚本 | `references/web-xss.md` |
| 命令执行（RCE）| `references/web-rce.md` |
| XXE（XML 外部实体）| `references/web-xxe.md` |
| 反序列化漏洞 | `references/web-deser.md` |
| 文件上传（含 Webshell 免杀）| `references/web-upload.md` |
| 文件遍历 / 文件包含 | `references/web-traversal.md` |
| 信息泄露（.git / 备份 / 错误信息）| `references/web-leak.md` |
| SSRF / 服务器配置错误 / CMS+URL 附录 | `references/web-ssrf-misc.md` |
| 越权 / 支付 / 密码重置 / 会话 / API 鉴权 | `references/web-logic-auth.md` |
| CORS / GraphQL / HTTP 走私 / WebSocket / OAuth | `references/web-modern-protocols.md` |
| 供应链 / 云配置 / 容器 / CI/CD / 框架 CVE | `references/web-deployment-security.md` |

### AI/LLM 安全（按 GAARM 阶段）

| 安全域 | 应用阶段 | 部署阶段 | 训练阶段 |
|--------|---------|---------|---------|
| **AI 应用**（应用阶段按风险大类细分↓）| 见下方细分表 | `ai-app-deploy.md` | `ai-app-train.md` |
| **AI 模型**（应用阶段按风险大类细分↓）| 见下方细分表 | `ai-model-deploy.md` | `ai-model-train.md` |
| **AI 数据**（Prompt 泄露/窃取/推断）| `ai-data-app-1.md`（API/隐私/企业/假定场景/假定角色/元Prompt/关键字/外部数据源泄露）<br>`ai-data-app-2.md`（成员推断/数据操纵/模型反演/推理API窃取/级联幻觉/触发异常/训练推导/隐私窃取）| `ai-data-deploy.md` | `ai-data-train-1.md`（外部数据源/隐私/企业/内部/对话语料投毒）<br>`ai-data-train-2.md`（匿名化/机密/投毒/泄露/篡改/预训练偏见）|
| **AI 身份**（角色逃逸/Agent 伪造）| `ai-identity-app-1.md`（Action权限/MCP越权/Prompt劫持/假定场景逃逸/假定角色逃逸/云凭证/外部数据源欺骗/多Agent伪造）<br>`ai-identity-app-2.md`（会话劫持/未授权访问/权限管控/模拟对话/角色逃逸/账户劫持/越权访问/遗忘法逃逸）| `ai-identity-deploy.md` | `ai-identity-train.md` |
| **AI 基座**（容器/沙箱/供应链）| `ai-baseline-app.md` | `ai-baseline-deploy-1.md`（CI&CD/多租户/云平台/不安全配置/向量DB）<br>`ai-baseline-deploy-2.md`（容器集群/部署服务/镜像污染/环境隔离/供应链）| `ai-baseline-train.md` |

**AI 应用 - 应用阶段按风险大类**:

| 风险类别 | GAARM 编号 | reference |
|---------|----------|----------|
| Prompt 注入与变种（直接/间接/XSS/Memory/蠕虫/混淆/编码/反向诱导/多模态）| GAARM.0039, 0040.x, 0043.x, 0044, 0045, 0061 | `ai-app-prompt-1.md`（Prompt注入/XSS劫持/间接注入/Memory/蠕虫）<br>`ai-app-prompt-2.md`（反向诱导/多模态/对抗编码/关键字混淆/同义词替换）|
| MCP 协议攻击（地毯式骗局/工具投毒/指令覆盖/隐藏指令）| GAARM.0046.x | `ai-app-mcp.md` |
| Agent 与 CoT 攻击（Agent 利用/SSRF/RCE/CoT/查询注入/环境注入）| GAARM.0041.x, 0042.x, 0047, 0056.001, 0060 | `ai-app-agent-cot-1.md`（CoT注入/SSRF探测/代码执行注入）<br>`ai-app-agent-cot-2.md`（Agent利用/思维链干扰&操纵/查询注入/环境注入/预期外代码执行）|

**AI 模型 - 应用阶段按风险大类**:

| 风险类别 | GAARM 编号 | reference |
|---------|----------|----------|
| 越狱（DAN/Many-shot/对抗后缀/概念激活）| GAARM.0027.x | `ai-model-jailbreak.md` |
| 幻觉（事实/跨模态）| GAARM.0028.x, 0064 | `ai-model-hallucination.md` |
| 非合规内容（偏见/暴力/政治/虚假/诱导）| GAARM.0029.x | `ai-model-content-1.md`（偏见仇恨/恐怖暴力/政治军事敏感）<br>`ai-model-content-2.md`（虚假信息/诱导不当言论/非合规输出）|
| 版权与商业违法 | GAARM.0030.x | `ai-model-copyright.md` |
| 功能滥用与信息伪造（图/音/视频/钓鱼）| GAARM.0031.x, 0033, 0062, 0063 | `ai-model-misuse-1.md`（图片伪造/多模态合规/恶意代码/意图破坏/数据漂移）<br>`ai-model-misuse-2.md`（功能滥用/视频伪造/钓鱼邮件/音频伪造）|
| 对抗样本与模型提取 | GAARM.0032.x | `ai-model-extraction.md` |

**专项 reference**:
- AI Agent / MCP / Skills 2025-2026 前沿风险 → `references/ai-app-frontier.md`
- 容器与沙箱逃逸实战方法论 → `references/ai-baseline-escape.md`

### Payload 速查（按场景在主 reference 中查找）

| 场景 | reference |
|------|----------|
| SQL 注入 Payload | `references/web-sqli.md` |
| XSS Payload | `references/web-xss.md` |
| RCE / 命令执行 Payload | `references/web-rce.md` |
| 反序列化 / XXE Payload | `references/web-deser.md` / `references/web-xxe.md` |
| 文件上传绕过 / 路径遍历 Payload | `references/web-upload.md` / `references/web-traversal.md` |
| SSRF Payload | `references/web-ssrf-misc.md` |
| Web 现代协议 Payload（GraphQL/HTTP 走私/WebSocket）| `references/web-modern-protocols.md` |
| Prompt 注入 Payload | `references/ai-app-prompt-1.md` / `references/ai-app-prompt-2.md` |
| MCP 投毒 Payload | `references/ai-app-mcp.md` |
| Agent / CoT 注入 Payload | `references/ai-app-agent-cot-1.md` / `references/ai-app-agent-cot-2.md` |
| 越狱 / 对抗后缀 Payload | `references/ai-model-jailbreak.md` |
| 容器逃逸 / 持久化 / 横向移动 | `references/ai-baseline-escape.md` |

## 零结果处理

| 情况 | 正确动作 |
|------|---------|
| Grep 未命中 reference | "UNABLE TO CITE: 该场景 {X} 未在 reference 中覆盖。建议 WebSearch 或补充 reference" |
| 用户给的 URL 无响应 | "UNABLE TO ASSESS: 目标不可达" — 不基于 URL 结构猜测漏洞 |
| 需要执行但无授权上下文 | "仅输出分析，不输出武器化链。如为授权测试，请明确授权范围" |
| reference 与用户场景部分匹配 | 引用已匹配部分 + 明确标注未覆盖部分为 "UNABLE TO CITE" |

## 与其他 Skill 的路由

| 用户诉求 | 正确路由 |
|---------|---------|
| 渗透测试 / 红队 / CTF / 挖洞 | **本 Skill** |
| Java/JS 深度白盒代码审计（Source-Sink）| code-audit-skill |
| Mirawork 平台专项测试 | mirawork-security-tester |
| WooYun 历史漏洞分析方法论 | wooyun-legacy |
| 先知社区研究方法论 | xianzhi-research |

---

*v2.2.0 | 知识源: WooYun 88,636 × 先知 5,600+ × GAARM 173（5 域, AISS 2026-06 快照）× OWASP LLM/ASI/WSTG*
