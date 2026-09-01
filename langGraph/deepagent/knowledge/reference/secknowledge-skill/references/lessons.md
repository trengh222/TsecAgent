# Lessons Learned: secknowledge-skill

> 由 skill-craft fix 模式自动维护。每条 lesson 来自一次真实修复，作为下次审计/修复的先验提示。

## L-1 (2026-05-29 由 fix 写入)

**触发场景**: skill-craft 系统审计 secknowledge-skill —— 这是一个 knowledge-base 型 skill（SKILL.md 是路由器，正文不含 payload，全部知识沉淀在 38+ 个 references/*.md），与同域的 code-audit-skill / llm-wiki / mira-pi-tester / mira-pi-ingest / agent-threat-modeling 共存且边界相邻。审计发现三类问题：(a) 触发条件只有"意图+关键词"，缺少现象信号路由；(b) 多个 reference 超 500 行（最大 906/903），SKILL.md 场景导航索引是唯一路由真值源，拆分必须原子同步索引 + gaarm-risk-matrix 逐 ID 映射 + testing-methodology OWASP 映射 + README×2；(c) ai-app-prompt 首节"案例一/案例二"无 payload/复现却列为"攻击案例"，易被误当可执行证据。

**规则**:
1. knowledge-base 型 skill 同样必须有 `metadata.version`，并与同域 skill（code-audit-skill / llm-wiki / mira-pi-tester / mira-pi-ingest）保持**对称的 DO-NOT 路由**——description 里要显式把"概念问答 / 纯白盒审计 / Mira handbook 跑测 / 构建用户 wiki / 录入 PI 文章"分别甩给正确的兄弟 skill，避免抢触发。
2. 单个 reference 控制在 ≤500 行；拆分只按已有 `### ` / `## ` 章节边界 VERBATIM 切，命名 `<orig>-1.md`/`-2.md`，并把 header（标题 + 来源 + 阶段行 + `## 阶段`/`---` 标记）原样复制进两半，标题追加 "(Part 1/2 …)" 子风险清单。
3. **拆分 = 原子操作**：SKILL.md 场景导航索引是路由真值源，拆一个文件必须同步更新 4 处消费方——SKILL 索引行（指向两半 + 子风险提示）、`gaarm-risk-matrix.md`（按"风险名称→所在小节"逐 ID 路由到 -1/-2）、`testing-methodology.md` 的 OWASP LLM/ASI 映射行（按场景路由）、`README.md`/`README_EN.md` 的目录树 + 流程图引用。漏一处即断链或误路由。
4. **现象信号优先于关键词**：用户常说"agent 行为异常 / RAG 返回可疑内容 / 输出疑似被注入 / WAF 误报 / 沙箱跑出来了"，这些是现象不是任务类型。触发条件里要把现象信号表放在 AND-组合关键词判断**之上**，命中即路由到对应 AI 安全测试路径（但不替代授权边界与"假设 vs 确认"分级）。
5. **退化证据要标注不要编造**：reference 里"攻击案例"若只有一句话描述、无 payload/无复现步骤，标注"⚠️ 概述级（无具体 Payload/复现，详见对应 reference 或待补）"，**绝不**为了凑证据而编造 payload/CVE。

**Why**:
- 来自本轮修复证据：ai-identity-app.md(906) / ai-data-app.md(903) 各含 16 个 `### ` 小节，gaarm-risk-matrix 里每个小节对应 1+ 个 GAARM ID 行（如 0040.001 XSS劫持 在 Part1、0029.001 虚假信息 在 Part2），若只改 SKILL 索引不改 matrix，Step 1→Step 3 流程会把 ID 路由到错误半边或断链。脚本化按"小节名→part"映射后，30+ 行 matrix + 19 行 OWASP 映射零 unrouted 全部命中。
- 现象信号路由对应 practical-best-practices §三（信号优先于关键词）与 anti-pattern #8；agent-threat-modeling 已用 phenomenon signals，本 skill 作为其相邻的"实战测试知识库"理应对称提供。
- 退化证据标注对应 Decision Gate（§六）：一句话描述只是 signal candidate，不能当 confirmed evidence。

**关联**:
- frontmatter `metadata.version`（2.0.0 → 2.1.0）+ description 的 DO-NOT 路由（对称 code-audit-skill / llm-wiki / mira-pi-tester / mira-pi-ingest）
- SKILL.md `## 触发条件`（新增"现象信号路由"表，置于 AND-组合之上）
- SKILL.md `## 场景导航索引`（路由真值源，拆分后指向 `*-1.md`/`*-2.md` + 子风险提示）
- `references/gaarm-risk-matrix.md`（逐 GAARM ID → 所在小节 part 的映射）
- `references/testing-methodology.md` §10.1/§10.2（OWASP LLM/ASI → part 路由）+ §6（绕过技巧，被现象信号"WAF 误报"引用）
- `README.md` / `README_EN.md`（目录树行数 + 流程图引用）
- `references/ai-app-prompt-1.md`（首节"案例一/案例二"退化证据标注）
- 仍 >500 待后续处理：`testing-methodology.md`(589，含 §X 锚点引用，拆分会破坏锚点语义)、`web-logic-auth.md`(582，WSTG 类别跨多个 `## ` 节，拆分需逐 WSTG 行重路由) —— 本轮保守留存并报告。

## L-2 (2026-06-17 由 wiki 交叉核对 + AISS 上游同步写入)

**触发场景**: 结合 Obsidian wiki 检查本 skill，发现 GAARM 计数自相矛盾（SKILL/methodology 宣称"6 安全域 / 150"，但 `gaarm-risk-matrix.md` 实测仅 137 唯一编码 / 148 行 / 5 域，且"AI合规治理"第 6 域零条目）。回到上游真值源 AISS 社区（https://aiss.nsfocus.com/）核对：社区已更新至 **173 风险 / 5 域**，改用"命名威胁矩阵"组织、不再公开 `GAARM.XXXX` 数字编号；本地另有 2 条抓取占位（"攻击案例/攻击概述"）实为 0028.002 忠实性幻觉 / 0029.006 敏感数据泄露 的错名，1 条 SSRF 改名、1 处 typo。

**规则**:
1. **计数类声明必须可被 reference 实体证实**：SKILL.md/方法论里的"GAARM N 风险""M 安全域"等数字，必须等于 `gaarm-risk-matrix.md` 实际可数行/域；改任一处需原子同步 SKILL.md(描述+知识源+导航+页脚) + testing-methodology.md(§1.3+页脚) + README×2。一处对不上即属幻觉风险（违背行为准则 §1）。
2. **上游是动态站点时抓取层要选对**：AISS 是 MkDocs 外壳 + React SPA（`/build/static/js/main.*.js`），正文 JS 渲染，curl/WebFetch 只拿到空壳。正确路径：`sitemap.xml`（拿全量页面=风险名/域/阶段）+ 逆向 bundle 找同源 API（`/api/v1/matrix` 返回命名矩阵 parent/sub）。CDP 仅在需登录态/纯前端渲染且无 API 时才用。
3. **上游"无编号"就不要编号**：社区现版不公开数字编号，2026 增量条目编号一律标 `—` + 注明"社区未公开"，禁止为对齐旧格式编造 GAARM.XXXX（行为准则 §1）。
4. **抓取占位名回上游校正而非删除**：表里混入"攻击案例""攻击概述"这类小节标题，先对照上游命名矩阵 parent/sub 层级还原真名（忠实性幻觉/敏感数据泄露），多半编号是对的、只是名错。

**Why**:
- 本轮证据：sitemap 173 页 vs 本地 137 编码，diff 出 23 条真增量，集中在 Agent 自治/失控、RAG&记忆投毒、多Agent协同、规划推理链 —— 正是 2026 agentic 前沿；wiki AI 安全攻防语料（Lethal Trifecta / Tool-Chain ACL / LoopTrap 等）与之印证。
- `/api/v1/matrix` 的 parent/sub 层级让"攻击案例→忠实性幻觉"的还原有据可依，否则只能盲删丢信息。

**关联**:
- `references/gaarm-risk-matrix.md`（头部快照说明 + 4 处行内修正 + "## 2026 增量"23 行 + 计数脚注）
- `references/testing-methodology.md` §1.3（5 域表 + 2026 增量标注）+ 页脚 v1.1
- `SKILL.md` 描述/知识源/导航/页脚（GAARM 173, 5 域）+ `metadata.version` 2.1.1→2.2.0
- `README.md` / `README_EN.md`（9 处计数/域同步）
- 上游真值源 https://aiss.nsfocus.com/ （sitemap.xml + /api/v1/matrix）；wiki 快照 `concepts/AI 安全攻防/AISS GAARM 风险矩阵快照 2026-06.md`
- 待补 backlog：23 条增量 Reference 多标"（待补）"，需后续在对应 ai-*.md 补详细 Payload/复现（参 wiki 前沿页）

**同会话续作（2026-06-17，同属 v2.2.0）**:
- **新增正交矩阵**：AISS 同站公开（前端 bundle `main.*.js` 内嵌 JSON，`/claw-matrix` 路由，无需登录）一套"类Claw 智能体威胁矩阵"=杀伤链 6 阶段×36 威胁 + 39 防御 + AISS-ATLAS 式编号。已落 `references/claw-agent-threat-matrix.md`（reference 数 47→48）+ SKILL 核心方法论导航行 + wiki 快照页 §五。**注**：`AML.xxx` 是 AISS 自有 ATLAS 式编号≠官方 MITRE ATLAS（官方 `AML.T00xx`），如实标注。GAARM(分类法) 与 类Claw(杀伤链) 正交互补。
- **选择性回填 2 高价值簇**（取自 wiki 带 CVE/出处，非 AISS 登录库——`/api/v1/cases` 401 且属绿盟自有内容，不抄录）：`ai-app-agent-cot-2.md` §2026增量（工具链误调用/循环执行失控/Agent自治，引 Tool-Chain-ACL-Bypass / LoopTrap arXiv:2605.05846 / EchoLeak CVE-2025-32711）+ `ai-data-app-2.md` §2026增量（RAG投毒/记忆投毒，引 Agentic-PI-注入面分类法 Class B/C / invariantlabs GitHub MCP / MemMorph）。matrix 对应 16 行 (待补)→§2026增量；剩 7 行(3 身份+4 模型推理链)仍待补。
- **判断**：OWASP(LLM2025/Agentic2026/WSTG4.2)等框架引用均当前版，无版本性陈旧——本轮唯一陈旧源是 GAARM(已修)。"案例"应取 wiki 公开语料而非 AISS 登录库（IP+抓取双约束）。
