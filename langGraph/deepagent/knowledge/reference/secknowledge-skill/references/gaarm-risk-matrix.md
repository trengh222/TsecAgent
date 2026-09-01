# GAARM 风险索引矩阵

> 来源: AISS绿盟大模型安全智链社区（https://aiss.nsfocus.com/）
> 快照: 2026-06-17 同步（社区 sitemap 173 个风险页 + /api/v1/matrix 命名矩阵）
> 结构: **5 安全域**（AI应用/AI模型/AI数据/AI身份/AI基座）× 3 阶段（训练/部署/应用）。
> ⚠️ 社区当前版本以"命名威胁矩阵"组织风险，已不再对外公开 `GAARM.XXXX` 数字编号；2026 增量条目编号标 `—`（未公开，禁止编造）。
> ⚠️ "AI合规治理"非 GAARM 安全域（属合规视角）；如需合规对标见 testing-methodology.md。

| 风险编号 | 安全域 | 阶段 | 风险名称 | Reference文件 |
|----------|--------|------|----------|---------------|
| GAARM.0042 | AI应用安全 | 应用阶段 | CoT注入攻击 | ai-app-agent-cot-1.md |
| GAARM.0046.001 | AI应用安全 | 应用阶段 | MCP地毯式骗局 | ai-app-mcp.md |
| GAARM.0046 | AI应用安全 | 应用阶段 | MCP工具投毒攻击 | ai-app-mcp.md |
| GAARM.0046.002 | AI应用安全 | 应用阶段 | MCP指令覆盖攻击 | ai-app-mcp.md |
| GAARM.0046.003 | AI应用安全 | 应用阶段 | MCP隐藏指令攻击 | ai-app-mcp.md |
| GAARM.0039 | AI应用安全 | 应用阶段 | Prompt注入 | ai-app-prompt-1.md |
| GAARM.0041.001 | AI应用安全 | 应用阶段 | SSRF模型环境探测 | ai-app-agent-cot-1.md |
| GAARM.0040.001 | AI应用安全 | 应用阶段 | XSS会话内容劫持 | ai-app-prompt-1.md |
| GAARM.0041.002 | AI应用安全 | 应用阶段 | 代码执行注入 | ai-app-agent-cot-1.md |
| GAARM.0043 | AI应用安全 | 应用阶段 | 关键字混淆 | ai-app-prompt-2.md |
| GAARM.0045 | AI应用安全 | 应用阶段 | 反向诱导&抑制攻击 | ai-app-prompt-2.md |
| GAARM.0043.001 | AI应用安全 | 应用阶段 | 同义词替换攻击 | ai-app-prompt-2.md |
| GAARM.0061 | AI应用安全 | 应用阶段 | 多模态协同注入攻击 | ai-app-prompt-2.md |
| GAARM.0044 | AI应用安全 | 应用阶段 | 对抗编码攻击 | ai-app-prompt-2.md |
| GAARM.0040.003 | AI应用安全 | 应用阶段 | 应用对话Memory攻击 | ai-app-prompt-1.md |
| GAARM.0041 | AI应用安全 | 应用阶段 | 应用智能体Agent利用 | ai-app-agent-cot-2.md |
| GAARM.0042.001 | AI应用安全 | 应用阶段 | 思维链干扰注入 | ai-app-agent-cot-2.md |
| GAARM.0042.002 | AI应用安全 | 应用阶段 | 思维链操纵注入 | ai-app-agent-cot-2.md |
| GAARM.0056.001 | AI应用安全 | 应用阶段 | 查询注入攻击 | ai-app-agent-cot-2.md |
| GAARM.0047 | AI应用安全 | 应用阶段 | 环境注入攻击 | ai-app-agent-cot-2.md |
| GAARM.0040.002 | AI应用安全 | 应用阶段 | 环路Agent蠕虫 | ai-app-prompt-1.md |
| GAARM.0040 | AI应用安全 | 应用阶段 | 间接Prompt注入 | ai-app-prompt-1.md |
| GAARM.0060 | AI应用安全 | 应用阶段 | 预期外代码执行 | ai-app-agent-cot-2.md |
| GAARM.0049 | AI应用安全 | 部署阶段 | LLMs应用API管理不当 | ai-app-deploy.md |
| GAARM.0038 | AI应用安全 | 部署阶段 | LLMs应用源代码投毒 | ai-app-deploy.md |
| GAARM.0037 | AI应用安全 | 部署阶段 | LLMs应用源代码窃取 | ai-app-deploy.md |
| GAARM.0035.003 | AI应用安全 | 训练阶段 | LLMs应用不安全输出处理 | ai-app-train.md |
| GAARM.0035.002 | AI应用安全 | 训练阶段 | LLMs应用传统漏洞风险 | ai-app-train.md |
| GAARM.0035.001 | AI应用安全 | 训练阶段 | LLMs插件：不安全输入处理 | ai-app-train.md |
| GAARM.0036 | AI应用安全 | 训练阶段 | LLMs插件：业务过度代理 | ai-app-train.md |
| GAARM.0034.002 | AI应用安全 | 训练阶段 | RAG开发框架漏洞 | ai-app-train.md |
| GAARM.0035 | AI应用安全 | 训练阶段 | 不安全的代码实践 | ai-app-train.md |
| GAARM.0034.001 | AI应用安全 | 训练阶段 | 数据处理组件漏洞 | ai-app-train.md |
| GAARM.0034 | AI应用安全 | 训练阶段 | 第三方组件漏洞 | ai-app-train.md |
| GAARM.0027.001 | AI模型安全 | 应用阶段 | DAN(Do Anything Now) | ai-model-jailbreak.md |
| GAARM.0027.002 | AI模型安全 | 应用阶段 | Many-shot越狱 | ai-model-jailbreak.md |
| GAARM.0028.001 | AI模型安全 | 应用阶段 | 事实性幻觉 | ai-model-hallucination.md |
| GAARM.0032.003 | AI模型安全 | 应用阶段 | 代理预训练模型创建 | ai-model-extraction.md |
| GAARM.0027.003 | AI模型安全 | 应用阶段 | 假定场景越狱 | ai-model-jailbreak.md |
| GAARM.0027.004 | AI模型安全 | 应用阶段 | 假定角色越狱 | ai-model-jailbreak.md |
| GAARM.0030 | AI模型安全 | 应用阶段 | 商业违法输出 | ai-model-copyright.md |
| GAARM.0031.003 | AI模型安全 | 应用阶段 | 图片信息伪造 | ai-model-misuse-1.md |
| GAARM.0062 | AI模型安全 | 应用阶段 | 多模态内容合规安全风险 | ai-model-misuse-1.md |
| GAARM.0027.005 | AI模型安全 | 应用阶段 | 对抗性后缀攻击 | ai-model-jailbreak.md |
| GAARM.0032.004 | AI模型安全 | 应用阶段 | 对抗样本攻击 | ai-model-extraction.md |
| GAARM.0029.003 | AI模型安全 | 应用阶段 | 带有偏见、仇恨、歧视或侮辱问题 | ai-model-content-1.md |
| GAARM.0028.002 | AI模型安全 | 应用阶段 | 忠实性幻觉 | ai-model-hallucination.md |
| GAARM.0029.004 | AI模型安全 | 应用阶段 | 恐怖主义&&带有暴力倾向 | ai-model-content-1.md |
| GAARM.0031.001 | AI模型安全 | 应用阶段 | 恶意代码生成 | ai-model-misuse-1.md |
| GAARM.0063 | AI模型安全 | 应用阶段 | 意图破坏&目标操纵 | ai-model-misuse-1.md |
| GAARM.0029.005 | AI模型安全 | 应用阶段 | 政治&&军事敏感问题 | ai-model-content-1.md |
| GAARM.0029.006 | AI模型安全 | 应用阶段 | 敏感数据泄露 | ai-model-content-2.md |
| GAARM.0033 | AI模型安全 | 应用阶段 | 数据漂移 | ai-model-misuse-1.md |
| GAARM.0027.006 | AI模型安全 | 应用阶段 | 概念激活攻击 | ai-model-jailbreak.md |
| GAARM.0031 | AI模型安全 | 应用阶段 | 模型功能滥用 | ai-model-misuse-2.md |
| GAARM.0028 | AI模型安全 | 应用阶段 | 模型幻觉风险 | ai-model-hallucination.md |
| - | AI模型安全 | 应用阶段 | 模型提取与盗窃 | ai-model-extraction.md |
| GAARM.0027 | AI模型安全 | 应用阶段 | 模型越狱攻击 | ai-model-jailbreak.md |
| GAARM.0030.001 | AI模型安全 | 应用阶段 | 知识产权版权侵犯 | ai-model-copyright.md |
| GAARM.0029.001 | AI模型安全 | 应用阶段 | 虚假信息生成 | ai-model-content-2.md |
| GAARM.0031.005 | AI模型安全 | 应用阶段 | 视频信息伪造 | ai-model-misuse-2.md |
| GAARM.0029.002 | AI模型安全 | 应用阶段 | 诱导&&不当言论 | ai-model-content-2.md |
| GAARM.0064 | AI模型安全 | 应用阶段 | 跨模态幻觉 | ai-model-hallucination.md |
| GAARM.0031.002 | AI模型安全 | 应用阶段 | 钓鱼邮件生成 | ai-model-misuse-2.md |
| GAARM.0029 | AI模型安全 | 应用阶段 | 非合规内容输出 | ai-model-content-2.md |
| GAARM.0031.004 | AI模型安全 | 应用阶段 | 音频信息伪造 | ai-model-misuse-2.md |
| GAARM.0032 | AI模型安全 | 应用阶段 | 预训练模型信息窃取与攻击 | ai-model-extraction.md |
| GAARM.0032.001 | AI模型安全 | 应用阶段 | 预训练模型家族探测 | ai-model-extraction.md |
| GAARM.0032.002 | AI模型安全 | 应用阶段 | 预训练模型本体探测 | ai-model-extraction.md |
| GAARM.0026 | AI模型安全 | 部署阶段 | 模型参数篡改 | ai-model-deploy.md |
| GAARM.0025 | AI模型安全 | 部署阶段 | 模型文件窃取 | ai-model-deploy.md |
| GAARM.0023 | AI模型安全 | 训练阶段 | 模型后门 | ai-model-train.md |
| GAARM.0033 | AI模型安全 | 训练阶段 | 模型安全对齐不足 | ai-model-train.md |
| GAARM.0023.001 | AI模型安全 | 训练阶段 | 模型序列化后门 | ai-model-train.md |
| GAARM.0024 | AI模型安全 | 训练阶段 | 预训练模型不安全依赖 | ai-model-train.md |
| GAARM.0023.002 | AI模型安全 | 训练阶段 | 预训练模型投毒 | ai-model-train.md |
| GAARM.0022 | AI数据安全 | 应用阶段 | API信息泄露 | ai-data-app-1.md |
| GAARM.0019.001 | AI数据安全 | 应用阶段 | 个人隐私数据窃取 | ai-data-app-1.md |
| GAARM.0019.002 | AI数据安全 | 应用阶段 | 企业机密数据窃取 | ai-data-app-1.md |
| GAARM.0017.001 | AI数据安全 | 应用阶段 | 假定场景泄露 | ai-data-app-1.md |
| GAARM.0017.002 | AI数据安全 | 应用阶段 | 假定角色泄露 | ai-data-app-1.md |
| GAARM.0017 | AI数据安全 | 应用阶段 | 元Prompt泄露 | ai-data-app-1.md |
| GAARM.0017.003 | AI数据安全 | 应用阶段 | 关键字前后定位泄露 | ai-data-app-1.md |
| GAARM.0030 | AI数据安全 | 应用阶段 | 外部数据源信息泄露 | ai-data-app-1.md |
| GAARM.0029 | AI数据安全 | 应用阶段 | 成员推断攻击 | ai-data-app-2.md |
| GAARM.0028 | AI数据安全 | 应用阶段 | 数据操纵 | ai-data-app-2.md |
| GAARM.0018 | AI数据安全 | 应用阶段 | 模型反演攻击 | ai-data-app-2.md |
| GAARM.0020 | AI数据安全 | 应用阶段 | 模型推理API数据窃取 | ai-data-app-2.md |
| GAARM.0065 | AI数据安全 | 应用阶段 | 级联幻觉攻击 | ai-data-app-2.md |
| GAARM.0018.001 | AI数据安全 | 应用阶段 | 触发模型异常 | ai-data-app-2.md |
| GAARM.0018.002 | AI数据安全 | 应用阶段 | 训练数据推导 | ai-data-app-2.md |
| GAARM.0019 | AI数据安全 | 应用阶段 | 隐私数据窃取 | ai-data-app-2.md |
| GAARM.0012 | AI数据安全 | 部署阶段 | 备份数据窃取 | ai-data-deploy.md |
| GAARM.0013 | AI数据安全 | 部署阶段 | 数据传输劫持 | ai-data-deploy.md |
| GAARM.0014 | AI数据安全 | 部署阶段 | 数据存储服务攻击 | ai-data-deploy.md |
| GAARM.0015 | AI数据安全 | 部署阶段 | 日志和审计记录窃取 | ai-data-deploy.md |
| GAARM.0016 | AI数据安全 | 部署阶段 | 缓存数据&索引信息窃取 | ai-data-deploy.md |
| GAARM.0010 | AI数据安全 | 训练阶段 | 不正确&恶意外部数据源 | ai-data-train-1.md |
| GAARM.0009.001 | AI数据安全 | 训练阶段 | 个人隐私数据保护缺陷 | ai-data-train-1.md |
| GAARM.0009.002 | AI数据安全 | 训练阶段 | 企业敏感数据保护缺陷 | ai-data-train-1.md |
| GAARM.0009 | AI数据安全 | 训练阶段 | 内部数据保护缺陷 | ai-data-train-1.md |
| GAARM.0011.001 | AI数据安全 | 训练阶段 | 对话语料投毒 | ai-data-train-1.md |
| GAARM.0018.003 | AI数据安全 | 训练阶段 | 数据匿名化处理不当 | ai-data-train-2.md |
| GAARM.0009.003 | AI数据安全 | 训练阶段 | 机密敏感数据保护缺陷 | ai-data-train-2.md |
| GAARM.0011 | AI数据安全 | 训练阶段 | 训练数据投毒 | ai-data-train-2.md |
| GAARM.0020 | AI数据安全 | 训练阶段 | 训练数据泄露 | ai-data-train-2.md |
| GAARM.0011.002 | AI数据安全 | 训练阶段 | 训练数据篡改 | ai-data-train-2.md |
| GAARM.0010.001 | AI数据安全 | 训练阶段 | 预训练模型数据偏见 | ai-data-train-2.md |
| GAARM.0058 | AI身份安全 | 应用阶段 | Action模块权限失控 | ai-identity-app-1.md |
| GAARM.0057 | AI身份安全 | 应用阶段 | MCP未授权获取系统资源 | ai-identity-app-1.md |
| GAARM.0052.004 | AI身份安全 | 应用阶段 | Prompt目标劫持 | ai-identity-app-1.md |
| GAARM.0052.001 | AI身份安全 | 应用阶段 | 假定场景逃逸 | ai-identity-app-1.md |
| GAARM.0052.002 | AI身份安全 | 应用阶段 | 假定角色逃逸 | ai-identity-app-1.md |
| GAARM.0053.002 | AI身份安全 | 应用阶段 | 利用云凭证非法访问云端模型 | ai-identity-app-1.md |
| GAARM.0073 | AI身份安全 | 应用阶段 | 外部数据源欺骗 | ai-identity-app-1.md |
| GAARM.0059 | AI身份安全 | 应用阶段 | 多Agent访问身份伪造 | ai-identity-app-1.md |
| GAARM.0055 | AI身份安全 | 应用阶段 | 应用会话劫持 | ai-identity-app-2.md |
| GAARM.0053.001 | AI身份安全 | 应用阶段 | 未授权访问模型 | ai-identity-app-2.md |
| GAARM.0053 | AI身份安全 | 应用阶段 | 权限管控不当 | ai-identity-app-2.md |
| GAARM.0054 | AI身份安全 | 应用阶段 | 模拟对话攻击 | ai-identity-app-2.md |
| GAARM.0052 | AI身份安全 | 应用阶段 | 角色逃逸 | ai-identity-app-2.md |
| GAARM.0056 | AI身份安全 | 应用阶段 | 账户劫持风险 | ai-identity-app-2.md |
| GAARM.0053.003 | AI身份安全 | 应用阶段 | 账户越权访问 | ai-identity-app-2.md |
| GAARM.0052.003 | AI身份安全 | 应用阶段 | 遗忘法角色逃逸 | ai-identity-app-2.md |
| GAARM.0049.001 | AI身份安全 | 部署阶段 | 公开服务API密钥利用 | ai-identity-deploy.md |
| GAARM.0050 | AI身份安全 | 部署阶段 | 向量数据库未授权访问 | ai-identity-deploy.md |
| GAARM.0051 | AI身份安全 | 部署阶段 | 未授权访问模型部署环境 | ai-identity-deploy.md |
| GAARM.0049 | AI身份安全 | 部署阶段 | 滥用部署环境凭据 | ai-identity-deploy.md |
| GAARM.0048 | AI身份安全 | 训练阶段 | LLMs插件：权限管控设计缺陷 | ai-identity-train.md |
| GAARM.0046 | AI身份安全 | 训练阶段 | 训练环境缺少认证授权 | ai-identity-train.md |
| GAARM.0047 | AI身份安全 | 训练阶段 | 训练环境过度权限分配 | ai-identity-train.md |
| GAARM.0008 | AI基座安全 | 应用阶段 | LLMs拒绝服务&资源耗尽 | ai-baseline-app.md |
| GAARM.0007.001 | AI基座安全 | 应用阶段 | 代码解析器执行逃逸 | ai-baseline-app.md |
| - | AI基座安全 | 应用阶段 | 容器运行时风险 | ai-baseline-app.md |
| GAARM.0006 | AI基座安全 | 应用阶段 | 容器集群环境探测 | ai-baseline-app.md |
| GAARM.0007 | AI基座安全 | 应用阶段 | 容器集群环境攻击 | ai-baseline-app.md |
| GAARM.0004 | AI基座安全 | 部署阶段 | CI&CD流程攻击 | ai-baseline-deploy-1.md |
| GAARM.0003.001 | AI基座安全 | 部署阶段 | 云平台多租户隔离失效 | ai-baseline-deploy-1.md |
| GAARM.005 | AI基座安全 | 部署阶段 | 云平台安全漏洞 | ai-baseline-deploy-1.md |
| GAARM.0003 | AI基座安全 | 部署阶段 | 利用不安全系统配置 | ai-baseline-deploy-1.md |
| GAARM.0005 | AI基座安全 | 部署阶段 | 向量数据库漏洞 | ai-baseline-deploy-1.md |
| GAARM.0005 | AI基座安全 | 部署阶段 | 容器&&集群系统漏洞 | ai-baseline-deploy-2.md |
| GAARM.0004.001 | AI基座安全 | 部署阶段 | 模型部署服务漏洞 | ai-baseline-deploy-2.md |
| GAARM.0004.002 | AI基座安全 | 部署阶段 | 模型镜像污染 | ai-baseline-deploy-2.md |
| GAARM.0003.001 | AI基座安全 | 部署阶段 | 环境隔离缺陷 | ai-baseline-deploy-2.md |
| GAARM.0005 | AI基座安全 | 部署阶段 | 部署环境组件供应链漏洞 | ai-baseline-deploy-2.md |
| GAARM.0001.001 | AI基座安全 | 训练阶段 | 模型开发工具漏洞 | ai-baseline-train.md |
| GAARM.0001.002 | AI基座安全 | 训练阶段 | 训练数据管理系统漏洞 | ai-baseline-train.md |
| GAARM.0001 | AI基座安全 | 训练阶段 | 训练环境安全风险 | ai-baseline-train.md |
| GAARM.0002 | AI基座安全 | 训练阶段 | 训练环境隔离缺陷 | ai-baseline-train.md |

## 2026 增量（AISS 社区快照 2026-06-17 · 命名矩阵新增，当前未公开数字编号）

> 以下为社区相对本地基线新增的 23 条风险，集中在 **Agent 自治/失控、RAG 与记忆投毒、多 Agent 协同、规划与推理链** 四个 2026 前沿方向。编号 `—`=社区未公开（禁止编造）；Reference 标 `（待补）`=尚无专属小节，暂指最相近文件，后续补全详细 Payload/复现。

| 风险编号 | 安全域 | 阶段 | 风险名称 | Reference文件 |
|----------|--------|------|----------|---------------|
| — | AI应用安全 | 应用阶段 | Agent执行与自治风险 | ai-app-agent-cot-2.md §2026增量 |
| — | AI应用安全 | 应用阶段 | 业务应用API利用 | ai-app-agent-cot-2.md §2026增量 |
| — | AI应用安全 | 应用阶段 | 工具链误调用 | ai-app-agent-cot-2.md §2026增量（跨工具信任传递/ACL 提权）|
| — | AI应用安全 | 应用阶段 | 循环执行失控 | ai-app-agent-cot-2.md §2026增量（终止中毒/控制流 DoS）|
| — | AI应用安全 | 应用阶段 | 自动任务失控 | ai-app-agent-cot-2.md §2026增量|
| — | AI数据安全 | 应用阶段 | RAG投毒 | ai-data-app-2.md §2026增量（RAG/检索/知识投毒；并参 ai-app-prompt-1.md）|
| — | AI数据安全 | 应用阶段 | RAG知识污染风险 | ai-data-app-2.md §2026增量|
| — | AI数据安全 | 应用阶段 | 检索污染 | ai-data-app-2.md §2026增量|
| — | AI数据安全 | 应用阶段 | 知识源污染 | ai-data-app-2.md §2026增量|
| — | AI数据安全 | 应用阶段 | 知识伪造 | ai-data-app-2.md §2026增量|
| — | AI数据安全 | 应用阶段 | 记忆与上下文风险 | ai-data-app-2.md §2026增量|
| — | AI数据安全 | 应用阶段 | 长期记忆投毒 | ai-data-app-2.md §2026增量|
| — | AI数据安全 | 应用阶段 | 共享记忆污染 | ai-data-app-2.md §2026增量|
| — | AI数据安全 | 应用阶段 | 上下文持久污染 | ai-data-app-2.md §2026增量|
| — | AI数据安全 | 应用阶段 | 历史对话污染 | ai-data-app-2.md §2026增量|
| — | AI数据安全 | 应用阶段 | 跨会话状态污染 | ai-data-app-2.md §2026增量|
| — | AI身份安全 | 应用阶段 | Agent权限与身份协同风险 | ai-identity-app-1.md（待补）|
| — | AI身份安全 | 应用阶段 | 多Agent协同失控 | ai-identity-app-1.md（待补）|
| — | AI身份安全 | 应用阶段 | 高权限操作滥用 | ai-identity-app-1.md（待补）|
| — | AI模型安全 | 应用阶段 | 子任务注入攻击 | ai-app-agent-cot-2.md（待补）|
| — | AI模型安全 | 应用阶段 | 推理链污染 | ai-app-agent-cot-2.md（待补）|
| — | AI模型安全 | 应用阶段 | 规划与推理风险 | ai-app-agent-cot-2.md（待补）|
| — | AI模型安全 | 应用阶段 | 规划路径篡改 | ai-app-agent-cot-2.md（待补）|

---

**计数（2026-06-17 快照）**:
- 基线条目（含数字编号）: 150 条（其中 2 条原为抓取占位"攻击案例/攻击概述"，已据社区命名矩阵更正为"忠实性幻觉/敏感数据泄露"）
- 2026 增量（命名矩阵新增，未公开编号）: 23 条
- 与社区 sitemap（173 风险页）对齐；差额为父/子风险归并与命名差异，已逐项核对。
