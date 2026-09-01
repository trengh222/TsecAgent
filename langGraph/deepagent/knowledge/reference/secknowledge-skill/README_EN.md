# SecKnowledge - Web & AI Security Testing Skill

📖 [中文](README.md)

![version](https://img.shields.io/badge/version-2.2.0-blue)
![license](https://img.shields.io/badge/license-MIT-green)
![references](https://img.shields.io/badge/references-48-orange)

> A security-testing expert skill (Agent Skill) that distills WooYun's 88,636 real-world vulnerability cases, 5,600+ research papers, GAARM's 173 AI security risks (5 domains), the OWASP LLM/ASI/WSTG frameworks, and 200+ common test cases into an on-demand, battle-tested penetration-testing knowledge base — giving any AI coding assistant systematic offensive/defensive knowledge during security assessments.

---

## Why This Skill?

When using an AI assistant for security testing, generic model knowledge often falls short in depth and coverage. This Skill transforms your AI into a **seasoned security testing expert**:

- Given a target, it systematically enumerates attack surfaces and test cases
- When blocked by a WAF, it draws from 88,636 real bypass cases to suggest countermeasures
- For AI application testing, it covers 173 GAARM risks (5 domains, AISS 2026-06 snapshot) + OWASP LLM/Agent Top 10
- When you need payloads, it provides battle-tested cheat sheets

## Knowledge Sources

| Source | Scale | Content |
|--------|-------|---------|
| **WooYun Vulnerability DB** | 88,636 real vulnerabilities | SQL injection, XSS, command execution, file upload, logic flaws — real-world cases & bypass techniques |
| **Xianzhi Security Community** | 5,600+ security papers | L1-L4 Security Research Thinking Pyramid methodology |
| **GAARM Risk Matrix** | 173 AI security risks | From NSFOCUS AISS community, 5 security domains × 3 lifecycle stages (2026-06 snapshot, +23 deltas: RAG/memory poisoning, agent loss-of-control) |
| **OWASP Frameworks** | LLM Top 10 / Agentic AI Top 10 / WSTG | Latest 2025-2026 compliance mapping |

## Coverage

### Web Security (Traditional + Modern)

```
Injection Attacks    SQL Injection / XSS / Command Execution / XXE / Deserialization
Logic Flaws          Authorization Bypass / Payment Tampering / Password Reset / Race Conditions
File Security        File Upload / Path Traversal / SSRF / Information Disclosure
Modern Protocols     CORS / GraphQL / HTTP Smuggling / WebSocket / OAuth
Deployment           Supply Chain / Cloud Services / TLS / Containers / CI/CD
Framework Security   Fingerprinting → CVE Matching → PoC Verification (generic methodology)
```

### AI Security (5 Domains × 173 Risks)

```
AI App Security(39)       Prompt Injection / CoT Attacks / MCP Poisoning / Agent Exploitation / Tool-Chain Misuse·Loop-Failure(2026)
AI Model Security(46)     Jailbreak / Hallucination Abuse / Adversarial Samples / Model Theft / Reasoning-Chain Poisoning·Plan Tampering(2026)
AI Data Security(43)      Prompt Leakage / Data Exfiltration / Inference Attacks / RAG Poisoning·Memory Poisoning(2026)
AI Identity Security(26)  Role Escape / Permission Failures / Agent Impersonation / Session Hijacking / Multi-Agent Loss-of-Control(2026)
AI Infra Security(19)     Sandbox Escape / Container Escape / Supply Chain / DoS
Frontier Risks            Claw-like Kill-Chain Matrix / MCP Tool Poisoning / Agent Worms / Skills Injection / Claude Code CVEs
```

### Core Methodologies

```
Xianzhi L1-L4          Attack Surface ID → Hypothesis Verification → Deep Exploitation → Defense Reversal
WooYun Essence         Vuln = Expected Behavior - Actual Behavior = Developer Assumptions ⊕ Attacker Input
GAARM Matrix           6 Security Domains × 3 Lifecycle Stages = Systematic AI Risk Coverage
OWASP Mapping          LLM01-10 / ASI01-10 / WSTG-* Compliance IDs
```

## File Structure

```
SKILL.md                              # Entry: quick-ref cards + decision tree + navigation
references/
├── [Web - by vulnerability type]
│   ├── web-sqli.md                   # SQL Injection + SQLMap cheat (~245 lines)
│   ├── web-xss.md                    # XSS (~187 lines)
│   ├── web-rce.md                    # Command Execution (~232 lines)
│   ├── web-xxe.md                    # XXE External Entity (~106 lines)
│   ├── web-deser.md                  # Deserialization (~151 lines)
│   ├── web-upload.md                 # File Upload + Webshell bypass (~174 lines)
│   ├── web-traversal.md              # Path Traversal / File Inclusion (~145 lines)
│   ├── web-leak.md                   # Information Disclosure (~136 lines)
│   └── web-ssrf-misc.md              # SSRF + Misconfig + CMS/URL appendix (~191 lines)
├── [Web - logic & modern protocols]
│   ├── web-logic-auth.md             # AuthZ/Payment/Password Reset/Logic (582 lines)
│   ├── web-modern-protocols.md       # CORS/GraphQL/HTTP Smuggling/WS/OAuth (348 lines)
│   └── web-deployment-security.md    # Supply Chain/Cloud/Framework CVE (449 lines)
├── [AI App Security - App phase by risk class + Deploy/Training + Frontier]
│   ├── ai-app-prompt-1.md            # App subset: Prompt inj/XSS hijack/Indirect/Memory/Worm (~301 lines)
│   ├── ai-app-prompt-2.md            # App subset: Reverse-induce/Multimodal/Encoding/Keyword&Synonym obfusc (~242 lines)
│   ├── ai-app-mcp.md                 # App subset: MCP protocol attacks (~261 lines)
│   ├── ai-app-agent-cot-1.md         # App subset: CoT inj/SSRF probe/Code-exec inj (~177 lines)
│   ├── ai-app-agent-cot-2.md         # App subset: Agent abuse/CoT manip/Query&Env inj/Unexpected code-exec (~365 lines)
│   ├── ai-app-deploy.md              # Deploy phase: API/Source (~154 lines)
│   ├── ai-app-train.md               # Training phase: 3rd-party/Plugins (~427 lines)
│   └── ai-app-frontier.md            # Frontier: Agent/MCP/Skills 2025-2026 (~121 lines)
├── [AI Model Security - App phase by risk category + Deploy/Training]
│   ├── ai-model-jailbreak.md         # App subset: Jailbreak GAARM.0027.x (~404 lines)
│   ├── ai-model-hallucination.md     # App subset: Hallucination GAARM.0028/0064 (~252 lines)
│   ├── ai-model-content-1.md         # App subset: Non-compliant Bias/Violence/Political GAARM.0029.x (~315 lines)
│   ├── ai-model-content-2.md         # App subset: Non-compliant Misinfo/Inducement/Output GAARM.0029.x (~241 lines)
│   ├── ai-model-copyright.md         # App subset: Copyright/Commercial GAARM.0030.x (~154 lines)
│   ├── ai-model-misuse-1.md          # App subset: Image fakery/Multimodal/Malcode/Intent/Drift (~316 lines)
│   ├── ai-model-misuse-2.md          # App subset: Function misuse/Video&Audio fakery/Phishing GAARM.0031.x/0033/0062/0063 (~233 lines)
│   ├── ai-model-extraction.md        # App subset: Adversarial/Extraction GAARM.0032.x (~363 lines)
│   ├── ai-model-deploy.md            # Deploy: File theft/Param tamper (~136 lines)
│   └── ai-model-train.md             # Training: Backdoor/Alignment/Poison (~292 lines)
├── [AI Data Security - GAARM 3-phase]
│   ├── ai-data-app-1.md              # App: API/Privacy/Corp/Assumed scene&role/Meta-prompt/Keyword/Ext-src leak (~477 lines)
│   ├── ai-data-app-2.md              # App: Membership inference/Manipulation/Inversion/Inference-API/Cascade halluc (~432 lines)
│   ├── ai-data-deploy.md             # Deploy: Backup/Transit/Storage (~230 lines)
│   ├── ai-data-train-1.md            # Training: Ext-src/Privacy/Corp/Internal/Dialog-corpus poison (~263 lines)
│   └── ai-data-train-2.md            # Training: Anonymization/Confidential/Poison/Leak/Tamper/Pretrain-bias (~333 lines)
├── [AI Identity Security - GAARM 3-phase]
│   ├── ai-identity-app-1.md          # App: Action-perm/MCP-unauth/Prompt-hijack/Assumed-escape/Cloud-cred/Ext-src-spoof/Multi-agent-spoof (~462 lines)
│   ├── ai-identity-app-2.md          # App: Session-hijack/Unauth-access/Perm-mgmt/Sim-dialog/Role-escape/Account-hijack&priv/Amnesia (~450 lines)
│   ├── ai-identity-deploy.md         # Deploy: Unauthorized access (~226 lines)
│   └── ai-identity-train.md          # Training: Permission design (~148 lines)
├── [AI Infra Security - GAARM 3-phase + escape]
│   ├── ai-baseline-app.md            # App: Container escape/DoS (~278 lines)
│   ├── ai-baseline-deploy-1.md       # Deploy: CI&CD/Multi-tenant/Cloud/Insecure-config/Vector-DB (~290 lines)
│   ├── ai-baseline-deploy-2.md       # Deploy: Container-cluster/Deploy-svc/Image-poison/Env-isolation/Supply (~267 lines)
│   ├── ai-baseline-train.md          # Training: Dev tools/Env isolation (~202 lines)
│   └── ai-baseline-escape.md         # Container & sandbox escape methodology (~159 lines)
├── [Core index & methodology]
│   ├── gaarm-risk-matrix.md          # 173 AI Risk Index Table (5 domains × 3 stages, AISS 2026-06)
│   ├── claw-agent-threat-matrix.md   # Claw-like agent threat matrix (kill-chain 6 stages × 36 threats + 39 defenses + ATLAS-style IDs)
│   └── testing-methodology.md        # Unified Testing Methodology (589 lines)
```

> **Split principles**:
> - AI files first split by GAARM 3-phase (App/Deploy/Training)
> - AI App/Model app-phase further split by risk class (Prompt/MCP/Agent-CoT, Jailbreak/Hallucination/Content/Copyright/Misuse/Extraction)
> - Web injection/file split by vuln subtype (SQLi/XSS/RCE/XXE/Deser/Upload/Traversal/Leak/SSRF)
> - Payloads inlined per topic file, no standalone payload file
> - All 48 reference files ≤ 1000 lines (single-Read friendly)

**Total**: 48 reference files + 1 SKILL.md = 49 files | Max file 589 lines | 100% single-Read friendly

## Installation

### Claude Code

Clone this repo to Claude Code's skills directory:

```bash
git clone https://github.com/Pa55w0rd/secknowledge-skill.git ~/.claude/skills/secknowledge
```

### Cursor

Clone this repo to Cursor's skills directory:

```bash
git clone https://github.com/Pa55w0rd/secknowledge-skill.git ~/.cursor/skills/secknowledge
```

Once cloned, the AI will automatically load this Skill when you engage in security-related tasks.

## Usage Examples

### Scenario 1: Web Penetration Testing

```
User: Test target.com for SQL injection
AI:   [Auto-loads SKILL.md → web-sqli.md]
      → Lists high-risk injection points, DB fingerprinting, WAF bypass techniques, full exploitation chain
```

### Scenario 2: AI Application Security Assessment

```
User: Test this chatbot's prompt injection defenses
AI:   [Auto-loads SKILL.md → ai-app-prompt-1.md/-2.md / ai-app-mcp.md (by risk type)]
      → Systematic testing: direct injection / indirect injection / MCP poisoning / Agent exploitation
```

### Scenario 3: Hybrid Application Attack Chains

```
User: This AI app has file upload and RAG features, how to test?
AI:   [Loads cross-layer attack chains]
      → Web layer (file upload bypass) → AI layer (RAG poisoning / indirect injection) → combined exploitation
```

### Scenario 4: Query Specific Risks

```
User: What is GAARM.0039?
AI:   [Consults gaarm-risk-matrix.md → ai-app-prompt-1.md (GAARM.0039 is app-phase Prompt injection, Part 1)]
      → Returns full attack overview, cases, risk analysis, mitigations
```

## Trigger Keywords

The following keywords automatically trigger Skill loading:

> vulnerability research, penetration testing, security audit, code review, security assessment, red team,
> CTF, SQL injection, XSS, command execution, file upload, SSRF, authorization bypass, logic flaws,
> prompt injection, jailbreak, MCP security, agent security, LLM security, sandbox escape,
> data leakage, model security, RAG poisoning, supply chain security

## Methodology Framework

```
User Request
│
├─ Web App ──→ SQL? → [web-sqli.md]   XSS? → [web-xss.md]   RCE? → [web-rce.md]
│              Upload? → [web-upload.md]   Traversal? → [web-traversal.md]
│              Logic? → [web-logic-auth.md]   Modern? → [web-modern-protocols.md]
│
├─ AI App ──→ Prompt inj → [ai-app-prompt-1/-2.md]   MCP → [ai-app-mcp.md]   Agent/CoT → [ai-app-agent-cot-1/-2.md]
│              Jailbreak → [ai-model-jailbreak.md]   Hallucination → [ai-model-hallucination.md]
│              Prompt leak/Data theft → [ai-data-app-1/-2.md]
│              Role escape/Permission → [ai-identity-app-1/-2.md]
│
├─ Deployment → Supply chain/Cloud/Framework CVE [web-deployment-security.md]
│
└─ Container/Sandbox → Escape/Persistence/Lateral movement [ai-baseline-escape.md]
```

## Changelog

### v2.2.0 (2026-06-17) — AISS upstream sync + Claw-like threat matrix

- **GAARM matrix synced to AISS 2026-06 snapshot**: 150→**173 risks**, confirmed **5 domains** (not 6; "AI Compliance & Governance" is not a GAARM domain); the community now organizes by a named threat matrix and no longer publishes `GAARM.XXXX` numeric IDs (delta entries marked `—`, fabrication forbidden)
- **23 deltas (2026)**: agent autonomy/loss-of-control (tool-chain misuse · loop failure · runaway tasks), RAG & memory poisoning (11), multi-agent coordination, planning & reasoning-chain; 4 scrape-placeholder/typo entries corrected against upstream
- **New `claw-agent-threat-matrix.md`**: Claw-like agent threat matrix (kill-chain 6 stages × 36 threats + 39 defenses + AISS-ATLAS-style IDs), orthogonal & complementary to the GAARM taxonomy
- **Selective backfill** of 2 high-value clusters into `ai-app-agent-cot-2.md` / `ai-data-app-2.md` (from public corpus, with CVE/source)
- references 46→**48**; wiki snapshot page synced; fetch method (sitemap + `/api/v1/matrix`; site is a React SPA) recorded in `lessons.md` L-2

### v2.1.1 (2026-05-29) — skill-craft audit fixes

- Added `metadata.version` to frontmatter (machine-readable version gate, check-version PASS)
- Added **phenomenon-signal routing table** to triggers ("agent misbehaving" / "RAG returns suspicious" / "output seems injected" take priority over keyword routing)
- Symmetric DO-NOT routing with sibling skills: Mira PI testing→mira-pi-tester, build-your-own wiki→llm-wiki, article ingest→mira-pi-ingest
- 2nd-split of 8 >500-line references to ≤500 (max 906→589; scenario index / GAARM matrix / OWASP mapping atomically synced, zero broken links)
- Added `references/lessons.md`; README counts synced

### v2.0 (2026-05-18) — Structural refactor + split optimization

**SKILL.md entry upgrade**:
- 3 behavioral rules with ❗ marker (Payload citation / Hypothesis vs Confirmed / Authorization boundary) + "self-check before every output" mechanism
- New "Dependency chain constraints" section: Step 2 input == Step 1 output, Step 3 references ⊆ Step 2 loaded set, no re-searching
- Equation-based acceptance criteria: `cited count + UNABLE TO CITE count == total hypothesis count`
- Each Step adds "fail → retry → degrade → no skipping" 3-stage failure path
- Trigger refinement: CTF short code snippet + exploit idea → this Skill; full project dir + systematic white-box → code-audit-skill

**Reference split** (12 → 38 files):
- 1st split (by GAARM 3-phase): 5 AI files + 2 Web files → 26 sub-files
- 2nd split (ai-model-app.md 2231 lines) → 6 risk categories (Jailbreak/Hallucination/Content/Copyright/Misuse/Extraction)
- 3rd split (ai-app-app.md 1318 lines) → 3 risk classes (Prompt injection/MCP/Agent-CoT)
- Max file 2651 → 906 lines, **100% references ≤ 1000 lines**
- Removed redundant payloads.md; payloads now inlined per scenario

**Index reconstruction**:
- gaarm-risk-matrix.md 116 risk entries remapped by "GAARM domain + phase + risk category" to 38 sub-files
- testing-methodology.md OWASP three frameworks (LLM01-10 / ASI01-10 / WSTG-*) mappings fully aligned
- SKILL.md scenario navigation: AI security by "domain × phase × risk category" 3-level navigation

### v1.0 (Initial) — 12 reference files

Initial fusion of WooYun 88,636 cases + Xianzhi 5,600+ docs + GAARM 150 risks + OWASP three frameworks.

---

## Acknowledgments & References

This Skill's knowledge system is built upon the following outstanding projects and communities:

| Project | Description |
|---------|-------------|
| [WooYun Legacy](https://github.com/tanweai/wooyun-legacy) | A Claude Code Skill curated by the Tanwei Security Research Team, containing 88,636 real vulnerability cases. This project's web security knowledge (injection, file operations, logic flaws, etc.) is distilled from this vulnerability database |
| [Xianzhi Security Research Methodology](https://github.com/tanweai/xianzhi-research) | L1-L4 meta-thinking methodology framework extracted from 5,621 security papers in the Xianzhi community. This project's four-layer thinking model and cross-domain attack chain thinking originate from this work |
| [AISS - NSFOCUS AI Security Smart Link Community](https://aiss.nsfocus.com/) | AI security knowledge base by NSFOCUS, providing the GAARM risk matrix (2026-06 snapshot: 173 entries) covering 5 security domains × 3 lifecycle stages |
| [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/) | 2025 edition — Top 10 risks for LLM applications |
| [OWASP Agentic AI Security Top 10](https://owasp.org/www-project-agentic-ai-security-initiative/) | 2026 edition — Top 10 risks for AI Agents |
| [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) | v4.2 — Web Security Testing Guide with WSTG-* classification |

## Author

[Pa55w0rd](https://github.com/Pa55w0rd)

## Disclaimer

All content in this Skill is **for security research and defensive purposes only**. Please conduct security testing only with proper authorization and in compliance with local laws and regulations. All knowledge sources are from publicly available security communities and standard frameworks.

## License

MIT License

---

*Version: v2.2.0 (2026-06-17) | Author: Pa55w0rd | Knowledge Fusion: WooYun 88,636 cases × Xianzhi 5,600+ papers × GAARM 173 risks (5 domains) × OWASP LLM/ASI/WSTG × 200+ test cases | Structure: 48 references, 100% single-Read friendly*
