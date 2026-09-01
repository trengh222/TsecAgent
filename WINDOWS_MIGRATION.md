# TsecAgent Windows 适配转换文档

> 状态：**P0 已实施并验证通过**（2026-09-01），P1/P2 待做
> 目标：在不破坏 Linux 行为的前提下，让 TsecAgent 在 Windows 上原生运行全部功能
> 原则：**双后端兼容**——所有改造通过运行时平台检测分支实现，Linux 路径保持原样，不引入 WSL 硬依赖
>
> 已确认决策：① 终端主后端 = PowerShell 长驻会话；② 词表全部随仓库分发；③ 默认工作目录 = %TEMP%\tsecagent-sandbox

## P0 实施记录（已完成）

| 项 | 实施内容 | 验证结果 |
|----|----------|----------|
| TerminalExecutor | 新增 `PowerShellSession`（长驻 `powershell -NoExit -Command -` REPL + 读线程环形缓冲）；直接模式改 `powershell -Command` + `exit $LASTEXITCODE` 传播退出码；工作目录无效时自动回退沙箱目录 | 持久 CWD/退出码透传/UTF-8 中文/超时/会话销毁 全部通过 |
| 哨兵泄漏修复 | 解析后 `mark_consumed()` 清空已消费输出，防止上一次哨兵行混入下一次结果 | stdout 干净无 `DEEPAGENT_DONE` 残留 |
| config.py / mcp_ser.py | `TERMINAL_DEFAULT_DIR` 未配置时 Windows 落到 `%TEMP%\tsecagent-sandbox`（自动创建），POSIX 保持 `/home/daytona` | `run_server --print-config` 正确 |
| run_agent.py | 健康检查 Windows 分支（`$PSVersionTable` 冒烟 + 本地 `platform.machine()`） | `Terminal Executor OK (Windows AMD64 PS 5)` |
| DirectoryScanner | common/big/api 词表候选追加 `langGraph/data/wordlists/`；Windows 提示改 scoop | 三个词表解析全部命中 |
| 词表入库 | `langGraph/data/wordlists/`：common.txt(4752行)、big.txt(166KB)、api_objects.txt(20KB) | 随仓库分发，离线可用 |
| PortScanner/DirectoryScanner | 工具缺失提示增加 Windows 安装指引（winget/scoop） | — |

**健康检查实测**（`python deepagent/run_agent.py --check`）：
Python Executor OK / Terminal Executor OK (Windows AMD64 PS 5) / Browser OK / Knowledge OK(8 collections)；
Proxy WARN（Caido 未启动）、Recon WARN（nmap/gobuster 未安装）为预期可选组件；
LLM FAIL(403) 为用户 API Key 失效，非代码问题。

---

## 1. 背景

项目当前面向 Linux（Ubuntu/Debian）设计，核心依赖：

- `tmux` 终端会话（TerminalExecutor 主模式）
- POSIX shell 语法（`shlex.quote`、`cd X && cmd`、`echo sentinel:$?`）
- `resource` 模块资源限制（已在上一轮修复为条件导入）
- 硬编码 Linux 词表路径 `/usr/share/wordlists/...`
- 默认工作目录 `/home/daytona`、`/tmp`
- 外部安全工具：nmap、gobuster、ffuf（Linux 包管理器安装）

## 2. 兼容性现状盘点

### 2.1 无需改动（已兼容）

| 模块 | 说明 |
|------|------|
| [graph.py](langGraph/deepagent/graph.py) / agent.py / memory.py / context.py / guard.py | 纯逻辑 + LLM 调用，跨平台 |
| [PythonExecutor.py](langGraph/deepagent/mcp/executors/PythonExecutor.py) | 进程内 `exec` + `asyncio.wait_for` 超时；`resource` 已条件导入（Windows 静默跳过 rlimit，超时限制仍生效） |
| [ProxyExecutor.py](langGraph/deepagent/mcp/executors/ProxyExecutor.py) | 纯 HTTP 调用 Caido API，跨平台 |
| [KnowledgeExecutor.py](langGraph/deepagent/mcp/executors/KnowledgeExecutor.py) / knowledge/* | ChromaDB + OpenViking（未安装时自动 fallback），pathlib 路径 |
| [BrowserExecutor.py](langGraph/deepagent/mcp/executors/BrowserExecutor.py) | Playwright 跨平台（需 `playwright install chromium`） |
| [meta_executor.py](langGraph/deepagent/mcp/executors/meta_executor.py) | 快照/截断逻辑，os.path 路径 |
| chat_server.py / run_server.py / mcp_ser.py | FastAPI / MCP stdio 跨平台（Windows 默认 Proactor 事件循环支持 asyncio 子进程） |
| failure_attribution.py / anti_addiction.py | 纯逻辑 |

### 2.2 需要改造（按优先级）

| # | 位置 | 问题 | 阻断级 |
|---|------|------|--------|
| 1 | [TerminalExecutor.py](langGraph/deepagent/mcp/executors/TerminalExecutor.py)（整文件） | tmux 会话模式无 Windows 版；fallback 直接模式用 POSIX 语法（`shlex.quote` + `cd X &&` + `$?` 哨兵） | **P0 高**（execute_shell 是核心工具） |
| 2 | [TerminalExecutor.py#L187](langGraph/deepagent/mcp/executors/TerminalExecutor.py#L187) | 默认目录兜底 `/tmp` | **P0 高** |
| 3 | [config.py#L85](langGraph/deepagent/mcp/config.py#L85) | `TERMINAL_DEFAULT_DIR` 默认 `/home/daytona` | **P0 高** |
| 4 | [DirectoryScanner.py#L58-L72](langGraph/deepagent/mcp/executors/DirectoryScanner.py#L58-L72) | 词表硬编码 `/usr/share/seclists/...`、`/usr/share/wordlists/...` | **P0 高**（directory_scan 功能不可用） |
| 5 | [run_agent.py#L168](langGraph/deepagent/run_agent.py#L168) | 健康检查 `echo $(uname -s) $(uname -m)` | **P0 中**（CLI 检查必失败） |
| 6 | [PortScanner.py#L88](langGraph/deepagent/mcp/executors/PortScanner.py#L88) / DirectoryScanner.py#L170 | 工具缺失提示仅给 Linux 安装命令 | **P1 低** |
| 7 | [mcp_ser.py#L79](langGraph/deepagent/mcp/mcp_ser.py#L79)、[L432](langGraph/deepagent/mcp/mcp_ser.py#L432) | MCP 入口默认目录 `/home/daytona` | **P1 中**（仅 MCP 入口） |

## 3. 核心设计方案

### 3.1 TerminalExecutor — Windows 三后端架构（重点）

现状为「tmux 模式 + 直接模式 fallback」，改造为平台感知的多后端：

```
TerminalExecutor
├── 检测顺序（Windows）:
│   1. PowerShellSession  ← Windows 原生持久会话（推荐主模式）
│   2. WSLTmuxSession     ← 检测到 WSL + tmux 时可选启用（TMUX_BACKEND=wsl）
│   3. 直接模式            ← 兜底（cmd/powershell 一次性执行）
└── 检测顺序（Linux/macOS）: tmux → 直接模式（现状不变）
```

#### 方案 A：PowerShellSession（Windows 原生持久会话，推荐）

用长驻 PowerShell 子进程替代 tmux 会话，接口与 TmuxSession 对齐：

```python
# 创建
proc = subprocess.Popen(
    ["powershell", "-NoProfile", "-NoExit", "-Command", "-"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT, text=True,
    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
)
# 发送命令 + 哨兵（PowerShell 退出码变量）
proc.stdin.write(f"{command}; Write-Host \"{sentinel}:$LASTEXITCODE\"\n")
# 轮询读取输出直到哨兵出现（复用现有轮询/超时逻辑）
```

- **持久会话**：进程长驻，CWD / `$env:` 变量跨调用保留（与 tmux 语义一致）
- **输出历史**：进程内维护环形缓冲区（deque(maxlen=500)）替代 tmux 的 `capture-pane -S -500`
- **哨兵协议**：`echo {sentinel}:$?` → `Write-Host "{sentinel}:$LASTEXITCODE"`
- **cd 语义**：会话内 `Set-Location`，无需 `shlex.quote`（改用双引号转义 `'` → `''`）
- **会话销毁**：`proc.terminate()` + 进程树清理（`taskkill /T /F` 或 psutil）

#### 方案 B：WSL tmux（可选，改动最小）

`_check_tmux()` 扩展：检测 `wsl tmux -V`，命中则 TmuxSession 所有 `subprocess.run(["tmux", ...])` 前缀 `wsl`。由环境变量 `TMUX_BACKEND=wsl` 显式开启，默认不启用。

#### 方案 C：直接模式适配（兜底，必做）

```python
# 现状（POSIX）:
full_command = f"cd {shlex.quote(working_dir)} && {command}"
await asyncio.create_subprocess_shell(full_command, ...)

# Windows 适配: cwd 参数替代 cd 链，shell 换 powershell
await asyncio.create_subprocess_shell(
    command, cwd=working_dir,
    executable="powershell" if sys.platform == "win32" else None,  # Linux 走默认 /bin/sh
    ...
)
```

#### 后端选择逻辑

```python
def _pick_backend(config) -> str:
    if sys.platform != "win32":
        return "tmux" if _check_tmux() else "direct"
    if os.getenv("TMUX_BACKEND") == "wsl" and _check_wsl_tmux():
        return "wsl_tmux"
    if _check_powershell():          # 恒真（Windows 自带）
        return "powershell"
    return "direct"
```

### 3.2 词表本地化（DirectoryScanner）

Windows 无 `/usr/share/wordlists`，改为项目内分发 + 环境变量覆盖：

```
langGraph/data/wordlists/
├── common.txt        # ~4600 条（源：dirb common）
├── big.txt           # ~20000 条
└── api_objects.txt   # API 路径字典
```

```python
def _resolve_wordlist(name: str) -> Optional[str]:
    # 1. 显式路径（存在即用，Linux 原路径保持优先）
    # 2. WORDLIST_DIR 环境变量
    # 3. Windows: PROJECT_ROOT/data/wordlists/{name}.txt
    # 4. Linux: /usr/share/... 原路径（行为不变）
```

配套 `knowledge/`-style 下载脚本 `tools/fetch_wordlists.py`（首次运行自动从 SecLists 镜像拉取），词表文件加入 `.gitignore` 可选项。

### 3.3 默认目录平台化

```python
# config.py
DEFAULT_WORKDIR = os.getenv(
    "TERMINAL_DEFAULT_DIR",
    os.path.expanduser("~\\Desktop") if sys.platform == "win32" else "/home/daytona",
)
# TerminalExecutor 兜底: "/tmp" → tempfile.gettempdir()
```

`.env.example` 补充说明：Windows 下建议设为专用沙箱目录（如 `D:\pts-sandbox`），并给出创建命令。

### 3.4 健康检查平台化（run_agent.py）

```python
# 现状: executor.execute("echo $(uname -s) $(uname -m)", ...)
# 改为:
if sys.platform == "win32":
    r = executor.execute("echo ok", timeout=10)      # 验证会话可用性
    sysinfo = f"{platform.system()} {platform.machine()}"   # 本地直接获取
else:
    r = executor.execute("echo $(uname -s) $(uname -m)", timeout=10)  # Linux 原样
```

### 3.5 外部工具链（安装指引，不改代码逻辑）

| 工具 | Windows 安装方式 | 备注 |
|------|------------------|------|
| nmap | `winget install Insecure.Nmap` 或官网安装包 | 安装时勾选"Add to PATH"；`-oG -` 输出解析跨平台一致 |
| gobuster | `scoop install gobuster` 或 GitHub Releases exe | 参数一致，无需改代码 |
| ffuf | `scoop install ffuf` | 同上 |
| Playwright | `pip install playwright && playwright install chromium` | 模拟器路径自动处理 |

错误提示文案增加 Windows 分支（`P1`）：

```python
if sys.platform == "win32":
    hint = "nmap 未安装: winget install Insecure.Nmap 或 https://nmap.org/download.html"
```

### 3.6 明确不做的事（范围控制）

- 不迁移到 Windows 服务/计划任务
- 不引入 pywin32/pywinpty 硬依赖（Job Object 内存限制、conpty 真实屏幕缓冲列为 P2 可选）
- 不改动 knowledge/reference 下的第三方知识源文件
- 不重构 PythonExecutor 的进程内 exec 模型（Linux/Windows 行为一致）

## 4. 分阶段实施计划

| 阶段 | 内容 | 涉及文件 | 验收标准 |
|------|------|----------|----------|
| **P0 可运行** | ① TerminalExecutor 三后端（PowerShell 会话 + 直接模式适配 + 平台选择）② 默认目录平台化 ③ run_agent 健康检查 ④ 词表本地化解析 | TerminalExecutor.py、config.py、DirectoryScanner.py、run_agent.py、.env.example | `python deepagent/run_agent.py --target <本机> --dry-run` 组件自检全绿；execute_shell 可执行 `echo ok`、`Get-ChildItem` 并返回正确退出码 |
| **P1 完整功能** | ⑤ 词表下载脚本 + 实际扫描 ⑥ nmap/gobuster/ffuf Windows 提示文案 ⑦ mcp_ser.py 默认目录 ⑧ WSL tmux 后端（可选开关） | DirectoryScanner.py、PortScanner.py、mcp_ser.py、TerminalExecutor.py、tools/fetch_wordlists.py | recon_port_scan 扫 127.0.0.1 出结果；recon_directory_scan 用本地词表完成扫描 |
| **P2 可选增强** | ⑨ Job Object CPU/内存限制（pywin32 可选依赖） ⑩ pywinpty 真实终端缓冲 ⑪ Windows 打包/一键启动脚本 | PythonExecutor.py、新文件 | 长时间死循环脚本被 Job Object 终止 |

## 5. 测试与验收

### 5.1 单元级（每阶段必过）

```powershell
cd langGraph
python -m compileall -q -x "reference|__pycache__" deepagent          # 语法
python -c "import deepagent.agent, deepagent.graph; print('ok')"      # 导入链
```

### 5.2 功能级（P0 验收脚本要点）

| 用例 | 命令 | 期望 |
|------|------|------|
| 一次性执行 | `execute_shell "echo hello"` | success=True, stdout 含 hello |
| 退出码透传 | `execute_shell "cmd /c exit 2"` | exit_code=2 |
| 持久会话 CWD | 会话内 `cd` 后再 `pwd`（`Get-Location`） | 目录保持 |
| 超时杀进程 | `execute_shell "Start-Sleep 999" -t 5` | 5s 返回 timeout，进程树被清理 |
| Python 沙箱 | `execute_python "print(1+1)"` | stdout=2 |
| 目录扫描 | `recon_directory_scan http://127.0.0.1 common` | 使用本地词表返回结果 |
| 端口扫描 | `recon_port_scan 127.0.0.1` | nmap 正常输出 |
| 浏览器 | `browser_navigate http://example.com` | 截图/内容正常 |
| 端到端 | chat_server + chat.html 对测试站走完一轮 PER | 生成最终报告 |

### 5.3 回归保障

所有平台分支以 `sys.platform == "win32"` 判定，Linux 路径逐行保持原实现；改造后需在 Linux（或 WSL）跑一遍 5.2 全量用例确认无回归。

## 6. 风险与缓解

| 风险 | 影响 | 缓解 |
|------|------|------|
| PowerShell 输出编码（GBK/UTF-8 混杂） | 中文乱码 | 会话创建时强制 `[Console]::OutputEncoding=[Text.Encoding]::UTF8` + `chcp 65001` |
| 管道读阻塞（命令永不结束） | 会话挂死 | 哨兵轮询 + 硬超时 + `taskkill /T` 清进程树 |
| `powershell` vs `pwsh` 差异 | 语法边缘不兼容 | 固定 `powershell`（Windows PowerShell 5.1，系统自带），不依赖 pwsh |
| nmap Windows 需要 Npcap | 扫描失败 | 文档注明安装 Npcap；错误提示引导 |
| Ctrl+C 信号语义不同 | Agent 无法中断前台命令 | W1 后端暂不支持中断（工具描述注明）；P2 用 Job Object 补齐 |
| ReconExecutor 的 `analyze_js`/`fuzz_auth_bypass` 依赖 Python 库 | 功能降级 | 与平台无关，按 requirements.txt 安装即可 |

## 7. Windows 环境准备清单（附录）

```powershell
# 1. Python 3.12+（确认 python --version）
winget install Python.Python.3.12

# 2. 项目依赖
cd langGraph
pip install -r requirements.txt
playwright install chromium

# 3. 安全工具（P1 阶段需要）
winget install Insecure.Nmap          # 含 Npcap 向导
scoop install gobuster ffuf           # 或从 GitHub Releases 下载 exe 放入 PATH

# 4. 配置
cp deepagent\.env.example deepagent\.env
# 编辑 .env: TERMINAL_DEFAULT_DIR=D:\pts-sandbox  （建议专用目录，勿用系统盘根目录）

# 5. 词表（P1）
python tools\fetch_wordlists.py

# 6. 启动
python deepagent\chat_server.py       # Web UI: http://localhost:8000
python deepagent\run_agent.py --target http://测试目标 --goal "..."
```

---

**评审要点**：① TerminalExecutor 主后端选 PowerShell 会话（方案 A）是否接受？② 词表随仓库分发 vs 首次自动下载？③ 默认工作目录倾向 `%USERPROFILE%` 还是专用沙箱目录？确认后按 P0 → P1 → P2 实施。
