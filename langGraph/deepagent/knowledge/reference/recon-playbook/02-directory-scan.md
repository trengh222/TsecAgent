# 目录/文件爆破 Playbook

替代 MCP 工具 `recon_directory_scan`。用 `execute_shell` 调 gobuster/ffuf。

## 依赖
- gobuster 或 ffuf（任一）
- 词表：仓库自带 `langGraph/data/wordlists/`（common / big / api_objects）

## 命令模板

### 1. gobuster 基础目录爆破
```bash
gobuster dir -u https://target -w common.txt -t 30 -s 200,204,301,302,401,403
```

### 2. ffuf 基础（更灵活，推荐）
```bash
ffuf -u https://target/FUZZ -w common.txt -t 50 -mc 200,301,403 -o result.json
```

### 3. 带扩展名
```bash
ffuf -u https://target/FUZZ -w common.txt -e .php,.html,.txt,.bak -mc 200,301
```

### 4. 递归爆破
```bash
ffuf -u https://target/FUZZ -w common.txt -recursion -recursion-depth 2 -mc 200,301,403
```

### 5. 虚拟主机爆破（vhost）
```bash
ffuf -u https://target -H "Host: FUZZ.target" -w subdomains.txt -mc 200 -fs 1234
```
`-fs` 过滤默认响应大小，排除无效 vhost。

## 词表选择
| 词表 | 适用 |
|---|---|
| common.txt | 通用首选 |
| big.txt | common 无果时深度补充 |
| api_objects.txt | API 接口枚举 |

## 结果判读
- `200` 存在；`301/302` 跳转（追链）；`401/403` 存在但受限（重点：可试鉴权绕过，见 `07-fuzz-auth-bypass.md`）
- 注意误报：全 404 伪装时所有路径同状态码同大小，用 `-fs`/`-fc` 过滤基准响应

## 注意
- 加 `-rate 50` 限速避免触发 WAF
- ffuf 结果 `-o json` 落盘，便于 agent 后续解析定位高价值路径
- 已知技术栈时优先用 `03-smart-directory-scan.md` 选词表
