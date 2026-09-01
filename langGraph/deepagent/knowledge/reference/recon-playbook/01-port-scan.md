# 端口扫描 Playbook

替代 MCP 工具 `recon_port_scan`。用 `execute_shell` 调 nmap，参数自由度远高于封装工具
（原工具仅 target/ports/timeout，无法加 `-sC`/`--script`）。

## 适用场景
- 资产发现、开放端口枚举、服务版本识别、漏洞脚本探测
- 目标为 IP / 域名 / CIDR

## 依赖
- nmap（需在 PATH；Windows 常装于 `C:\Program Files (x86)\Nmap\`）

## 命令模板

### 1. 主机存活探测
```bash
nmap -sn -PE -n 192.168.1.0/24
```
判读：`Host is up` 列表即存活主机，先缩小目标范围。

### 2. 快速全端口扫描
```bash
nmap -p- --min-rate=5000 -T4 --open target -oN ports.txt
```
用途：先枚举所有开放端口，再对开放端口做深度扫描。

### 3. 指定端口服务指纹
```bash
nmap -sV -sC -p 80,443,8080,8443,3306,6379 -T4 target
```
`-sV` 版本探测，`-sC` 默认脚本（含 Banner、部分漏洞检查）。

### 4. 漏洞脚本探测
```bash
nmap --script vuln -p 80,443 target
```
脚本库位置：`/usr/share/nmap/scripts/`（Linux）。

### 5. UDP 顶部端口
```bash
nmap -sU --top-ports 50 -T3 target
```
UDP 较慢，缩小端口范围。

## 参数选择
| 目的 | 推荐参数 |
|---|---|
| 内网快速摸底 | `-sn -PE` |
| Web 资产 | `-sV -sC -p 80,443,8080,8443` |
| 全资产枚举 | `-p- --min-rate=5000` |
| 漏洞验证 | `--script vuln,banner` |
| 数据库/缓存 | `-p 3306,5432,6379,27017,9200` |

## 结果判读
- `open` 端口为重点；`filtered` 多为防火墙过滤
- 服务版本用于后续 A06（已知漏洞组件）方向匹配 nuclei 模板
- 用 `-oN result.txt` 落盘后，再 `execute_shell` 读取解析

## 注意
- 大规模扫描降速：`-T3` 或 `--max-rate 1000`
- Windows 环境部分扫描需管理员权限（SYN scan 等）
- 触发 WAF/IPS 时降速并减少并发
