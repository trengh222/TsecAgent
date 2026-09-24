---
name: scenario-playbook
description: Web 渗透测试场景方法论速查表。当目标含登录框、API 接口、文件上传、搜索框、支付、注册、评论、后台、文件下载、短信验证码、SSRF 触发点、文件包含等高频场景时，提供"该场景应测的全部角度"清单，避免只测当前方向的单一漏洞（如登录框只会 SQL 注入而漏掉弱口令爆破）。
license: MIT
metadata:
  user-invocable: "false"
---

# Web 渗透场景方法论速查表

本 skill 是「场景 → 多角度」的横向速查：方向是纵向（一个漏洞深挖），场景是横向（一个场景多角度）。

数据在 [scenarios.yaml](scenarios.yaml)，由 graph.py 服务端确定性加载并注入 Planner 提示词——识别目标 URL / 威胁模型入口点 / 任务描述所处的场景后，注入该场景的「角度清单 + 关联手册 payload 片段」。

## 覆盖场景

登录/认证、API 接口、文件上传、搜索/查询、支付/订单、密码重置/找回、注册流程、评论/留言、个人中心/用户信息、文件下载/读取、短信/验证码、后台管理、SSRF/URL 跳转、文件包含。

## 字段说明

- `regex`：场景识别正则（对目标 URL + 入口点 + 任务描述做 IGNORECASE 匹配）
- `name`：场景中文名
- `angles`：该场景应测的全部角度（不止当前方向的单一漏洞）
- `files`：关联的 secknowledge 手册文件名（服务端读取 payload 片段注入）

## 扩展

新增场景只需在 [scenarios.yaml](scenarios.yaml) 的 `scenarios` 列表加一条 `{regex, name, angles, files}`，无需改动任何执行逻辑。
