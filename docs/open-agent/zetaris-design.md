# Zetaris 集成设计（Open Agent Wildcard 用，代码待账号）

## 为什么是 Zetaris，而不是硬贴
Wildcard 要求集成 Zetaris + Meterless，且只按新工作打分。Meterless 已有
可跑的适配器（见 meterless-adapter/）。Zetaris 是数据层：它把碎片数据源
连成可查询的湖仓。对 agent-guard 来说，最诚实、最有用的接法不是"查数据
做决策"（guard 决策必须快、本地、fail-open，不能依赖远端查询），而是
**审计写入**：每一次拦截/警告/语义评审 verdict，都写成一行结构化记录
进 Zetaris 表。这样：
- 评审叙事成立：guard 的决策变成可跨源调查的证据（呼应 Track 02
  "有证据的答案"），而不是黑盒日志。
- 不破坏 guard 的 fail-open 哲学：写入失败只记本地日志，绝不影响拦截决定。
- 新工作边界清晰：写入器 + 表结构 + 一段"事后调查"演示，全是比赛窗口内新增。

## 接口契约（账号到手后按控制台核对，不猜字段）
- 写路径：审计事件（时间、命令/diff 摘要 hash、pattern  verdict、语义 verdict、
  模型名、耗时）-> Zetaris 表（表名、认证方式、endpoint 以控制台为准）。
- 读路径（演示用）：按时间/ verdict 查最近 N 条决策，拼成"为什么这条命令
  被拦"的证据链页面或 CLI 输出。
- 失败策略：写入超时/失败 -> 本地 append-only 日志兜底，下次重放（不丢事件，
  不阻塞 hook）。

## 待他
1. Zetaris 账号 + credits（开工当天领，build-plan §7 已列）
2. 控制台确认：API endpoint、认证方式、建表/写入 API 的确切字段
3. 确认后，写入器代码约 1–2 小时可写完（含 mock 测试）
