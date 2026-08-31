# Aegis V6.4 设计文档

- **版本**：V6.4 方案版
- **日期**：2026-08-31
- **状态**：设计完成，V6.4 垂直切片已实现（Agent 采集、静态规则、API、前端、迁移骨架）
- **首批适配产品**：Codex、Claude Code、OpenClaw
- **主题**：智能体 Skill 获取、完整内容提取、提示词攻击与投毒检测

## 1. 版本定位

V6.4 在 V6.2 Agent Guard 的智能体识别、配置检测和运行时行为证据，以及 V6.3 的
会话提示词安全分析之上，新增独立的“智能体 Skill 安全”产品域：

```text
Codex / Claude Code / OpenClaw 已安装 Skill
  -> Aegis Agent 只读发现
  -> 完整原文提取（SKILL.md、引用文本、脚本）
  -> 版本、来源、同名优先级和漂移盘点
  -> 确定性投毒/提示词/执行能力规则
  -> 无工具 AI 语义分析
  -> 前端展示、告警、人工研判和版本追踪
```

V6.4 的“获取”仅指从受控主机读取已经存在的 Skill，不包含联网搜索、市场下载、安装、
更新、启用或执行 Skill。“完整内容提取”不做内容脱敏或字段掩码，保存原始
`SKILL.md`、引用文本、脚本、frontmatter、URL、命令和绝对路径。为控制原文风险，系统
使用 mTLS、对象加密、细粒度 RBAC、访问审计、`no-store` 和日志禁载，而不是修改内容。

## 2. 用户结果

- 查看每台主机上 Codex、Claude Code、OpenClaw 的完整 Skill 清单；
- 查看用户、项目、workspace、受管、插件等来源和实际生效/遮蔽关系；
- 查看完整原始 Skill 内容、文件清单、引用图、脚本和 revision 历史；
- 检测 Skill 投毒、提示词注入、提示词攻击、越狱、审批绕过、系统提示窃取、隐瞒、
  凭据访问、数据外传和高风险执行能力；
- 分开查看规则结果、AI 结果、覆盖状态和运行时行为证据；
- 对 finding 做确认、误报、接受风险和外部已修复标记；
- V6.4 不自动删除、修改、禁用或隔离主机上的 Skill。

## 3. 文档索引

| 文档 | 内容 |
| --- | --- |
| [prd_design_v6.4.md](prd_design_v6.4.md) | 完整 PRD、用户角色、场景、功能需求、页面范围、指标和产品验收 |
| [overall_architecture_design_v6.4.md](overall_architecture_design_v6.4.md) | 总体架构、组件边界、数据流、信任边界、状态和核心决策 |
| [agent_skill_collection_design_v6.4.md](agent_skill_collection_design_v6.4.md) | Agent 三产品适配、发现根、完整原文提取、路径安全、分页和资源限制 |
| [backend_api_protocol_design_v6.4.md](backend_api_protocol_design_v6.4.md) | api-server/Server 服务、任务、HTTP API、工具协议、RBAC、WebSocket 和错误 |
| [database_design_v6.4.md](database_design_v6.4.md) | migration 037、表、索引、对象存储、幂等、保留和回滚 |
| [security_analysis_design_v6.4.md](security_analysis_design_v6.4.md) | 威胁模型、规则目录、AI 分析、证据、风险聚合与误报控制 |
| [frontend_design_v6.4.md](frontend_design_v6.4.md) | 路由、页面、组件、状态、完整原文查看、权限和前端测试 |
| [implementation_test_rollout_v6.4.md](implementation_test_rollout_v6.4.md) | 分阶段实施、测试矩阵、E2E、日志指标、灰度、停止条件和回滚 |

## 4. 核心决策

| 编号 | 决策 |
| --- | --- |
| V64-D01 | 首批只适配 Codex、Claude Code、OpenClaw，不提供通用 AgentSkills 猜测解析 |
| V64-D02 | 只获取本机已存在 Skill，不联网下载、安装、更新或执行 |
| V64-D03 | 采集完整原文，不脱敏、不掩码、不伪名化；原始内容可被授权用户查看和安全分析 |
| V64-D04 | 原文只进入 mTLS 链路、加密对象和授权 API；日志、指标、WebSocket 通知不承载原文 |
| V64-D05 | 扫描根只来自 adapter 默认根或已签名策略，HTTP/工具请求不能传任意路径 |
| V64-D06 | `SKILL.md`、引用和脚本都只静态读取；变量、动态上下文、脚本和安装器一律不执行 |
| V64-D07 | Skill 身份由 host、UID、agent type、source root、相对位置组成，不能只按名称去重 |
| V64-D08 | 同名副本全部保存，并计算 effective/shadowed/duplicate/disabled/ineligible/unknown |
| V64-D09 | 完整原文保存到 MinIO 加密对象，PostgreSQL 保存索引、manifest、digest、证据和状态 |
| V64-D10 | 规则和 AI 独立；AI 无工具、强制 schema，不能降低规则风险或执行处置 |
| V64-D11 | 未命中只表示 `no_known_risk`；partial/unsupported/failed 不能显示为安全 |
| V64-D12 | 静态 Skill 是能力证据，不等于已执行；执行事实只能来自可信 Hook/eBPF/行为链 |
| V64-D13 | 首版复用白名单 ToolExecute 分页拉取，不新增 Kafka；单页/单文件/单任务均有硬上限 |
| V64-D14 | migration 使用 `037_v6.4_agent_skill_security.sql` 与 `038_v6.4_agent_skill_scan_snapshots.sql`，只新增表和权限 |
| V64-D15 | V6.4 只检测、展示、告警和人工研判，不自动禁用、隔离、删除或修改 Skill |
| V64-D16 | 功能默认关闭，按 metadata -> full content -> rules -> AI -> scheduled scan 灰度 |

## 5. 完成标准

当前代码已落地首个可运行垂直切片：三类 Agent 的只读 Skill 发现与分页原文提取、服务端
ASK 静态规则检测、同名来源遮蔽标记、Agent Guard API、前端原文/证据查看和 migration 037
骨架。当前扫描结果还会按主机保存最新完整快照，页面刷新可恢复原文和规则命中，并由服务端分页读取；异步 durable worker、MinIO 对象归档、AI worker、revision 持久化与调度属于后续增量，
不会改变本切片的 Tool/API schema。

1. Codex、Claude Code、OpenClaw 的用户/项目或 workspace/受管/插件来源具有版本化 adapter、
   current/previous/unknown fixture 和明确降级状态。
2. 同名 Skill 的所有副本、来源优先级和生效关系完整展示，不因名称去重隐藏投毒证据。
3. `SKILL.md`、被引用文本和脚本以原始字节完整采集，中心 digest 与 Agent 原始 digest 一致；
   不执行动态上下文、脚本、安装器、变量替换或网络请求。
4. symlink、path traversal、TOCTOU、FIFO/device、超深目录、超大文件和引用逃逸均被阻止；
   扫描不越过批准 root，也不修改来源文件。
5. 原文在 mTLS、加密 MinIO、细分正文权限和访问审计下可用；未授权 API/UI、日志、指标、
   WebSocket 和错误信息中的原文泄漏数为 0。
6. 规则覆盖 Skill 投毒、提示词注入、越狱、审批绕过、提示窃取、混淆、检测规避、隐瞒、
   secret 访问/外传和高风险执行链。
7. 安全检测、红队和教学 Skill 中的攻击样例不会仅因关键词被宣称恶意，证据保留
   instruction/example/quoted/script 上下文和 actionability。
8. AI 使用完整原文时无任何工具和动作权限，伪造 verdict/evidence ID、索取系统提示和
   要求执行命令的输入被拒绝或标记 inconclusive。
9. 规则、AI、coverage、extraction、effective state 和综合风险独立可见；AI 失败不覆盖
   规则，覆盖不足不显示 clean。
10. revision 漂移、消失、重现、分页重放和任务恢复可审计且幂等，不产生重复 revision、
    finding 或 AI 计费。
11. 页面具备总览、列表、完整内容、规则命中、AI 分析、版本历史和关联行为，满足完整的
    加载、空、错误、离线、partial、stale 和权限状态。
12. V6.4 flags 关闭时，V6.2 Agent Guard、V6.3 会话感知和 MCP 聚合治理无行为回归。

## 6. 不在 V6.4 范围

- Skill 市场、ClawHub、Git、URL 或上传包的下载、安装和更新；
- 自动修改、禁用、隔离或删除 Skill；
- Windows、远程 OpenClaw node 和容器镜像离线扫描；
- OCR、图片隐写、二进制反编译、归档递归解包和依赖 CVE 扫描；
- 证明某条静态 Skill 一定被调用或已经攻击成功；
- Codex、Claude Code、OpenClaw 之外产品的兼容实现。

## 7. 参考资料

路径和格式按 2026-08-31 的官方资料校准，实现必须以 adapter version 和 fixture 固化：

- [OpenAI：Build skills](https://developers.openai.com/codex/skills)
- [Anthropic：Extend Claude with skills](https://code.claude.com/docs/en/skills)
- [Anthropic Agent SDK：Extend agents with skills](https://code.claude.com/docs/en/agent-sdk/skills)
- [OpenClaw：Skills](https://github.com/openclaw/openclaw/blob/main/docs/tools/skills.md)
- [Agent Skills 开放规范](https://agentskills.io/)
