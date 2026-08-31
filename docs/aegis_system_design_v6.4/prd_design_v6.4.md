# Aegis V6.4 智能体 Skill 安全 PRD

## 1. 产品背景

Skill 已成为 Codex、Claude Code、OpenClaw 扩展能力和固化工作流的主要载体。一个 Skill
可以通过 description 被自动选择，在正文中改变智能体的决策流程，通过引用文件扩大上下文，
并通过脚本、动态命令和工具权限触发真实操作。企业目前缺少统一视角来回答：

- 哪些主机和用户安装了哪些 Skill；
- Skill 来自个人、项目、workspace、受管目录还是插件；
- 同名 Skill 中哪份生效，是否发生可信名称遮蔽；
- Skill 完整内容是什么，何时发生变化；
- 是否包含投毒、提示词攻击、越狱、审批绕过或敏感数据外传能力；
- 风险只是静态能力，还是已有会话/工具/eBPF 证据确认执行。

V6.4 建立完整的 Skill 资产发现、原文提取、版本追踪和安全分析产品。它是 Agent Guard
下的新领域，不替代配置检测、会话感知或运行时防护。

## 2. 产品目标

### 2.1 核心目标

1. 在一套页面中盘点 Codex、Claude Code、OpenClaw 的 Skill；
2. 获取并展示完整原始 `SKILL.md`、引用文本、脚本和文件 manifest；
3. 准确表达每种产品的 source scope、优先级、eligible/effective 和同名关系；
4. 识别 Skill 投毒、提示词攻击、提示词越狱、检测规避和高风险执行能力；
5. 通过 revision digest 追踪首次发现、变化、消失、恢复和外部修复；
6. 将确定性规则、AI 语义判断和运行时事实分层展示；
7. 在完整原文不脱敏的前提下，通过权限、加密、审计和数据最小分发保护内容。

### 2.2 非目标

- 不提供 Skill 商店、下载、安装、更新、编辑和运行；
- 不自动 quarantine、disable、delete 或修改任何产品配置；
- 不根据静态文本直接 freeze/kill Agent；
- 不把 Skill 内容风险等同于已经执行或造成影响；
- 不适配 Codex、Claude Code、OpenClaw 之外的产品；
- 不扫描任意目录，不支持用户在页面输入自定义文件路径。

## 3. 产品角色

| 角色 | 核心诉求 | 默认权限建议 |
| --- | --- | --- |
| 安全管理员 | 全局盘点、发起扫描、查看完整原文、规则/AI 研判、确认风险 | 全部 Skill 权限 |
| 安全分析师 | 查看资产/原文/证据、发起分析、处理 finding | read/content/analyze/review |
| 主机管理员 | 查看授权主机、发起扫描、定位外部修复路径 | scoped read/content/scan |
| 审计员 | 查看元数据、revision、finding、操作记录 | read/audit，不含原文可选 |
| 普通用户 | 默认不可访问 Skill 安全模块 | 无 |

完整正文权限必须与元数据权限分离。`full_access`、Assistant 模式或其他 Agent Guard 权限
不能隐式获得 `agent_skill:content:read`。

## 4. 术语

| 术语 | 定义 |
| --- | --- |
| Skill | 某产品可发现的一个 Skill 逻辑位置，不以名称作为唯一身份 |
| Binding | 同一物理目录在某个 agent type/source scope 下的产品语义 |
| Revision | Skill 文件 manifest 和原始内容 digest 确定的不可变版本 |
| Full content | 未脱敏、未掩码的原始文本、frontmatter、脚本、命令、URL 和路径 |
| Source root | adapter 或签名策略批准的 Skill 根目录 |
| Effective | adapter 根据当前产品规则确认生效/可选择的副本 |
| Shadowed | 被更高优先级同名副本遮蔽 |
| Duplicate | 产品允许同名副本同时出现或需要 qualified name |
| Eligible | OpenClaw gating/allowlist 或产品配置判断该 Skill 当前可用 |
| Finding | 规则、AI 或运行时关联产生的独立风险证据 |
| Drift | 相对已确认/稳定 baseline revision 的内容或关键能力变化 |

## 5. 关键用户场景

### US-01 全局盘点

作为安全管理员，我希望查看所有在线/离线主机上的三类 Skill、数量、来源和最后扫描时间，
以确认组织的智能体扩展面。

验收：

- 支持主机、agent type、scope、effective state、risk、coverage 和关键词过滤；
- 离线/从未扫描/stale/partial 与“没有 Skill”严格区分；
- 同名 Skill 不合并隐藏。

### US-02 手工获取

作为主机管理员，我希望选择一台或多台授权主机发起 Skill 获取，查看每台任务的进度和
失败原因。

验收：

- 请求只能选 host、agent type、scope 和 metadata/full 模式，不能输入路径；
- 返回每台主机独立 job，支持排队、运行、完成、partial、失败和取消等待态；
- 同一 host 同策略任务不并发重复扫描。

### US-03 查看完整原文

作为安全分析师，我希望按文件查看完整原始 Skill 内容和引用关系，以准确研判提示词和脚本。

验收：

- `SKILL.md`、引用文本和脚本保持原始字符、换行和内容，不做脱敏；
- 显示绝对路径、相对路径、owner、mode、size、digest、语言和引用边；
- 正文只由具备 `agent_skill:content:read` 的用户加载；
- 文本安全转义，不执行 HTML、SVG、Markdown link、脚本或动态上下文；
- API `Cache-Control: no-store`，前端不持久化正文。

### US-04 识别同名投毒

作为安全管理员，我希望看到可信名称被项目/workspace 高优先级副本遮蔽或出现新 digest，
以判断供应链投毒。

验收：

- 展示所有副本及 adapter precedence evidence；
- 首次发现标 new/unbaselined，不伪造 drift；
- confirmed baseline 变化后产生 drift finding；
- 不同产品的同名解析语义独立。

### US-05 提示词攻击检测

作为安全分析师，我希望检测 Skill 是否试图覆盖系统指令、越狱、绕过审批、窃取提示词、
关闭审计或诱导外传。

验收：

- 规则命中定位到 revision/file/span/字符区间；
- 规则和 AI 独立展示；
- 安全检测/教学样例不因单关键词直接被判恶意；
- AI 无工具、不能按 Skill 指令执行动作或伪造证据。

### US-06 Revision 对比

作为分析师，我希望比较任意两个 revision，定位 frontmatter、指令、引用、脚本、权限和
digest 的变化。

验收：

- 支持文件增删改、manifest 和文本 diff；
- 原文 diff 仅对正文权限用户开放；
- baseline/current/selected revision 明确；
- 大文件 diff 有上限和下载/分页策略，不阻塞页面。

### US-07 人工处置

作为分析师，我希望确认 finding、标记误报、接受风险或记录外部修复。

验收：

- disposition 需要理由和 optimistic version；
- 保留原 severity、规则版本、证据和历史操作；
- `remediated_external` 不代表验证通过，必须等待新 scan/revision；
- 无自动主机写入或禁用动作。

### US-08 关联实际行为

作为安全管理员，我希望区分“Skill 有危险能力”和“该能力已经运行”。

验收：

- 静态 finding 默认 `capability_only`；
- exact invocation/script digest/tool call 才能标 confirmed；
- 仅时间窗口关系标 probable；
- eBPF/工具行为确认影响后标 impact_observed。

## 6. 产品信息架构

菜单位置：

```text
检测响应
  智能体事件感知与防护
  智能体逃逸防护
  智能体配置检测
  智能体会话感知
  智能体 Skill 安全        <- V6.4
```

页面结构：

```text
智能体 Skill 安全
  ├── 顶部 KPI
  ├── 筛选与批量扫描
  ├── Skill 列表
  ├── 扫描任务抽屉
  └── Skill 详情抽屉
        ├── 概览
        ├── 完整内容
        ├── 安全规则
        ├── AI 分析
        ├── 版本历史
        └── 关联行为
```

首版采用单页面 + drawer，不拆多个菜单，减少 Agent Guard 导航膨胀。

## 7. 功能需求

### FR-001 Skill 扫描任务

- 手工扫描支持 1～50 台已授权主机；
- agent types 仅允许 `codex|claude-code|openclaw`；
- scope 由服务端枚举，不接收路径；
- content mode 为 `metadata_only|full_content`；
- 默认 `full_content`，受 collection policy 上限约束；
- 同一 host + policy + scope 只有一个 active job；
- 支持计划任务，默认关闭，默认周期 24 小时、最小 1 小时。

### FR-002 三产品发现

- Codex：repo `.agents/skills`、user `.agents/skills`、admin `/etc/codex/skills`、受支持
  legacy home 和已启用 plugin skills；
- Claude Code：enterprise、personal `.claude/skills`、project/nested、plugin 和 synced；
- OpenClaw：workspace、project-agent、personal-agent、managed、bundled、extra/plugin；
- 每个来源保存 adapter version、scope、precedence、eligible/effective evidence；
- unknown layout 标 unsupported，不使用全盘 `find SKILL.md` 兜底。

### FR-003 完整内容提取

- 原样读取 `SKILL.md`；
- 解析并保留完整 frontmatter 与 Markdown body；
- 读取 Skill 根内被引用的支持文本；
- 读取支持语言脚本原文；
- 不支持的二进制/图片/归档只保存 metadata 和 digest；
- 原始正文、URL、命令、secret、路径不做脱敏；
- 不做变量替换、动态命令执行、脚本执行、URL 下载或归档解包。

### FR-004 文件 manifest 与引用图

- 每个文件保存绝对路径、相对路径、kind、language、mode、owner、size、mtime、digest；
- 保存 SKILL.md -> reference -> script 的有向图；
- cycle、越界、缺失、过深和 unsupported node 明确显示；
- revision digest 覆盖排序 manifest、内容 digest、mode 和 symlink state。

### FR-005 原文存储与访问

- PostgreSQL 不保存大段正文；
- MinIO 保存完整原文对象，按 tenant/host/revision 加密；
- API 下载前校验 tenant、host scope、正文权限和 object ownership；
- 所有原文访问写安全审计；
- 正文不进入日志、普通错误、指标、WebSocket、通知和前端持久化。

### FR-006 规则检测

- 投毒/来源：同名遮蔽、异常 drift、冒充、宽触发、越界引用；
- 提示词：指令覆盖、角色伪造、越狱、审批绕过、系统提示窃取、分析器操控；
- 防御规避：关闭 Aegis/日志/Hook、隐瞒副作用、伪造成功；
- 执行能力：动态命令、download-execute、secret 读取、网络外传、破坏、提权；
- 完整性：解析失败、超限、unknown adapter、文件权限异常。

### FR-007 AI 分析

- 支持 manual、rule_hit_only、all_changed；
- 默认 `rule_hit_only`，上线初期 shadow；
- 输入使用完整原文，不脱敏；
- 管理员必须明确配置允许当前 LLM provider 接收完整 Skill 内容；
- AI client 无工具、无 MCP、无文件/网络/动作 callback；
- 输出强制 schema，evidence ID 必须属于当前 revision；
- AI 不能降低规则风险。

### FR-008 Revision 与 baseline

- 首次 revision 为 `new_unbaselined`；
- 支持管理员确认 baseline；
- 内容/mode/source/关键 frontmatter 变化生成新 revision；
- mtime-only 不生成新 revision；
- Skill 消失只标 disappeared，不删除历史；
- 外部恢复旧 digest 仍记录新的 scan observation。

### FR-009 Finding 研判

- disposition：open、confirmed、dismissed_false_positive、accepted_risk、remediated_external；
- 支持 reason、operator、time、version 和审计；
- 规则/AI/behavior finding 不相互覆盖；
- 新 revision 默认重新分析，不继承旧 disposition 为已解决。

### FR-010 实时更新

- WebSocket 只发送 scan/revision/finding/analysis 状态 ID 和计数；
- 不发送原文、命令、URL、路径、evidence excerpt；
- 前端收到通知后按权限 REST 刷新。

### FR-011 设置与策略

- 三类 adapter 可分别启用/关闭；
- 配置 metadata/full-content、文件/Skill/任务预算、保留期和计划周期；
- 额外 workspace/root 只能从已批准主机策略中选择，不能输入任意路径；
- 规则目录只读，tenant 设置只控制 enable/threshold/trigger，不原地修改内置定义；
- AI 设置展示 provider/model、trigger、允许的 host scope 和完整内容外发确认；
- provider、model、数据策略或允许 scope 变化后必须重新确认 full-content egress；
- 所有设置变更版本化、审计并可回滚到上一已发布版本。

## 8. 状态语义

### 8.1 Scan job

```text
queued | dispatching | collecting | storing | rules_pending | rules_running
ai_pending | ai_running | completed | partial | failed | cancelled
```

### 8.2 Coverage

```text
complete | partial | metadata_only | root_not_found | permission_denied
unsupported | budget_exhausted | policy_rejected | offline | failed
```

### 8.3 Extraction

```text
complete | partial | metadata_only | invalid_frontmatter
unsupported_encoding | too_large | missing_reference | failed
```

### 8.4 Effective

```text
effective | shadowed | duplicate | disabled | ineligible | unknown
```

### 8.5 Risk

```text
unknown | info | low | medium | high | critical
```

`complete + no open medium+ finding + AI no_known_risk` 才能显示“未发现已知风险”。任何
partial/unsupported/failed/unknown 必须同时显示覆盖警告。

## 9. 权限模型

```text
agent_skill:read
agent_skill:content:read
agent_skill:scan
agent_skill:analyze
agent_skill:review
agent_skill:baseline:write
agent_skill:settings:read
agent_skill:settings:write
agent_skill:audit:read
```

权限同时受 tenant、host scope 和数据保留策略约束。正文 API 不能只依赖 Skill ID；必须
校验 Skill -> host -> tenant ownership。Assistant 工具首版只开放聚合查询，不开放完整原文。

## 10. 非功能需求

### 10.1 安全

- Agent/Server/api-server 使用现有双向认证链路；
- 原文对象服务端加密并支持密钥轮换；
- 正文 API `Cache-Control: no-store`；
- 前端纯文本展示，不执行 Markdown/HTML/SVG/URL；
- 原文访问 100% 审计；
- 未授权表面原文泄漏为 0。

### 10.2 性能与容量

- 单页 Tool response <= 512 KiB；
- 单文件默认 <= 2 MiB，单 Skill <= 16 MiB，单 scan <= 256 MiB；
- 单 host 默认最多 2,000 Skill、每 Skill 256 文件；
- 列表 P95 <= 500 ms，详情 metadata P95 <= 500 ms；
- 原文首屏 P95 <= 2 s（不含超大文件后续分页）；
- 规则任务排队 P95 <= 2 分钟，AI 排队 P95 <= 15 分钟。

### 10.3 可靠性

- scan page、revision、finding 和 AI run 幂等；
- API/Agent 重启后任务可恢复；
- MinIO 不可用时 metadata 可保存但任务必须 partial；
- LLM 不可用不影响规则结果和原文查看。

### 10.4 兼容

- 旧 Agent 返回 capability unsupported；
- flags off 时不改变 V6.2/V6.3 数据流；
- adapter unknown fail closed；
- migration 037 只新增结构。

## 11. 产品指标

| 指标 | 目标 |
| --- | --- |
| 纳管主机 Skill scan coverage | 灰度稳定后 >= 95% |
| 支持 adapter 解析成功率 | >= 99% 已声明版本 |
| 完整原文 digest 对账率 | 100% |
| 同名副本丢失率 | 0 |
| 未授权表面原文泄漏 | 0 |
| 规则 finding 可定位率 | 100% |
| 重复 revision/finding/AI 计费 | 0 |
| AI invalid output | < 5% |
| 分析师 finding 推翻率 | shadow 阶段持续观测，不预设虚假目标 |

## 12. 产品验收清单

1. 三类产品各完成至少一个完整 E2E；
2. 用户/项目或 workspace/插件来源可见；
3. 完整原文和 Agent digest 对账一致；
4. 原文只能由正文权限用户获取；
5. 同名优先级和 drift 正确；
6. 投毒、注入、越狱、审批绕过和外传规则可定位证据；
7. 防御性样例不会仅凭关键词判恶意；
8. AI 攻击测试不产生工具调用或跨 revision 证据；
9. partial/offline/unsupported 不显示安全；
10. scan 重试和组件重启不重复数据；
11. 页面所有 loading/empty/error/permission/stale 状态完成；
12. 关闭 V6.4 后 V6.2/V6.3 无回归。
