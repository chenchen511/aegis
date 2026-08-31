# Aegis V6.4 智能体 Skill 安全前端设计

## 1. 目标

新增“智能体 Skill 安全”页面，完成主机 Skill 盘点、扫描任务、完整原文查看、规则/AI
研判、revision 对比和行为关联。页面必须准确表达覆盖和证据强度，不能把“未扫描”“部分
采集”“AI 失败”显示为安全。

## 2. 路由与菜单

建议路由：

```text
/detection/agent-skill-security
```

```ts
{
  path: '/detection/agent-skill-security',
  name: 'AgentSkillSecurity',
  component: () => import('@/views/detection/AgentGuard/AgentSkillSecurity.vue'),
  meta: { permission: 'agent_skill:read' }
}
```

菜单位于“检测响应”下，与配置检测、会话感知并列。feature flag 关闭或无 read 权限时不显示。

## 3. 页面结构

```text
AgentSkillSecurity.vue
  ├── SkillOverviewCards
  ├── SkillFilterBar
  ├── SkillInventoryTable
  ├── SkillScanDialog
  ├── SkillScanJobsDrawer
  ├── SkillSettingsDrawer
  └── SkillDetailDrawer
        ├── SkillOverviewTab
        ├── SkillContentTab
        ├── SkillFindingsTab
        ├── SkillAIAnalysisTab
        ├── SkillRevisionHistoryTab
        └── SkillRelatedBehaviorTab
```

建议文件：

```text
frontend/src/views/detection/AgentGuard/AgentSkillSecurity.vue
frontend/src/components/agentSkill/SkillOverviewCards.vue
frontend/src/components/agentSkill/SkillFilterBar.vue
frontend/src/components/agentSkill/SkillInventoryTable.vue
frontend/src/components/agentSkill/SkillScanDialog.vue
frontend/src/components/agentSkill/SkillScanJobsDrawer.vue
frontend/src/components/agentSkill/SkillSettingsDrawer.vue
frontend/src/components/agentSkill/SkillDetailDrawer.vue
frontend/src/components/agentSkill/SkillContentViewer.vue
frontend/src/components/agentSkill/SkillFindingList.vue
frontend/src/components/agentSkill/SkillRevisionDiff.vue
frontend/src/api/agentSkill.ts
frontend/src/types/agentSkill.ts
frontend/src/stores/agentSkill.ts
```

## 4. 顶部 KPI

| 卡片 | 定义 | 点击行为 |
| --- | --- | --- |
| 已发现 Skill | 当前未 disappeared 的逻辑 Skill | 清除风险筛选 |
| 当前有效 | effective state=effective | 筛选 effective |
| 高危/严重 | overall risk high/critical | 筛选高风险 |
| 发生漂移 | current revision != active baseline | 筛选 changed |
| 覆盖不完整 | latest coverage 非 complete | 筛选 coverage |
| 待研判 | open finding 数 | 筛选 open findings |

KPI 显示数据更新时间和 host coverage，不能把未扫描主机从分母中隐藏。

## 5. 筛选区

```text
主机
智能体：Codex / Claude Code / OpenClaw
主体 UID
来源 scope
生效状态
风险级别
覆盖状态
只看发生变化
只看已消失
关键词（名称/插件/主机，不搜正文）
```

支持重置、刷新、发起扫描、查看扫描任务。筛选状态可进入 route query，但禁止正文、路径、
finding excerpt 和 AI reason 进入 URL。

### 5.1 Skill 扫描主机选择

Skill 安全页的扫描入口直接复用 `GET /agent-guard/agents` 的已连接 Agent 列表，按 host 去重
后展示主机名、IP、在线状态和已发现的 Agent 类型。在线主机可以在下拉框中多选，离线主机只
用于提示并禁止提交；“一键扫描全部已连接主机”自动选中当前在线主机。前端最多并发 3 台主机，
单台主机仍调用兼容的 `GET /agent-guard/skills?host_id=...` 契约，部分主机失败时保留成功结果
并逐主机显示安全错误。

扫描完成后，跨主机合并的 Skill 清单通过 `/agent-guard/skills/inventory` 使用服务端分页（10/20/50
条）。扫描结果按主机保存最新完整快照，页面初始化/刷新先读取该接口，再展示当前页。Skill 详情采用“文件原文 / 规则命中”双栏布局；规则返回的 codepoint span
在左侧原文中以红色背景和文字高亮，右侧显示规则、严重级别、证据和定位按钮。内容以 Vue 纯文本
节点渲染，不将原文转换为 HTML。

## 6. Skill 列表

列：

```text
Skill 名称
智能体
主机/UID
来源 scope
生效状态
当前 revision（短 digest）
规则风险
AI 结论
综合风险
覆盖状态
最后发现时间
操作
```

交互：

- 名称缺失时显示目录名并标 invalid frontmatter；
- 同名副本显示 badge 和“查看同名关系”；
- shadowed 不隐藏；
- `unknown` 使用灰色警告，不用正常绿色；
- `no_known_risk` 仅在 complete 且无 open medium+ 时显示“未发现已知风险”；
- 列表不返回/展示完整绝对路径和 description，避免扩大正文权限面；
- 点击行打开详情 drawer，不跳新页面。

## 7. 发起扫描

### 7.1 Dialog

字段：

- 主机：1～50，多选，仅授权且已安装 Aegis Agent；
- 智能体：默认三类全选；
- scope：根据产品显示可选枚举；
- 内容模式：完整内容（默认）/仅元数据；
- 提示：完整内容不脱敏，将保存原始命令、URL、路径和可能的凭据；
- 计划任务不在 dialog 临时设置，进入 Settings。

提交前二次确认只说明数据范围，不要求用户输入 host path。

### 7.2 任务状态

任务 drawer 显示：host、agent types、mode、progress、bytes、skills、coverage、started、duration、
safe error。不能展示 Tool result 或原文。

取消按钮只在 queued/dispatching/collecting/storing 可见，并解释已入库内容不会删除。

## 8. 设置抽屉

仅 `agent_skill:settings:read` 可见，写操作需要 `agent_skill:settings:write`。

分区：

```text
采集
  adapter enable
  metadata/full content
  approved scopes/roots（只选已有策略，不输入路径）
  file/Skill/scan budgets

计划
  enabled
  interval（>=1h）
  jitter
  host scope

保留
  content days
  metadata days
  confirmed finding legal hold

规则
  catalog digest
  enable/threshold/trigger override

AI
  provider/model
  trigger policy
  allowed host scope
  full-content egress acknowledgement
```

完整内容外发确认必须明确展示“原始 Skill 内容可能包含凭据、内部路径、命令和 URL，将发送
给所选模型提供方”，记录操作者和版本。provider/model/scope 改变后确认失效。设置保存采用
optimistic version，并显示 policy 发布/Agent 投递状态。

## 9. 详情抽屉

宽度建议桌面端 80vw，最大 1440px；移动端全屏。header 显示 name、agent、host、scope、
effective/risk/coverage、revision digest。

### 9.1 概览 Tab

- 身份：agent type、scope、plugin、UID、完整路径（需 content 权限）；
- 生效：precedence、eligible/effective、同名副本关系和 resolution evidence；
- manifest：file count/bytes/digest/frontmatter status/capabilities；
- 时间：first/last/disappeared/baseline；
- 风险：规则、AI、行为 stage、coverage；
- 操作：重新扫描、重新分析、设 baseline（按权限）。

### 9.2 完整内容 Tab

只在 `agent_skill:content:read` 时显示。进入 Tab 后才发 content request。

布局：

```text
左侧文件树
  SKILL.md
  references/
  scripts/
  other text

右侧原文查看器
  absolute path / mode / owner / size / digest / encoding
  line number
  raw text
  finding highlights
```

原文查看器要求：

- 使用 `<pre><code>`/虚拟列表纯文本，不使用 `v-html`；
- 不把 Markdown 渲染为链接/图片；
- URL 不自动可点击；
- SVG/HTML/JS 作为文本；
- 控制字符可切换可视化，但默认原文不修改；
- 大文件按 byte/line range 加载；
- copy/download 操作受权限控制并写后端审计；
- drawer 关闭、权限撤销、登出时清空内存正文。

### 9.3 安全规则 Tab

顶部：rule run 状态、catalog digest、最高风险、命中数。列表：rule、category、severity、
context、actionability、file:line、excerpt、status。

点击 finding：

- 有 content 权限：跳到完整内容 Tab 并高亮 span；
- 无 content 权限：只显示分类/严重级别/文件 kind，不请求 excerpt。

支持 disposition dialog，必须填写理由。

### 9.4 AI 分析 Tab

- 状态：not authorized/not run/queued/running/succeeded/inconclusive/failed；
- provider/model/prompt version/ack version/usage；
- verdict/severity/confidence/categories；
- evidence/counter-evidence；
- uncertainties/recommended disposition；
- 手工重新分析按钮。

AI 未获 full-content egress approval 时显示明确原因，不提供“自动脱敏后分析”旁路。

### 9.5 版本历史 Tab

时间线：revision digest、first/last seen、scan、baseline、risk、file/byte count。选择两个 revision
进行 diff：

- manifest diff 可用 metadata 权限；
- frontmatter/body/script 原文 diff 需要 content 权限；
- 文件增删、mode/owner、capability、text lines 分层展示；
- mtime-only observation 不显示为新 revision。

### 9.6 关联行为 Tab

分组：capability_only、probable_use、confirmed_use、impact_observed。展示关联时间、session/tool/
event/finding ID、confidence 和证据类型。probable 使用“可能关联”，禁止“已执行”文案。

## 10. TypeScript 类型

```ts
export type AgentSkillAgentType = 'codex' | 'claude-code' | 'openclaw'
export type AgentSkillCoverage =
  | 'complete' | 'partial' | 'metadata_only' | 'root_not_found'
  | 'permission_denied' | 'unsupported' | 'budget_exhausted'
  | 'policy_rejected' | 'offline' | 'failed'
export type AgentSkillEffectiveState =
  | 'effective' | 'shadowed' | 'duplicate' | 'disabled' | 'ineligible' | 'unknown'
export type AgentSkillRisk = 'unknown' | 'info' | 'low' | 'medium' | 'high' | 'critical'

export interface AgentSkillListItem {
  id: string
  host_id: string
  agent_type: AgentSkillAgentType
  declared_name?: string
  scope: string
  effective_state: AgentSkillEffectiveState
  revision_digest?: string
  rule_risk: AgentSkillRisk
  ai_risk: AgentSkillRisk
  overall_risk: AgentSkillRisk
  coverage: AgentSkillCoverage
  last_seen_at?: string
}
```

正文类型不进入 Pinia 持久 store：

```ts
export interface AgentSkillFileContent {
  revision_id: string
  file_id: string
  absolute_path: string
  encoding: string
  offset: number
  total_size: number
  content: string
  content_digest: string
}
```

## 11. API 层

`frontend/src/api/agentSkill.ts` 封装：

```text
getAgentSkillOverview
listAgentSkills
getAgentSkill
listAgentSkillRevisions
listAgentSkillFiles
getAgentSkillFileContent
diffAgentSkillRevisions
createAgentSkillScans
listAgentSkillScans
getAgentSkillScan
cancelAgentSkillScan
listAgentSkillRules
listAgentSkillFindings
analyzeAgentSkillRevision
updateAgentSkillFindingDisposition
setAgentSkillBaseline
get/updateAgentSkillSettings
```

content 请求必须设置取消 token；切换 Skill/file/drawer 后取消旧请求，防止原文串到新详情。

## 12. 状态管理

Pinia 只保存：filters、list metadata、selected IDs、scan jobs、rule/AI metadata。禁止持久化：

```text
file content
absolute path
evidence excerpt
AI detailed reason
revision raw diff
```

正文只存在组件局部 shallowRef，关闭/切换/403/登出时置空。

## 13. 权限行为

| 权限 | UI |
| --- | --- |
| 无 read | 无菜单/路由 403 |
| read | 列表、metadata、风险摘要 |
| content:read | 完整路径、正文、excerpt、原文 diff |
| scan | 扫描/取消按钮 |
| analyze | 手工 AI 按钮 |
| review | disposition 操作 |
| baseline:write | baseline 操作 |
| settings | 设置入口 |

权限在 drawer 打开期间撤销时：立即取消 content 请求、清空正文、隐藏 Tab，并显示权限变化。

## 14. Loading/Empty/Error

必须覆盖：

- 首次 loading skeleton；
- 无纳管主机；
- 主机从未扫描；
- 扫描完成且无 Skill；
- Agent offline/unsupported；
- partial/metadata_only；
- MinIO/content expired；
- rule/AI queued/running/failed/inconclusive；
- WebSocket 断开；
- 403 权限变化；
- content range/digest error。

保留已有 metadata 时，刷新错误不清空列表；原文 digest error 时清空当前正文，不能展示旧内容。

## 15. i18n

新增：

```text
frontend/src/i18n/locales/zh-CN/agentSkill.ts
frontend/src/i18n/locales/en-US/agentSkill.ts
```

重要中文文案：

- 智能体 Skill 安全
- 完整内容不脱敏
- 未发现已知风险
- 覆盖不完整，无法确认全部内容
- 发现静态能力，未观察到执行
- 已确认使用
- 已观察到行为影响
- AI 未获完整内容外发授权

## 16. 可访问性与响应式

- 风险/状态不能只靠颜色；
- 表格和 drawer 支持键盘焦点；
- 原文行号/高亮不破坏屏幕阅读顺序；
- 1024px 以下隐藏次要列，详情全屏；
- 代码区可横向滚动，页面本身不横向溢出；
- 动画遵循 reduced motion。

## 17. 前端测试

### Unit/Component

- risk/coverage/effective label；
- filter/query 序列化不含正文；
- 权限矩阵；
- content viewer HTML/SVG/script/URL 纯文本；
- 大文件 range 和取消请求；
- finding -> span 定位；
- revision diff 权限；
- drawer close 清空正文；
- WebSocket metadata refresh。

### E2E

1. 发起三产品 scan -> 任务 -> 列表更新；
2. 打开 Skill -> 完整原文 -> rule span；
3. 无 content 权限不产生 content API 请求；
4. 权限实时撤销后正文清空；
5. 同名 shadow/duplicate 关系可见；
6. partial/offline/unsupported 不显示安全；
7. AI 未授权/运行/失败/成功状态；
8. revision diff 和 baseline；
9. XSS/Markdown/URL 不执行；
10. URL/storage/console/analytics/错误上报无原文。

## 18. 前端验收

- 页面功能覆盖 PRD 所有用户场景；
- 原文按权限延迟加载且不脱敏；
- UI 不执行原文；
- 状态语义与后端完全一致；
- 规则/AI/行为/coverage 独立；
- 所有异常/权限/空状态可理解；
- 正文不持久化、不进遥测；
- 首版无自动禁用/删除/隔离按钮。
