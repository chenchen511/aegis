# Aegis V6.4 后端、API 与工具协议设计

## 1. 组件变更

| 组件 | 新增职责 |
| --- | --- |
| Agent | `AgentSkillScan`、三 adapter、完整原文分页 |
| Server | 认证并透明转发固定 Tool 请求/响应 |
| api-server | 扫描任务、对象写入、inventory/revision、规则/AI、API、RBAC、审计 |
| DC | 首版无变化 |
| Frontend | Skill 安全页面与完整原文查看 |

## 2. 后端模块

建议新增：

```text
api-server/internal/model/agent_skill.go
api-server/internal/repository/agent_skill_repo.go
api-server/internal/service/agent_skill_scan_service.go
api-server/internal/service/agent_skill_ingest_service.go
api-server/internal/service/agent_skill_inventory_service.go
api-server/internal/service/agent_skill_resolution_service.go
api-server/internal/service/agent_skill_content_service.go
api-server/internal/service/agent_skill_rule_service.go
api-server/internal/service/agent_skill_ai_service.go
api-server/internal/service/agent_skill_diff_service.go
api-server/internal/service/agent_skill_review_service.go
api-server/internal/service/agent_skill_settings_service.go
api-server/internal/api/handler/agent_skill_handler.go
api-server/internal/api/router/agent_skill_routes.go
```

现有 `AgentConfigSecurityService` 只作为 ToolExecute client 模式参考，不扩展其返回结构或
页面。Skill 是持久化、异步、多页、多 revision 领域。

## 3. Server/Agent Tool 协议

### 3.1 复用协议

首版复用：

```protobuf
message ToolExecuteRequest {
  string call_id = 1;
  string host_id = 2;
  string tool = 3;
  string arguments = 4;
  int32 timeout_seconds = 5;
}

message ToolExecuteResponse {
  string call_id = 1;
  bool success = 2;
  string result = 3;
  string error = 4;
  int64 execution_time_ms = 5;
}
```

`tool` 固定为 `AgentSkillScan`。`arguments/result` 使用版本化 JSON。单页 512 KiB，保留在
默认 gRPC message limit 内。若实现阶段证明编码开销或代理上限无法稳定支持，必须先升级
设计为专用 stream RPC，不能提高到无界消息。

### 3.2 请求校验

api-server：

- call ID 使用 `agent-skill:<scan-id>:<page-index>`；
- host 必须属于 tenant 和操作者 scope；
- Agent capability >=1；
- active scan lease 唯一；
- timeout 默认 30 秒、最大 60 秒；
- arguments 不含路径、URL、shell 或任意配置内容。

Server：

- 使用连接表解析 host，不信任 request 自报 host；
- tool 必须在 Agent allowlist；
- result 不写 INFO/ERROR body；
- response size 超限返回 `agent_skill_response_too_large`。

Agent：

- policy version 必须存在且验签；
- request 范围必须是 policy 子集；
- cursor 必须属于 scan/call sequence；
- 相同 cursor 返回相同 page digest。

### 3.3 Page envelope

完整 JSON schema 见 Agent 设计。api-server 验证：

- schema、scan ID、policy version、adapter versions；
- page index 连续且 previous digest 链一致；
- base64 可解码、fragment offset/length/total 合法；
- file/manifest/page SHA-256；
- path/root/agent type/scope enum；
- page <=512 KiB，file/Skill/scan 累计预算；
- done 与 next cursor 互斥。

验证失败不写 current revision、不推进 durable cursor。

## 4. Scan durable worker

### 4.1 创建任务

每个 host 创建一条 `agent_skill_scan_jobs`。worker 使用：

```sql
SELECT ... FOR UPDATE SKIP LOCKED
```

领取 `queued` 或 lease 过期任务。进程内 channel 只负责 wake-up，不是队列真相。

### 4.2 页事务

单页处理：

1. 调用 Agent；
2. 校验 envelope/page digest；
3. 将 file fragment 写入临时对象分段；
4. upsert page receipt；
5. 更新 job cursor/page/byte counters；
6. commit；
7. 请求下一页。

完成 Skill 全部 fragment 后：

1. 按 file offset 重组原始 bytes；
2. 校验 file digest；
3. 生成 canonical revision object；
4. 写 MinIO 临时 key；
5. 校验 object digest；
6. 数据库事务 upsert skill/binding/revision/files/edges/observation；
7. commit 后将 object 标 final；
8. 创建 rule run watermark。

需要 orphan temp object 清理任务；数据库 rollback 后临时对象不能被 content API 查询。

### 4.3 任务恢复

- cursor 和 page receipt 加密持久化；
- worker crash 后从最后 commit page 恢复；
- Agent cursor 过期时以相同 scan ID 请求 checkpoint；无法恢复则 job partial/failed 并创建
  新 scan，不把两次来源快照拼成一个 revision；
- page digest 冲突为 non-retryable integrity failure；
- transport timeout、offline、temporary MinIO 为 retryable，指数退避。

## 5. Inventory 与 resolution

### 5.1 Upsert

逻辑唯一键：

```text
host + UID + agent_type + source_root_id + relative_locator
```

revision 唯一键：

```text
skill_id + revision_digest
```

每次 scan 创建 observation；相同 revision 只更新 last_seen，不覆盖历史 rule/AI result。

### 5.2 Effective 计算

`AgentSkillResolutionService` 使用 adapter version 的确定性规则：

- Codex：保留 repo 多级副本和当前产品 selector 语义；
- Claude：enterprise > personal > project，nested/plugin namespace 独立；
- OpenClaw：workspace > project-agent > personal-agent > managed > bundled > extra/plugin；
- disabled/ineligible 优先于 effective；
- 缺配置/unknown adapter 时 state=unknown，不猜测。

结果保存 resolution digest/evidence，不只保存最终字符串。

### 5.3 Drift

baseline 来源：

```text
operator_confirmed
trusted_manifest
stable_history (可配置，默认不自动成为 trusted)
```

首次 revision 不命中 drift。新 revision 与 baseline 比较 frontmatter、正文、file manifest、
script capability、mode/owner/source，创建结构化 diff 和 supply finding。

## 6. 原文对象服务

### 6.1 对象格式

```json
{
  "schema": "aegis.agent_skill_content.v1",
  "revision_id": "uuid",
  "revision_digest": "sha256:...",
  "manifest": {},
  "files": [
    {
      "file_id": "uuid",
      "absolute_path": "/srv/work/project/.agents/skills/foo/SKILL.md",
      "relative_path": "SKILL.md",
      "encoding": "utf-8",
      "content_base64": "...",
      "content_digest": "sha256:..."
    }
  ]
}
```

对象压缩后进行服务端信封加密。内容不脱敏。PostgreSQL 只保存 ref/digest/size/key version。

### 6.2 读取

`AgentSkillContentService`：

1. 校验 `agent_skill:content:read`；
2. 校验 revision -> skill -> host -> tenant scope；
3. 记录 content access audit（成功/拒绝）；
4. 读取/解密/校验 object digest；
5. 按 file/byte range 返回；
6. 设置 `Cache-Control: no-store, private`、`X-Content-Type-Options: nosniff`；
7. 不创建长期 presigned URL。

## 7. 规则与 AI worker

### 7.1 Rule worker

- 从 DB 领取 pending run；
- 通过内部 content service 读取原文；
- 构造 span/match view；
- 运行版本化 ASK catalog；
- 保存 file/span/codepoint evidence；
- 更新 deterministic risk；
- 不执行内容、命令、URL 或脚本。

### 7.2 AI worker

启动前检查：

```text
feature enabled
provider configured
full_content_egress_acknowledged=true
revision content complete
trigger policy satisfied
```

AI client 不接受 tools/action callbacks。输入完整原文，输出 JSON schema。所有 evidence ID
必须属于当前 revision/chunk。provider 原始响应可加密存储或按现有 LLM 审计策略保存，但
不得写普通日志。

## 8. HTTP API

根路径：

```text
/api/v1/agent-guard/skills
```

### 8.1 Overview/List

```text
GET /overview
GET /
GET /inventory
```

`GET /inventory` 是当前页面使用的持久化清单接口，读取每台主机最近一次完成的完整扫描快照。
支持 `host_id`/`host_ids`、`page`、`page_size`（最大 100）；分页在服务端执行，返回 `items`、
`total`、扫描统计和原文/规则命中数据，因此刷新浏览器不会丢失结果。`GET /` 仍用于触发
单主机只读扫描并在成功后更新快照。

查询参数：

```text
page page_size
host_id agent_type scope
effective_state coverage risk
changed_only disappeared_only
keyword sort order
```

keyword 匹配 declared/qualified name、plugin、host display name；默认不全文搜索原文，避免
把原文复制进 PostgreSQL 搜索索引。后续全文搜索需独立安全设计。

### 8.2 Skill/Revision

```text
GET /:skill_id
GET /:skill_id/bindings
GET /:skill_id/revisions
GET /revisions/:revision_id
GET /revisions/:revision_id/files
GET /revisions/:revision_id/references
GET /revisions/:revision_id/diff?base_revision_id=
```

metadata endpoint 不返回完整正文。diff 若包含原文，需要 content 权限。

### 8.3 Content

```text
GET /revisions/:revision_id/content
GET /revisions/:revision_id/files/:file_id/content
```

支持 `offset/limit` 或 HTTP Range，单响应默认最大 2 MiB。返回 JSON text view 或
`application/octet-stream` 原始 bytes；禁止浏览器 inline 执行可执行 MIME。

### 8.4 Scan

```text
POST /scans
GET /scans
GET /scans/:scan_id
POST /scans/:scan_id/cancel
```

请求：

```json
{
  "host_ids": ["uuid"],
  "agent_types": ["codex", "claude-code", "openclaw"],
  "scopes": ["user", "project", "workspace", "managed", "plugin"],
  "content_mode": "full_content"
}
```

取消只阻止后续 page/analysis；已入库 revision 不删除。

### 8.5 Analysis/Findings

```text
GET /rules
GET /revisions/:revision_id/rule-runs
GET /revisions/:revision_id/findings
POST /revisions/:revision_id/analyze
GET /revisions/:revision_id/ai-runs
PATCH /findings/:finding_id/disposition
```

手工 analyze 使用 idempotency key；相同 revision/input/prompt/model 的 active/succeeded run 返回
现有对象。

### 8.6 Baseline/Settings/Audit

```text
GET /:skill_id/baselines
POST /:skill_id/baselines
GET /settings
PUT /settings
GET /audit
```

baseline 写入需要 `agent_skill:baseline:write`，只引用不可变 revision。

## 9. RBAC

| 权限 | 能力 |
| --- | --- |
| `agent_skill:read` | 元数据、规则/AI摘要、任务状态 |
| `agent_skill:content:read` | 原始正文、路径、evidence excerpt、原文 diff |
| `agent_skill:scan` | 发起/取消授权主机扫描 |
| `agent_skill:analyze` | 手工 AI 分析 |
| `agent_skill:review` | finding disposition |
| `agent_skill:baseline:write` | 建立/变更 baseline |
| `agent_skill:settings:read/write` | 计划、范围、规则、AI provider 数据策略 |
| `agent_skill:audit:read` | 内容访问和操作审计 |

每个 service 方法都接收 auth scope；repository 不能提供无 scope 的通用 GetRawContent。

## 10. WebSocket

事件：

```json
{
  "type": "agent_skill.updated",
  "host_id": "uuid",
  "skill_id": "uuid",
  "revision_id": "uuid",
  "scan_id": "uuid",
  "status": "rules_running",
  "finding_count": 3,
  "occurred_at": "RFC3339"
}
```

禁止字段：name、path、description、content、command、URL、evidence excerpt、AI reason。

## 11. 错误码

```text
agent_skill_feature_disabled
agent_skill_permission_denied
agent_skill_content_permission_denied
agent_skill_host_not_found
agent_skill_host_offline
agent_skill_agent_unsupported
agent_skill_policy_not_found
agent_skill_policy_rejected
agent_skill_scan_in_progress
agent_skill_scan_not_cancellable
agent_skill_cursor_invalid
agent_skill_source_changed
agent_skill_page_invalid
agent_skill_page_digest_conflict
agent_skill_response_too_large
agent_skill_content_incomplete
agent_skill_content_not_found
agent_skill_object_store_unavailable
agent_skill_object_digest_invalid
agent_skill_ai_egress_not_approved
agent_skill_analysis_unavailable
agent_skill_analysis_invalid_output
agent_skill_baseline_conflict
agent_skill_review_conflict
```

error message 只含 safe code/ID，不含原文和路径。

## 12. 配置

```text
AGENT_SKILL_SECURITY_ENABLED
AGENT_SKILL_METADATA_COLLECTION_ENABLED
AGENT_SKILL_FULL_CONTENT_COLLECTION_ENABLED
AGENT_SKILL_RULE_ANALYSIS_ENABLED
AGENT_SKILL_AI_ANALYSIS_ENABLED
AGENT_SKILL_SCHEDULED_SCAN_ENABLED
AGENT_SKILL_BEHAVIOR_LINK_ENABLED

AGENT_SKILL_MAX_PAGE_BYTES=524288
AGENT_SKILL_MAX_FILE_BYTES=2097152
AGENT_SKILL_MAX_SKILL_BYTES=16777216
AGENT_SKILL_MAX_SCAN_BYTES=268435456
AGENT_SKILL_SCAN_INTERVAL=24h
AGENT_SKILL_CONTENT_RETENTION_DAYS=30
AGENT_SKILL_METADATA_RETENTION_DAYS=180
AGENT_SKILL_AI_FULL_CONTENT_EGRESS_ACK=false
```

路径不能从环境变量直接配置；额外 root 必须走签名 collection policy。

## 13. 后端验收

1. Tool request 无任意 path/shell；
2. page/fragment/object digest 全链校验；
3. task/page/revision/finding/AI 幂等；
4. 原文对象 byte-for-byte 与 Agent 对账；
5. metadata/content 权限分离且跨 tenant/host 拒绝；
6. 原文访问 100% 审计；
7. 日志/WebSocket/error 无原文和路径；
8. rules/AI 各自失败不覆盖另一结果；
9. AI 未确认 full-content egress 时不发送 provider；
10. flags off 时旧 API/Agent Guard 无回归。
