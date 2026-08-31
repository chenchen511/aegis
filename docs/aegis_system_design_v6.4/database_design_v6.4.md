# Aegis V6.4 智能体 Skill 安全数据库设计

## 1. 设计原则

- migration 使用 `037_v6.4_agent_skill_security.sql`；`038_v6.4_agent_skill_scan_snapshots.sql` 增加每台主机最新完整扫描快照，保证刷新后可恢复原文和规则命中。
- 只新增表、索引、权限和内置规则，不改变 V6.2/V6.3 表语义；
- PostgreSQL 保存元数据、状态、digest、证据和对象引用；
- 完整原文不脱敏，保存在 MinIO 加密对象，不把大正文重复写入 PostgreSQL；
- Skill、binding、revision、scan observation 分离，避免按名称错误去重；
- 所有 run/任务有 lease、attempt、input digest 和幂等索引；
- 软生命周期/retention 优先，不级联误删审计。

当前可运行切片额外使用 `agent_skill_scan_snapshots` 保存每台主机最近一次完成扫描的完整
JSON 快照（包括未脱敏原文和规则命中），通过 `host_id` 唯一约束原子覆盖。正式历史化
worker 可继续把同一结果拆分写入下方的 scan/revision/file 表；快照表保证前端刷新恢复和
服务端分页在异步 worker 完整落地前即可用。

## 2. 枚举约束

```text
agent_type:
  codex | claude-code | openclaw

scan_status:
  queued | dispatching | collecting | storing | rules_pending | rules_running
  ai_pending | ai_running | completed | partial | failed | cancelled

coverage:
  complete | partial | metadata_only | root_not_found | permission_denied
  unsupported | budget_exhausted | policy_rejected | offline | failed

effective_state:
  effective | shadowed | duplicate | disabled | ineligible | unknown

run_status:
  pending | running | succeeded | failed | invalid_output | inconclusive | cancelled

risk:
  unknown | info | low | medium | high | critical
```

## 3. `agent_skill_scan_jobs`

```text
id UUID PK
tenant_id UUID NOT NULL
host_id UUID NOT NULL FK hosts ON DELETE CASCADE
requested_by VARCHAR(100)
trigger_type VARCHAR(24) NOT NULL
agent_types JSONB NOT NULL
scope_filter JSONB NOT NULL
content_mode VARCHAR(24) NOT NULL
policy_version BIGINT NOT NULL
active_scope_digest VARCHAR(80) NOT NULL
status VARCHAR(24) NOT NULL
collection_coverage VARCHAR(32) NOT NULL DEFAULT 'unknown'
current_cursor_encrypted BYTEA
current_page_index BIGINT NOT NULL DEFAULT 0
previous_page_digest VARCHAR(80)
page_count BIGINT NOT NULL DEFAULT 0
skill_count BIGINT NOT NULL DEFAULT 0
revision_count BIGINT NOT NULL DEFAULT 0
finding_count BIGINT NOT NULL DEFAULT 0
bytes_received BIGINT NOT NULL DEFAULT 0
lease_owner VARCHAR(100)
lease_expires_at TIMESTAMPTZ
attempt INT NOT NULL DEFAULT 0
requested_at / started_at / completed_at TIMESTAMPTZ
error_code VARCHAR(100)
error_message_safe TEXT
created_at / updated_at TIMESTAMPTZ NOT NULL
```

索引：

```text
(tenant_id, created_at DESC)
(host_id, status, created_at DESC)
(status, lease_expires_at)
UNIQUE(host_id, policy_version, active_scope_digest)
  WHERE status IN active states
```

`active_scope_digest` 可作为 materialized column 或显式字段，digest 覆盖 agent types、scope 和
content mode。

## 4. `agent_skill_scan_pages`

```text
id UUID PK
scan_id UUID NOT NULL FK scan jobs ON DELETE CASCADE
page_index BIGINT NOT NULL
page_digest VARCHAR(80) NOT NULL
previous_page_digest VARCHAR(80)
request_cursor_digest VARCHAR(80)
next_cursor_encrypted BYTEA
payload_size BIGINT NOT NULL
skill_fragment_count INT NOT NULL
status VARCHAR(24) NOT NULL
received_at TIMESTAMPTZ NOT NULL
error_code VARCHAR(100)
UNIQUE(scan_id, page_index)
UNIQUE(scan_id, page_digest)
```

不保存完整 page JSON；file fragment 在临时加密对象中，完成后清理。

## 5. `agent_skill_scan_coverage`

```text
id UUID PK
scan_id UUID NOT NULL FK scan jobs ON DELETE CASCADE
agent_type VARCHAR(32) NOT NULL
source_subject_uid BIGINT
source_root_id UUID NOT NULL
scope VARCHAR(32) NOT NULL
status VARCHAR(32) NOT NULL
adapter_version VARCHAR(64)
schema_fingerprint VARCHAR(80)
candidate_count BIGINT NOT NULL DEFAULT 0
extracted_count BIGINT NOT NULL DEFAULT 0
partial_count BIGINT NOT NULL DEFAULT 0
bytes_read BIGINT NOT NULL DEFAULT 0
budget_reason VARCHAR(100)
error_code VARCHAR(100)
created_at / updated_at TIMESTAMPTZ
UNIQUE(scan_id, agent_type, source_subject_uid, source_root_id, scope)
```

## 6. `agent_skills`

逻辑位置表：

```text
id UUID PK
tenant_id UUID NOT NULL
host_id UUID NOT NULL FK hosts ON DELETE CASCADE
source_subject_uid BIGINT NOT NULL
agent_type VARCHAR(32) NOT NULL
source_root_id UUID NOT NULL
scope VARCHAR(32) NOT NULL
relative_locator TEXT NOT NULL
relative_locator_digest VARCHAR(80) NOT NULL
absolute_path TEXT NOT NULL
declared_name VARCHAR(255)
directory_name VARCHAR(255)
qualified_name VARCHAR(512)
plugin_name VARCHAR(255)
first_seen_at / last_seen_at / disappeared_at TIMESTAMPTZ
current_revision_id UUID
current_effective_state VARCHAR(24) NOT NULL DEFAULT 'unknown'
current_eligible_state VARCHAR(24) NOT NULL DEFAULT 'unknown'
current_overall_risk VARCHAR(16) NOT NULL DEFAULT 'unknown'
created_at / updated_at TIMESTAMPTZ
UNIQUE(host_id, source_subject_uid, agent_type, source_root_id, relative_locator_digest)
```

`absolute_path` 属于完整原文权限数据。metadata API 默认可返回 symbolic path；完整绝对路径
仅在 content/path 权限策略允许时返回。数据库列仍保存原值并受数据库访问边界保护。

## 7. `agent_skill_bindings`

同一物理目录在一个产品 source 下的解析结果：

```text
id UUID PK
skill_id UUID NOT NULL FK agent_skills ON DELETE CASCADE
adapter_version VARCHAR(64) NOT NULL
source_scope VARCHAR(32) NOT NULL
precedence INT
eligible_state VARCHAR(24) NOT NULL
effective_state VARCHAR(24) NOT NULL
resolution_evidence JSONB NOT NULL DEFAULT '{}'
resolution_digest VARCHAR(80) NOT NULL
resolved_at TIMESTAMPTZ NOT NULL
UNIQUE(skill_id, adapter_version, resolution_digest)
```

## 8. `agent_skill_revisions`

```text
id UUID PK
skill_id UUID NOT NULL FK agent_skills ON DELETE CASCADE
first_scan_id UUID NOT NULL FK scan jobs
revision_digest VARCHAR(80) NOT NULL
adapter_version VARCHAR(64) NOT NULL
manifest_schema VARCHAR(64) NOT NULL
manifest JSONB NOT NULL DEFAULT '{}'
frontmatter_parse_status VARCHAR(32) NOT NULL
frontmatter_keys JSONB NOT NULL DEFAULT '[]'
description TEXT
content_object_ref TEXT
content_object_digest VARCHAR(80)
content_object_size BIGINT
content_key_version VARCHAR(64)
extraction_status VARCHAR(32) NOT NULL
file_count BIGINT NOT NULL DEFAULT 0
text_file_count BIGINT NOT NULL DEFAULT 0
content_bytes BIGINT NOT NULL DEFAULT 0
normalized_capabilities JSONB NOT NULL DEFAULT '{}'
provenance_state VARCHAR(32) NOT NULL DEFAULT 'unverified'
rule_status VARCHAR(24) NOT NULL DEFAULT 'pending'
ai_status VARCHAR(24) NOT NULL DEFAULT 'not_requested'
deterministic_risk VARCHAR(16) NOT NULL DEFAULT 'unknown'
ai_risk VARCHAR(16) NOT NULL DEFAULT 'unknown'
overall_risk VARCHAR(16) NOT NULL DEFAULT 'unknown'
first_seen_at / last_seen_at / created_at TIMESTAMPTZ
UNIQUE(skill_id, revision_digest)
```

完整 frontmatter/body 不写 `description` 以外的正文列；`description` 本身是原文且按 content
权限处理。若希望 metadata 用户可见描述，应新增显式权限决策，不能默认复制。

## 9. `agent_skill_scan_observations`

```text
id UUID PK
scan_id UUID NOT NULL FK scan jobs ON DELETE CASCADE
skill_id UUID NOT NULL FK agent_skills ON DELETE CASCADE
revision_id UUID NOT NULL FK revisions ON DELETE RESTRICT
binding_id UUID FK bindings ON DELETE SET NULL
effective_state VARCHAR(24) NOT NULL
eligible_state VARCHAR(24) NOT NULL
file_mtime_max TIMESTAMPTZ
observed_at TIMESTAMPTZ NOT NULL
observation_digest VARCHAR(80) NOT NULL
UNIQUE(scan_id, skill_id, revision_id)
```

相同 revision 每次 scan 都有 observation，支持消失/重现和审计。

## 10. `agent_skill_revision_files`

```text
id UUID PK
revision_id UUID NOT NULL FK revisions ON DELETE CASCADE
file_key VARCHAR(128) NOT NULL
absolute_path TEXT NOT NULL
relative_path TEXT NOT NULL
path_digest VARCHAR(80) NOT NULL
kind VARCHAR(32) NOT NULL
language VARCHAR(32)
encoding VARCHAR(32)
size BIGINT NOT NULL
mode VARCHAR(16)
owner_uid BIGINT
owner_gid BIGINT
executable BOOLEAN NOT NULL DEFAULT false
symlink_state VARCHAR(32) NOT NULL
content_status VARCHAR(32) NOT NULL
content_digest VARCHAR(80)
object_offset BIGINT
object_length BIGINT
capability_summary JSONB NOT NULL DEFAULT '{}'
created_at TIMESTAMPTZ
UNIQUE(revision_id, file_key)
UNIQUE(revision_id, path_digest)
```

绝对路径受 content/path 权限保护。

## 11. `agent_skill_reference_edges`

```text
id UUID PK
revision_id UUID NOT NULL FK revisions ON DELETE CASCADE
from_file_id UUID NOT NULL FK revision_files ON DELETE CASCADE
to_file_id UUID FK revision_files ON DELETE SET NULL
raw_target TEXT NOT NULL
edge_type VARCHAR(32) NOT NULL
depth INT NOT NULL
status VARCHAR(32) NOT NULL
target_digest VARCHAR(80)
created_at TIMESTAMPTZ
UNIQUE(revision_id, from_file_id, raw_target, edge_type)
```

`raw_target` 是原文，按 content 权限返回。

## 12. `agent_skill_baselines`

```text
id UUID PK
skill_id UUID NOT NULL FK agent_skills ON DELETE CASCADE
revision_id UUID NOT NULL FK revisions ON DELETE RESTRICT
source VARCHAR(32) NOT NULL
status VARCHAR(24) NOT NULL
reason TEXT
created_by VARCHAR(100) NOT NULL
created_at TIMESTAMPTZ NOT NULL
superseded_at TIMESTAMPTZ
UNIQUE(skill_id) WHERE status='active'
```

baseline 不改变 revision，建立或替换必须审计。

## 13. 规则表

### 13.1 `agent_skill_rule_definitions`

```text
id UUID PK
rule_key VARCHAR(128) NOT NULL
version BIGINT NOT NULL
name VARCHAR(255) NOT NULL
description TEXT
category VARCHAR(64) NOT NULL
default_severity VARCHAR(16) NOT NULL
target_kinds JSONB NOT NULL
definition JSONB NOT NULL
immutable BOOLEAN NOT NULL DEFAULT true
enabled BOOLEAN NOT NULL DEFAULT true
digest VARCHAR(80) NOT NULL
created_at / updated_at TIMESTAMPTZ
UNIQUE(rule_key, version)
```

### 13.2 `agent_skill_rule_runs`

```text
id UUID PK
revision_id UUID NOT NULL FK revisions ON DELETE CASCADE
status VARCHAR(24) NOT NULL
input_digest VARCHAR(80) NOT NULL
rule_catalog_digest VARCHAR(80) NOT NULL
normalizer_version VARCHAR(64) NOT NULL
matched_rule_count INT NOT NULL DEFAULT 0
highest_severity VARCHAR(16)
lease_owner / lease_expires_at / attempt
queued_at / started_at / completed_at
error_code VARCHAR(100)
error_message_safe TEXT
created_at / updated_at
UNIQUE(revision_id, input_digest, rule_catalog_digest, normalizer_version)
```

### 13.3 `agent_skill_findings`

```text
id UUID PK
revision_id UUID NOT NULL FK revisions ON DELETE CASCADE
rule_run_id UUID FK rule_runs ON DELETE SET NULL
ai_run_id UUID FK ai_runs ON DELETE SET NULL
source VARCHAR(16) NOT NULL
rule_key VARCHAR(128)
rule_version BIGINT
category VARCHAR(64) NOT NULL
severity VARCHAR(16) NOT NULL
confidence NUMERIC(5,4)
context VARCHAR(24)
polarity VARCHAR(24)
actionability VARCHAR(24)
target VARCHAR(32)
file_id UUID FK revision_files ON DELETE SET NULL
span_id VARCHAR(128)
start_codepoint INT
end_codepoint INT
evidence_excerpt TEXT
evidence_digest VARCHAR(80) NOT NULL
runtime_stage VARCHAR(24) NOT NULL DEFAULT 'capability_only'
status VARCHAR(32) NOT NULL DEFAULT 'open'
created_at / updated_at
UNIQUE(revision_id, source, evidence_digest)
```

`evidence_excerpt` 是未脱敏原文，只允许 content 权限返回，数据库备份和访问策略必须按敏感
内容处理。

## 14. AI 表

### 14.1 `agent_skill_ai_runs`

```text
id UUID PK
revision_id UUID NOT NULL FK revisions ON DELETE CASCADE
trigger_type VARCHAR(24) NOT NULL
status VARCHAR(24) NOT NULL
input_digest VARCHAR(80) NOT NULL
provider VARCHAR(64) NOT NULL
model VARCHAR(128) NOT NULL
prompt_version VARCHAR(64) NOT NULL
schema_version VARCHAR(64) NOT NULL
full_content_egress_ack_version BIGINT NOT NULL
chunk_count / completed_chunk_count INT
verdict VARCHAR(24)
severity VARCHAR(16)
confidence NUMERIC(5,4)
summary TEXT
categories JSONB NOT NULL DEFAULT '[]'
evidence_span_ids JSONB NOT NULL DEFAULT '[]'
uncertainties JSONB NOT NULL DEFAULT '[]'
input_tokens / output_tokens / cached_tokens BIGINT
lease_owner / lease_expires_at / attempt
queued_at / started_at / completed_at
error_code VARCHAR(100)
error_message_safe TEXT
created_at / updated_at
UNIQUE(revision_id, input_digest, prompt_version, model)
  WHERE status NOT IN ('failed','cancelled')
```

### 14.2 `agent_skill_ai_chunks`

```text
id UUID PK
run_id UUID NOT NULL FK ai_runs ON DELETE CASCADE
chunk_index INT NOT NULL
input_digest VARCHAR(80) NOT NULL
file_span_refs JSONB NOT NULL
estimated_tokens INT NOT NULL
status VARCHAR(24) NOT NULL
result JSONB NOT NULL DEFAULT '{}'
evidence_span_ids JSONB NOT NULL DEFAULT '[]'
provider_input_tokens / provider_output_tokens / provider_cached_tokens BIGINT
attempt INT NOT NULL DEFAULT 0
started_at / completed_at
error_code VARCHAR(100)
UNIQUE(run_id, chunk_index)
```

## 15. Review 与访问审计

### 15.1 `agent_skill_review_actions`

```text
id UUID PK
finding_id UUID NOT NULL FK findings ON DELETE CASCADE
from_status / to_status VARCHAR(32)
reason TEXT NOT NULL
operator VARCHAR(100) NOT NULL
expected_version BIGINT NOT NULL
created_at TIMESTAMPTZ NOT NULL
```

### 15.2 `agent_skill_content_access_audits`

```text
id UUID PK
tenant_id UUID NOT NULL
operator VARCHAR(100) NOT NULL
host_id UUID NOT NULL
skill_id UUID NOT NULL
revision_id UUID NOT NULL
file_id UUID
action VARCHAR(24) NOT NULL
result VARCHAR(24) NOT NULL
request_id VARCHAR(100)
source_ip_digest VARCHAR(80)
bytes_returned BIGINT NOT NULL DEFAULT 0
created_at TIMESTAMPTZ NOT NULL
```

审计不保存原文、路径和查询内容。

## 16. Settings

`agent_skill_settings` 保存 tenant 级设置：扫描范围/周期、大小预算、adapter enable、规则策略、
AI trigger、provider、`full_content_egress_acknowledged`、ack version/operator/time、retention。

每次 scan/AI run 固化 settings/policy/ack version，不能用当前设置重写历史。

## 17. MinIO

对象 key：

```text
agent-skills/<tenant-uuid>/<host-uuid>/<revision-uuid>/<digest>.json.zst.enc
```

临时 key：

```text
agent-skills-tmp/<scan-uuid>/<skill-fragment-uuid>/<page-index>
```

要求：

- 服务端信封加密和 key version；
- object metadata 只保存 UUID、digest、schema、size；
- final object digest 与 DB 一致；
- temp object TTL 24h；
- content retention 默认 30 天，metadata 180 天；
- confirmed/accepted finding 关联对象可按策略 legal hold；
- content 到期后 revision metadata 保留，content_status=expired，不能重新 AI 分析。

## 18. Migration 与回滚

升级：

1. 创建规则/设置/任务/领域表；
2. 创建索引/check constraint/FK；
3. 插入 ASK rule catalog；
4. 插入 RBAC permission；
5. 不 backfill 旧配置/会话数据为 Skill；
6. flags 保持关闭。

应用回滚不 drop 表。先关 scheduled/AI/content/rules/metadata，再回滚服务。migration downgrade
只在明确维护窗口执行，必须确认对象/审计保留要求；正常回滚保留全部 V6.4 数据。

DDL 顺序需要处理两个引用环：先创建 `agent_skills` 时暂不添加 `current_revision_id` 外键，创建
`agent_skill_revisions` 后再 `ALTER TABLE` 添加；先创建 rule/AI run 表，再创建同时引用两者的
`agent_skill_findings`，或在最后统一添加外键。禁止为了绕过顺序永久省略外键。

## 19. 数据库验收

1. 空库和 V6.3 升级通过；
2. GORM/model/table/check constraint 对齐；
3. Skill identity 不按 name 合并；
4. revision/page/run/finding 幂等索引有效；
5. scan observation 完整；
6. object ownership 跨 tenant/host 无法读取；
7. evidence/content 字段权限不被 metadata API 暴露；
8. retention 后状态正确且历史 finding 不丢；
9. 规则代码和 migration digest 一致；
10. flags off 无旧表回归。
