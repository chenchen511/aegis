# Aegis V6.4 Agent Skill 获取与完整内容提取设计

## 1. Agent 职责

V6.4 的 Agent 负责在主机上安全地发现 Skill、读取完整原始内容并分页上报。Agent 不判断
提示词是否恶意，也不执行任何 Skill 内容。

```text
signed collection policy
  -> adapter root discovery
  -> Skill candidate discovery
  -> file/path guard
  -> full raw-content extraction
  -> manifest/reference graph/digests
  -> deterministic pagination/cursor
  -> AgentSkillScan result pages
```

## 2. 模块设计

新增建议目录：

```text
agent/internal/agentskill/
  manager.go
  policy.go
  scanner.go
  file_guard.go
  candidate.go
  frontmatter.go
  markdown.go
  reference_graph.go
  script_classifier.go
  manifest.go
  digest.go
  paginator.go
  cursor_store.go
  capability.go
  adapters/
    codex/
      roots.go
      config.go
      parser.go
      precedence.go
    claude/
      roots.go
      config.go
      parser.go
      precedence.go
    openclaw/
      roots.go
      config.go
      parser.go
      precedence.go
```

`agent/internal/tools/tool_manager.go` 新增唯一白名单入口 `AgentSkillScan`。禁止新增通用
`ReadFile`、`Glob`、`FindSkill` 或 shell 参数透传。

## 3. Collection policy

```json
{
  "schema": "aegis.agent_skill.collection_bundle.v1",
  "version": 1,
  "targets": {
    "host_ids": ["uuid"],
    "subjects": [{"uid": 1000, "home": "/home/alice"}],
    "agent_types": ["codex", "claude-code", "openclaw"]
  },
  "roots": [
    {
      "root_id": "uuid",
      "kind": "workspace",
      "path": "/srv/work/project-a",
      "owner_uid": 1000,
      "recursive_projects": true
    }
  ],
  "collection": {
    "max_skills_per_scan": 2000,
    "max_files_per_skill": 256,
    "max_file_bytes": 2097152,
    "max_skill_bytes": 16777216,
    "max_scan_bytes": 268435456,
    "max_page_bytes": 524288,
    "max_page_duration_ms": 20000,
    "reference_depth": 3,
    "include_full_content": true,
    "include_scripts": true,
    "include_assets_metadata": true
  }
}
```

policy 由 api-server 发布并沿用现有签名/版本/投递机制。明文 home/workspace/extra root 只
存在于签名策略和 Agent 本地内存/受限配置；V6.4 明确允许在授权 API 展示完整路径，因此
上报 manifest 可以包含绝对路径，但 Tool/Agent 日志不得记录路径或原文。

请求的 agent types、scope 和 content mode 必须是 policy 的子集。不存在 policy、版本不匹配
或请求扩大权限时返回 `agent_skill_policy_rejected`。

## 4. Codex adapter

### 4.1 默认来源

| scope | 路径/发现方式 | 备注 |
| --- | --- | --- |
| repo | approved CWD 到 repo root 每级 `.agents/skills` | 每级副本独立保存 |
| user | `<home>/.agents/skills` | 当前官方用户级来源 |
| admin | `/etc/codex/skills` | 仅 policy 开启系统 root |
| system | 可信 Codex manifest 可枚举的内置 Skill | 无 manifest 时 metadata unsupported |
| plugin | 已安装且启用 plugin manifest 的 `skills/` | 不递归猜 plugin cache |
| legacy_user | `<resolved_codex_home>/skills` | 仅兼容 profile 显式开启 |

`resolved_codex_home` 只来自 Agent 服务配置或签名 policy，不读取任意 Codex 进程环境。

### 4.2 解析内容

- `SKILL.md` 完整原文；
- frontmatter 的全部原始键值和规范化 name/description；
- `agents/openai.yaml` 完整原文、UI metadata、implicit invocation policy 和 dependencies；
- `references/`、`scripts/` 的完整支持文本；
- `assets/` 的 metadata/digest，文本 asset 在预算内可完整读取；
- `~/.codex/config.toml` 只解析 `skills.config` 精确 enabled/disabled 绑定，不把整份配置作为
  Skill 内容上传。

当前 Codex 对同名 repo Skill 不简单合并。adapter 必须保存所有候选和产品可见性证据，
不能套用 OpenClaw 的 highest-wins 规则。

## 5. Claude Code adapter

### 5.1 默认来源

| scope | 路径/发现方式 | 优先级 |
| --- | --- | --- |
| enterprise | managed settings 下 `.claude/skills` | enterprise > personal > project |
| personal | `<home>/.claude/skills` | 高于 project |
| synced | `<home>/.claude/skills/synced` 的受支持布局 | 单独标 source |
| project | approved repo 内 `.claude/skills` | root project |
| nested_project | repo 子目录 `.claude/skills` | qualified name |
| plugin | enabled plugin `skills/<name>` | `plugin:skill` namespace |

### 5.2 动态上下文

Claude Skill 可能包含：

```text
!`git diff HEAD`
```

Aegis 必须原样采集这段文字并标记 `dynamic_context=true`、command span 和风险能力，但
不得执行命令。`$ARGUMENTS`、`$0`、`${CLAUDE_*}` 等变量也原样保留，不展开。

### 5.3 Frontmatter

adapter 识别但不修改：

```text
name
description
allowed-tools
user-invocable
disable-model-invocation
argument-hint
model
context
agent
hooks
```

未知字段完整保留在原文对象，并在 manifest 中记录字段名/类型。解析失败不妨碍保存原始
`SKILL.md`，但 extraction 标 `invalid_frontmatter`，effective 可能 unknown。

## 6. OpenClaw adapter

### 6.1 Source precedence

| precedence | scope | 路径 |
| --- | --- | --- |
| 1 | workspace | `<workspace>/skills` |
| 2 | project_agent | `<workspace>/.agents/skills` |
| 3 | personal_agent | `<home>/.agents/skills`，仅默认 state |
| 4 | managed | `<state_dir>/skills`，默认 `~/.openclaw/skills` |
| 5 | bundled/custodian | 可信安装 manifest |
| 6 | extra/plugin | `skills.load.extraDirs` 和 enabled plugin skills |

同名时最高来源生效，其他标 shadowed。adapter 同时解析 agent allowlist、gating、
`skills.entries` 和 state/profile 差异，输出 `eligible=true|false|unknown`。

### 6.2 Root 解析

从 `openclaw.json`/受支持 JSON5 中只读取固定字段：

```text
agents.defaults.workspace
agents.entries.*.workspace
skills.load.extraDirs
skills.load.allowSymlinkTargets
agents.defaults.skills
agents.entries.*.skills
plugins entries/manifests
```

字段值完整保存到产品配置检测域不属于本任务；Skill adapter 只使用 canonical root 和
allowlist 结果。extra dir 必须仍落在 policy 批准边界内，否则拒绝并产生 coverage evidence。

### 6.3 Grouped layout

OpenClaw 支持配置 root 下最多 6 层发现 `SKILL.md`。Aegis 使用 adapter 上限 6，目录组织
路径不改变 declared name。超过深度只返回 `budget_exhausted/unsupported_layout`，不继续遍历。

## 7. 候选与文件发现

### 7.1 Skill candidate

候选目录必须包含普通文件 `SKILL.md`。缺少/不可读/超限时保存 candidate coverage，不将
其他 Markdown 猜成 Skill。

候选字段：

```text
agent_type
adapter_version
source_scope
source_root_id
absolute_skill_path
relative_skill_path
owner_uid/gid
directory_mode
symlink_state
declared_name/directory_name/qualified_name
plugin_name
precedence/eligible/effective evidence
```

### 7.2 文件范围

完整读取首批支持文本：

```text
.md .mdx .txt .yaml .yml .json .json5 .toml
.sh .bash .zsh .py .js .mjs .cjs .ts .ps1
```

二进制、图片、字体、压缩包和可执行产物只保存 metadata/digest，不把 binary bytes 送入
提示词分析。V6.4 的“完整原文”指支持的提示词、配置、引用和脚本文本，不是 Skill 目录备份。

### 7.3 引用图

入口为 `SKILL.md`。识别 Markdown link、明确相对路径、`{baseDir}` 引用和 adapter 特定
reference 指令：

- 只读取 Skill trusted root 内相对目标；
- 最大深度 3、最多 128 个 reference node；
- cycle 按 canonical path + inode + digest 去重；
- URL 原样保存但不请求；
- 缺失/越界/不支持目标保存 edge status；
- 不因正文写有“读取 /etc/passwd”就读取该文件。

## 8. 文件安全

每个 root/candidate/file 执行：

1. `lstat`；
2. canonical root containment；
3. owner/mode/type/size 检查；
4. `openat` + `O_NOFOLLOW` 只读打开；
5. 打开后 `fstat` 比对 dev/inode/owner/mode/size；
6. 限制读取字节和 deadline；
7. 读取后再次校验需要的 identity；
8. 关闭 fd，不锁文件、不写入、不 chmod/chown。

拒绝：device、socket、FIFO、越界 symlink、未批准 symlink target、TOCTOU、超限 sparse file、
路径逃逸和 owner 不符。产品官方允许 symlink 时，只有 target root 明确进入 policy 才可跟随。

## 9. 原文提取

### 9.1 不脱敏原则

Agent 不做 secret detector、掩码、路径伪名化或正文截断式改写。读取到的支持文本按原始字节
和编码上报，确保：

- frontmatter/body/脚本语义不损失；
- evidence offset 可回到原文；
- Agent file digest、中心 object digest 和 revision digest 可对账；
- 安全分析能识别真实 token 访问、命令、URL 和外传链。

资源超限时不截断成“看似完整”的内容；该文件返回 metadata + `too_large`，coverage partial。

### 9.2 编码

- UTF-8/UTF-8 BOM：原样保存 bytes，同时生成 codepoint span view；
- 有效 UTF-16 LE/BE：原始 bytes 保存，manifest 标 encoding，中心可生成只读 text view；
- invalid/unknown encoding：保存原始 digest/metadata，默认不上传不可安全分页的文本，标
  unsupported_encoding；
- 换行、空白、Unicode control 和 zero-width 原样保留。

### 9.3 Manifest

```json
{
  "schema": "aegis.agent_skill_manifest.v1",
  "adapter": "claude-code",
  "adapter_version": "1",
  "scope": "project",
  "absolute_skill_path": "/srv/work/project/.claude/skills/deploy",
  "declared_name": "deploy",
  "files": [
    {
      "file_id": "stable-local-id",
      "absolute_path": "/srv/work/project/.claude/skills/deploy/SKILL.md",
      "relative_path": "SKILL.md",
      "kind": "instruction",
      "encoding": "utf-8",
      "size": 1234,
      "mode": "0644",
      "owner_uid": 1000,
      "digest": "sha256:...",
      "content_status": "complete"
    }
  ],
  "reference_edges": []
}
```

## 10. Tool 协议

### 10.1 Request

```json
{
  "schema": "aegis.agent_skill_scan_request.v1",
  "scan_id": "uuid",
  "policy_version": 7,
  "agent_types": ["codex", "claude-code", "openclaw"],
  "scopes": ["user", "project", "workspace", "managed", "plugin"],
  "content_mode": "full_content",
  "cursor": "opaque-or-empty"
}
```

### 10.2 Page response

```json
{
  "schema": "aegis.agent_skill_scan_page.v1",
  "scan_id": "uuid",
  "page_index": 0,
  "policy_version": 7,
  "adapter_versions": {"codex": "1", "claude-code": "1", "openclaw": "1"},
  "page_digest": "sha256:...",
  "skill_fragments": [],
  "coverage": [],
  "next_cursor": "opaque-or-empty",
  "done": false
}
```

内容 bytes 使用 base64 fragment，fragment 包含 file ID、offset、length、total size、content
digest、index/count。单 page 序列化后不得超过 512 KiB。

## 11. 游标与幂等

cursor 绑定：

```text
scan_id
policy_version
adapter version set
root/candidate/file position
file dev/inode/size/mtime
fragment offset
previous page digest
expiry
```

cursor 由 Agent 签名或保存在 root-only `0700` 状态目录并返回 opaque ID。相同 cursor 重试
必须返回相同 page digest；若来源文件变化，返回 `source_changed`，中心结束当前 revision 并
在下次 scan 重新获取，不把新旧字节拼接。

## 12. 资源与并发

- 同一 host 仅一个 Skill scan lease；
- 单 page deadline 默认 20 秒；
- 单 page 读取最多 8 MiB 原始 bytes，但响应分片 <=512 KiB；
- 单 scan 默认最多 256 MiB；
- context cancel 必须在目录、文件和 fragment 边界检查；
- 扫描优先级低于 Agent Guard 实时事件和命令；
- CPU/IO pressure 超阈值时返回 retryable deferred，不抢占实时防护。

## 13. Capability

Agent 注册能力：

```json
{
  "name": "agent_skill_scan",
  "version": 1,
  "agent_types": ["codex", "claude-code", "openclaw"],
  "content_modes": ["metadata_only", "full_content"],
  "max_page_bytes": 524288
}
```

旧 Agent 无能力时 api-server 不下发工具调用，页面显示“Agent 版本不支持”。

## 14. 日志与指标

日志只包含 scan ID、agent type、scope、root ID、计数、字节数、digest、duration、safe error。
禁止记录原文、路径、Skill name、frontmatter、URL、command、secret 和 Tool result。

事件：

```text
agent_skill_scan_started
agent_skill_scan_page_completed
agent_skill_source_unsupported
agent_skill_candidate_rejected
agent_skill_file_too_large
agent_skill_source_changed
agent_skill_budget_exhausted
agent_skill_scan_completed
agent_skill_scan_failed
```

指标：

```text
agent_skill_scan_duration_seconds{agent_type}
agent_skill_candidates_total{agent_type,scope}
agent_skill_files_total{kind,status}
agent_skill_content_bytes_total{agent_type}
agent_skill_pages_total{agent_type}
agent_skill_budget_exhausted_total{reason}
agent_skill_source_changed_total{agent_type}
```

## 15. Agent 验收

1. 三 adapter current/previous/unknown fixture；
2. 来源优先级和同名关系正确；
3. 支持文本原始 bytes/digest 与中心对账 100%；
4. 无 secret/path/content 修改或掩码；
5. dynamic command/script/URL/变量从未执行；
6. symlink/path/TOCTOU/device/FIFO/owner/size 防护通过；
7. page/cursor 重试幂等；
8. source change 不拼接不同 revision；
9. 扫描不修改来源 inode/size/mtime/content；
10. Agent 日志无原文和路径。
