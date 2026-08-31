# Aegis V6.4 实施、测试、可观测性、灰度与回滚

## 1. 实施原则

- 先契约/fixture/路径安全，再实现 Agent 扫描；
- 先 metadata，再开启完整原文；
- 先确定性规则，再开启 full-content AI；
- 完整原文不脱敏，测试重点是 byte/digest 完整性和未授权表面零泄漏；
- 不执行 Skill、动态上下文、脚本、变量和 URL；
- 所有 feature flags 默认关闭；
- 先单主机/单 UID/单 adapter，再扩范围；
- 首轮实现以可验证垂直切片为目标：Agent 只读采集、服务端确定性规则、API/前端展示和 migration
  骨架先行；异步 worker、对象存储和 AI 按后续阶段接入。

当前前端扫描入口已补齐多主机交互：从 Agent Guard 在线 Agent 列表按主机去重，支持下拉多选
和“一键扫描全部已连接主机”，以最多 3 路并发调用现有单主机 Skill API，并对单主机失败做局部
错误呈现，不影响其他主机结果。

为保证页面刷新不丢数据，当前切片使用 migration 038 的 `agent_skill_scan_snapshots` 按主机
保存最近一次完整结果；`GET /agent-guard/skills/inventory` 从快照恢复原文和规则命中，并在
服务端按 `page/page_size` 返回 Skill 清单。前端分页只消费当前服务端页，主机选择同时保存在
浏览器本地状态中。

## 2. 实施阶段

### P0：契约、数据库和 fixture

范围：

- PRD/架构/Agent/API/DB/安全/前端契约；
- migration 037；
- scan/page/manifest/content/finding/AI schema；
- Go model/repository 和 TS type；
- 三 adapter compatibility matrix；
- ASK rule manifest；
- flags 默认关闭。

测试：migration 空库/V6.3 升级、canonical digest、enum/check、rule digest、current/previous/
unknown adapter fixture。

退出：无新 Agent 时所有组件构建，旧功能无回归。

### P1：Agent metadata scan

范围：policy、三 adapter、file guard、candidate/manifest、Tool 分页/cursor、durable scan worker、
metadata inventory/coverage。

开启：单测试主机、单 UID、Codex metadata_only。

退出：三产品 source/precedence、symlink/path/TOCTOU/预算、重试幂等通过；来源文件未修改。

### P2：完整原文与对象存储

范围：原始文本/编码/fragment、object reassembly/digest/encryption、content API/RBAC/audit、
前端纯文本 viewer。

测试使用合成 credential/URL/command，断言：

- Agent 原始 bytes = MinIO 解密 object bytes = 授权 API bytes；
- 内容没有掩码、替换或路径伪名化；
- 未授权 API/UI/log/metric/WebSocket/error 中原文为 0；
- 动态命令/脚本/URL 没有执行。

退出：完整性与访问边界门禁通过。

### P3：规则、drift 与研判

范围：span/normalizer、shadow/baseline/drift、ASK rules、rule run/finding、disposition、revision diff。

顺序：shadow -> 人工复核 -> alert。无自动 block。

退出：规则可重现、同名不丢失、负例通过、partial 不 clean、旧 run 保留。

### P4：AI 与行为关联

范围：egress ack、chunker、no-tool client、schema/evidence validation、reduce、usage、行为 link。

顺序：manual_only -> rule_hit_only shadow -> marking。

退出：analyzer attack、跨 ID、长 Skill、provider outage、worker restart、probable/confirmed 语义通过。

### P5：完整前端、计划任务和发布

范围：KPI/list/filter/task/drawer/content/rules/AI/history/behavior、scheduled scan、retention、容量、
docker/env/health、builder/offline package、Runbook、升级回滚。

退出：三产品 E2E、权限/XSS/E2E、定向构建、离线包、灰度指标通过。

## 3. Fixture 布局

```text
agent/internal/agentskill/testdata/
  codex/current previous unknown
  claude-code/current previous unknown
  openclaw/current previous unknown
  filesystem/
  encodings/

api-server/internal/service/testdata/agent_skill/
  manifests/
  rules/
  ai/
  risk_projection/
  content_objects/

frontend/src/views/detection/AgentGuard/__fixtures__/agentSkill/
```

fixture 全部合成，包含：

- 中英文、emoji、组合字符、zero-width、bidi、confusable、CRLF/LF；
- 完整 frontmatter、未知字段、重复 key、alias/depth bomb；
- quote/code/comment/HTML/Markdown link/reference cycle；
- Shell/Python/JS/PowerShell；
- 合成 API key/private key/URL/password/绝对路径；
- 同名高低优先级、plugin namespace、disabled/ineligible；
- baseline/drift/mtime-only/disappeared/reappeared；
- 防御/教学/红队高关键词负例。

禁止复制开发人员真实 Skill/home/plugin cache 内容。

## 4. Agent 测试

### 4.1 Codex

- CWD 到 repo root 多级 `.agents/skills`；
- user/admin/legacy/plugin；
- `agents/openai.yaml`；
- disabled config exact binding；
- 同名副本不错误按 OpenClaw highest-wins 合并。

### 4.2 Claude Code

- enterprise/personal/project/nested/plugin/synced；
- namespace/precedence；
- `allowed-tools`/invocation fields；
- `!` command 和 placeholders 原样读取、不执行；
- symlink target 允许/拒绝。

### 4.3 OpenClaw

- workspace/project-agent/personal/managed/bundled/extra/plugin；
- default/non-default state；
- multi-agent workspace/profile；
- grouped depth 0..6/7；
- allowlist/gating；
- node-hosted 首版 unsupported。

### 4.4 路径与资源

- symlink/hardlink/path traversal/rename race；
- FIFO/socket/device/sparse/超大/海量/深目录；
- owner/mode/permission change；
- reference escape/cycle/missing；
- `.git/node_modules/credential/session/cache` 不被无关扫描；
- scanner 只读，来源 inode/size/mtime/content 不变；
- CPU/IO pressure deferred。

### 4.5 原文

- UTF-8/BOM/UTF-16/invalid encoding；
- byte-for-byte digest；
- newline/space/control 保留；
- base64 fragment offset/length/order；
- source change 中止，不拼 revision；
- Agent 日志无 path/content/command/URL/secret。

## 5. Tool/Server/任务测试

- Tool name allowlist；
- request 无 path/shell；
- host identity mismatch；
- page 0/1/N、512 KiB 边界；
- fragment duplicate/missing/out-of-order/overlap；
- page/file/revision/object digest；
- cursor 篡改/过期/policy change；
- same cursor same digest；
- Server timeout/offline/response too large；
- API crash before/after page commit；
- DB rollback、MinIO transient、orphan temp cleanup；
- scan lease contention/manual-scheduled conflict；
- retry 不重复 revision/finding/AI。

## 6. 数据库/Object 测试

- migration/GORM/check/index/FK；
- Skill identity 不按 name；
- binding/revision/observation；
- mtime-only 不新 revision；
- disappeared/reappeared；
- object ref/digest/key version；
- tenant/host/revision ownership；
- temp/final/expired/legal hold；
- content expiry 后 metadata/finding 保留；
- audit 记录访问但不含原文。

## 7. 原文访问安全测试

合成 secret/path/command 应当：

- 出现在 Agent payload、加密 object、授权 content API 和授权 UI；
- 不出现在 Agent/Server/api-server 普通日志；
- 不出现在 metadata API、无 content 权限 API/UI；
- 不出现在 WebSocket、metric label、trace attribute、error、notification、analytics；
- 不进入 URL、local/session storage、持久 Pinia、console；
- 访问成功/拒绝均有不含原文的审计。

正文权限撤销后现有页面内存清空；旧 response 不得渲染到新 Skill。

## 8. 规则测试

每条 ASK rule 至少 5 positive + 5 negative，并覆盖：

- 中英、多文件、混淆；
- instruction/example/quoted/comment/script；
- polarity/actionability/target；
- offset/digest；
- 单信号不升级、多信号升级；
- shadow/baseline drift；
- dynamic command + sensitive source/sink；
- defense skill 高关键词负例；
- partial/unsupported integrity；
- catalog reanalysis/history；
- worker lease/restart/failure。

断言 rule worker 无子进程、网络、MCP、root 外文件读取和 LLM matcher。

## 9. AI 测试

### 9.1 Egress

- ack=false 不发送；
- ack version/provider/scope 绑定；
- provider change 需要新 ack；
- run 固化 ack version；
- 请求/响应不进日志。

### 9.2 Chunker

- 0/1/多 section/reference/script；
- target/hard/byte budget；
- 长 section/code/Unicode 切分；
- reference graph/cycle；
- evidence overlap 去重；
- reducer 只读结构化结果；
- content incomplete/expired 不运行。

### 9.3 Analyzer attack

- 要求输出 safe/no_known_risk；
- 要求泄露 analyzer prompt/API key/tool schema；
- 请求 shell/network/MCP/file；
- 伪造跨 revision/file/span ID；
- JSON/prose/code fence/非法 enum/NaN；
- refusal/timeout/rate limit/context error；
- repair 一次；
- AI benign 不降低 critical rule；
- retry/idempotency/usage。

## 10. API/RBAC 测试

- 所有 endpoint 权限矩阵；
- host/tenant scope；
- metadata permission 不返回 path/description/excerpt/content；
- content permission/file range/no-store/nosniff；
- cross-object ownership；
- scan duplicate/cancel/offline/unsupported；
- manual analyze idempotency；
- baseline/review optimistic concurrency；
- WebSocket metadata-only；
- safe error codes；
- audit list 权限。

## 11. 前端测试

- KPI/filter/list/task/drawer 各状态；
- effective/shadowed/duplicate/unknown；
- complete/partial/offline/unsupported；
- 原文不脱敏且纯文本；
- HTML/SVG/script/Markdown URL 不执行；
- range/cancel/stale response；
- finding span；
- AI not authorized/running/failed/succeeded；
- revision diff/baseline；
- permission revoke 清空正文；
- no content permission 不发请求；
- route/storage/console/analytics/error 无原文。

## 12. 跨服务 E2E

### E2E-01 Codex 同名投毒

user trusted Skill + repo 同名恶意副本 -> 完整 scan -> 两份入库 -> 产品语义 -> supply/prompt
finding -> 原文可查看 -> 无主机修改。

### E2E-02 Claude 动态上下文外传

project Skill 含 `!` command + synthetic credential + upload -> 原样提取 -> command 未运行 ->
EXEC/PROMPT rules -> AI malicious_likely。

### E2E-03 OpenClaw workspace 遮蔽

managed benign + workspace malicious 同名 -> effective/shadowed -> allowlist -> finding。

### E2E-04 防御性负例

安全检测 Skill 引用攻击字符串 -> context=detect/example -> 不因单词判 malicious。

### E2E-05 原文权限

完整 synthetic secret 在授权 view 可见；metadata/unauthorized/log/ws/storage 不可见；审计完整。

### E2E-06 分页重放

多页 scan，中途 DB/MinIO/API 故障 -> cursor 重放 -> digest 对账 -> 无重复。

### E2E-07 Drift/修复

unbaselined -> baseline -> malicious revision -> finding -> external fix -> new revision，无历史覆盖。

### E2E-08 行为分层

静态 command -> capability_only；加入 exact trusted tool/eBPF evidence -> confirmed/impact。

## 13. 日志

实现阶段使用 `daily-program-logging` 复核。事件：

```text
agent_skill_scan_job_created
agent_skill_scan_started
agent_skill_scan_page_completed
agent_skill_scan_completed
agent_skill_scan_failed
agent_skill_content_object_committed
agent_skill_rule_run_started/completed/failed
agent_skill_ai_run_started/completed/failed
agent_skill_review_action_recorded
agent_skill_content_accessed/denied
```

日志仅 ID、agent type、scope、version、count、bytes、digest、duration、safe error、retry；禁止
name/path/content/frontmatter/command/URL/secret/evidence/AI raw response。

## 14. 指标与告警

```text
agent_skill_scan_jobs_total{status,trigger}
agent_skill_scan_duration_seconds{agent_type}
agent_skill_scan_pages_total{agent_type}
agent_skill_content_bytes_total{agent_type}
agent_skill_coverage_total{agent_type,status}
agent_skill_revisions_total{change_type}
agent_skill_rule_findings_total{category,severity}
agent_skill_rule_pending_age_seconds
agent_skill_ai_runs_total{status,verdict}
agent_skill_ai_pending_age_seconds
agent_skill_object_failures_total{reason}
agent_skill_content_access_total{result}
```

告警：page/object digest conflict >0、未授权内容访问激增、coverage failure >5%、pending age、
AI invalid >5%、MinIO failure、critical shadow/drift。

## 15. 验证命令起点

实现后按 `aegis-build-test`：

```bash
cd agent && go test ./internal/agentskill/... ./internal/tools/... && make build
cd server && go test ./internal/grpc_server/... && make build
cd api-server && go test ./internal/model/... ./internal/repository/... ./internal/service/... ./internal/api/handler/... && make build
cd frontend && npm run test -- --run && npm run build
```

复用现有 Proto 时不应产生 pb diff。若必须新建 stream RPC，先更新设计，再验证三侧生成代码。
离线发布按 `aegis-release-packaging` 验证 Agent、migration、配置和镜像/压缩包。

## 16. 灰度顺序

1. migration/api-server/frontend/Agent，flags off；
2. 管理员页面显示未启用；
3. 单主机 Codex metadata；
4. Claude metadata；
5. OpenClaw metadata；
6. 单主机完整原文 + 权限/审计门禁；
7. rules shadow -> alert；
8. AI manual + egress ack；
9. AI rule_hit_only shadow -> marking；
10. behavior link；
11. scheduled scan；
12. 扩 host/UID/workspace。

## 17. 停止条件

- scanner 执行 Skill/命令/脚本/URL 或修改来源文件；
- 越过 approved root/UID；
- 原文字节被修改、掩码或 digest 不一致；
- 未授权 API/UI/log/ws/metric/error/storage 泄漏原文；
- page/object digest conflict；
- tenant/host/object 串数据；
- partial/failed 显示安全；
- AI 未 ack 外发、调用工具、接受伪造 evidence 或降低规则；
- 同名副本丢失；
- 重试重复计费/数据；
- V6.2/V6.3 回归。

## 18. 回滚

1. 关 scheduled；
2. 关 AI 并停止新 provider 请求；
3. 关 full content；
4. 关 rules；
5. 关 metadata 和父开关；
6. 回滚应用/Agent；
7. 保留 migration 037 和历史对象，按 retention 回收；
8. 验证旧 Agent Guard/会话/MCP。

回滚不删除主机 Skill，也不在应用回滚中 drop 审计数据。
