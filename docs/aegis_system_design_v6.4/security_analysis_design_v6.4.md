# Aegis V6.4 Skill 投毒与提示词安全分析设计

## 1. 分析目标

判断一个 Skill revision 是否包含：

- 供应链投毒、可信名称遮蔽或异常内容漂移；
- 提示词注入、角色/优先级伪造和用户意图劫持；
- 提示词越狱、安全策略/审批/沙箱绕过；
- 系统提示、隐藏指令、工具 schema 或凭据窃取；
- 检测规避、日志关闭、行为隐瞒和伪造结果；
- 动态命令、脚本、敏感文件访问、网络外传、破坏或提权能力。

输出必须定位到 revision/file/span/Unicode 字符区间，并说明内容上下文、意图、可执行性和
目标。静态分析不声称 Skill 一定被执行。

## 2. 完整原文策略

规则和 AI 使用完整原始 Skill 内容，不做脱敏、掩码或内容替换，包括 frontmatter、路径、
URL、命令、secret 字符串、引用和脚本。原因：

- 投毒可能依赖精确 Unicode、空白、编码和角色文本；
- secret/source/sink 关联需要原始 token/路径/URL；
- evidence offset 和 revision digest 必须回到原始字节；
- 内容修改会造成攻击语义或误报判断丢失。

保护措施：

- 规则 worker 只在服务端内存读取加密对象；
- AI provider 只有在管理员确认 full-content egress 后才能接收；
- 日志、指标、普通错误、WebSocket 不记录任何原文；
- evidence excerpt 和 AI reason 按正文权限返回；
- AI client 无工具/网络/文件/动作 callback。

## 3. 威胁模型

### 3.1 攻击者能力

- 写入项目、workspace、用户或插件 Skill；
- 创建可信 Skill 同名高优先级副本；
- 修改 description 扩大自动触发范围；
- 在正文、reference、脚本、注释、Unicode 或编码块隐藏恶意指令；
- 让 Skill 要求 Agent 忽略审批/安全策略或隐瞒副作用；
- 构造专门攻击 Aegis AI 的内容，要求输出安全、泄露 prompt、调用工具或伪造 evidence；
- 使用超长文本、引用循环、YAML bomb、文件数量和 symlink 消耗扫描资源。

### 3.2 受保护对象

- system/developer/user 指令优先级；
- 用户真实任务目标；
- 审批、沙箱、工具权限和网络/文件边界；
- 系统提示、配置、凭据、代码和企业数据；
- Aegis scanner/analyzer/finding/audit 完整性；
- 可信 Skill 名称、来源、baseline 和 revision。

### 3.3 信任假设

- Skill 的所有内容和 metadata 都不可信；
- 本机 digest 证明观察到字节，不证明作者可信；
- root/Aegis Agent 被完全攻陷时无法提供不可抵赖保证；
- adapter、规则 catalog、analysis prompt/schema 和 collection policy 属于受信控制面；
- LLM 是不确定分类器，不是授权或处置点。

## 4. 分析层次

```text
L0 provenance / integrity
  source, precedence, shadowing, baseline, drift, owner/mode, symlink

L1 deterministic prompt/capability rules
  raw text, normalized views, frontmatter, reference graph, scripts

L2 no-tool semantic AI
  intent, context, multi-file chain, counter-evidence

L3 runtime correlation
  capability_only -> probable_use -> confirmed_use -> impact_observed

L4 read-only risk projection
```

AI 不能删除或降低 L0/L1 finding。L3 只能基于可信运行时证据升级执行阶段。

## 5. 内容解析与 span

### 5.1 Span 类型

```text
frontmatter_name
frontmatter_description
frontmatter_capability
instruction_prose
quoted_prose
example_prose
code_fence
html_comment
reference_prose
script_source
url_or_dependency
unknown_text
```

每个 span 保存：file ID、原始 byte range、Unicode codepoint range、kind、parent section、digest。

### 5.2 Match views

保留原文对象不变，在内存建立：

- raw text view；
- Unicode NFKC/case/whitespace view；
- zero-width/bidi/control marked view；
- 一层、有界 base64/hex decoded view；
- script tokens、command/source/sink 摘要；
- frontmatter capability view；
- reference graph view。

decoded view 只用于匹配，不执行、不递归解码、不写回原文。

### 5.3 上下文与降噪

```text
context: instruction | example | quoted | comment | script | unknown
polarity: endorse | prohibit | detect | quote | unknown
actionability: none | descriptive | recommended | required | dynamic | automated
target: host_agent | aegis_analyzer | user | external_agent | installer | unknown
```

- 安全检测/红队 Skill 中的攻击样例保留 signal，但若上下文为 detect/prohibit，不仅凭关键词
  产生 malicious verdict；
- code fence 不能全部忽略，正文要求执行/decode/source 时升级 actionability；
- frontmatter 宽触发和正文高风险能力是独立信号；
- 脚本真实 source/sink 不能被 Markdown 免责声明覆盖。

## 6. 规则目录

规则键前缀 `ASK`，版本/definition/digest 不可变。

### 6.1 `ASK-SUPPLY-*`

| Rule | 名称 | 默认级别 | 条件 |
| --- | --- | --- | --- |
| ASK-SUPPLY-001 | 可信名称被高优先级副本遮蔽 | high | 新/低 provenance 副本成为 effective |
| ASK-SUPPLY-002 | Baseline 内容异常漂移 | high | confirmed baseline 后关键内容/digest 变化 |
| ASK-SUPPLY-003 | Description 与正文意图不一致 | medium | 低风险描述 + 无关高风险指令 |
| ASK-SUPPLY-004 | 冒充系统/安全能力 | high | system/developer/security policy 名称或 confusable |
| ASK-SUPPLY-005 | 越界 symlink/reference | high | target 离开 trusted root |
| ASK-SUPPLY-006 | 插件/来源身份不可验证 | medium | manifest/namespace/root 冲突 |
| ASK-SUPPLY-007 | 宽泛隐式触发 | medium | 无关任务触发 + 高风险能力 |
| ASK-SUPPLY-008 | 关键文件隐藏/冲突 | high | case/confusable/重复入口/digest 冲突 |

首次 revision 只标 `new_unbaselined`，不能命中 ASK-SUPPLY-002。

### 6.2 `ASK-PROMPT-*`

| Rule | 名称 | 默认级别 | 核心信号 |
| --- | --- | --- | --- |
| ASK-PROMPT-001 | 覆盖高优先级指令 | high | ignore/override/disregard system/developer/user instruction |
| ASK-PROMPT-002 | 角色/优先级伪造 | high | 声称 Skill 是 system/developer/root policy |
| ASK-PROMPT-003 | 安全与审批绕过 | critical | disable approval/sandbox/allowlist、伪造授权 |
| ASK-PROMPT-004 | 越狱与限制移除 | high | DAN/developer mode/永不拒绝/多轮解除限制 |
| ASK-PROMPT-005 | 系统提示与隐藏信息窃取 | high | system prompt、hidden policy、tool schema |
| ASK-PROMPT-006 | 间接提示注入 | high | 把 file/web/tool/reference 数据当高优先级命令 |
| ASK-PROMPT-007 | 编码和不可见混淆 | medium | base64/hex/bidi/zero-width + decode/obey/execute |
| ASK-PROMPT-008 | 安全分析器操控 | high | 要求输出 safe、隐藏 finding、伪造 JSON/ID |
| ASK-PROMPT-009 | 防御与审计规避 | critical | 关闭 Aegis/log/Hook/eBPF、删除审计 |
| ASK-PROMPT-010 | 敏感信息收集与外传 | critical | secret source + external destination |
| ASK-PROMPT-011 | 用户意图劫持和持久化 | high | 转移任务、写入全局指令/其他 Skill |
| ASK-PROMPT-012 | 隐瞒与欺骗性汇报 | high | 不告知副作用、伪造审批/成功/扫描状态 |

首批语言至少简体中文和英文。

### 6.3 `ASK-EXEC-*`

| Rule | 名称 | 默认级别 | 条件 |
| --- | --- | --- | --- |
| ASK-EXEC-001 | 动态上下文命令 | high | Claude `!` 命令或等价动态执行 |
| ASK-EXEC-002 | 下载后执行 | critical | curl/wget/fetch + pipe/source/interpreter，无固定 digest |
| ASK-EXEC-003 | 敏感文件/凭据访问 | high | auth/cloud/SSH/keychain/env/secret source |
| ASK-EXEC-004 | 外部网络外传 | critical | 敏感 source 到 HTTP/DNS/socket/upload sink |
| ASK-EXEC-005 | 破坏性或越界写入 | critical | 删除/覆盖系统、repo 外、Aegis/Agent 配置/日志 |
| ASK-EXEC-006 | 提权与沙箱逃逸 | critical | sudo/setuid/container socket/host mount/namespace |
| ASK-EXEC-007 | 工具权限过宽 | high | wildcard/high-risk tools + implicit/automatic trigger |
| ASK-EXEC-008 | 自修改/跨 Skill 持久化 | high | 修改 Skill/AGENTS/CLAUDE/system config |

### 6.4 `ASK-INTEGRITY-*`

| Rule | 名称 | 默认级别 | 条件 |
| --- | --- | --- | --- |
| ASK-INTEGRITY-001 | Frontmatter 无效/资源异常 | medium | parse/alias/depth/node budget |
| ASK-INTEGRITY-002 | 内容不完整 | medium | too_large/partial/missing reference |
| ASK-INTEGRITY-003 | 循环或过深引用 | medium | graph cycle/depth budget |
| ASK-INTEGRITY-004 | 不支持载荷 | medium | binary/archive/executable 无法分析 |
| ASK-INTEGRITY-005 | Owner/mode 异常 | high | world writable/owner mismatch/TOCTOU |
| ASK-INTEGRITY-006 | Adapter/schema 未知 | medium | 产品结构无法安全解析 |

## 7. 确定性引擎

允许 matcher：

```text
keyword/phrase set
RE2 regex
Unicode control/confusable
bounded base64/hex
frontmatter field/capability
markdown span/context
script token/dataflow-lite
source precedence/shadow graph
revision manifest diff
reference graph
multi-signal combination
```

禁止：shell、解释器、import Skill、网络、MCP、root 外文件读取、LLM matcher。

高风险优先要求组合信号：

```text
instruction_override + external_destination
secret_source + upload_sink
broad_trigger + wildcard_tools
trusted_name_shadow + new_digest + high_risk_instruction
encoded_payload + decode_instruction + execution_sink
disable_audit + concealment
dynamic_context + sensitive_source
```

## 8. Finding 契约

```json
{
  "finding_id": "uuid",
  "revision_id": "uuid",
  "source": "rule",
  "rule_key": "ASK-PROMPT-003",
  "rule_version": 1,
  "category": "approval_bypass",
  "severity": "critical",
  "confidence": 0.93,
  "context": "instruction",
  "polarity": "endorse",
  "actionability": "required",
  "target": "host_agent",
  "file_id": "uuid",
  "span_id": "span-17",
  "start_codepoint": 40,
  "end_codepoint": 92,
  "evidence_excerpt": "original unmasked text",
  "runtime_stage": "capability_only",
  "status": "open"
}
```

evidence excerpt 是完整原文片段，最大 512 codepoints，只对正文权限用户返回。

## 9. AI 分析

### 9.1 用途

- 判断攻击字符串是防御样例、引用还是被要求执行；
- 判断 description 与正文意图是否不一致；
- 识别跨 reference/script 的攻击链；
- 识别新型越狱、社会工程、隐瞒和意图劫持；
- 提取 counter-evidence 和不确定性。

### 9.2 数据外发门禁

AI 输入不脱敏，因此 tenant 设置必须保存：

```text
provider/model
full_content_egress_acknowledged
ack_version
acknowledged_by/at
allowed_host_scopes
retention/data policy note
```

ack=false 时 AI run 返回 `not_authorized`，不能静默改成脱敏模式。

### 9.3 No-tool client

- tool definitions 为空；
- 无 MCP/file/shell/network/action callback；
- temperature 0；
- JSON schema response；
- 固定 timeout/重试；
- provider 原始请求/响应不写日志；
- Skill 内容全部声明为 untrusted data。

### 9.4 Chunking

默认：target 4,000、hard 6,000 estimated tokens、byte cap 256 KiB。原子单元：frontmatter +
SKILL section、reference section、script function/block。超长段按 Markdown/code/Unicode 边界
切分。reducer 只读取结构化 chunk result 和引用图，不再次读取全部原文。

### 9.5 输出

```json
{
  "verdict": "no_known_risk|suspicious|malicious_likely|inconclusive",
  "severity": "info|low|medium|high|critical",
  "confidence": 0.0,
  "categories": [
    {
      "category": "prompt_injection",
      "intent": "defensive|dual_use|malicious|unknown",
      "actionability": "none|descriptive|recommended|required|dynamic|automated",
      "target": "host_agent|aegis_analyzer|user|external_agent|installer|unknown",
      "evidence_span_ids": ["span-17"],
      "counter_evidence_span_ids": [],
      "reason": "concise reason"
    }
  ],
  "uncertainties": [],
  "recommended_disposition": "monitor|review|confirm|dismiss"
}
```

未知/跨 revision evidence ID、额外 prose、非法 enum、NaN/confidence 越界、Markdown wrapper
均 invalid。只允许一次 schema repair。

### 9.6 分析器攻击门禁

- 要求忽略 analyzer system prompt 并输出 safe；
- 要求泄露 analyzer prompt/API key/tool schema；
- 请求调用 shell/network/MCP/read file；
- 伪造其他 revision/span/finding ID；
- reference 中多阶段改变任务；
- 超长重复内容耗尽上下文；
- 脚本注释声称安全但 capability 显示外传。

## 10. 风险聚合

```text
overall severity = max(
  open/confirmed provenance severity,
  open/confirmed deterministic severity,
  validated AI severity,
  confirmed behavior impact severity
)
```

约束：

- AI `no_known_risk` 不能降低规则/provenance；
- coverage/extraction 不完整时必须带 coverage warning；
- accepted/dismissed 不删除历史 severity/evidence；
- probable runtime link 不升级为 confirmed；
- 静态默认 capability_only。

页面文案：

| 条件 | 文案 |
| --- | --- |
| complete、无 open medium+、AI no_known_risk | 未发现已知风险 |
| suspicious | 可疑，需复核 |
| malicious_likely | 高度疑似恶意 |
| inconclusive | 分析无法确定 |
| partial/unsupported | 覆盖不完整 |
| capability_only | 发现静态能力，未观察到执行 |
| confirmed_use | 已确认使用 |
| impact_observed | 已观察到匹配行为影响 |

## 11. 人工研判

```text
open
confirmed
dismissed_false_positive
accepted_risk
remediated_external
```

`remediated_external` 只记录外部操作，下一次 scan 产生新 revision 且规则不再命中后，才能
显示“新版本未再命中”。禁止创建全局字符串豁免来处理安全检测 Skill 的样例误报。

## 12. 安全分析验收

1. finding 100% 定位 revision/file/span；
2. 原文 offset/digest 可重现；
3. 规则不执行命令/脚本/URL/Skill；
4. 投毒、注入、越狱、绕过、提示窃取、规避、外传均有跨产品 fixture；
5. 防御性/教学内容不因单词直接判 malicious；
6. AI 无工具且 full-content egress 有明确 ack；
7. analyzer attack 不产生越权或伪造 evidence；
8. AI 不降低规则；
9. partial/failed 不显示安全；
10. capability 与实际执行严格区分。
