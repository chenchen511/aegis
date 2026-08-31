package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	pb "api-server/pkg/api/v1"
	"go.uber.org/zap"
)

const agentSkillScanTool = "AgentSkillScan"

type AgentSkillToolClient interface {
	ExecuteTool(ctx context.Context, callID, hostID, tool, arguments string, timeoutSeconds int32) (*pb.ToolExecuteResponse, error)
}

// AgentSkillInventoryQuery describes the durable Skill inventory page. The
// service deliberately keeps pagination server-side so a browser refresh does
// not discard the scan result or fall back to an in-memory slice.
type AgentSkillInventoryQuery struct {
	HostIDs  []string
	Page     int
	PageSize int
}

type AgentSkillInventoryItem struct {
	ID        string                `json:"id"`
	HostID    string                `json:"host_id"`
	ScannedAt time.Time             `json:"scanned_at"`
	Agent     AgentSkillResultAgent `json:"agent"`
	Skill     AgentSkillResultSkill `json:"skill"`
}

type AgentSkillInventoryPage struct {
	Items           []AgentSkillInventoryItem `json:"items"`
	Total           int                       `json:"total"`
	Page            int                       `json:"page"`
	PageSize        int                       `json:"page_size"`
	HostCount       int                       `json:"host_count"`
	SkillCount      int                       `json:"skill_count"`
	FindingCount    int                       `json:"finding_count"`
	PageCount       int                       `json:"page_count"`
	LatestScannedAt *time.Time                `json:"latest_scanned_at,omitempty"`
	Errors          []AgentSkillScanError     `json:"errors,omitempty"`
}

// AgentSkillResultStore is implemented by the durable repository. Keeping the
// interface in the service package makes the scanner easy to unit test without
// requiring a live PostgreSQL/MinIO stack.
type AgentSkillResultStore interface {
	SaveScan(context.Context, *AgentSkillScanResult) error
	ListInventory(context.Context, AgentSkillInventoryQuery) (*AgentSkillInventoryPage, error)
}

type AgentSkillSecurityService struct {
	client AgentSkillToolClient
	store  AgentSkillResultStore
	logger *zap.Logger
}

type AgentSkillScanResult struct {
	Schema       string                  `json:"schema"`
	HostID       string                  `json:"host_id"`
	ScannedAt    time.Time               `json:"scanned_at"`
	Agents       []AgentSkillResultAgent `json:"agents"`
	Errors       []AgentSkillScanError   `json:"errors,omitempty"`
	SkillCount   int                     `json:"skill_count"`
	FindingCount int                     `json:"finding_count"`
	PageCount    int                     `json:"page_count"`
}

type AgentSkillResultAgent struct {
	AgentType   string                  `json:"agent_type"`
	DisplayName string                  `json:"display_name"`
	Skills      []AgentSkillResultSkill `json:"skills"`
}

type AgentSkillResultSkill struct {
	Name             string                 `json:"name"`
	DirectoryName    string                 `json:"directory_name"`
	QualifiedName    string                 `json:"qualified_name"`
	AgentType        string                 `json:"agent_type"`
	SourceScope      string                 `json:"source_scope"`
	SourceRoot       string                 `json:"source_root"`
	SkillPath        string                 `json:"skill_path"`
	RelativePath     string                 `json:"relative_path"`
	DirectoryMode    string                 `json:"directory_mode,omitempty"`
	OwnerUID         int                    `json:"owner_uid,omitempty"`
	OwnerGID         int                    `json:"owner_gid,omitempty"`
	Precedence       int                    `json:"precedence"`
	EffectiveState   string                 `json:"effective_state"`
	Eligible         string                 `json:"eligible"`
	FrontmatterState string                 `json:"frontmatter_state"`
	FrontmatterKeys  []string               `json:"frontmatter_keys,omitempty"`
	Files            []AgentSkillResultFile `json:"files"`
	FindingCount     int                    `json:"finding_count"`
	Risk             string                 `json:"risk"`
	Findings         []AgentSkillFinding    `json:"findings,omitempty"`
}

type AgentSkillResultFile struct {
	Path          string    `json:"path"`
	RelativePath  string    `json:"relative_path"`
	Kind          string    `json:"kind"`
	Encoding      string    `json:"encoding,omitempty"`
	Size          int64     `json:"size"`
	Mode          string    `json:"mode,omitempty"`
	OwnerUID      int       `json:"owner_uid,omitempty"`
	OwnerGID      int       `json:"owner_gid,omitempty"`
	Executable    bool      `json:"executable"`
	SymlinkState  string    `json:"symlink_state"`
	ContentStatus string    `json:"content_status"`
	ContentDigest string    `json:"content_digest,omitempty"`
	Content       string    `json:"content,omitempty"`
	Error         string    `json:"error,omitempty"`
	Binary        bool      `json:"binary"`
	ModifiedAt    time.Time `json:"modified_at,omitempty"`
}

// AgentSkillFinding is intentionally returned with the original evidence
// excerpt. V6.4 does not redact Skill content; callers must enforce the
// content-read permission before exposing this response.
type AgentSkillFinding struct {
	RuleKey         string  `json:"rule_key"`
	RuleVersion     int     `json:"rule_version"`
	Severity        string  `json:"severity"`
	Category        string  `json:"category"`
	FilePath        string  `json:"file_path"`
	RelativePath    string  `json:"relative_path"`
	StartByte       int     `json:"start_byte"`
	EndByte         int     `json:"end_byte"`
	StartCodepoint  int     `json:"start_codepoint"`
	EndCodepoint    int     `json:"end_codepoint"`
	EvidenceExcerpt string  `json:"evidence_excerpt"`
	Context         string  `json:"context"`
	Polarity        string  `json:"polarity"`
	Actionability   string  `json:"actionability"`
	Target          string  `json:"target"`
	Reason          string  `json:"reason"`
	Confidence      float64 `json:"confidence"`
}

type AgentSkillScanError struct {
	Stage   string `json:"stage"`
	Message string `json:"message"`
}

type rawAgentSkillPage struct {
	Schema      string                  `json:"schema"`
	HostID      string                  `json:"host_id"`
	CollectedAt time.Time               `json:"collected_at"`
	Offset      int                     `json:"offset"`
	NextOffset  int                     `json:"next_offset"`
	Done        bool                    `json:"done"`
	Agents      []AgentSkillResultAgent `json:"agents"`
	Errors      []AgentSkillScanError   `json:"errors"`
}

type skillRule struct {
	key, name, category, severity, reason string
	re                                    *regexp.Regexp
}

var agentSkillRules = []skillRule{
	{key: "ASK-PROMPT-001", name: "覆盖高优先级指令", category: "prompt_injection", severity: "high", re: regexp.MustCompile(`(?is)\b(ignore|disregard|override)\s+(all\s+)?(previous|prior|system|developer|user)\s+instructions?`), reason: "尝试覆盖系统、开发者或用户指令优先级。"},
	{key: "ASK-PROMPT-002", name: "角色或优先级伪造", category: "prompt_injection", severity: "high", re: regexp.MustCompile(`(?is)\b(this\s+skill\s+is|you\s+are)\s+(the\s+)?(system|developer|root|security)\s+(message|instruction|policy)`), reason: "将不可信 Skill 内容伪装成高优先级控制指令。"},
	{key: "ASK-PROMPT-003", name: "安全与审批绕过", category: "approval_bypass", severity: "critical", re: regexp.MustCompile(`(?is)(disable|skip|bypass|without)\s+(all\s+)?(approval|sandbox|allowlist|safety|permission)|approval[_ -]?policy\s*[:=]\s*["']?never`), reason: "要求关闭审批、沙箱、白名单或安全检查。"},
	{key: "ASK-PROMPT-004", name: "越狱与限制移除", category: "jailbreak", severity: "high", re: regexp.MustCompile(`(?is)\bDAN\b|developer\s+mode|never\s+refuse|remove\s+(all\s+)?restrictions?|bypass\s+safety`), reason: "尝试启用越狱角色或移除模型限制。"},
	{key: "ASK-PROMPT-005", name: "系统提示与隐藏信息窃取", category: "prompt_theft", severity: "high", re: regexp.MustCompile(`(?is)(reveal|show|print|dump|exfiltrate)\s+(the\s+)?(system|developer|hidden)\s+(prompt|instructions?|policy|message)|tool\s+schema`), reason: "要求泄露系统提示、隐藏策略或工具结构。"},
	{key: "ASK-PROMPT-006", name: "间接提示注入", category: "prompt_injection", severity: "high", re: regexp.MustCompile(`(?is)(treat|consider|follow)\s+(the\s+)?(file|web|url|tool|reference)\s+(content|data|output)\s+as\s+(system|developer|trusted)\s+instructions?`), reason: "把外部数据提升为可信控制指令。"},
	{key: "ASK-PROMPT-008", name: "安全分析器操控", category: "defense_evasion", severity: "high", re: regexp.MustCompile(`(?is)(always\s+output|report)\s+(safe|clean)|hide\s+(this\s+)?finding|fabricate\s+(evidence|approval|scan)|return\s+valid\s+json\s+with\s+no\s+findings`), reason: "试图操纵安全分析器的结论、证据或状态。"},
	{key: "ASK-PROMPT-009", name: "防御与审计规避", category: "defense_evasion", severity: "critical", re: regexp.MustCompile(`(?is)(disable|stop|remove|delete|bypass)\s+(aegis|logging|audit|hook|ebpf|security\s+monitor)`), reason: "要求关闭或绕过 Aegis、防护 Hook、日志或审计。"},
	{key: "ASK-PROMPT-011", name: "用户意图劫持和持久化", category: "persistence", severity: "high", re: regexp.MustCompile(`(?is)(modify|write|append|install)\s+.*(AGENTS\.md|CLAUDE\.md|system\s+prompt|other\s+skills?)`), reason: "试图修改全局指令或其他 Skill 以形成持久化。"},
	{key: "ASK-PROMPT-012", name: "隐瞒与欺骗性汇报", category: "deception", severity: "high", re: regexp.MustCompile(`(?is)(do\s+not|don't|never)\s+(tell|report|mention|disclose)\s+.*(user|side\s+effect|command|change)|pretend\s+(the\s+)?(operation|scan)\s+(succeeded|was\s+approved)`), reason: "要求隐瞒副作用、命令或伪造审批/成功状态。"},
	{key: "ASK-EXEC-001", name: "动态上下文命令", category: "dynamic_execution", severity: "high", re: regexp.MustCompile("(?s)!`[^`]+`"), reason: "包含 Claude 动态上下文命令；Aegis 只记录，不执行。"},
	{key: "ASK-EXEC-002", name: "下载后执行", category: "download_execute", severity: "critical", re: regexp.MustCompile(`(?is)(curl|wget|fetch)\s+[^\n|;]+(\||;|&&)\s*(bash|sh|python|node)|\b(base64\s+(-d|--decode)|eval)\b`), reason: "存在下载、解码并交给解释器执行的组合能力。"},
	{key: "ASK-EXEC-003", name: "敏感文件或凭据访问", category: "secret_access", severity: "high", re: regexp.MustCompile(`(?is)(/etc/(shadow|passwd)|\.ssh/|id_rsa|credentials|api[_ -]?key|access[_ -]?token|process\.env|环境变量|密钥|凭据)`), reason: "引用了主机敏感文件、环境变量或凭据来源。"},
	{key: "ASK-EXEC-004", name: "外部网络外传", category: "exfiltration", severity: "critical", re: regexp.MustCompile(`(?is)(curl|wget|nc|http[s]?://|upload|webhook|dns)`), reason: "包含外部网络、上传或回连目标。"},
	{key: "ASK-EXEC-005", name: "破坏性或越界写入", category: "destructive_write", severity: "critical", re: regexp.MustCompile(`(?is)\brm\s+-rf\s+/|\b(delete|overwrite|truncate|write)\b.*(/etc/|\.aegis|\.claude|\.codex|\.openclaw|logs?)`), reason: "可能删除、覆盖 Agent/Aegis 配置或系统文件。"},
	{key: "ASK-EXEC-006", name: "提权与沙箱逃逸", category: "privilege_escape", severity: "critical", re: regexp.MustCompile(`(?is)\b(sudo|setuid|docker\.sock|/var/run/docker|nsenter|--privileged|host\s+mount)\b`), reason: "引用提权、容器控制面或沙箱逃逸能力。"},
	{key: "ASK-EXEC-008", name: "自修改或跨 Skill 持久化", category: "persistence", severity: "high", re: regexp.MustCompile(`(?is)(edit|modify|replace|append|write)\s+.*(SKILL\.md|\.agents/skills|\.claude/skills|\.openclaw/skills)`), reason: "试图修改 Skill 本身或其他 Skill 目录。"},
}

func NewAgentSkillSecurityService(client AgentSkillToolClient, logger *zap.Logger, stores ...AgentSkillResultStore) *AgentSkillSecurityService {
	if logger == nil {
		logger = zap.NewNop()
	}
	var store AgentSkillResultStore
	if len(stores) > 0 {
		store = stores[0]
	}
	return &AgentSkillSecurityService{client: client, store: store, logger: logger}
}

func (s *AgentSkillSecurityService) Scan(ctx context.Context, hostID string) (*AgentSkillScanResult, error) {
	if strings.TrimSpace(hostID) == "" {
		return nil, errors.New("host_id is required")
	}
	if s == nil || s.client == nil {
		return nil, errors.New("agent skill tool client is unavailable")
	}
	result := &AgentSkillScanResult{Schema: "aegis.agent_skill_scan_result.v1", HostID: hostID, ScannedAt: time.Now().UTC(), Agents: make([]AgentSkillResultAgent, 0), Errors: make([]AgentSkillScanError, 0)}
	byAgent := make(map[string]*AgentSkillResultAgent)
	offset := 0
	for pageIndex := 0; pageIndex < 256; pageIndex++ {
		args, _ := json.Marshal(map[string]any{"host_id": hostID, "offset": offset, "limit": 16})
		callCtx, cancel := context.WithTimeout(ctx, 35*time.Second)
		resp, err := s.client.ExecuteTool(callCtx, fmt.Sprintf("agent-skill:%s:%d", hostID, pageIndex), hostID, agentSkillScanTool, string(args), 30)
		cancel()
		if err != nil {
			return nil, fmt.Errorf("agent skill scan failed: %w", err)
		}
		if resp == nil || !resp.Success {
			message := "agent skill scan failed"
			if resp != nil && resp.Error != "" {
				message = resp.Error
			}
			return nil, errors.New(message)
		}
		var page rawAgentSkillPage
		if err := json.Unmarshal([]byte(resp.Result), &page); err != nil {
			return nil, fmt.Errorf("agent skill result is invalid: %w", err)
		}
		if page.Schema != "aegis.agent_skill_scan.v1" {
			return nil, fmt.Errorf("agent skill result schema is unsupported")
		}
		if page.HostID != "" && page.HostID != hostID {
			return nil, errors.New("agent skill result host identity mismatch")
		}
		result.PageCount++
		result.ScannedAt = page.CollectedAt
		for _, item := range page.Errors {
			result.Errors = append(result.Errors, item)
		}
		for _, sourceAgent := range page.Agents {
			entry := byAgent[sourceAgent.AgentType]
			if entry == nil {
				entry = &AgentSkillResultAgent{AgentType: sourceAgent.AgentType, DisplayName: sourceAgent.DisplayName, Skills: make([]AgentSkillResultSkill, 0)}
				byAgent[sourceAgent.AgentType] = entry
				result.Agents = append(result.Agents, *entry)
			}
			for _, rawSkill := range sourceAgent.Skills {
				skill := analyzeSkill(rawSkill)
				result.SkillCount++
				result.FindingCount += skill.FindingCount
				entry.Skills = append(entry.Skills, skill)
				for i := range result.Agents {
					if result.Agents[i].AgentType == entry.AgentType {
						result.Agents[i] = *entry
						break
					}
				}
			}
		}
		if page.Done {
			break
		}
		if page.NextOffset <= offset {
			return nil, errors.New("agent skill pagination cursor did not advance")
		}
		offset = page.NextOffset
		if pageIndex == 255 {
			return nil, errors.New("agent skill pagination limit exceeded")
		}
	}
	s.resolveDuplicateSkills(result)
	sort.Slice(result.Agents, func(i, j int) bool { return result.Agents[i].AgentType < result.Agents[j].AgentType })
	result.FindingCount = 0
	for _, agent := range result.Agents {
		for _, skill := range agent.Skills {
			result.FindingCount += skill.FindingCount
		}
	}
	if s.store != nil {
		if err := s.store.SaveScan(ctx, result); err != nil {
			s.logger.Error("agent_skill_security_scan_persist_failed", zap.String("host_id", hostID), zap.Error(err))
			return nil, fmt.Errorf("persist agent skill scan: %w", err)
		}
	}
	s.logger.Info("agent_skill_security_scan_completed", zap.String("host_id", hostID), zap.Int("skill_count", result.SkillCount), zap.Int("finding_count", result.FindingCount), zap.Int("page_count", result.PageCount))
	return result, nil
}

func (s *AgentSkillSecurityService) resolveDuplicateSkills(result *AgentSkillScanResult) {
	for _, agent := range result.Agents {
		byName := make(map[string][]int)
		for i := range agent.Skills {
			name := strings.ToLower(strings.TrimSpace(agent.Skills[i].QualifiedName))
			if name == "" {
				name = strings.ToLower(strings.TrimSpace(agent.Skills[i].DirectoryName))
			}
			if name != "" {
				byName[name] = append(byName[name], i)
			}
		}
		for _, indexes := range byName {
			if len(indexes) < 2 {
				continue
			}
			sort.SliceStable(indexes, func(i, j int) bool {
				return agent.Skills[indexes[i]].Precedence < agent.Skills[indexes[j]].Precedence
			})
			for _, index := range indexes[1:] {
				agent.Skills[index].EffectiveState = "shadowed"
				agent.Skills[index].Findings = append(agent.Skills[index].Findings, AgentSkillFinding{RuleKey: "ASK-SUPPLY-001", RuleVersion: 1, Severity: "high", Category: "supply_chain", FilePath: agent.Skills[index].SkillPath, EvidenceExcerpt: "duplicate qualified Skill name", Context: "provenance", Polarity: "unknown", Actionability: "descriptive", Target: "host_agent", Reason: "同名 Skill 副本存在来源优先级遮蔽关系，请确认生效来源。", Confidence: 0.99})
				agent.Skills[index].Findings = uniqueSkillFindings(agent.Skills[index].Findings)
				agent.Skills[index].FindingCount = len(agent.Skills[index].Findings)
				agent.Skills[index].Risk = skillRisk(agent.Skills[index].Findings)
			}
		}
	}
}

func BuiltinAgentSkillRules() []AgentSkillRuleDefinition {
	result := make([]AgentSkillRuleDefinition, 0, len(agentSkillRules)+3)
	for _, rule := range agentSkillRules {
		result = append(result, makeSkillRuleDefinition(rule))
	}
	for _, rule := range []AgentSkillRuleDefinition{
		{RuleKey: "ASK-SUPPLY-001", Name: "可信名称被高优先级副本遮蔽", Category: "supply_chain", Severity: "high", Description: "检测同名 Skill 的来源优先级和 shadowed 关系。"},
		{RuleKey: "ASK-INTEGRITY-001", Name: "Frontmatter 无效或资源异常", Category: "integrity", Severity: "medium", Description: "检测无法解析的 frontmatter、不可读或超限文件。"},
		{RuleKey: "ASK-INTEGRITY-002", Name: "内容不完整", Category: "integrity", Severity: "medium", Description: "检测未能完整提取的 Skill 内容。"},
	} {
		rule.RuleVersion, rule.Source, rule.Engine, rule.DefaultEnabled, rule.Immutable, rule.DefaultAction, rule.RecommendedAction = 1, "builtin", "agent_skill_static", true, true, "alert", "alert"
		payload, _ := json.Marshal(rule)
		digest := sha256.Sum256(payload)
		rule.Digest = "sha256:" + hex.EncodeToString(digest[:])
		result = append(result, rule)
	}
	return result
}

type AgentSkillRuleDefinition struct {
	RuleKey           string   `json:"rule_key"`
	RuleVersion       int      `json:"rule_version"`
	Name              string   `json:"name"`
	Category          string   `json:"category"`
	Severity          string   `json:"severity"`
	Description       string   `json:"description"`
	Source            string   `json:"source"`
	Engine            string   `json:"engine"`
	DefaultEnabled    bool     `json:"default_enabled"`
	DefaultAction     string   `json:"default_action"`
	RecommendedAction string   `json:"recommended_action"`
	Immutable         bool     `json:"immutable"`
	Digest            string   `json:"digest"`
	Categories        []string `json:"categories"`
}

func makeSkillRuleDefinition(rule skillRule) AgentSkillRuleDefinition {
	definition := AgentSkillRuleDefinition{RuleKey: rule.key, RuleVersion: 1, Name: rule.name, Category: rule.category, Severity: rule.severity, Description: rule.reason, Source: "builtin", Engine: "agent_skill_static", DefaultEnabled: true, DefaultAction: "alert", RecommendedAction: "alert", Immutable: true, Categories: []string{rule.category}}
	payload, _ := json.Marshal(struct{ Key, Regex string }{rule.key, rule.re.String()})
	digest := sha256.Sum256(payload)
	definition.Digest = "sha256:" + hex.EncodeToString(digest[:])
	return definition
}

func analyzeSkill(skill AgentSkillResultSkill) AgentSkillResultSkill {
	skill.Findings = make([]AgentSkillFinding, 0)
	if skill.FrontmatterState == "invalid" {
		skill.Findings = append(skill.Findings, AgentSkillFinding{RuleKey: "ASK-INTEGRITY-001", RuleVersion: 1, Severity: "medium", Category: "integrity", FilePath: skill.SkillPath + "/SKILL.md", RelativePath: "SKILL.md", EvidenceExcerpt: "invalid frontmatter", Context: "frontmatter", Polarity: "unknown", Actionability: "descriptive", Target: "host_agent", Reason: "Skill frontmatter 无法解析。", Confidence: 1})
	}
	for _, file := range skill.Files {
		if file.ContentStatus != "complete" {
			if file.ContentStatus == "too_large" || file.ContentStatus == "unreadable" || file.ContentStatus == "rejected" {
				skill.Findings = append(skill.Findings, AgentSkillFinding{RuleKey: "ASK-INTEGRITY-002", RuleVersion: 1, Severity: "medium", Category: "integrity", FilePath: file.Path, RelativePath: file.RelativePath, EvidenceExcerpt: file.ContentStatus, Context: "unknown", Polarity: "unknown", Actionability: "descriptive", Target: "host_agent", Reason: "文件内容未能完整提取。", Confidence: 1})
			}
			continue
		}
		for _, rule := range agentSkillRules {
			match := rule.re.FindStringIndex(file.Content)
			if match == nil {
				continue
			}
			start, end := match[0], match[1]
			skill.Findings = append(skill.Findings, AgentSkillFinding{RuleKey: rule.key, RuleVersion: 1, Severity: rule.severity, Category: rule.category, FilePath: file.Path, RelativePath: file.RelativePath, StartByte: start, EndByte: end, StartCodepoint: utf8.RuneCountInString(file.Content[:start]), EndCodepoint: utf8.RuneCountInString(file.Content[:end]), EvidenceExcerpt: skillEvidence(file.Content, start, end), Context: skillContext(file.Content, start), Polarity: skillPolarity(file.Content, start), Actionability: "required", Target: "host_agent", Reason: rule.reason, Confidence: 0.93})
		}
		if strings.ContainsAny(file.Content, "\u200b\u200c\u200d\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2060") && regexp.MustCompile(`(?is)(decode|base64|hex|execute|run|obey)`).MatchString(file.Content) {
			start := strings.IndexFunc(file.Content, func(r rune) bool { return r >= 0x200b && r <= 0x200f || r >= 0x202a && r <= 0x202e || r == 0x2060 })
			if start >= 0 {
				skill.Findings = append(skill.Findings, AgentSkillFinding{RuleKey: "ASK-PROMPT-007", RuleVersion: 1, Severity: "medium", Category: "obfuscation", FilePath: file.Path, RelativePath: file.RelativePath, StartByte: start, EndByte: start + 3, StartCodepoint: utf8.RuneCountInString(file.Content[:start]), EndCodepoint: utf8.RuneCountInString(file.Content[:start]) + 1, EvidenceExcerpt: skillEvidence(file.Content, start, start+3), Context: skillContext(file.Content, start), Polarity: "unknown", Actionability: "required", Target: "host_agent", Reason: "不可见 Unicode 控制字符与解码/执行指令同时出现。", Confidence: 0.84})
			}
		}
	}
	skill.Findings = uniqueSkillFindings(skill.Findings)
	skill.FindingCount = len(skill.Findings)
	skill.Risk = skillRisk(skill.Findings)
	return skill
}

func skillEvidence(text string, start, end int) string {
	if start < 0 {
		start = 0
	}
	if end < start {
		end = start
	}
	runes := []rune(text)
	startRune := utf8.RuneCountInString(text[:start])
	endRune := utf8.RuneCountInString(text[:end])
	left := startRune - 160
	if left < 0 {
		left = 0
	}
	right := endRune + 352
	if right > len(runes) {
		right = len(runes)
	}
	return string(runes[left:right])
}

func skillContext(text string, start int) string {
	lineStart := strings.LastIndex(text[:start], "\n") + 1
	line := strings.ToLower(strings.TrimSpace(text[lineStart:]))
	if strings.HasPrefix(line, ">") || strings.Contains(line, "example") {
		return "example"
	}
	if strings.HasPrefix(line, "#") {
		return "comment"
	}
	return "instruction"
}

func skillPolarity(text string, start int) string {
	lineStart := strings.LastIndex(text[:start], "\n") + 1
	line := strings.ToLower(strings.TrimSpace(text[lineStart:start]))
	if strings.Contains(line, "do not") || strings.Contains(line, "don't") || strings.Contains(line, "never") {
		return "prohibit"
	}
	return "endorse"
}

func skillRisk(findings []AgentSkillFinding) string {
	level := "unknown"
	for _, finding := range findings {
		if finding.Severity == "critical" {
			return "critical"
		}
		if finding.Severity == "high" {
			level = "high"
		} else if finding.Severity == "medium" && level == "unknown" {
			level = "medium"
		}
	}
	if level == "unknown" {
		return "low"
	}
	return level
}

func uniqueSkillFindings(items []AgentSkillFinding) []AgentSkillFinding {
	seen := make(map[string]bool, len(items))
	result := make([]AgentSkillFinding, 0, len(items))
	for _, item := range items {
		key := item.RuleKey + "\x00" + item.FilePath + "\x00" + fmt.Sprint(item.StartByte)
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, item)
	}
	return result
}
