package assets

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// The Skill collector is deliberately read-only. It only walks roots derived
// from the existing home/project discovery policy; callers cannot provide a
// filesystem path through the tool arguments.
const (
	maxAgentSkillsPerScan = 2000
	maxSkillFiles         = 256
	maxSkillBytes         = 16 * 1024 * 1024
	maxSkillFileBytes     = 2 * 1024 * 1024
	maxSkillPageBytes     = 480 * 1024
	maxOpenClawDepth      = 6
)

type AgentSkillScanPage struct {
	Schema      string            `json:"schema"`
	HostID      string            `json:"host_id"`
	CollectedAt time.Time         `json:"collected_at"`
	Offset      int               `json:"offset"`
	NextOffset  int               `json:"next_offset,omitempty"`
	Done        bool              `json:"done"`
	Skills      []AgentSkillAgent `json:"agents"`
	Errors      []CollectError    `json:"errors,omitempty"`
}

type AgentSkillAgent struct {
	AgentType   string           `json:"agent_type"`
	DisplayName string           `json:"display_name"`
	Skills      []AgentSkillItem `json:"skills"`
}

type AgentSkillItem struct {
	Name             string              `json:"name"`
	DirectoryName    string              `json:"directory_name"`
	QualifiedName    string              `json:"qualified_name"`
	AgentType        string              `json:"agent_type"`
	SourceScope      string              `json:"source_scope"`
	SourceRoot       string              `json:"source_root"`
	SkillPath        string              `json:"skill_path"`
	RelativePath     string              `json:"relative_path"`
	DirectoryMode    string              `json:"directory_mode,omitempty"`
	OwnerUID         int                 `json:"owner_uid,omitempty"`
	OwnerGID         int                 `json:"owner_gid,omitempty"`
	Precedence       int                 `json:"precedence"`
	EffectiveState   string              `json:"effective_state"`
	Eligible         string              `json:"eligible"`
	FrontmatterState string              `json:"frontmatter_state"`
	FrontmatterKeys  []string            `json:"frontmatter_keys,omitempty"`
	Files            []AgentSkillFile    `json:"files"`
	FindingCount     int                 `json:"finding_count"`
	Risk             string              `json:"risk"`
	Findings         []AgentSkillFinding `json:"findings,omitempty"`
}

type AgentSkillFile struct {
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

type AgentSkillFinding struct {
	RuleKey         string `json:"rule_key"`
	RuleVersion     int    `json:"rule_version"`
	Severity        string `json:"severity"`
	Category        string `json:"category"`
	FilePath        string `json:"file_path"`
	RelativePath    string `json:"relative_path"`
	StartByte       int    `json:"start_byte"`
	EndByte         int    `json:"end_byte"`
	StartCodepoint  int    `json:"start_codepoint"`
	EndCodepoint    int    `json:"end_codepoint"`
	EvidenceExcerpt string `json:"evidence_excerpt"`
	Context         string `json:"context"`
	Polarity        string `json:"polarity"`
	Actionability   string `json:"actionability"`
	Target          string `json:"target"`
	Reason          string `json:"reason"`
}

type agentSkillRoot struct {
	agentType   string
	displayName string
	scope       string
	path        string
	precedence  int
	maxDepth    int
}

type AgentSkillCollector struct {
	logger      *zap.Logger
	homeDirs    []string
	projectDirs []string
}

func NewAgentSkillCollector(logger *zap.Logger) *AgentSkillCollector {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &AgentSkillCollector{logger: logger, homeDirs: discoverHomeDirs(), projectDirs: discoverProjectDirs()}
}

// Collect returns a deterministic page. Offset is the only paging input; no
// path, command, URL, or arbitrary content is accepted from the caller.
func (c *AgentSkillCollector) Collect(ctx context.Context, hostID string, offset, limit int) *AgentSkillScanPage {
	if offset < 0 {
		offset = 0
	}
	if limit < 1 || limit > 32 {
		limit = 16
	}
	start := time.Now().UTC()
	page := &AgentSkillScanPage{Schema: "aegis.agent_skill_scan.v1", HostID: hostID, CollectedAt: start, Offset: offset, Skills: make([]AgentSkillAgent, 0), Errors: make([]CollectError, 0)}
	candidates := c.discoverCandidates(ctx, page)
	if offset >= len(candidates) {
		page.Done = true
		return page
	}
	end := offset + limit
	if end > len(candidates) {
		end = len(candidates)
	}
	byAgent := make(map[string]*AgentSkillAgent)
	bytesUsed := 0
	for i := offset; i < end; i++ {
		select {
		case <-ctx.Done():
			page.Errors = append(page.Errors, CollectError{Stage: "skill_collection", Message: ctx.Err().Error()})
			page.Done = true
			return page
		default:
		}
		item := readAgentSkill(candidates[i])
		if item == nil {
			continue
		}
		// Keep the gRPC payload bounded. A single oversized skill is returned as
		// metadata with content_status=too_large by readAgentSkill.
		size := estimateSkillPayload(item)
		if len(page.Skills) > 0 && bytesUsed+size > maxSkillPageBytes {
			end = i
			break
		}
		bytesUsed += size
		entry := byAgent[candidates[i].root.agentType]
		if entry == nil {
			entry = &AgentSkillAgent{AgentType: candidates[i].root.agentType, DisplayName: candidates[i].root.displayName, Skills: make([]AgentSkillItem, 0)}
			byAgent[candidates[i].root.agentType] = entry
			page.Skills = append(page.Skills, *entry)
		}
		entry.Skills = append(entry.Skills, *item)
		for j := range page.Skills {
			if page.Skills[j].AgentType == entry.AgentType {
				page.Skills[j] = *entry
				break
			}
		}
	}
	page.NextOffset = end
	page.Done = end >= len(candidates)
	if page.Done {
		page.NextOffset = 0
	}
	c.logger.Info("agent_skill_collection_page_completed", zap.String("host_id", hostID), zap.Int("offset", offset), zap.Int("skill_count", countSkills(page.Skills)), zap.Bool("done", page.Done), zap.Duration("duration", time.Since(start)))
	return page
}

type skillCandidate struct {
	root        agentSkillRoot
	dir         string
	relativeDir string
}

func (c *AgentSkillCollector) discoverCandidates(ctx context.Context, page *AgentSkillScanPage) []skillCandidate {
	roots := c.roots()
	var result []skillCandidate
	seen := make(map[string]bool)
	for _, root := range roots {
		if root.path == "" {
			continue
		}
		info, err := os.Lstat(root.path)
		if err != nil {
			if !os.IsNotExist(err) {
				page.Errors = append(page.Errors, CollectError{Stage: "skill_root_discovery", Message: "root unavailable"})
			}
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			if info.Mode()&os.ModeSymlink != 0 {
				page.Errors = append(page.Errors, CollectError{Stage: "skill_root_discovery", Message: "symbolic-link root rejected"})
			}
			continue
		}
		_ = filepath.WalkDir(root.path, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			select {
			case <-ctx.Done():
				return context.Canceled
			default:
			}
			if entry.Type()&os.ModeSymlink != 0 {
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			rel, relErr := filepath.Rel(root.path, path)
			if relErr != nil {
				return nil
			}
			depth := 0
			if rel != "." {
				depth = len(strings.Split(filepath.Clean(rel), string(filepath.Separator)))
			}
			if entry.IsDir() && depth > root.maxDepth {
				return filepath.SkipDir
			}
			if entry.IsDir() || !strings.EqualFold(entry.Name(), "SKILL.md") {
				return nil
			}
			manifestInfo, manifestErr := os.Lstat(path)
			if manifestErr != nil || manifestInfo.Mode()&os.ModeSymlink != 0 || !manifestInfo.Mode().IsRegular() {
				return nil
			}
			dir := filepath.Dir(path)
			key := root.agentType + "\x00" + root.scope + "\x00" + dir
			if seen[key] || len(result) >= maxAgentSkillsPerScan {
				return nil
			}
			seen[key] = true
			result = append(result, skillCandidate{root: root, dir: dir, relativeDir: filepath.Dir(rel)})
			return nil
		})
		if len(result) >= maxAgentSkillsPerScan {
			break
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].root.agentType != result[j].root.agentType {
			return result[i].root.agentType < result[j].root.agentType
		}
		if result[i].root.precedence != result[j].root.precedence {
			return result[i].root.precedence < result[j].root.precedence
		}
		return result[i].dir < result[j].dir
	})
	return result
}

func (c *AgentSkillCollector) roots() []agentSkillRoot {
	var roots []agentSkillRoot
	for _, home := range c.homeDirs {
		codex := resolveCodexHome(home)
		roots = append(roots,
			agentSkillRoot{"codex", "Codex", "user", filepath.Join(home, ".agents", "skills"), 2, 3},
			agentSkillRoot{"codex", "Codex", "legacy_user", filepath.Join(codex, "skills"), 4, 3},
			agentSkillRoot{"claude-code", "Claude Code", "personal", filepath.Join(home, ".claude", "skills"), 2, 3},
			agentSkillRoot{"openclaw", "OpenClaw", "personal_agent", filepath.Join(home, ".agents", "skills"), 3, maxOpenClawDepth},
			agentSkillRoot{"openclaw", "OpenClaw", "managed", filepath.Join(home, ".openclaw", "skills"), 4, maxOpenClawDepth},
		)
	}
	for _, project := range c.projectDirs {
		roots = append(roots,
			agentSkillRoot{"codex", "Codex", "repo", filepath.Join(project, ".agents", "skills"), 1, 3},
			agentSkillRoot{"claude-code", "Claude Code", "project", filepath.Join(project, ".claude", "skills"), 3, 3},
			agentSkillRoot{"openclaw", "OpenClaw", "workspace", filepath.Join(project, "skills"), 1, maxOpenClawDepth},
			agentSkillRoot{"openclaw", "OpenClaw", "project_agent", filepath.Join(project, ".agents", "skills"), 2, maxOpenClawDepth},
		)
	}
	roots = append(roots, agentSkillRoot{"codex", "Codex", "admin", "/etc/codex/skills", 0, 3})
	return roots
}

func readAgentSkill(candidate skillCandidate) *AgentSkillItem {
	item := &AgentSkillItem{AgentType: candidate.root.agentType, SourceScope: candidate.root.scope, SourceRoot: candidate.root.path, SkillPath: candidate.dir, RelativePath: candidate.relativeDir, DirectoryName: filepath.Base(candidate.dir), Precedence: candidate.root.precedence, EffectiveState: "effective", Eligible: "unknown", Files: make([]AgentSkillFile, 0), Findings: make([]AgentSkillFinding, 0), Risk: "unknown"}
	if info, err := os.Lstat(candidate.dir); err == nil && info.IsDir() {
		item.DirectoryMode = info.Mode().String()
		item.OwnerUID, item.OwnerGID = fileOwners(info)
	}
	item.QualifiedName = item.DirectoryName
	var paths []string
	_ = filepath.WalkDir(candidate.dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		if len(paths) >= maxSkillFiles {
			return filepath.SkipDir
		}
		paths = append(paths, path)
		return nil
	})
	sort.Strings(paths)
	total := 0
	for _, path := range paths {
		file := readSkillFile(candidate.dir, path)
		if file == nil {
			continue
		}
		item.Files = append(item.Files, *file)
		total += int(file.Size)
		if total > maxSkillBytes {
			item.FrontmatterState = "partial"
			break
		}
		if strings.EqualFold(file.RelativePath, "SKILL.md") {
			item.Name, item.FrontmatterKeys, item.FrontmatterState = parseSkillFrontmatter(file.Content)
			if item.Name == "" {
				item.Name = item.DirectoryName
			}
			item.QualifiedName = item.Name
		}
	}
	if item.FrontmatterState == "" {
		item.FrontmatterState = "missing"
	}
	return item
}

func readSkillFile(root, path string) *AgentSkillFile {
	info, err := os.Lstat(path)
	if err != nil {
		return nil
	}
	rel, err := filepath.Rel(root, path)
	if err != nil || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil
	}
	ownerUID, ownerGID := fileOwners(info)
	file := &AgentSkillFile{Path: path, RelativePath: filepath.ToSlash(rel), Mode: info.Mode().String(), Size: info.Size(), OwnerUID: ownerUID, OwnerGID: ownerGID, ModifiedAt: info.ModTime(), Executable: info.Mode()&0o111 != 0, SymlinkState: "none", ContentStatus: "metadata_only"}
	if !info.Mode().IsRegular() {
		file.ContentStatus, file.Error = "rejected", "not a regular file"
		return file
	}
	file.Kind = skillFileKind(rel)
	if info.Size() > maxSkillFileBytes {
		file.ContentStatus, file.Error = "too_large", fmt.Sprintf("file exceeds %d bytes", maxSkillFileBytes)
		return file
	}
	data, err := os.ReadFile(path)
	if err != nil {
		file.ContentStatus, file.Error = "unreadable", "file could not be read"
		return file
	}
	digest := sha256.Sum256(data)
	file.ContentDigest = "sha256:" + hex.EncodeToString(digest[:])
	file.Binary = !utf8.Valid(data) || strings.HasPrefix(string(data), "\x00")
	if file.Binary {
		file.ContentStatus = "binary"
		return file
	}
	file.Encoding, file.ContentStatus, file.Content = "utf-8", "complete", string(data)
	return file
}

func fileOwners(info os.FileInfo) (int, int) {
	if info == nil || info.Sys() == nil {
		return 0, 0
	}
	value := reflect.ValueOf(info.Sys())
	if value.Kind() == reflect.Ptr {
		if value.IsNil() {
			return 0, 0
		}
		value = value.Elem()
	}
	if value.Kind() != reflect.Struct {
		return 0, 0
	}
	uid, gid := 0, 0
	if field := value.FieldByName("Uid"); field.IsValid() && field.CanUint() {
		uid = int(field.Uint())
	}
	if field := value.FieldByName("Gid"); field.IsValid() && field.CanUint() {
		gid = int(field.Uint())
	}
	return uid, gid
}

func parseSkillFrontmatter(content string) (string, []string, string) {
	lines := strings.Split(content, "\n")
	if len(lines) < 3 || strings.TrimSpace(lines[0]) != "---" {
		return "", nil, "missing"
	}
	end := -1
	for i := 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "---" {
			end = i
			break
		}
	}
	if end < 0 {
		return "", nil, "invalid"
	}
	var value map[string]any
	if err := yaml.Unmarshal([]byte(strings.Join(lines[1:end], "\n")), &value); err != nil {
		return "", nil, "invalid"
	}
	keys := make([]string, 0, len(value))
	for key := range value {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	name, _ := value["name"].(string)
	return strings.TrimSpace(name), keys, "valid"
}

func skillFileKind(path string) string {
	base := strings.ToLower(filepath.Base(path))
	if base == "skill.md" {
		return "skill_manifest"
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".md", ".mdx", ".txt", ".yaml", ".yml", ".json", ".json5", ".toml":
		return "text"
	case ".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts", ".ps1":
		return "script"
	default:
		return "asset"
	}
}

func estimateSkillPayload(item *AgentSkillItem) int {
	total := 256
	for _, file := range item.Files {
		if file.ContentStatus == "complete" {
			total += len(file.Content)
		} else {
			total += 128
		}
	}
	return total
}

func countSkills(agents []AgentSkillAgent) int {
	total := 0
	for _, agent := range agents {
		total += len(agent.Skills)
	}
	return total
}
