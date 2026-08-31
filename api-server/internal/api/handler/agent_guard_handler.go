package handler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"api-server/internal/model"
	"api-server/internal/repository"
	"api-server/internal/service"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

const (
	agentGuardPanoramaNodeTTL = 10 * time.Minute
	agentGuardMaxPageSize     = 100
)

type agentGuardCatalogReader interface {
	ListProfiles(context.Context, model.AgentGuardProfileQuery) ([]model.AgentGuardAdapterProfile, int64, error)
	GetProfile(context.Context, uuid.UUID) (*model.AgentGuardAdapterProfile, error)
	ListRules(context.Context, model.AgentBehaviorRuleQuery) ([]model.AgentBehaviorRuleDefinition, int64, error)
	GetRule(context.Context, string, int64) (*model.AgentBehaviorRuleDefinition, error)
	ListRuleVersions(context.Context, string, int, int) ([]model.AgentBehaviorRuleDefinition, int64, error)
}

type agentGuardPolicyReader interface {
	List(context.Context, model.AgentGuardPolicyQuery) ([]model.AgentGuardPolicy, int64, error)
	GetByID(context.Context, uuid.UUID) (*model.AgentGuardPolicy, error)
	ListDeliveries(context.Context, string, int64, model.AgentGuardDeliveryQuery) ([]model.AgentGuardPolicyDelivery, int64, error)
}

type agentGuardQueryReader interface {
	GetOverview(context.Context) (*model.AgentGuardOverview, error)
	GetCoverage(context.Context, model.AgentRuntimeInstanceQuery) ([]model.AgentGuardCoverageSummary, int64, error)
	GetHostStatus(context.Context, uuid.UUID) (*model.AgentGuardHostStatus, error)
	ListAgents(context.Context, model.AgentGuardAgentQuery) ([]model.AgentGuardAgentSummary, int64, error)
	ListInstances(context.Context, model.AgentRuntimeInstanceQuery) ([]model.AgentRuntimeInstance, int64, error)
	GetInstance(context.Context, uuid.UUID) (*model.AgentRuntimeInstance, error)
	ListSessions(context.Context, model.AgentBehaviorSessionQuery) ([]model.AgentBehaviorSession, int64, error)
	GetSession(context.Context, uuid.UUID) (*model.AgentBehaviorSession, error)
	ListExecutionUnits(context.Context, model.AgentExecutionUnitQuery) ([]model.AgentExecutionUnit, int64, error)
	GetExecutionUnit(context.Context, uuid.UUID) (*model.AgentExecutionUnit, error)
	ListBehaviors(context.Context, model.AgentBehaviorEventQuery) ([]model.AgentBehaviorEvent, int64, error)
	ListProcessFacts(context.Context, model.AgentBehaviorEventQuery, int) ([]model.AgentBehaviorEvent, int64, error)
	GetBehavior(context.Context, string) (*model.AgentBehaviorEvent, error)
	GetRuntimeEvent(context.Context, string) (*model.RuntimeEvent, error)
	GetRawBehavior(context.Context, string) (*model.RuntimeEvent, error)
	ListFindings(context.Context, model.AgentSecurityFindingQuery) ([]model.AgentSecurityFinding, int64, error)
	GetFinding(context.Context, uuid.UUID) (*model.AgentSecurityFinding, error)
	ListAnalyses(context.Context, model.AgentSecurityAnalysisQuery) ([]model.AgentSecurityAnalysisRun, int64, error)
	GetAnalysis(context.Context, uuid.UUID) (*model.AgentSecurityAnalysisRun, error)
	ListActions(context.Context, model.AgentGuardActionQuery) ([]model.AgentGuardAction, int64, error)
	GetAction(context.Context, uuid.UUID) (*model.AgentGuardAction, error)
}

type agentGuardSessionDeleter interface {
	DeleteSessions(context.Context, []uuid.UUID) error
}

type agentGuardAnalysisRequester interface {
	Request(context.Context, uuid.UUID, string) (*model.AgentSecurityAnalysisRun, error)
}

type agentGuardActionRequester interface {
	RequestExecutionUnit(context.Context, uuid.UUID, string, service.AgentGuardManualActionRequest, string) (*model.AgentGuardAction, error)
	RequestInstanceKill(context.Context, uuid.UUID, service.AgentGuardManualActionRequest, string) (*model.AgentGuardAction, error)
}

type agentGuardRuntimeSettingsReader interface {
	Get(context.Context, uuid.UUID) (*model.AgentGuardRuntimeSettings, error)
}

type agentGuardRuntimeSettingsWriter interface {
	Update(context.Context, model.AgentGuardRuntimeSettings, string) (*model.AgentGuardRuntimeSettings, error)
}

type agentConfigSecurityScanner interface {
	Scan(context.Context, string) (*service.AgentConfigScanResult, error)
}

type agentSkillSecurityScanner interface {
	Scan(context.Context, string) (*service.AgentSkillScanResult, error)
}

type agentSkillInventoryReader interface {
	ListInventory(context.Context, service.AgentSkillInventoryQuery) (*service.AgentSkillInventoryPage, error)
}

type agentGuardFindingDetail struct {
	model.AgentSecurityFinding
	EvidenceCompleteness map[string]any                 `json:"evidence_completeness"`
	CounterEvidence      []string                       `json:"counter_evidence"`
	Uncertainties        []string                       `json:"uncertainties"`
	MatchedRules         []agentGuardFindingRuleDetail  `json:"matched_rules"`
	EscapeChain          *agentGuardEscapeEvidenceChain `json:"escape_chain,omitempty"`
}

type agentGuardEscapeEvidenceChain struct {
	HookEventIDs      []string                    `json:"hook_event_ids"`
	HookEvents        []agentGuardEscapeHookEvent `json:"hook_events,omitempty"`
	ProcessEvidence   []map[string]any            `json:"process_evidence"`
	ExecutionEvidence []map[string]any            `json:"execution_evidence,omitempty"`
	Permission        map[string]any              `json:"permission,omitempty"`
	Classification    string                      `json:"classification,omitempty"`
	Gaps              []string                    `json:"gaps,omitempty"`
}

type agentGuardEscapeHookEvent struct {
	EventID           string `json:"event_id"`
	EventType         string `json:"event_type,omitempty"`
	ToolName          string `json:"tool_name,omitempty"`
	Command           string `json:"command,omitempty"`
	CommandLine       string `json:"command_line,omitempty"`
	PID               int    `json:"pid,omitempty"`
	PPID              int    `json:"ppid,omitempty"`
	ProcessStartTicks string `json:"process_start_ticks,omitempty"`
	ProcessName       string `json:"process_name,omitempty"`
	ProcessExe        string `json:"process_exe,omitempty"`
	CWD               string `json:"cwd,omitempty"`
	Outcome           string `json:"outcome,omitempty"`
	Decision          string `json:"decision,omitempty"`
	Target            string `json:"target,omitempty"`
}

// AgentGuardHandler exposes the Agent Guard control plane. Analysis and manual
// actions use separate services so AI output cannot reach an action executor.
type AgentGuardHandler struct {
	catalog               agentGuardCatalogReader
	policies              agentGuardPolicyReader
	query                 agentGuardQueryReader
	policyService         *service.AgentGuardPolicyService
	bundleService         *service.AgentGuardBundleService
	analysis              agentGuardAnalysisRequester
	actions               agentGuardActionRequester
	runtimeSettingsReader agentGuardRuntimeSettingsReader
	runtimeSettingsWriter agentGuardRuntimeSettingsWriter
	configScanner         agentConfigSecurityScanner
	skillScanner          agentSkillSecurityScanner
	skillInventoryReader  agentSkillInventoryReader
	scopeSigner           *service.AgentGuardScopeSigner
	logger                *zap.Logger
}

func NewAgentGuardHandler(
	catalog agentGuardCatalogReader,
	policies agentGuardPolicyReader,
	query agentGuardQueryReader,
	policyService *service.AgentGuardPolicyService,
	scopeSigner *service.AgentGuardScopeSigner,
	logger *zap.Logger,
) *AgentGuardHandler {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &AgentGuardHandler{
		catalog:       catalog,
		policies:      policies,
		query:         query,
		policyService: policyService,
		scopeSigner:   scopeSigner,
		logger:        logger,
	}
}

func (h *AgentGuardHandler) SetBundleService(bundleService *service.AgentGuardBundleService) {
	h.bundleService = bundleService
}

func (h *AgentGuardHandler) SetAnalysisService(analysis agentGuardAnalysisRequester) {
	h.analysis = analysis
}

func (h *AgentGuardHandler) SetActionService(actions agentGuardActionRequester) {
	h.actions = actions
}

func (h *AgentGuardHandler) SetRuntimeSettingsService(settings agentGuardRuntimeSettingsReader, writer agentGuardRuntimeSettingsWriter) {
	h.runtimeSettingsReader = settings
	h.runtimeSettingsWriter = writer
}

func (h *AgentGuardHandler) SetConfigScanner(scanner agentConfigSecurityScanner) {
	h.configScanner = scanner
}

func (h *AgentGuardHandler) SetSkillScanner(scanner agentSkillSecurityScanner) {
	h.skillScanner = scanner
}

func (h *AgentGuardHandler) SetSkillInventoryReader(reader agentSkillInventoryReader) {
	h.skillInventoryReader = reader
}

// RegisterRoutes keeps the permission boundary visible next to every route.
// The caller supplies the existing role middleware so tests can assert that
// policy publish cannot inherit the less privileged draft-write permission.
func (h *AgentGuardHandler) RegisterRoutes(
	api *gin.RouterGroup,
	read gin.HandlerFunc,
	evidenceRead gin.HandlerFunc,
	analysisRead gin.HandlerFunc,
	analysisRun gin.HandlerFunc,
	policyWrite gin.HandlerFunc,
	policyPublish gin.HandlerFunc,
	sessionDelete gin.HandlerFunc,
	actionFreeze gin.HandlerFunc,
	actionResume gin.HandlerFunc,
	actionKill gin.HandlerFunc,
	settingsWrite ...gin.HandlerFunc,
) {
	guard := api.Group("/agent-guard")
	settingsPermission := policyWrite
	if len(settingsWrite) > 0 && settingsWrite[0] != nil {
		settingsPermission = settingsWrite[0]
	}

	guard.GET("/overview", read, h.GetOverview)
	guard.GET("/coverage", read, h.GetCoverage)
	guard.GET("/hosts/:host_id/status", read, h.GetHostStatus)
	guard.GET("/agents", read, h.ListAgents)
	if h.configScanner != nil {
		guard.GET("/configurations", read, h.ListConfigurations)
	}
	if h.skillScanner != nil {
		guard.GET("/skills", read, h.ListSkills)
		guard.GET("/skills/inventory", read, h.ListSkillInventory)
		guard.GET("/skill-rules", read, h.ListSkillRules)
	}
	guard.GET("/configuration-rules", read, h.ListConfigurationRules)

	guard.GET("/profiles", read, h.ListProfiles)
	guard.GET("/profiles/:id", read, h.GetProfile)
	guard.GET("/runtime-settings", read, h.GetRuntimeSettings)
	guard.PUT("/runtime-settings", settingsPermission, h.UpdateRuntimeSettings)
	guard.GET("/rules", read, h.ListRules)
	guard.GET("/escape-rules", read, h.ListEscapeRules)
	guard.GET("/rules/:rule_key", read, h.GetRule)
	guard.GET("/rules/:rule_key/versions", read, h.ListRuleVersions)

	guard.GET("/policies", read, h.ListPolicies)
	guard.POST("/policies", policyWrite, h.CreatePolicyDraft)
	guard.GET("/policies/:id", read, h.GetPolicy)
	guard.PUT("/policies/:id", policyWrite, h.UpdatePolicyDraft)
	guard.POST("/policies/:id/validate", policyWrite, h.ValidatePolicyDraft)
	guard.POST("/policies/:id/publish", policyPublish, h.PublishPolicy)
	guard.GET("/policies/:id/deliveries", read, h.ListPolicyDeliveries)

	guard.GET("/instances", read, h.ListInstances)
	guard.GET("/instances/:id", read, h.GetInstance)
	guard.POST("/instances/:id/kill", actionKill, h.KillInstance)
	guard.GET("/instances/:id/sessions", read, h.ListInstanceSessions)
	guard.DELETE("/sessions", sessionDelete, h.DeleteSessions)
	guard.GET("/sessions/:id", read, h.GetSession)
	guard.GET("/execution-units", read, h.ListExecutionUnits)
	guard.GET("/execution-units/:id", evidenceRead, h.GetExecutionUnit)
	guard.GET("/execution-units/:id/timeline", read, h.ListExecutionUnitTimeline)
	guard.POST("/execution-units/:id/freeze", actionFreeze, h.FreezeExecutionUnit)
	guard.POST("/execution-units/:id/resume", actionResume, h.ResumeExecutionUnit)
	guard.POST("/execution-units/:id/kill", actionKill, h.KillExecutionUnit)

	guard.GET("/panorama", read, h.GetPanorama)
	guard.GET("/panorama/nodes/:node_id/children", evidenceRead, h.GetPanoramaNodeChildren)

	guard.GET("/behaviors", read, h.ListBehaviors)
	guard.GET("/behaviors/:event_id", evidenceRead, h.GetBehavior)
	guard.GET("/behaviors/:event_id/raw", evidenceRead, h.GetRawBehavior)
	guard.GET("/findings", read, h.ListFindings)
	guard.GET("/findings/:finding_id", analysisRead, h.GetFinding)
	guard.GET("/findings/:finding_id/analyses", analysisRead, h.ListFindingAnalyses)
	guard.POST("/findings/:finding_id/analyze", analysisRun, h.AnalyzeFinding)
	guard.GET("/analyses/:analysis_id", analysisRead, h.GetAnalysis)
	guard.GET("/actions", read, h.ListActions)
	guard.GET("/actions/:id", read, h.GetAction)
}

// ListConfigurations performs a bounded, read-only configuration scan on one
// connected host. The Agent owns path discovery; the API owns policy scoring.
func (h *AgentGuardHandler) ListConfigurations(c *gin.Context) {
	hostID := strings.TrimSpace(c.Query("host_id"))
	if hostID == "" {
		agentGuardError(c, http.StatusBadRequest, "agent_config_host_required", "host_id is required", nil)
		return
	}
	result, err := h.configScanner.Scan(c.Request.Context(), hostID)
	if err != nil {
		h.logger.Warn("agent_configuration_scan_failed", zap.String("host_id", hostID), zap.Error(err))
		agentGuardError(c, http.StatusBadGateway, "agent_config_scan_failed", "Agent configuration scan failed", nil)
		return
	}
	agentGuardSuccess(c, result)
}

// ListSkills performs the V6.4 read-only Skill extraction and static prompt
// security scan. The response contains full original content by design; the
// route remains behind the Agent Guard read permission and never logs it.
func (h *AgentGuardHandler) ListSkills(c *gin.Context) {
	if h.skillScanner == nil {
		agentGuardError(c, http.StatusServiceUnavailable, "agent_skill_scanner_unavailable", "Agent Skill scanner is unavailable", nil)
		return
	}
	hostID := strings.TrimSpace(c.Query("host_id"))
	if hostID == "" {
		agentGuardError(c, http.StatusBadRequest, "agent_skill_host_required", "host_id is required", nil)
		return
	}
	result, err := h.skillScanner.Scan(c.Request.Context(), hostID)
	if err != nil {
		h.logger.Warn("agent_skill_security_scan_failed", zap.String("host_id", hostID), zap.Error(err))
		agentGuardError(c, http.StatusBadGateway, "agent_skill_scan_failed", "Agent Skill scan failed", nil)
		return
	}
	agentGuardSuccess(c, result)
}

// ListSkillInventory reads the latest durable scan snapshot(s). Unlike
// ListSkills, this endpoint never talks to an Agent and is therefore safe to
// call during page initialization or browser refresh. Pagination is applied
// by the repository before the response is returned.
func (h *AgentGuardHandler) ListSkillInventory(c *gin.Context) {
	if h.skillInventoryReader == nil {
		agentGuardError(c, http.StatusServiceUnavailable, "agent_skill_inventory_unavailable", "Agent Skill inventory is unavailable", nil)
		return
	}
	hostIDs := agentGuardQueryValues(c, "host_id")
	hostIDs = append(hostIDs, agentGuardQueryValues(c, "host_ids")...)
	hostIDs = uniqueStrings(hostIDs)
	if !agentGuardValidateUUIDs(c, "host_id", hostIDs) {
		return
	}
	page, pageSize, ok := agentGuardPageParamsFromContext(c)
	if !ok {
		return
	}
	result, err := h.skillInventoryReader.ListInventory(c.Request.Context(), service.AgentSkillInventoryQuery{
		HostIDs: hostIDs, Page: page, PageSize: pageSize,
	})
	if err != nil {
		h.logger.Warn("agent_skill_inventory_list_failed", zap.Error(err))
		agentGuardError(c, http.StatusInternalServerError, "agent_skill_inventory_failed", "Agent Skill inventory could not be loaded", nil)
		return
	}
	agentGuardSuccess(c, result)
}

func (h *AgentGuardHandler) ListSkillRules(c *gin.Context) {
	rules := service.BuiltinAgentSkillRules()
	keyword := strings.ToLower(strings.TrimSpace(c.Query("keyword")))
	filtered := make([]service.AgentSkillRuleDefinition, 0, len(rules))
	for _, rule := range rules {
		if keyword != "" && !strings.Contains(strings.ToLower(rule.RuleKey+" "+rule.Name+" "+rule.Description), keyword) {
			continue
		}
		filtered = append(filtered, rule)
	}
	page, pageSize, valid := agentGuardPageParamsFromContext(c)
	if !valid {
		return
	}
	start := (page - 1) * pageSize
	if start > len(filtered) {
		start = len(filtered)
	}
	end := start + pageSize
	if end > len(filtered) {
		end = len(filtered)
	}
	agentGuardSuccess(c, gin.H{"items": filtered[start:end], "total": len(filtered)})
}

func (h *AgentGuardHandler) ListConfigurationRules(c *gin.Context) {
	rules := service.BuiltinAgentConfigRules()
	keyword := strings.ToLower(strings.TrimSpace(c.Query("keyword")))
	filtered := make([]service.AgentConfigRuleDefinition, 0, len(rules))
	for _, rule := range rules {
		if keyword != "" && !strings.Contains(strings.ToLower(rule.RuleKey+" "+rule.Name+" "+rule.Description), keyword) {
			continue
		}
		filtered = append(filtered, rule)
	}
	page, pageSize, valid := agentGuardPageParamsFromContext(c)
	if !valid {
		return
	}
	start := (page - 1) * pageSize
	if start > len(filtered) {
		start = len(filtered)
	}
	end := start + pageSize
	if end > len(filtered) {
		end = len(filtered)
	}
	agentGuardSuccess(c, gin.H{"items": filtered[start:end], "total": len(filtered)})
}

// ListEscapeRules serves the immutable isolation-boundary catalog. It is a
// separate endpoint from /rules so behavior policy changes cannot accidentally
// provision or remove escape Hooks.
func (h *AgentGuardHandler) ListEscapeRules(c *gin.Context) {
	rules := model.BuiltinAgentEscapeRuleManifest()
	keyword := strings.ToLower(strings.TrimSpace(c.Query("keyword")))
	filtered := make([]model.AgentEscapeRuleDefinition, 0, len(rules))
	for _, rule := range rules {
		if keyword != "" && !strings.Contains(strings.ToLower(rule.RuleKey+" "+rule.Name+" "+rule.Description), keyword) {
			continue
		}
		filtered = append(filtered, rule)
	}
	page, pageSize, valid := agentGuardPageParamsFromContext(c)
	if !valid {
		return
	}
	start := (page - 1) * pageSize
	if start > len(filtered) {
		start = len(filtered)
	}
	end := start + pageSize
	if end > len(filtered) {
		end = len(filtered)
	}
	items := filtered[start:end]
	agentGuardSuccess(c, gin.H{"items": items, "total": len(filtered)})
}

func (h *AgentGuardHandler) GetRuntimeSettings(c *gin.Context) {
	if h.runtimeSettingsReader == nil {
		h.failWith(c, http.StatusServiceUnavailable, "agent_guard_runtime_settings_unavailable", "Agent Guard runtime settings are unavailable")
		return
	}
	hostID, err := uuid.Parse(strings.TrimSpace(c.Query("host_id")))
	if err != nil {
		agentGuardError(c, http.StatusBadRequest, "agent_guard_runtime_settings_invalid", "host_id must be a UUID", nil)
		return
	}
	settings, err := h.runtimeSettingsReader.Get(c.Request.Context(), hostID)
	if err != nil {
		h.fail(c, err)
		return
	}
	agentGuardSuccess(c, settings)
}

func (h *AgentGuardHandler) UpdateRuntimeSettings(c *gin.Context) {
	if h.runtimeSettingsWriter == nil {
		h.failWith(c, http.StatusServiceUnavailable, "agent_guard_runtime_settings_unavailable", "Agent Guard runtime settings are unavailable")
		return
	}
	var request model.AgentGuardRuntimeSettings
	if !agentGuardBindJSON(c, &request) {
		return
	}
	settings, err := h.runtimeSettingsWriter.Update(c.Request.Context(), request, agentGuardUsername(c))
	if err != nil {
		if settings != nil && settings.DispatchStatus != "" {
			status, code, message := agentGuardErrorMapping(err)
			agentGuardError(c, status, code, message, settings)
			return
		}
		h.fail(c, err)
		return
	}
	agentGuardSuccess(c, settings)
}

func (h *AgentGuardHandler) GetOverview(c *gin.Context) {
	item, err := h.query.GetOverview(c.Request.Context())
	if err != nil {
		h.fail(c, err)
		return
	}
	agentGuardSuccess(c, item)
}

func (h *AgentGuardHandler) GetCoverage(c *gin.Context) {
	query, ok := bindAgentRuntimeInstanceQuery(c)
	if !ok {
		return
	}
	items, total, err := h.query.GetCoverage(c.Request.Context(), query)
	if err != nil {
		h.fail(c, err)
		return
	}
	agentGuardPage(c, items, total)
}

func (h *AgentGuardHandler) GetHostStatus(c *gin.Context) {
	id, ok := agentGuardPathUUID(c, "host_id", "agent_guard_host_not_found")
	if !ok {
		return
	}
	item, err := h.query.GetHostStatus(c.Request.Context(), id)
	if err != nil {
		h.fail(c, err)
		return
	}
	agentGuardSuccess(c, item)
}

func (h *AgentGuardHandler) ListAgents(c *gin.Context) {
	var query model.AgentGuardAgentQuery
	if !agentGuardBindQuery(c, &query) {
		return
	}
	if !agentGuardNormalizeBoundPage(c, &query.Page, &query.PageSize) {
		return
	}
	query.HostIDs = agentGuardQueryValues(c, "host_ids")
	query.AgentTypes = agentGuardQueryValues(c, "agent_types")
	if !agentGuardValidateUUIDs(c, "host_ids", query.HostIDs) {
		return
	}
	items, total, err := h.query.ListAgents(c.Request.Context(), query)
	if err != nil {
		h.fail(c, err)
		return
	}
	for index := range items {
		if h.scopeSigner == nil {
			h.failWith(c, http.StatusServiceUnavailable, "agent_guard_scope_unavailable", "Agent scope signing is unavailable")
			return
		}
		scopeKey, signErr := h.scopeSigner.Sign(service.AgentGuardScope{
			HostID:     items[index].Host.ID.String(),
			AgentType:  items[index].AgentType,
			ProfileKey: items[index].ProfileKey,
			// The outer list represents one logical product per host. Keep the
			// primary asset ID in the DTO for compatibility, but scope details by
			// host/type/profile so assetless and historical bindings cannot split
			// the runtime view.
			AssetID: "",
		})
		if signErr != nil {
			h.failWith(c, http.StatusInternalServerError, "agent_guard_scope_unavailable", "Agent scope could not be created")
			return
		}
		items[index].AgentScopeKey = scopeKey
	}
	agentGuardPage(c, items, total)
}

func (h *AgentGuardHandler) ListProfiles(c *gin.Context) {
	var query model.AgentGuardProfileQuery
	if !agentGuardBindQuery(c, &query) {
		return
	}
	if !agentGuardNormalizeBoundPage(c, &query.Page, &query.PageSize) {
		return
	}
	items, total, err := h.catalog.ListProfiles(c.Request.Context(), query)
	if err != nil {
		h.fail(c, err)
		return
	}
	agentGuardPage(c, items, total)
}

func (h *AgentGuardHandler) GetProfile(c *gin.Context) {
	id, ok := agentGuardPathUUID(c, "id", "agent_guard_profile_not_found")
	if !ok {
		return
	}
	item, err := h.catalog.GetProfile(c.Request.Context(), id)
	if err != nil {
		h.fail(c, err)
		return
	}
	agentGuardSuccess(c, item)
}

func (h *AgentGuardHandler) ListRules(c *gin.Context) {
	var query model.AgentBehaviorRuleQuery
	if !agentGuardBindQuery(c, &query) {
		return
	}
	if !agentGuardNormalizeBoundPage(c, &query.Page, &query.PageSize) {
		return
	}
	items, total, err := h.catalog.ListRules(c.Request.Context(), query)
	if err != nil {
		h.fail(c, err)
		return
	}
	agentGuardPage(c, items, total)
}

func (h *AgentGuardHandler) GetRule(c *gin.Context) {
	version, ok := agentGuardPositiveInt64Query(c, "version", false)
	if !ok {
		return
	}
	item, err := h.catalog.GetRule(c.Request.Context(), c.Param("rule_key"), version)
	if err != nil {
		h.fail(c, err)
		return
	}
	agentGuardSuccess(c, item)
}

func (h *AgentGuardHandler) ListRuleVersions(c *gin.Context) {
	page, pageSize, ok := agentGuardPageParamsFromContext(c)
	if !ok {
		return
	}
	items, total, err := h.catalog.ListRuleVersions(c.Request.Context(), c.Param("rule_key"), page, pageSize)
	if err != nil {
		h.fail(c, err)
		return
	}
	agentGuardPage(c, items, total)
}

func (h *AgentGuardHandler) ListPolicies(c *gin.Context) {
	var query model.AgentGuardPolicyQuery
	if !agentGuardBindQuery(c, &query) {
		return
	}
	if !agentGuardNormalizeBoundPage(c, &query.Page, &query.PageSize) {
		return
	}
	items, total, err := h.policies.List(c.Request.Context(), query)
	if err != nil {
		h.fail(c, err)
		return
	}
	agentGuardPage(c, items, total)
}

func (h *AgentGuardHandler) GetPolicy(c *gin.Context) {
	id, ok := agentGuardPathUUID(c, "id", "agent_guard_policy_not_found")
	if !ok {
		return
	}
	item, err := h.policies.GetByID(c.Request.Context(), id)
	if err != nil {
		h.fail(c, err)
		return
	}
	agentGuardSuccess(c, item)
}

func (h *AgentGuardHandler) CreatePolicyDraft(c *gin.Context) {
	var request model.AgentGuardPolicyDraftRequest
	if !agentGuardBindJSON(c, &request) {
		return
	}
	username := agentGuardUsername(c)
	policy, preview, err := h.policyService.CreateDraft(c.Request.Context(), request, username)
	if err != nil {
		h.logPolicyResult("agent_guard_policy_create", username, uuid.Nil, preview, err)
		h.failPolicy(c, err, preview)
		return
	}
	h.logPolicyResult("agent_guard_policy_create", username, policy.ID, preview, nil)
	agentGuardSuccess(c, gin.H{"policy": policy, "validation": preview})
}

func (h *AgentGuardHandler) UpdatePolicyDraft(c *gin.Context) {
	id, ok := agentGuardPathUUID(c, "id", "agent_guard_policy_not_found")
	if !ok {
		return
	}
	var request model.AgentGuardPolicyDraftRequest
	if !agentGuardBindJSON(c, &request) {
		return
	}
	policy, preview, err := h.policyService.UpdateDraft(c.Request.Context(), id, request)
	username := agentGuardUsername(c)
	if err != nil {
		h.logPolicyResult("agent_guard_policy_update", username, id, preview, err)
		h.failPolicy(c, err, preview)
		return
	}
	h.logPolicyResult("agent_guard_policy_update", username, id, preview, nil)
	agentGuardSuccess(c, gin.H{"policy": policy, "validation": preview})
}

func (h *AgentGuardHandler) ValidatePolicyDraft(c *gin.Context) {
	id, ok := agentGuardPathUUID(c, "id", "agent_guard_policy_not_found")
	if !ok {
		return
	}
	existing, err := h.policies.GetByID(c.Request.Context(), id)
	if err != nil {
		h.fail(c, err)
		return
	}
	var request model.AgentGuardPolicyDraftRequest
	if !agentGuardBindJSON(c, &request) {
		return
	}
	preview := h.policyService.Validate(c.Request.Context(), request)
	if request.PolicyKey != existing.PolicyKey {
		preview.Valid = false
		preview.Errors = append(preview.Errors, model.AgentGuardPolicyValidationIssue{
			Field: "policy_key", Code: "immutable", Message: "policy_key cannot change",
		})
	}
	h.logPolicyResult("agent_guard_policy_validate", agentGuardUsername(c), id, preview, nil)
	agentGuardSuccess(c, preview)
}

func (h *AgentGuardHandler) PublishPolicy(c *gin.Context) {
	id, ok := agentGuardPathUUID(c, "id", "agent_guard_policy_not_found")
	if !ok {
		return
	}
	var request struct {
		Reason string `json:"reason,omitempty"`
	}
	if c.Request.ContentLength > 0 && !agentGuardBindJSON(c, &request) {
		return
	}
	if h.bundleService == nil {
		h.fail(c, service.ErrAgentGuardPolicyPublishDisabled)
		return
	}
	username := agentGuardUsername(c)
	result, err := h.bundleService.Publish(c.Request.Context(), id, username)
	if err != nil {
		h.logger.Warn("agent_guard_policy_publish_failed",
			zap.String("policy_id", id.String()),
			zap.String("username", username),
			zap.Error(err),
		)
		h.fail(c, err)
		return
	}
	h.logger.Info("agent_guard_policy_publish_accepted",
		zap.String("policy_id", id.String()),
		zap.String("username", username),
		zap.Int("delivery_count", len(result.Deliveries)),
	)
	c.JSON(http.StatusAccepted, gin.H{"code": 0, "message": "accepted", "data": result})
}

func (h *AgentGuardHandler) ListPolicyDeliveries(c *gin.Context) {
	id, ok := agentGuardPathUUID(c, "id", "agent_guard_policy_not_found")
	if !ok {
		return
	}
	policy, err := h.policies.GetByID(c.Request.Context(), id)
	if err != nil {
		h.fail(c, err)
		return
	}
	var query model.AgentGuardDeliveryQuery
	if !agentGuardBindQuery(c, &query) {
		return
	}
	if !agentGuardNormalizeBoundPage(c, &query.Page, &query.PageSize) {
		return
	}
	if query.HostID != "" && !agentGuardValidateUUIDs(c, "host_id", []string{query.HostID}) {
		return
	}
	items, total, err := h.policies.ListDeliveries(
		c.Request.Context(),
		policy.PolicyKey,
		policy.Version,
		query,
	)
	if err != nil {
		h.fail(c, err)
		return
	}
	agentGuardPage(c, items, total)
}

func (h *AgentGuardHandler) ListInstances(c *gin.Context) {
	query, ok := bindAgentRuntimeInstanceQuery(c)
	if !ok {
		return
	}
	if !h.applyAgentScope(c, &query) {
		return
	}
	items, total, err := h.query.ListInstances(c.Request.Context(), query)
	if err != nil {
		h.fail(c, err)
		return
	}
	agentGuardSuccess(c, gin.H{"items": redactAgentGuardInstances(items), "total": total})
}

func (h *AgentGuardHandler) GetInstance(c *gin.Context) {
	id, ok := agentGuardPathUUID(c, "id", "agent_guard_instance_not_found")
	if !ok {
		return
	}
	item, err := h.query.GetInstance(c.Request.Context(), id)
	if err != nil {
		h.fail(c, err)
		return
	}
	agentGuardSuccess(c, redactAgentGuardInstance(*item))
}

func (h *AgentGuardHandler) ListInstanceSessions(c *gin.Context) {
	instanceID, ok := agentGuardPathUUID(c, "id", "agent_guard_instance_not_found")
	if !ok {
		return
	}
	page, pageSize, pageOK := agentGuardPageParamsFromContext(c)
	if !pageOK {
		return
	}
	query := model.AgentBehaviorSessionQuery{
		AgentGuardPageQuery: model.AgentGuardPageQuery{Page: page, PageSize: pageSize},
		InstanceID:          instanceID.String(),
		Status:              c.Query("status"),
		Source:              c.Query("source"),
		TrustedOnly:         true,
	}
	items, total, err := h.query.ListSessions(c.Request.Context(), query)
	if err != nil {
		h.fail(c, err)
		return
	}
	agentGuardPage(c, redactAgentGuardSessions(items), total)
}

func (h *AgentGuardHandler) GetSession(c *gin.Context) {
	id, ok := agentGuardPathUUID(c, "id", "agent_guard_session_not_found")
	if !ok {
		return
	}
	item, err := h.query.GetSession(c.Request.Context(), id)
	if err != nil {
		h.fail(c, err)
		return
	}
	agentGuardSuccess(c, redactAgentGuardSession(*item))
}

func (h *AgentGuardHandler) DeleteSessions(c *gin.Context) {
	deleter, ok := h.query.(agentGuardSessionDeleter)
	if !ok {
		h.failWith(c, http.StatusServiceUnavailable, "agent_guard_session_delete_unavailable", "Session deletion is unavailable")
		return
	}
	var request struct {
		SessionIDs []string `json:"session_ids"`
	}
	if !agentGuardBindJSON(c, &request) {
		return
	}
	if len(request.SessionIDs) == 0 || len(request.SessionIDs) > agentGuardMaxPageSize {
		h.failWith(c, http.StatusBadRequest, "agent_guard_request_invalid", "session_ids must contain between 1 and 100 IDs")
		return
	}
	ids := make([]uuid.UUID, 0, len(request.SessionIDs))
	seen := make(map[uuid.UUID]struct{}, len(request.SessionIDs))
	for _, raw := range request.SessionIDs {
		id, err := uuid.Parse(strings.TrimSpace(raw))
		if err != nil || id == uuid.Nil {
			h.failWith(c, http.StatusBadRequest, "agent_guard_request_invalid", "session_ids contains an invalid UUID")
			return
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	if err := deleter.DeleteSessions(c.Request.Context(), ids); err != nil {
		h.fail(c, err)
		return
	}
	h.logger.Info("agent_guard_sessions_deleted",
		zap.String("username", agentGuardUsername(c)),
		zap.Int("session_count", len(ids)),
	)
	agentGuardSuccess(c, gin.H{"deleted": len(ids)})
}

func (h *AgentGuardHandler) ListExecutionUnits(c *gin.Context) {
	var query model.AgentExecutionUnitQuery
	if !agentGuardBindQuery(c, &query) {
		return
	}
	if !agentGuardNormalizeBoundPage(c, &query.Page, &query.PageSize) {
		return
	}
	if !agentGuardValidateOptionalUUIDFields(c, map[string]string{
		"host_id": query.HostID, "instance_id": query.InstanceID,
	}) {
		return
	}
	items, total, err := h.query.ListExecutionUnits(c.Request.Context(), query)
	if err != nil {
		h.fail(c, err)
		return
	}
	agentGuardPage(c, redactAgentGuardExecutionUnits(items), total)
}

func (h *AgentGuardHandler) GetExecutionUnit(c *gin.Context) {
	id, ok := agentGuardPathUUID(c, "id", "agent_guard_execution_unit_not_found")
	if !ok {
		return
	}
	item, err := h.query.GetExecutionUnit(c.Request.Context(), id)
	if err != nil {
		h.fail(c, err)
		return
	}
	agentGuardSuccess(c, item)
}

func (h *AgentGuardHandler) ListBehaviors(c *gin.Context) {
	query, ok := bindAgentBehaviorEventQuery(c)
	if !ok {
		return
	}
	items, total, err := h.query.ListBehaviors(c.Request.Context(), query)
	if err != nil {
		h.fail(c, err)
		return
	}
	agentGuardPage(c, redactAgentGuardBehaviors(items), total)
}

func (h *AgentGuardHandler) GetBehavior(c *gin.Context) {
	item, err := h.query.GetBehavior(c.Request.Context(), c.Param("event_id"))
	if err != nil {
		h.fail(c, err)
		return
	}
	agentGuardSuccess(c, item)
}

func (h *AgentGuardHandler) GetRawBehavior(c *gin.Context) {
	item, err := h.query.GetRawBehavior(c.Request.Context(), c.Param("event_id"))
	if err != nil {
		h.fail(c, err)
		return
	}
	agentGuardSuccess(c, item)
}

func (h *AgentGuardHandler) ListFindings(c *gin.Context) {
	query, ok := bindAgentSecurityFindingQuery(c)
	if !ok {
		return
	}
	if query.FindingDomain != "" &&
		query.FindingDomain != model.AgentSecurityFindingDomainTool &&
		query.FindingDomain != model.AgentSecurityFindingDomainEscape {
		agentGuardError(c, http.StatusBadRequest, "agent_guard_request_invalid", "finding_domain is invalid", nil)
		return
	}
	// Both domains are session-scoped. Escape rules are evaluated from the
	// permission snapshot of one Hook session; host-wide legacy rows are not a
	// valid detail scope anymore.
	if (query.FindingDomain == model.AgentSecurityFindingDomainTool || query.FindingDomain == model.AgentSecurityFindingDomainEscape) && query.SessionID == "" {
		agentGuardError(c, http.StatusBadRequest, "agent_guard_request_invalid", "session_id is required with finding_domain", nil)
		return
	}
	if !h.applyFindingScope(c, &query) {
		return
	}
	items, total, err := h.query.ListFindings(c.Request.Context(), query)
	if err != nil {
		h.fail(c, err)
		return
	}
	agentGuardPage(c, redactAgentGuardFindings(items), total)
}

func (h *AgentGuardHandler) GetFinding(c *gin.Context) {
	id, ok := agentGuardPathUUID(c, "finding_id", "agent_guard_finding_not_found")
	if !ok {
		return
	}
	item, err := h.query.GetFinding(c.Request.Context(), id)
	if err != nil {
		h.fail(c, err)
		return
	}
	if sessionID := strings.TrimSpace(c.Query("session_id")); sessionID != "" {
		parsedSessionID, parseErr := uuid.Parse(sessionID)
		if parseErr != nil || item.SessionID == nil || *item.SessionID != parsedSessionID {
			h.fail(c, repository.ErrAgentGuardFindingNotFound)
			return
		}
	}
	if instanceID := strings.TrimSpace(c.Query("instance_id")); instanceID != "" {
		parsedInstanceID, parseErr := uuid.Parse(instanceID)
		if parseErr != nil || item.InstanceID == nil || *item.InstanceID != parsedInstanceID {
			h.fail(c, repository.ErrAgentGuardFindingNotFound)
			return
		}
	}
	detail := agentGuardFindingDetail{
		AgentSecurityFinding: *item,
		EvidenceCompleteness: map[string]any{
			"referenced_event_count": len(decodeAgentGuardJSONStrings(item.EvidenceEventIDs)),
		},
		CounterEvidence: []string{},
		Uncertainties:   []string{},
	}
	var graph map[string]any
	if json.Unmarshal(item.EvidenceGraph, &graph) == nil {
		if counterIDs, ok := graph["counter_evidence_ids"].([]any); ok {
			for _, value := range counterIDs {
				if id, stringOK := value.(string); stringOK && strings.TrimSpace(id) != "" {
					detail.CounterEvidence = append(detail.CounterEvidence, id)
				}
			}
			detail.EvidenceCompleteness["counter_evidence_count"] = len(detail.CounterEvidence)
		}
		if completeness, ok := graph["evidence_completeness"].(map[string]any); ok {
			for key, value := range completeness {
				detail.EvidenceCompleteness[key] = value
			}
		} else if completeness, ok := graph["completeness"].(map[string]any); ok {
			for key, value := range completeness {
				detail.EvidenceCompleteness[key] = value
			}
		}
	}
	if item.LatestAnalysisID != nil {
		if run, analysisErr := h.query.GetAnalysis(c.Request.Context(), *item.LatestAnalysisID); analysisErr == nil {
			var output service.AgentGuardAnalysisOutput
			if json.Unmarshal(run.Output, &output) == nil {
				detail.CounterEvidence = uniqueStrings(append(detail.CounterEvidence, output.CounterEvidence...))
				detail.Uncertainties = output.Uncertainties
			}
		}
	}
	if matchedRules, rulesErr := h.buildFindingRuleDetails(c.Request.Context(), item); rulesErr != nil {
		h.logger.Warn("agent guard finding process tree unavailable",
			zap.String("finding_id", item.ID.String()), zap.Error(rulesErr))
		detail.MatchedRules = []agentGuardFindingRuleDetail{}
	} else {
		detail.MatchedRules = matchedRules
	}
	if isEscapeFinding(item) {
		detail.EscapeChain = h.buildEscapeEvidenceChain(c.Request.Context(), item, detail.MatchedRules)
		if item.SessionID != nil {
			if session, sessionErr := h.query.GetSession(c.Request.Context(), *item.SessionID); sessionErr == nil {
				if len(detail.EscapeChain.Permission) == 0 {
					var permission map[string]any
					if json.Unmarshal(session.Permission, &permission) == nil && len(permission) > 0 {
						detail.EscapeChain.Permission = permission
					}
				}
			}
		}
	}
	agentGuardSuccess(c, detail)
}

func isEscapeFinding(item *model.AgentSecurityFinding) bool {
	if item == nil {
		return false
	}
	var hits []map[string]any
	if json.Unmarshal(item.RuleHits, &hits) == nil {
		for _, hit := range hits {
			if key, _ := hit["rule_key"].(string); isEscapeRuleKey(key) {
				return true
			}
		}
	}
	return strings.Contains(strings.ToLower(item.Title), "escape") || strings.Contains(strings.ToLower(item.Title), "sandbox") || strings.Contains(strings.ToLower(item.Title), "逃逸")
}

func isEscapeRuleKey(key string) bool {
	key = strings.TrimSpace(strings.ToLower(key))
	if strings.HasPrefix(key, "age-") || strings.Contains(key, "escape") {
		return true
	}
	switch key {
	case "access_container_runtime_socket", "access_outside_workspace", "network_boundary_violation", "process_boundary_operation":
		return true
	default:
		return false
	}
}

func (h *AgentGuardHandler) buildEscapeEvidenceChain(ctx context.Context, item *model.AgentSecurityFinding, rules []agentGuardFindingRuleDetail) *agentGuardEscapeEvidenceChain {
	chain := &agentGuardEscapeEvidenceChain{HookEventIDs: uniqueStrings(decodeAgentGuardJSONStrings(item.EvidenceEventIDs)), HookEvents: []agentGuardEscapeHookEvent{}, ProcessEvidence: []map[string]any{}, ExecutionEvidence: []map[string]any{}, Gaps: []string{}}
	for _, rule := range rules {
		for _, process := range rule.ProcessTree {
			chain.ProcessEvidence = append(chain.ProcessEvidence, map[string]any{"pid": process.PID, "ppid": process.PPID, "start_ticks": process.ProcessStartTicks, "name": process.ProcessName, "exe": process.ProcessExe, "status": process.ProcessStatus})
		}
	}
	for _, eventID := range chain.HookEventIDs {
		if h == nil || h.query == nil {
			break
		}
		raw, err := h.query.GetRuntimeEvent(ctx, eventID)
		if err != nil || raw == nil || raw.HostID != item.HostID {
			continue
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(raw.EventData), &payload); err != nil {
			continue
		}
		actor := escapeEvidenceMap(payload["actor"])
		resource := escapeEvidenceMap(payload["resource"])
		resourceAttributes := escapeEvidenceMap(resource["attributes"])
		argv := escapeEvidenceStrings(actor["argv"])
		commandLine := strings.TrimSpace(raw.CommandLine)
		if commandLine == "" {
			commandLine = firstNonEmpty(escapeEvidenceString(resourceAttributes["command"]), escapeEvidenceCommand(resourceAttributes["tool_input"]))
		}
		if commandLine == "" {
			commandLine = strings.Join(argv, " ")
		}
		processName := escapeEvidenceString(actor["process_name"])
		if processName == "" {
			if exe := escapeEvidenceString(actor["exe"]); exe != "" {
				processName = filepath.Base(exe)
			}
		}
		processName = firstNonEmpty(processName, escapeRuntimeCommandName(raw.CommandLine), raw.EventType)
		processName = firstNonEmpty(escapeEvidenceString(resourceAttributes["tool_name"]), processName)
		processExe := escapeEvidenceString(actor["exe"])
		pid := escapeEvidenceInt(actor["pid"])
		if pid == 0 {
			pid = raw.PID
		}
		hook := agentGuardEscapeHookEvent{
			EventID: eventID, EventType: raw.EventType, ToolName: processName,
			Command: commandLine, CommandLine: commandLine, PID: pid,
			PPID: escapeEvidenceInt(actor["ppid"]), ProcessStartTicks: escapeEvidenceString(actor["start_ticks"]),
			ProcessName: processName, ProcessExe: processExe, CWD: escapeEvidenceString(actor["cwd"]),
			Outcome:  firstNonEmpty(escapeEvidenceString(payload["outcome"]), "unknown"),
			Decision: escapeEvidenceString(payload["decision"]),
			Target:   escapeEvidenceString(escapeEvidenceMap(payload["evidence"])["target"]),
		}
		chain.HookEvents = append(chain.HookEvents, hook)
		if hook.PID > 0 || hook.PPID > 0 || hook.ProcessName != "" || hook.Command != "" {
			chain.ProcessEvidence = append(chain.ProcessEvidence, map[string]any{
				"pid": hook.PID, "ppid": hook.PPID, "start_ticks": hook.ProcessStartTicks,
				"name": hook.ProcessName, "exe": hook.ProcessExe, "cmdline": hook.CommandLine,
				"cwd": hook.CWD, "status": firstNonEmpty(escapeEvidenceString(payload["process_status"]), "unknown"),
			})
		}
		evidence := escapeEvidenceMap(payload["evidence"])
		if chain.Permission == nil {
			chain.Permission = escapeEvidenceMap(evidence["permission"])
		}
		if chain.Classification == "" {
			chain.Classification = escapeEvidenceString(evidence["classification"])
		}
		chain.ExecutionEvidence = append(chain.ExecutionEvidence, map[string]any{
			"event_id": eventID, "operation": hook.EventType, "outcome": hook.Outcome,
			"return_code": evidence["return_code"], "hook_pid_matched": evidence["hook_pid_matched"],
			"tool_call_id": evidence["tool_call_id"], "reason": evidence["reason"],
		})
	}
	if len(chain.HookEventIDs) == 0 {
		chain.Gaps = append(chain.Gaps, "hook_event_missing")
	}
	if len(chain.ProcessEvidence) == 0 {
		chain.Gaps = append(chain.Gaps, "process_identity_missing")
	}
	return chain
}

func escapeEvidenceCommand(value any) string {
	if value == nil {
		return ""
	}
	if text := escapeEvidenceString(value); text != "" {
		return text
	}
	object := escapeEvidenceMap(value)
	for _, key := range []string{"command", "cmd", "command_line", "script"} {
		if text := escapeEvidenceString(object[key]); text != "" {
			return text
		}
	}
	return ""
}

func escapeEvidenceMap(value any) map[string]any {
	if result, ok := value.(map[string]any); ok {
		return result
	}
	return map[string]any{}
}

func escapeEvidenceString(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case json.Number:
		return typed.String()
	case float64:
		return strconv.FormatInt(int64(typed), 10)
	default:
		return ""
	}
}

func escapeEvidenceStrings(value any) []string {
	values, ok := value.([]any)
	if !ok {
		return nil
	}
	result := make([]string, 0, len(values))
	for _, item := range values {
		if value := escapeEvidenceString(item); value != "" {
			result = append(result, value)
		}
	}
	return result
}

func escapeEvidenceInt(value any) int {
	parsed, err := strconv.Atoi(escapeEvidenceString(value))
	if err != nil {
		return 0
	}
	return parsed
}

func escapeRuntimeCommandName(commandLine string) string {
	fields := strings.Fields(strings.TrimSpace(commandLine))
	if len(fields) == 0 {
		return ""
	}
	return filepath.Base(fields[0])
}

func (h *AgentGuardHandler) AnalyzeFinding(c *gin.Context) {
	id, ok := agentGuardPathUUID(c, "finding_id", "agent_guard_finding_not_found")
	if !ok {
		return
	}
	if c.Request.ContentLength != 0 {
		var request struct{}
		if !agentGuardBindJSON(c, &request) {
			return
		}
	}
	if h.analysis == nil {
		h.failWith(c, http.StatusServiceUnavailable, "agent_guard_analysis_disabled", "Agent Guard analysis is disabled")
		return
	}
	finding, err := h.query.GetFinding(c.Request.Context(), id)
	if err != nil {
		h.fail(c, err)
		return
	}
	scopeRequested := strings.TrimSpace(c.Query("agent_scope_key")) != "" ||
		strings.TrimSpace(c.Query("asset_id")) != ""
	if scopeRequested && finding.InstanceID == nil {
		h.failWith(c, http.StatusForbidden, "agent_guard_scope_invalid", "Finding is not bound to the selected Agent scope")
		return
	}
	scope := model.AgentSecurityFindingQuery{HostID: finding.HostID.String()}
	if finding.InstanceID != nil {
		scope.InstanceID = finding.InstanceID.String()
	}
	if !h.applyFindingScope(c, &scope) {
		return
	}
	requestedBy := c.GetString("username")
	if strings.TrimSpace(requestedBy) == "" {
		requestedBy = "system"
	}
	run, err := h.analysis.Request(c.Request.Context(), id, requestedBy)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"code": 0, "message": "accepted", "data": run})
}

func (h *AgentGuardHandler) ListFindingAnalyses(c *gin.Context) {
	findingID, ok := agentGuardPathUUID(c, "finding_id", "agent_guard_finding_not_found")
	if !ok {
		return
	}
	page, pageSize, pageOK := agentGuardPageParamsFromContext(c)
	if !pageOK {
		return
	}
	query := model.AgentSecurityAnalysisQuery{
		AgentGuardPageQuery: model.AgentGuardPageQuery{Page: page, PageSize: pageSize},
		FindingID:           findingID.String(),
		Status:              c.Query("status"),
	}
	items, total, err := h.query.ListAnalyses(c.Request.Context(), query)
	if err != nil {
		h.fail(c, err)
		return
	}
	agentGuardPage(c, redactAgentGuardAnalyses(items), total)
}

func (h *AgentGuardHandler) GetAnalysis(c *gin.Context) {
	id, ok := agentGuardPathUUID(c, "analysis_id", "agent_guard_analysis_not_found")
	if !ok {
		return
	}
	item, err := h.query.GetAnalysis(c.Request.Context(), id)
	if err != nil {
		h.fail(c, err)
		return
	}
	redacted := redactAgentGuardAnalysis(*item)
	agentGuardSuccess(c, redacted)
}

func (h *AgentGuardHandler) ListActions(c *gin.Context) {
	var query model.AgentGuardActionQuery
	if !agentGuardBindQuery(c, &query) {
		return
	}
	if !agentGuardNormalizeBoundPage(c, &query.Page, &query.PageSize) {
		return
	}
	if !agentGuardValidateOptionalUUIDFields(c, map[string]string{
		"host_id": query.HostID, "instance_id": query.InstanceID, "execution_unit_id": query.ExecutionUnitID,
	}) || !agentGuardBindTimeRange(c, &query.StartTime, &query.EndTime) {
		return
	}
	items, total, err := h.query.ListActions(c.Request.Context(), query)
	if err != nil {
		h.fail(c, err)
		return
	}
	agentGuardPage(c, items, total)
}

func (h *AgentGuardHandler) GetAction(c *gin.Context) {
	id, ok := agentGuardPathUUID(c, "id", "agent_guard_action_not_found")
	if !ok {
		return
	}
	item, err := h.query.GetAction(c.Request.Context(), id)
	if err != nil {
		h.fail(c, err)
		return
	}
	agentGuardSuccess(c, item)
}

func (h *AgentGuardHandler) ListExecutionUnitTimeline(c *gin.Context) {
	id, ok := agentGuardPathUUID(c, "id", "agent_guard_execution_unit_not_found")
	if !ok {
		return
	}
	if _, err := h.query.GetExecutionUnit(c.Request.Context(), id); err != nil {
		h.fail(c, err)
		return
	}
	page, pageSize, ok := agentGuardPageParamsFromContext(c)
	if !ok {
		return
	}
	items, total, err := h.query.ListActions(c.Request.Context(), model.AgentGuardActionQuery{
		AgentGuardPageQuery: model.AgentGuardPageQuery{Page: page, PageSize: pageSize},
		ExecutionUnitID:     id.String(),
	})
	if err != nil {
		h.fail(c, err)
		return
	}
	agentGuardPage(c, items, total)
}

func (h *AgentGuardHandler) FreezeExecutionUnit(c *gin.Context) {
	h.requestExecutionUnitAction(c, model.AgentGuardActionFreezeExecutionUnit)
}

func (h *AgentGuardHandler) ResumeExecutionUnit(c *gin.Context) {
	h.requestExecutionUnitAction(c, model.AgentGuardActionResumeExecutionUnit)
}

func (h *AgentGuardHandler) KillExecutionUnit(c *gin.Context) {
	h.requestExecutionUnitAction(c, model.AgentGuardActionKillExecutionUnit)
}

func (h *AgentGuardHandler) KillInstance(c *gin.Context) {
	id, ok := agentGuardPathUUID(c, "id", "agent_guard_instance_not_found")
	if !ok {
		return
	}
	request, ok := bindAgentGuardManualActionRequest(c)
	if !ok {
		return
	}
	if h.actions == nil {
		h.failWith(c, http.StatusServiceUnavailable, "agent_guard_actions_disabled", "Agent Guard actions are disabled")
		return
	}
	if agentGuardActionScopeRequested(c) {
		instance, err := h.query.GetInstance(c.Request.Context(), id)
		if err != nil {
			h.fail(c, err)
			return
		}
		if !h.validateActionScope(c, *instance) {
			return
		}
	}
	action, err := h.actions.RequestInstanceKill(
		c.Request.Context(), id, request, agentGuardActionUsername(c),
	)
	if err != nil {
		h.failAction(c, action, err)
		return
	}
	agentGuardAcceptedAction(c, action)
}

func (h *AgentGuardHandler) requestExecutionUnitAction(c *gin.Context, actionName string) {
	id, ok := agentGuardPathUUID(c, "id", "agent_guard_execution_unit_not_found")
	if !ok {
		return
	}
	request, ok := bindAgentGuardManualActionRequest(c)
	if !ok {
		return
	}
	if h.actions == nil {
		h.failWith(c, http.StatusServiceUnavailable, "agent_guard_actions_disabled", "Agent Guard actions are disabled")
		return
	}
	if agentGuardActionScopeRequested(c) {
		unit, err := h.query.GetExecutionUnit(c.Request.Context(), id)
		if err != nil {
			h.fail(c, err)
			return
		}
		instance, err := h.query.GetInstance(c.Request.Context(), unit.InstanceID)
		if err != nil {
			h.fail(c, err)
			return
		}
		if unit.HostID != instance.HostID || !h.validateActionScope(c, *instance) {
			if unit.HostID != instance.HostID {
				h.failWith(c, http.StatusForbidden, "agent_guard_action_target_invalid", "Action target ownership is invalid")
			}
			return
		}
	}
	action, err := h.actions.RequestExecutionUnit(
		c.Request.Context(), id, actionName, request, agentGuardActionUsername(c),
	)
	if err != nil {
		h.failAction(c, action, err)
		return
	}
	agentGuardAcceptedAction(c, action)
}

func (h *AgentGuardHandler) validateActionScope(c *gin.Context, instance model.AgentRuntimeInstance) bool {
	hostID := strings.TrimSpace(c.Query("host_id"))
	instanceID := strings.TrimSpace(c.Query("instance_id"))
	assetID := strings.TrimSpace(c.Query("asset_id"))
	scopeKey := strings.TrimSpace(c.Query("agent_scope_key"))
	if !agentGuardValidateOptionalUUIDFields(c, map[string]string{
		"host_id": hostID, "instance_id": instanceID, "asset_id": assetID,
	}) {
		return false
	}
	if assetID != "" && scopeKey != "" {
		h.failWith(c, http.StatusBadRequest, "agent_guard_request_invalid", "asset_id and agent_scope_key are mutually exclusive")
		return false
	}
	if hostID != "" && hostID != instance.HostID.String() ||
		instanceID != "" && instanceID != instance.ID.String() ||
		assetID != "" && (instance.AssetID == nil || assetID != instance.AssetID.String()) {
		h.failWith(c, http.StatusForbidden, "agent_guard_action_target_invalid", "Action target is outside the selected Agent scope")
		return false
	}
	if scopeKey == "" {
		return true
	}
	if h.scopeSigner == nil {
		h.failWith(c, http.StatusServiceUnavailable, "agent_guard_scope_unavailable", "Agent scope verification is unavailable")
		return false
	}
	scope, err := h.scopeSigner.Verify(scopeKey)
	if err != nil {
		h.failWith(c, http.StatusBadRequest, "agent_guard_scope_invalid", "Agent scope key is invalid")
		return false
	}
	if scope.HostID != instance.HostID.String() || scope.AgentType != instance.AgentType ||
		scope.ProfileKey != instance.ProfileKey ||
		scope.AssetID != "" && (instance.AssetID == nil || scope.AssetID != instance.AssetID.String()) {
		h.failWith(c, http.StatusForbidden, "agent_guard_action_target_invalid", "Action target is outside the selected Agent scope")
		return false
	}
	return true
}

func (h *AgentGuardHandler) failAction(c *gin.Context, action *model.AgentGuardAction, err error) {
	status, code, message := agentGuardErrorMapping(err)
	agentGuardError(c, status, code, message, action)
}

type agentGuardPanoramaNode struct {
	ID                string                                `json:"id"`
	ParentID          string                                `json:"parent_id,omitempty"`
	NodeType          string                                `json:"node_type"`
	Label             string                                `json:"label"`
	Severity          string                                `json:"severity,omitempty"`
	HasChildren       bool                                  `json:"has_children"`
	ChildCount        int64                                 `json:"child_count,omitempty"`
	OccurredAt        string                                `json:"occurred_at,omitempty"`
	PID               int                                   `json:"pid,omitempty"`
	PPID              int                                   `json:"ppid,omitempty"`
	StartTicks        string                                `json:"process_start_ticks,omitempty"`
	ProcessStatus     string                                `json:"process_status,omitempty"`
	Cmdline           string                                `json:"cmdline,omitempty"`
	ExternalSessionID string                                `json:"external_session_id,omitempty"`
	SessionSource     string                                `json:"session_source,omitempty"`
	SessionConfidence string                                `json:"session_confidence,omitempty"`
	ToolName          string                                `json:"tool_name,omitempty"`
	ToolCallID        string                                `json:"tool_call_id,omitempty"`
	TurnID            string                                `json:"turn_id,omitempty"`
	Command           string                                `json:"command,omitempty"`
	ToolInput         any                                   `json:"tool_input,omitempty"`
	ToolResponse      any                                   `json:"tool_response,omitempty"`
	CorrelationStatus string                                `json:"correlation_status,omitempty"`
	CorrelationMethod string                                `json:"correlation_method,omitempty"`
	Trust             *service.AgentGuardPanoramaTrust      `json:"trust,omitempty"`
	Collection        *service.AgentGuardPanoramaCollection `json:"collection,omitempty"`
}

func (h *AgentGuardHandler) GetPanorama(c *gin.Context) {
	if h.scopeSigner == nil {
		h.failWith(c, http.StatusServiceUnavailable, "agent_guard_scope_unavailable", "Panorama node signing is unavailable")
		return
	}
	query, ok := bindAgentRuntimeInstanceQuery(c)
	if !ok {
		return
	}
	// The session-scoped process tree is paginated at its root level, while the
	// instance lookup itself must always cover the selected scope.
	panoramaPage, panoramaPageSize := query.Page, query.PageSize
	query.Page, query.PageSize = 1, agentGuardMaxPageSize
	if !h.applyAgentScope(c, &query) {
		return
	}
	if len(query.InstanceIDs) == 0 && query.Status == "" {
		query.Status = "running"
	}
	if len(query.AssetIDs) == 0 && c.Query("agent_scope_key") == "" {
		agentGuardError(c, http.StatusBadRequest, "agent_guard_request_invalid", "Exactly one asset_id or agent_scope_key is required", nil)
		return
	}
	items, total, err := h.query.ListInstances(c.Request.Context(), query)
	if err != nil {
		h.fail(c, err)
		return
	}
	if len(items) == 0 {
		agentGuardSuccess(c, gin.H{"root": nil, "items": []agentGuardPanoramaNode{}, "total": 0})
		return
	}
	if query.SessionID != "" {
		sessionID, parseErr := uuid.Parse(query.SessionID)
		if parseErr != nil {
			agentGuardError(c, http.StatusBadRequest, "agent_guard_request_invalid", "session_id must be a UUID", nil)
			return
		}
		session, sessionErr := h.query.GetSession(c.Request.Context(), sessionID)
		if sessionErr != nil {
			h.fail(c, sessionErr)
			return
		}
		var selectedInstance *model.AgentRuntimeInstance
		for index := range items {
			if items[index].ID == session.InstanceID {
				selectedInstance = &items[index]
				break
			}
		}
		if selectedInstance == nil {
			h.failWith(c, http.StatusForbidden, "agent_guard_panorama_node_invalid", "Panorama session is outside the selected Agent scope")
			return
		}
		if session.ExecutionUnitID == nil {
			agentGuardSuccess(c, agentGuardPanoramaPage([]agentGuardPanoramaNode{}, 0, 1, 1))
			return
		}
		unit, unitErr := h.query.GetExecutionUnit(c.Request.Context(), *session.ExecutionUnitID)
		if unitErr != nil || unit.HostID != selectedInstance.HostID || unit.InstanceID != selectedInstance.ID {
			h.failWith(c, http.StatusForbidden, "agent_guard_panorama_node_invalid", "Panorama execution unit is outside the selected session")
			return
		}
		ref := service.AgentGuardPanoramaNodeRef{
			HostID: selectedInstance.HostID.String(), InstanceID: selectedInstance.ID.String(),
			SessionID: session.ID.String(), ExecutionUnitID: unit.ID.String(),
		}
		behaviors, toolTotal, behaviorErr := h.query.ListBehaviors(c.Request.Context(), model.AgentBehaviorEventQuery{
			AgentGuardPageQuery: model.AgentGuardPageQuery{Page: panoramaPage, PageSize: panoramaPageSize},
			HostID:              selectedInstance.HostID.String(), InstanceID: selectedInstance.ID.String(),
			SessionID: session.ID.String(), ExecutionUnitID: unit.ID.String(), Category: "tool",
		})
		if behaviorErr != nil {
			h.fail(c, behaviorErr)
			return
		}
		toolBehaviors := make([]model.AgentBehaviorEvent, 0, len(behaviors))
		for _, behavior := range behaviors {
			if behavior.Category == "tool" {
				toolBehaviors = append(toolBehaviors, behavior)
			}
		}
		if len(toolBehaviors) != len(behaviors) {
			toolTotal = int64(len(toolBehaviors))
		}
		nodes := make([]agentGuardPanoramaNode, 0, len(behaviors))
		for _, behavior := range toolBehaviors {
			node, nodeErr := h.panoramaBehaviorNode(ref, behavior, session)
			if nodeErr != nil {
				h.fail(c, nodeErr)
				return
			}
			nodes = append(nodes, node)
		}
		agentGuardSuccess(c, agentGuardPanoramaPage(nodes, toolTotal, panoramaPage, panoramaPageSize))
		return
	}
	hostID := items[0].HostID.String()
	objectID := c.Query("agent_scope_key")
	assetID := ""
	if objectID == "" {
		assetID = query.AssetIDs[0]
		objectID = assetID
	}
	rootToken, err := h.scopeSigner.SignPanoramaNode(service.AgentGuardPanoramaNodeRef{
		NodeType: "agent_asset",
		ObjectID: objectID,
		HostID:   hostID,
		AssetID:  assetID,
	}, agentGuardPanoramaNodeTTL)
	if err != nil {
		h.fail(c, err)
		return
	}
	label := items[0].DisplayName
	if label == "" {
		label = items[0].AgentType
	}
	root := agentGuardPanoramaNode{
		ID:          rootToken,
		NodeType:    "agent_asset",
		Label:       label,
		HasChildren: total > 0,
		ChildCount:  total,
	}
	agentGuardSuccess(c, gin.H{"root": root, "items": []agentGuardPanoramaNode{root}, "total": 1})
}

func (h *AgentGuardHandler) GetPanoramaNodeChildren(c *gin.Context) {
	if h.scopeSigner == nil {
		h.failWith(c, http.StatusServiceUnavailable, "agent_guard_scope_unavailable", "Panorama node signing is unavailable")
		return
	}
	ref, err := h.scopeSigner.VerifyPanoramaNode(c.Param("node_id"))
	if err != nil {
		h.fail(c, err)
		return
	}
	page, pageSize, ok := agentGuardPageParamsFromContext(c)
	if !ok {
		return
	}
	switch ref.NodeType {
	case "agent_asset":
		h.panoramaAgentChildren(c, ref, page, pageSize)
	case "instance":
		h.panoramaInstanceChildren(c, ref, page, pageSize)
	case "session":
		h.panoramaSessionChildren(c, ref)
	case "execution_unit":
		h.panoramaExecutionUnitChildren(c, ref, page, pageSize)
	case "process":
		if ref.ExecutionUnitID == "" || ref.ProcessPID <= 0 || ref.ProcessStartTicks == "" {
			h.panoramaBehaviorChildren(c, ref)
			return
		}
		h.panoramaProcessChildren(c, ref, page, pageSize)
	case "behavior", "process_event", "tool_call":
		h.panoramaBehaviorChildren(c, ref)
	default:
		h.failWith(c, http.StatusBadRequest, "agent_guard_panorama_node_invalid", "Panorama node type is not expandable")
	}
}

func (h *AgentGuardHandler) panoramaAgentChildren(
	c *gin.Context,
	ref service.AgentGuardPanoramaNodeRef,
	page int,
	pageSize int,
) {
	query := model.AgentRuntimeInstanceQuery{
		AgentGuardPageQuery: model.AgentGuardPageQuery{Page: page, PageSize: pageSize},
		HostID:              ref.HostID,
		Status:              "running",
	}
	if ref.AssetID != "" {
		query.AssetIDs = []string{ref.AssetID}
	} else {
		scope, err := h.scopeSigner.Verify(ref.ObjectID)
		if err != nil || scope.HostID != ref.HostID {
			h.failWith(c, http.StatusForbidden, "agent_guard_panorama_node_invalid", "Panorama node is outside the selected Agent scope")
			return
		}
		if scope.AssetID != "" {
			query.AssetIDs = []string{scope.AssetID}
		} else {
			query.AgentTypes = []string{scope.AgentType}
			query.ProfileKey = scope.ProfileKey
		}
	}
	instances, total, err := h.query.ListInstances(c.Request.Context(), query)
	if err != nil {
		h.fail(c, err)
		return
	}
	nodes := make([]agentGuardPanoramaNode, 0, len(instances))
	for _, instance := range instances {
		token, signErr := h.scopeSigner.SignPanoramaNode(service.AgentGuardPanoramaNodeRef{
			NodeType:   "instance",
			ObjectID:   instance.ID.String(),
			HostID:     instance.HostID.String(),
			AssetID:    ref.AssetID,
			InstanceID: instance.ID.String(),
		}, agentGuardPanoramaNodeTTL)
		if signErr != nil {
			h.fail(c, signErr)
			return
		}
		label := instance.DisplayName
		if label == "" {
			label = instance.AgentType
		}
		nodes = append(nodes, agentGuardPanoramaNode{
			ID: token, NodeType: "instance", Label: label, HasChildren: true,
			OccurredAt: instance.LastSeenAt.UTC().Format(time.RFC3339Nano),
		})
	}
	agentGuardSuccess(c, agentGuardPanoramaPage(nodes, total, page, pageSize))
}

func (h *AgentGuardHandler) panoramaInstanceChildren(
	c *gin.Context,
	ref service.AgentGuardPanoramaNodeRef,
	page int,
	pageSize int,
) {
	instanceID, parseErr := uuid.Parse(ref.ObjectID)
	if parseErr != nil {
		h.fail(c, service.ErrAgentGuardNodeInvalid)
		return
	}
	instance, err := h.query.GetInstance(c.Request.Context(), instanceID)
	if err != nil || instance.HostID.String() != ref.HostID {
		h.failWith(c, http.StatusForbidden, "agent_guard_panorama_node_invalid", "Panorama instance is outside the selected host")
		return
	}
	sessions, total, err := h.query.ListSessions(c.Request.Context(), model.AgentBehaviorSessionQuery{
		AgentGuardPageQuery: model.AgentGuardPageQuery{Page: page, PageSize: pageSize},
		InstanceID:          ref.ObjectID,
		PreferTrusted:       true,
		TrustedOnly:         true,
	})
	if err != nil {
		h.fail(c, err)
		return
	}
	nodes := make([]agentGuardPanoramaNode, 0, len(sessions))
	for _, session := range sessions {
		token, signErr := h.scopeSigner.SignPanoramaNode(service.AgentGuardPanoramaNodeRef{
			NodeType:   "session",
			ObjectID:   session.ID.String(),
			HostID:     ref.HostID,
			AssetID:    ref.AssetID,
			InstanceID: ref.ObjectID,
			SessionID:  session.ID.String(),
		}, agentGuardPanoramaNodeTTL)
		if signErr != nil {
			h.fail(c, signErr)
			return
		}
		nodes = append(nodes, agentGuardPanoramaNode{
			ID: token, NodeType: "session", Label: agentGuardSessionLabel(session), HasChildren: session.ExecutionUnitID != nil,
			ChildCount:    boolToInt64(session.ExecutionUnitID != nil),
			OccurredAt:    session.StartedAt.UTC().Format(time.RFC3339Nano),
			SessionSource: session.Source, SessionConfidence: session.Confidence,
			ExternalSessionID: session.ExternalSessionID,
		})
	}
	agentGuardSuccess(c, agentGuardPanoramaPage(nodes, total, page, pageSize))
}

func (h *AgentGuardHandler) panoramaSessionChildren(c *gin.Context, ref service.AgentGuardPanoramaNodeRef) {
	sessionID, err := uuid.Parse(ref.ObjectID)
	if err != nil {
		h.fail(c, service.ErrAgentGuardNodeInvalid)
		return
	}
	session, err := h.query.GetSession(c.Request.Context(), sessionID)
	if err != nil || session.HostID.String() != ref.HostID || session.InstanceID.String() != ref.InstanceID {
		h.failWith(c, http.StatusForbidden, "agent_guard_panorama_node_invalid", "Panorama session is outside the selected instance")
		return
	}
	if session.ExecutionUnitID == nil {
		agentGuardPage(c, []agentGuardPanoramaNode{}, 0)
		return
	}
	unit, err := h.query.GetExecutionUnit(c.Request.Context(), *session.ExecutionUnitID)
	if err != nil || unit.HostID.String() != ref.HostID || unit.InstanceID.String() != ref.InstanceID {
		h.failWith(c, http.StatusForbidden, "agent_guard_panorama_node_invalid", "Panorama execution unit is outside the selected session")
		return
	}
	token, err := h.scopeSigner.SignPanoramaNode(service.AgentGuardPanoramaNodeRef{
		NodeType:        "execution_unit",
		ObjectID:        unit.ID.String(),
		HostID:          ref.HostID,
		AssetID:         ref.AssetID,
		InstanceID:      ref.InstanceID,
		SessionID:       ref.ObjectID,
		ExecutionUnitID: unit.ID.String(),
	}, agentGuardPanoramaNodeTTL)
	if err != nil {
		h.fail(c, err)
		return
	}
	node := agentGuardPanoramaNode{
		ID: token, NodeType: "execution_unit", Label: unit.UnitType, HasChildren: true,
		OccurredAt: unit.FirstSeenAt.UTC().Format(time.RFC3339Nano),
	}
	remoteProjection := service.ProjectAgentGuardRemoteVisibility(*unit)
	node.Trust = remoteProjection.Trust
	node.Collection = remoteProjection.Collection
	agentGuardPage(c, []agentGuardPanoramaNode{node}, 1)
}

func (h *AgentGuardHandler) panoramaExecutionUnitChildren(
	c *gin.Context,
	ref service.AgentGuardPanoramaNodeRef,
	page int,
	pageSize int,
) {
	unitID, err := uuid.Parse(ref.ObjectID)
	if err != nil {
		h.fail(c, service.ErrAgentGuardNodeInvalid)
		return
	}
	unit, err := h.query.GetExecutionUnit(c.Request.Context(), unitID)
	if err != nil || unit.HostID.String() != ref.HostID || unit.InstanceID.String() != ref.InstanceID {
		h.failWith(c, http.StatusForbidden, "agent_guard_panorama_node_invalid", "Panorama execution unit is outside the selected instance")
		return
	}
	var trustedSession *model.AgentBehaviorSession
	if sessionID, parseErr := uuid.Parse(ref.SessionID); parseErr == nil {
		if session, sessionErr := h.query.GetSession(c.Request.Context(), sessionID); sessionErr == nil &&
			session.HostID.String() == ref.HostID && session.InstanceID.String() == ref.InstanceID {
			trustedSession = session
		}
	}
	processFacts, processTotal, err := h.query.ListProcessFacts(c.Request.Context(), model.AgentBehaviorEventQuery{
		HostID: ref.HostID, InstanceID: ref.InstanceID, SessionID: ref.SessionID,
		ExecutionUnitID: ref.ObjectID,
	}, agentGuardProcessFactLimit)
	if err != nil {
		h.fail(c, err)
		return
	}
	tree := buildAgentGuardProcessTree(processFacts)
	processRef := ref
	processRef.ExecutionUnitID = ref.ObjectID
	nodes := make([]agentGuardPanoramaNode, 0, len(tree.Roots)+pageSize)
	for _, process := range tree.Roots {
		node, nodeErr := h.panoramaProcessNode(processRef, process)
		if nodeErr != nil {
			h.fail(c, nodeErr)
			return
		}
		nodes = append(nodes, node)
	}

	behaviors, _, err := h.query.ListBehaviors(c.Request.Context(), model.AgentBehaviorEventQuery{
		AgentGuardPageQuery: model.AgentGuardPageQuery{Page: page, PageSize: pageSize},
		HostID:              ref.HostID,
		InstanceID:          ref.InstanceID,
		SessionID:           ref.SessionID,
		ExecutionUnitID:     ref.ObjectID,
	})
	if err != nil {
		h.fail(c, err)
		return
	}
	for _, behavior := range behaviors {
		if behavior.Category == "process" || behavior.PID != nil && tree.Nodes[agentGuardProcessKey(*behavior.PID, behavior.ProcessStartTicks)] != nil {
			continue
		}
		node, nodeErr := h.panoramaBehaviorNode(processRef, behavior, trustedSession)
		if nodeErr != nil {
			h.fail(c, nodeErr)
			return
		}
		nodes = append(nodes, node)
	}
	if processTotal > agentGuardProcessFactLimit {
		for index := range nodes {
			if nodes[index].NodeType == "process" {
				nodes[index].Collection = &service.AgentGuardPanoramaCollection{
					Limitations: []string{"process_fact_limit_reached"},
				}
			}
		}
	}
	agentGuardSuccess(c, agentGuardPanoramaPage(nodes, int64(len(nodes)), 1, len(nodes)))
}

func (h *AgentGuardHandler) panoramaProcessChildren(c *gin.Context, ref service.AgentGuardPanoramaNodeRef, page, pageSize int) {
	unitID, err := uuid.Parse(ref.ExecutionUnitID)
	if err != nil {
		h.fail(c, service.ErrAgentGuardNodeInvalid)
		return
	}
	unit, err := h.query.GetExecutionUnit(c.Request.Context(), unitID)
	if err != nil || unit.HostID.String() != ref.HostID || unit.InstanceID.String() != ref.InstanceID {
		h.failWith(c, http.StatusForbidden, "agent_guard_panorama_node_invalid", "Panorama process is outside the selected execution unit")
		return
	}
	facts, _, err := h.query.ListProcessFacts(c.Request.Context(), model.AgentBehaviorEventQuery{
		HostID: ref.HostID, InstanceID: ref.InstanceID, SessionID: ref.SessionID,
		ExecutionUnitID: ref.ExecutionUnitID,
	}, agentGuardProcessFactLimit)
	if err != nil {
		h.fail(c, err)
		return
	}
	tree := buildAgentGuardProcessTree(facts)
	process := tree.Nodes[ref.ObjectID]
	if process == nil || process.PID != ref.ProcessPID || process.StartTicks != ref.ProcessStartTicks {
		h.fail(c, service.ErrAgentGuardNodeInvalid)
		return
	}
	nodes := make([]agentGuardPanoramaNode, 0, len(process.Children)+pageSize)
	for _, child := range process.Children {
		node, nodeErr := h.panoramaProcessNode(ref, child)
		if nodeErr != nil {
			h.fail(c, nodeErr)
			return
		}
		nodes = append(nodes, node)
	}
	pid := process.PID
	behaviors, behaviorTotal, err := h.query.ListBehaviors(c.Request.Context(), model.AgentBehaviorEventQuery{
		AgentGuardPageQuery: model.AgentGuardPageQuery{Page: page, PageSize: pageSize},
		HostID:              ref.HostID, InstanceID: ref.InstanceID, SessionID: ref.SessionID,
		ExecutionUnitID: ref.ExecutionUnitID, PID: &pid, ProcessStartTicks: process.StartTicks,
	})
	if err != nil {
		h.fail(c, err)
		return
	}
	var trustedSession *model.AgentBehaviorSession
	if sessionID, parseErr := uuid.Parse(ref.SessionID); parseErr == nil {
		trustedSession, _ = h.query.GetSession(c.Request.Context(), sessionID)
	}
	for _, behavior := range behaviors {
		node, nodeErr := h.panoramaBehaviorNode(ref, behavior, trustedSession)
		if nodeErr != nil {
			h.fail(c, nodeErr)
			return
		}
		if behavior.Category == "process" {
			node.NodeType = "process_event"
			node.Label = strings.ReplaceAll(behavior.Operation, "_", " ")
		}
		nodes = append(nodes, node)
	}
	agentGuardSuccess(c, agentGuardPanoramaPage(nodes, int64(len(process.Children))+behaviorTotal, page, pageSize))
}

func (h *AgentGuardHandler) panoramaBehaviorChildren(c *gin.Context, ref service.AgentGuardPanoramaNodeRef) {
	behavior, err := h.query.GetBehavior(c.Request.Context(), ref.ObjectID)
	if err != nil ||
		behavior.HostID.String() != ref.HostID ||
		behavior.InstanceID == nil ||
		behavior.InstanceID.String() != ref.InstanceID {
		h.failWith(c, http.StatusForbidden, "agent_guard_panorama_node_invalid", "Panorama process is outside the selected instance")
		return
	}
	var trustedSession *model.AgentBehaviorSession
	if sessionID, parseErr := uuid.Parse(ref.SessionID); parseErr == nil {
		if session, sessionErr := h.query.GetSession(c.Request.Context(), sessionID); sessionErr == nil &&
			session.HostID.String() == ref.HostID && session.InstanceID.String() == ref.InstanceID {
			trustedSession = session
		}
	}
	projection := service.ProjectAgentGuardToolEvidence(*behavior, trustedSession)
	nodes := make([]agentGuardPanoramaNode, 0, 2)
	if behavior.Category == "tool" {
		label := service.AgentGuardToolSemanticsUnobservable
		if projection.Trust != nil && projection.Trust.ToolSemantics == service.AgentGuardToolSemanticsTrusted {
			label = strings.TrimSpace(behavior.ResourceIdentity)
		}
		nodes = append(nodes, agentGuardPanoramaNode{
			ID: "resource:" + behavior.RawEventID, NodeType: "tool", Label: label,
			Severity: behavior.Severity, Trust: projection.Trust, Collection: projection.Collection,
		})
	} else if behavior.ResourceType != "" {
		nodes = append(nodes, agentGuardPanoramaNode{
			ID:       "resource:" + behavior.RawEventID,
			NodeType: behavior.ResourceType,
			Label:    behavior.ResourceIdentity,
			Severity: behavior.Severity,
		})
	}
	if behavior.RuleID != "" {
		nodes = append(nodes, agentGuardPanoramaNode{
			ID:       "rule:" + behavior.RawEventID,
			NodeType: "rule",
			Label:    behavior.RuleID,
			Severity: behavior.Severity,
		})
	}
	agentGuardPage(c, nodes, int64(len(nodes)))
}

func (h *AgentGuardHandler) applyAgentScope(c *gin.Context, query *model.AgentRuntimeInstanceQuery) bool {
	scopeKey := strings.TrimSpace(c.Query("agent_scope_key"))
	if scopeKey == "" {
		query.AgentScopeKey = ""
		if len(query.AssetIDs) > 1 && c.FullPath() == "/api/v1/agent-guard/panorama" {
			agentGuardError(c, http.StatusBadRequest, "agent_guard_request_invalid", "Panorama requires exactly one asset_id", nil)
			return false
		}
		return true
	}
	if len(query.AssetIDs) > 0 || c.Query("asset_id") != "" {
		agentGuardError(c, http.StatusBadRequest, "agent_guard_request_invalid", "asset_id and agent_scope_key are mutually exclusive", nil)
		return false
	}
	if h.scopeSigner == nil {
		h.failWith(c, http.StatusServiceUnavailable, "agent_guard_scope_unavailable", "Agent scope verification is unavailable")
		return false
	}
	scope, err := h.scopeSigner.Verify(scopeKey)
	if err != nil {
		h.failWith(c, http.StatusBadRequest, "agent_guard_scope_invalid", "Agent scope key is invalid")
		return false
	}
	query.AgentScopeKey = ""
	if _, parseErr := uuid.Parse(scope.HostID); parseErr != nil {
		h.failWith(c, http.StatusBadRequest, "agent_guard_scope_invalid", "Agent scope contains an invalid host identity")
		return false
	}
	if query.HostID != "" && query.HostID != scope.HostID {
		h.failWith(c, http.StatusForbidden, "agent_guard_scope_invalid", "Agent scope does not match host_id")
		return false
	}
	if len(query.AgentTypes) > 0 && !containsString(query.AgentTypes, scope.AgentType) {
		h.failWith(c, http.StatusForbidden, "agent_guard_scope_invalid", "Agent scope does not match agent_types")
		return false
	}
	if query.ProfileKey != "" && query.ProfileKey != scope.ProfileKey {
		h.failWith(c, http.StatusForbidden, "agent_guard_scope_invalid", "Agent scope does not match profile_key")
		return false
	}
	query.HostID = scope.HostID
	if scope.AssetID != "" {
		if _, parseErr := uuid.Parse(scope.AssetID); parseErr != nil {
			h.failWith(c, http.StatusBadRequest, "agent_guard_scope_invalid", "Agent scope contains an invalid asset identity")
			return false
		}
		query.AssetIDs = []string{scope.AssetID}
		query.AgentTypes = nil
		query.ProfileKey = ""
	} else {
		query.AgentTypes = []string{scope.AgentType}
		query.ProfileKey = scope.ProfileKey
	}
	return true
}

func (h *AgentGuardHandler) applyFindingScope(c *gin.Context, query *model.AgentSecurityFindingQuery) bool {
	assetID := strings.TrimSpace(c.Query("asset_id"))
	scopeKey := strings.TrimSpace(c.Query("agent_scope_key"))
	query.AssetID = ""
	query.AgentScopeKey = ""
	if assetID != "" && scopeKey != "" {
		agentGuardError(c, http.StatusBadRequest, "agent_guard_request_invalid", "asset_id and agent_scope_key are mutually exclusive", nil)
		return false
	}
	if assetID == "" && scopeKey == "" {
		return true
	}
	if assetID != "" {
		if _, err := uuid.Parse(assetID); err != nil {
			agentGuardError(c, http.StatusBadRequest, "agent_guard_request_invalid", "asset_id must be a UUID", nil)
			return false
		}
		query.AssetID = assetID
	} else {
		if h.scopeSigner == nil {
			h.failWith(c, http.StatusServiceUnavailable, "agent_guard_scope_unavailable", "Agent scope verification is unavailable")
			return false
		}
		scope, err := h.scopeSigner.Verify(scopeKey)
		if err != nil {
			h.failWith(c, http.StatusBadRequest, "agent_guard_scope_invalid", "Agent scope key is invalid")
			return false
		}
		if _, parseErr := uuid.Parse(scope.HostID); parseErr != nil {
			h.failWith(c, http.StatusBadRequest, "agent_guard_scope_invalid", "Agent scope contains an invalid host identity")
			return false
		}
		if query.HostID != "" && query.HostID != scope.HostID {
			h.failWith(c, http.StatusForbidden, "agent_guard_scope_invalid", "Agent scope does not match host_id")
			return false
		}
		if query.AgentType != "" && query.AgentType != scope.AgentType {
			h.failWith(c, http.StatusForbidden, "agent_guard_scope_invalid", "Agent scope does not match agent_type")
			return false
		}
		if query.ProfileKey != "" && query.ProfileKey != scope.ProfileKey {
			h.failWith(c, http.StatusForbidden, "agent_guard_scope_invalid", "Agent scope does not match profile_key")
			return false
		}
		query.HostID = scope.HostID
		if scope.AssetID != "" {
			if _, parseErr := uuid.Parse(scope.AssetID); parseErr != nil {
				h.failWith(c, http.StatusBadRequest, "agent_guard_scope_invalid", "Agent scope contains an invalid asset identity")
				return false
			}
			query.AssetID = scope.AssetID
		} else {
			query.AgentType = scope.AgentType
			query.ProfileKey = scope.ProfileKey
		}
	}

	// A logical Agent scope is stable across runtime PID epochs. Do not enumerate
	// its complete instance history: the finding repository can apply the signed
	// host/type/profile or asset predicate directly, and history grows without a
	// fixed upper bound. Only explicit instance filters need membership checks.
	requestedInstanceIDs := append([]string(nil), query.InstanceIDs...)
	if query.InstanceID != "" {
		requestedInstanceIDs = append(requestedInstanceIDs, query.InstanceID)
	}
	requestedInstanceIDs = uniqueStrings(requestedInstanceIDs)
	if len(requestedInstanceIDs) == 0 {
		return true
	}
	if len(requestedInstanceIDs) > agentGuardMaxPageSize {
		h.failWith(c, http.StatusConflict, "agent_guard_scope_too_broad", "Agent scope contains too many requested runtime instances")
		return false
	}
	instanceQuery := model.AgentRuntimeInstanceQuery{
		AgentGuardPageQuery: model.AgentGuardPageQuery{Page: 1, PageSize: len(requestedInstanceIDs)},
		HostID:              query.HostID,
		InstanceIDs:         requestedInstanceIDs,
		ProfileKey:          query.ProfileKey,
	}
	if query.AssetID != "" {
		instanceQuery.AssetIDs = []string{query.AssetID}
	}
	if query.AgentType != "" {
		instanceQuery.AgentTypes = []string{query.AgentType}
	}
	instances, total, err := h.query.ListInstances(c.Request.Context(), instanceQuery)
	if err != nil {
		h.fail(c, err)
		return false
	}
	if total != int64(len(requestedInstanceIDs)) || len(instances) != len(requestedInstanceIDs) {
		h.failWith(c, http.StatusForbidden, "agent_guard_scope_invalid", "instance_id is outside the selected Agent scope")
		return false
	}
	query.InstanceIDs = requestedInstanceIDs
	return true
}

func bindAgentRuntimeInstanceQuery(c *gin.Context) (model.AgentRuntimeInstanceQuery, bool) {
	var query model.AgentRuntimeInstanceQuery
	if !agentGuardBindQuery(c, &query) {
		return query, false
	}
	if !agentGuardNormalizeBoundPage(c, &query.Page, &query.PageSize) {
		return query, false
	}
	query.AssetIDs = agentGuardQueryValues(c, "asset_ids")
	if assetID := strings.TrimSpace(c.Query("asset_id")); assetID != "" {
		query.AssetIDs = append(query.AssetIDs, assetID)
	}
	query.AssetIDs = uniqueStrings(query.AssetIDs)
	query.AgentTypes = agentGuardQueryValues(c, "agent_types")
	query.InstanceIDs = agentGuardQueryValues(c, "instance_ids")
	query.SessionID = strings.TrimSpace(c.Query("session_id"))
	if !agentGuardValidateUUIDs(c, "asset_ids", query.AssetIDs) ||
		!agentGuardValidateUUIDs(c, "instance_ids", query.InstanceIDs) ||
		!agentGuardValidateOptionalUUIDFields(c, map[string]string{
			"host_id": query.HostID, "session_id": query.SessionID,
		}) ||
		!agentGuardBindTimeRange(c, &query.StartTime, &query.EndTime) {
		return query, false
	}
	return query, true
}

func bindAgentBehaviorEventQuery(c *gin.Context) (model.AgentBehaviorEventQuery, bool) {
	var query model.AgentBehaviorEventQuery
	if !agentGuardBindQuery(c, &query) {
		return query, false
	}
	if !agentGuardNormalizeBoundPage(c, &query.Page, &query.PageSize) {
		return query, false
	}
	if !agentGuardValidateOptionalUUIDFields(c, map[string]string{
		"host_id": query.HostID, "instance_id": query.InstanceID, "session_id": query.SessionID,
		"execution_unit_id": query.ExecutionUnitID, "policy_id": query.PolicyID,
	}) || !agentGuardBindTimeRange(c, &query.StartTime, &query.EndTime) {
		return query, false
	}
	return query, true
}

func bindAgentSecurityFindingQuery(c *gin.Context) (model.AgentSecurityFindingQuery, bool) {
	var query model.AgentSecurityFindingQuery
	if !agentGuardBindQuery(c, &query) {
		return query, false
	}
	if !agentGuardNormalizeBoundPage(c, &query.Page, &query.PageSize) {
		return query, false
	}
	query.InstanceIDs = agentGuardQueryValues(c, "instance_ids")
	if !agentGuardValidateOptionalUUIDFields(c, map[string]string{
		"host_id": query.HostID, "instance_id": query.InstanceID, "session_id": query.SessionID,
		"execution_unit_id": query.ExecutionUnitID,
	}) || !agentGuardValidateUUIDs(c, "instance_ids", query.InstanceIDs) ||
		!agentGuardBindTimeRange(c, &query.StartTime, &query.EndTime) {
		return query, false
	}
	return query, true
}

func (h *AgentGuardHandler) failPolicy(
	c *gin.Context,
	err error,
	preview model.AgentGuardPolicyValidationPreview,
) {
	switch {
	case errors.Is(err, service.ErrAgentGuardPolicyInvalid):
		agentGuardError(c, http.StatusBadRequest, "agent_guard_policy_invalid", "Agent Guard policy validation failed", preview)
	case errors.Is(err, service.ErrAgentGuardPolicyWriteDisabled):
		agentGuardError(c, http.StatusServiceUnavailable, "agent_guard_policy_write_disabled", "Agent Guard policy writes are disabled", preview)
	default:
		h.fail(c, err)
	}
}

func (h *AgentGuardHandler) fail(c *gin.Context, err error) {
	status, code, message := agentGuardErrorMapping(err)
	if status >= http.StatusInternalServerError {
		h.logger.Error("agent_guard_api_failed",
			zap.String("error_code", code),
			zap.String("path", c.FullPath()),
			zap.Error(err),
		)
	}
	agentGuardError(c, status, code, message, nil)
}

func (h *AgentGuardHandler) failWith(c *gin.Context, status int, code string, message string) {
	agentGuardError(c, status, code, message, nil)
}

func (h *AgentGuardHandler) logPolicyResult(
	operation string,
	username string,
	id uuid.UUID,
	preview model.AgentGuardPolicyValidationPreview,
	err error,
) {
	fields := []zap.Field{
		zap.String("operation", operation),
		zap.String("username", username),
		zap.Bool("valid", preview.Valid),
		zap.Int("validation_error_count", len(preview.Errors)),
		zap.String("digest", preview.Digest),
	}
	if id != uuid.Nil {
		fields = append(fields, zap.String("policy_id", id.String()))
	}
	if err != nil {
		fields = append(fields, zap.String("result", "failed"), zap.Error(err))
		h.logger.Warn("agent_guard_policy_operation", fields...)
		return
	}
	fields = append(fields, zap.String("result", "success"))
	h.logger.Info("agent_guard_policy_operation", fields...)
}

func agentGuardErrorMapping(err error) (int, string, string) {
	switch {
	case errors.Is(err, service.ErrAgentGuardRuntimeSettingsInvalid):
		return http.StatusBadRequest, "agent_guard_runtime_settings_invalid", "Agent Guard runtime settings are invalid"
	case errors.Is(err, repository.ErrAgentGuardProfileNotFound):
		return http.StatusNotFound, "agent_guard_profile_not_found", "Agent Guard profile was not found"
	case errors.Is(err, repository.ErrAgentGuardRuleNotFound):
		return http.StatusNotFound, "agent_guard_rule_not_found", "Agent Guard rule was not found"
	case errors.Is(err, repository.ErrAgentGuardBuiltinDigestMismatch):
		return http.StatusConflict, "agent_guard_rule_digest_mismatch", "Built-in Agent Guard definition digest does not match"
	case errors.Is(err, repository.ErrAgentGuardPolicyNotFound):
		return http.StatusNotFound, "agent_guard_policy_not_found", "Agent Guard policy was not found"
	case errors.Is(err, repository.ErrAgentGuardPolicyNotDraft):
		return http.StatusConflict, "agent_guard_policy_not_draft", "Only a draft Agent Guard policy can be changed"
	case errors.Is(err, repository.ErrAgentGuardTargetHostNotFound):
		return http.StatusNotFound, "agent_guard_target_host_not_found", "A target host was not found"
	case errors.Is(err, repository.ErrAgentGuardHostGroupsUnsupported):
		return http.StatusUnprocessableEntity, "agent_guard_host_groups_unsupported", "Host group targeting is not available in this deployment"
	case errors.Is(err, service.ErrAgentGuardPolicyPublishDisabled):
		return http.StatusServiceUnavailable, "agent_guard_policy_publish_disabled", "Agent Guard policy publishing is disabled"
	case errors.Is(err, service.ErrAgentGuardPolicyNotDraft):
		return http.StatusConflict, "agent_guard_policy_not_draft", "Only a draft Agent Guard policy can be published"
	case errors.Is(err, service.ErrAgentGuardPolicyNoTargetHosts):
		return http.StatusUnprocessableEntity, "agent_guard_policy_no_target_hosts", "Agent Guard policy resolves to no target hosts"
	case errors.Is(err, service.ErrAgentGuardAnalysisDisabled):
		return http.StatusServiceUnavailable, "agent_guard_analysis_disabled", "Agent Guard analysis is disabled"
	case errors.Is(err, service.ErrAgentGuardAnalysisQueueFull):
		return http.StatusServiceUnavailable, "agent_guard_analysis_queue_full", "Agent Guard analysis queue is full"
	case errors.Is(err, service.ErrAgentGuardAnalysisEvidenceInvalid):
		return http.StatusUnprocessableEntity, "agent_guard_analysis_evidence_invalid", "Finding evidence is unavailable or incomplete"
	case errors.Is(err, service.ErrAgentGuardActionsDisabled):
		return http.StatusServiceUnavailable, "agent_guard_actions_disabled", "Agent Guard actions are disabled"
	case errors.Is(err, service.ErrAgentGuardActionRequestInvalid):
		return http.StatusBadRequest, "agent_guard_action_request_invalid", "Agent Guard action request is invalid"
	case errors.Is(err, service.ErrAgentGuardAgentOffline):
		return http.StatusConflict, "agent_guard_agent_offline", "Host Agent is offline"
	case errors.Is(err, service.ErrAgentGuardActionNotSupported):
		return http.StatusConflict, "agent_guard_action_not_supported", "Host does not support this action"
	case errors.Is(err, service.ErrAgentGuardUnitStateConflict), errors.Is(err, repository.ErrAgentGuardActionStateConflict):
		return http.StatusConflict, "agent_guard_unit_state_conflict", "Action conflicts with the current target state"
	case errors.Is(err, service.ErrAgentGuardRemoteUnobservable):
		return http.StatusConflict, "agent_guard_remote_unobservable", "Remote execution cannot be safely controlled"
	case errors.Is(err, service.ErrAgentGuardActionOwnershipInvalid):
		return http.StatusForbidden, "agent_guard_action_target_invalid", "Action target ownership is invalid"
	case errors.Is(err, service.ErrAgentGuardActionDispatchFailed):
		return http.StatusBadGateway, "agent_guard_action_dispatch_failed", "Agent Guard action dispatch failed"
	case errors.Is(err, repository.ErrAgentGuardHostNotFound):
		return http.StatusNotFound, "agent_guard_host_not_found", "Host was not found"
	case errors.Is(err, repository.ErrAgentGuardInstanceNotFound):
		return http.StatusNotFound, "agent_guard_instance_not_found", "Agent runtime instance was not found"
	case errors.Is(err, repository.ErrAgentGuardSessionNotFound):
		return http.StatusNotFound, "agent_guard_session_not_found", "Agent behavior session was not found"
	case errors.Is(err, repository.ErrAgentGuardExecutionUnitNotFound):
		return http.StatusNotFound, "agent_guard_execution_unit_not_found", "Agent execution unit was not found"
	case errors.Is(err, repository.ErrAgentGuardBehaviorNotFound):
		return http.StatusNotFound, "agent_guard_behavior_not_found", "Agent behavior event was not found"
	case errors.Is(err, repository.ErrAgentGuardFindingNotFound):
		return http.StatusNotFound, "agent_guard_finding_not_found", "Agent security finding was not found"
	case errors.Is(err, repository.ErrAgentGuardAnalysisNotFound):
		return http.StatusNotFound, "agent_guard_analysis_not_found", "Agent security analysis was not found"
	case errors.Is(err, repository.ErrAgentGuardActionNotFound):
		return http.StatusNotFound, "agent_guard_action_not_found", "Agent Guard action was not found"
	case errors.Is(err, service.ErrAgentGuardNodeInvalid):
		return http.StatusBadRequest, "agent_guard_panorama_node_invalid", "Panorama node is invalid or expired"
	case errors.Is(err, service.ErrAgentGuardScopeInvalid):
		return http.StatusBadRequest, "agent_guard_scope_invalid", "Agent scope key is invalid"
	default:
		return http.StatusInternalServerError, "agent_guard_internal_error", "Agent Guard request failed"
	}
}

func agentGuardSuccess(c *gin.Context, data any) {
	c.JSON(http.StatusOK, gin.H{"code": 0, "message": "success", "data": data})
}

func agentGuardAccepted(c *gin.Context, data any) {
	c.JSON(http.StatusAccepted, gin.H{"code": 0, "message": "accepted", "data": data})
}

func agentGuardAcceptedAction(c *gin.Context, action *model.AgentGuardAction) {
	agentGuardAccepted(c, gin.H{
		"action_id":  action.ID,
		"command_id": action.CommandID,
		"status":     action.Status,
	})
}

func agentGuardPage(c *gin.Context, items any, total int64) {
	agentGuardSuccess(c, gin.H{"items": items, "total": total})
}

func agentGuardError(c *gin.Context, status int, code string, message string, data any) {
	body := gin.H{"code": status, "error_code": code, "message": message}
	if data != nil {
		body["data"] = data
	}
	c.JSON(status, body)
}

func agentGuardBindQuery(c *gin.Context, target any) bool {
	if err := c.ShouldBindQuery(target); err != nil {
		agentGuardError(c, http.StatusBadRequest, "agent_guard_request_invalid", "Query parameters are invalid", nil)
		return false
	}
	return true
}

func agentGuardBindJSON(c *gin.Context, target any) bool {
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		agentGuardError(c, http.StatusBadRequest, "agent_guard_request_invalid", "Request body is invalid", nil)
		return false
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		agentGuardError(c, http.StatusBadRequest, "agent_guard_request_invalid", "Request body must contain exactly one JSON value", nil)
		return false
	}
	return true
}

func bindAgentGuardManualActionRequest(c *gin.Context) (service.AgentGuardManualActionRequest, bool) {
	var request service.AgentGuardManualActionRequest
	if !agentGuardBindJSON(c, &request) {
		return request, false
	}
	return request, true
}

func agentGuardActionScopeRequested(c *gin.Context) bool {
	for _, key := range []string{"host_id", "instance_id", "asset_id", "agent_scope_key"} {
		if strings.TrimSpace(c.Query(key)) != "" {
			return true
		}
	}
	return false
}

func agentGuardActionUsername(c *gin.Context) string {
	for _, key := range []string{"auth_username", "username"} {
		if username := strings.TrimSpace(c.GetString(key)); username != "" {
			return username
		}
	}
	return ""
}

func agentGuardPathUUID(c *gin.Context, name string, code string) (uuid.UUID, bool) {
	id, err := uuid.Parse(c.Param(name))
	if err != nil {
		agentGuardError(c, http.StatusBadRequest, code, "Path identifier must be a UUID", nil)
		return uuid.Nil, false
	}
	return id, true
}

func agentGuardNormalizeBoundPage(c *gin.Context, page *int, pageSize *int) bool {
	if strings.TrimSpace(c.Query("page")) != "" && *page < 1 {
		agentGuardError(c, http.StatusBadRequest, "agent_guard_request_invalid", "page must be a positive integer", nil)
		return false
	}
	if strings.TrimSpace(c.Query("page_size")) != "" && *pageSize < 1 {
		agentGuardError(c, http.StatusBadRequest, "agent_guard_request_invalid", "page_size must be a positive integer", nil)
		return false
	}
	if *page < 1 {
		*page = 1
	}
	if *pageSize < 1 {
		*pageSize = 20
	}
	if *pageSize > agentGuardMaxPageSize {
		*pageSize = agentGuardMaxPageSize
	}
	return true
}

func agentGuardPageParamsFromContext(c *gin.Context) (int, int, bool) {
	page, err := strconv.Atoi(c.DefaultQuery("page", "1"))
	if err != nil || page < 1 {
		agentGuardError(c, http.StatusBadRequest, "agent_guard_request_invalid", "page must be a positive integer", nil)
		return 0, 0, false
	}
	pageSize, err := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if err != nil || pageSize < 1 {
		agentGuardError(c, http.StatusBadRequest, "agent_guard_request_invalid", "page_size must be a positive integer", nil)
		return 0, 0, false
	}
	if pageSize > agentGuardMaxPageSize {
		pageSize = agentGuardMaxPageSize
	}
	return page, pageSize, true
}

func agentGuardQueryValues(c *gin.Context, key string) []string {
	values := append([]string{}, c.QueryArray(key)...)
	values = append(values, c.QueryArray(key+"[]")...)
	if len(values) == 0 {
		if raw := strings.TrimSpace(c.Query(key)); raw != "" {
			values = []string{raw}
		}
	}
	result := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		for _, item := range strings.Split(value, ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			if _, exists := seen[item]; exists {
				continue
			}
			seen[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

func uniqueStrings(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func agentGuardValidateUUIDs(c *gin.Context, field string, values []string) bool {
	for _, value := range values {
		if _, err := uuid.Parse(value); err != nil {
			agentGuardError(c, http.StatusBadRequest, "agent_guard_request_invalid", field+" must contain UUID values", nil)
			return false
		}
	}
	return true
}

func agentGuardValidateOptionalUUIDFields(c *gin.Context, fields map[string]string) bool {
	for field, value := range fields {
		if value != "" && !agentGuardValidateUUIDs(c, field, []string{value}) {
			return false
		}
	}
	return true
}

func agentGuardBindTimeRange(c *gin.Context, start **time.Time, end **time.Time) bool {
	parse := func(name string) (*time.Time, bool) {
		raw := strings.TrimSpace(c.Query(name))
		if raw == "" {
			return nil, true
		}
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			agentGuardError(c, http.StatusBadRequest, "agent_guard_request_invalid", name+" must be RFC3339", nil)
			return nil, false
		}
		return &parsed, true
	}
	var ok bool
	if *start, ok = parse("start_time"); !ok {
		return false
	}
	if *end, ok = parse("end_time"); !ok {
		return false
	}
	if *start != nil && *end != nil && (*start).After(**end) {
		agentGuardError(c, http.StatusBadRequest, "agent_guard_request_invalid", "start_time must not be after end_time", nil)
		return false
	}
	return true
}

func agentGuardPositiveInt64Query(c *gin.Context, key string, required bool) (int64, bool) {
	raw := strings.TrimSpace(c.Query(key))
	if raw == "" {
		if required {
			agentGuardError(c, http.StatusBadRequest, "agent_guard_request_invalid", key+" is required", nil)
			return 0, false
		}
		return 0, true
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value < 1 {
		agentGuardError(c, http.StatusBadRequest, "agent_guard_request_invalid", key+" must be a positive integer", nil)
		return 0, false
	}
	return value, true
}

func agentGuardUsername(c *gin.Context) string {
	if username := c.GetString("auth_username"); username != "" {
		return username
	}
	return "unknown"
}

func redactAgentGuardInstances(items []model.AgentRuntimeInstance) []model.AgentRuntimeInstance {
	result := make([]model.AgentRuntimeInstance, len(items))
	for index := range items {
		result[index] = redactAgentGuardInstance(items[index])
	}
	return result
}

func redactAgentGuardInstance(item model.AgentRuntimeInstance) model.AgentRuntimeInstance {
	item.ControllerExe = ""
	item.ControllerCmdline = ""
	item.RunUser = ""
	item.Metadata = []byte(`{}`)
	return item
}

func redactAgentGuardExecutionUnits(items []model.AgentExecutionUnit) []model.AgentExecutionUnit {
	result := make([]model.AgentExecutionUnit, len(items))
	for index, item := range items {
		item.CgroupPath = ""
		item.RemoteHostRef = ""
		item.IsolationBaseline = []byte(`{}`)
		item.IsolationActual = []byte(`{}`)
		item.IsolationDiff = []byte(`{}`)
		result[index] = item
	}
	return result
}

func redactAgentGuardSessions(items []model.AgentBehaviorSession) []model.AgentBehaviorSession {
	result := make([]model.AgentBehaviorSession, len(items))
	for index := range items {
		result[index] = redactAgentGuardSession(items[index])
	}
	return result
}

func redactAgentGuardSession(item model.AgentBehaviorSession) model.AgentBehaviorSession {
	item.CorrelationTokenHash = ""
	return item
}

func redactAgentGuardBehaviors(items []model.AgentBehaviorEvent) []model.AgentBehaviorEvent {
	result := make([]model.AgentBehaviorEvent, len(items))
	for index, item := range items {
		item.ProcessExe = ""
		item.CommandArgv = []byte(`[]`)
		item.CommandCwd = ""
		item.ProcessChain = []byte(`[]`)
		item.ResourceIdentity = ""
		item.Resource = []byte(`{}`)
		item.Isolation = []byte(`{}`)
		item.Collection = []byte(`{}`)
		item.Evidence = []byte(`{}`)
		result[index] = item
	}
	return result
}

func redactAgentGuardFindings(items []model.AgentSecurityFinding) []model.AgentSecurityFinding {
	result := make([]model.AgentSecurityFinding, len(items))
	for index, item := range items {
		item.EvidenceEventIDs = []byte(`[]`)
		item.EvidenceGraph = []byte(`{}`)
		item.Summary = ""
		item.HandledNote = ""
		result[index] = item
	}
	return result
}

func redactAgentGuardAnalyses(items []model.AgentSecurityAnalysisRun) []model.AgentSecurityAnalysisRun {
	result := make([]model.AgentSecurityAnalysisRun, len(items))
	for index, item := range items {
		result[index] = redactAgentGuardAnalysis(item)
	}
	return result
}

func redactAgentGuardAnalysis(item model.AgentSecurityAnalysisRun) model.AgentSecurityAnalysisRun {
	item.EvidenceEventIDs = []byte(`[]`)
	item.EvidenceSummary = []byte(`{}`)
	item.InputDigest = ""
	return item
}

func agentGuardPanoramaPage(items []agentGuardPanoramaNode, total int64, page int, pageSize int) gin.H {
	result := gin.H{"items": items, "total": total}
	if int64(page*pageSize) < total {
		result["next_cursor"] = base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(page + 1)))
	}
	return result
}

func boolToInt64(value bool) int64 {
	if value {
		return 1
	}
	return 0
}

func decodeAgentGuardJSONStrings(raw []byte) []string {
	var values []string
	if len(raw) == 0 || json.Unmarshal(raw, &values) != nil {
		return nil
	}
	return values
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
