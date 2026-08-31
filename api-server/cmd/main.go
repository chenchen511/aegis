package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"api-server/config"
	"api-server/internal/api"
	"api-server/internal/api/handler"
	"api-server/internal/assistant"
	assistantTools "api-server/internal/assistant/tools"
	"api-server/internal/checker"
	grpcclient "api-server/internal/grpc"
	"api-server/internal/ipdetect"
	"api-server/internal/queue"
	"api-server/internal/repository"
	"api-server/internal/seed"
	"api-server/internal/service"
	"api-server/internal/storage"
	"api-server/pkg/logger"

	"go.uber.org/zap"
)

func main() {
	// Parse command line flags
	configPath := flag.String("config", "config/api-server.yaml", "config file path")
	flag.Parse()

	fmt.Println("API Server starting...")

	// Initialize logger FIRST (per design spec)
	if err := logger.Init(&logger.Config{
		Level:      "info",
		FileName:   "api-server.log",
		MaxSize:    100,
		MaxBackups: 10,
		MaxAge:     7,
		Compress:   true,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	logger.Info("api-server initializing", zap.String("config", *configPath))

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Fatal("failed to load config", zap.Error(err))
	}
	logger.Info("config loaded successfully")

	// Initialize database
	db, err := repository.NewDB(&cfg.Database)
	if err != nil {
		logger.Fatal("failed to connect database", zap.Error(err))
	}
	logger.Info("database connected")

	// Initialize Redis
	redisClient, err := storage.NewRedisClient(&cfg.Redis)
	if err != nil {
		logger.Fatal("failed to connect Redis", zap.Error(err))
	}
	logger.Info("Redis connected")

	// Initialize MinIO
	minioClient, err := storage.NewMinIOClient(&cfg.MinIO)
	if err != nil {
		logger.Fatal("failed to connect MinIO", zap.Error(err))
	}
	logger.Info("MinIO connected")

	// Initialize Kafka producer
	kafkaBrokers := []string{}
	if len(cfg.Kafka.Brokers) > 0 {
		kafkaBrokers = cfg.Kafka.Brokers
	} else {
		kafkaBrokers = []string{"kafka:29092"}
	}
	kafkaProducer := queue.NewKafkaProducer(kafkaBrokers, logger.Get())
	logger.Info("Kafka producer initialized")

	// Initialize gRPC client to Server service
	var serverAddr string
	if cfg.GRPC.ServerAddress != "" {
		serverAddr = cfg.GRPC.ServerAddress
	} else {
		serverAddr = fmt.Sprintf("%s:%d", cfg.Server.ExternalIP, cfg.Server.GRPCPort)
		if cfg.Server.ExternalIP == "" {
			serverAddr = fmt.Sprintf("localhost:%d", cfg.Server.GRPCPort)
		}
	}
	serverClient, err := grpcclient.NewServerClient(serverAddr)
	if err != nil {
		logger.Fatal("failed to connect to Server gRPC", zap.Error(err), zap.String("addr", serverAddr))
	}
	defer serverClient.Close()
	logger.Info("Server gRPC client initialized", zap.String("addr", serverAddr))

	// Initialize repositories
	hostRepo := repository.NewHostRepository(db)
	templateRepo := repository.NewTemplateRepository(db)
	ruleRepo := repository.NewRuleRepository(db)
	taskLogRepo := repository.NewTaskLogRepository(db)
	configRepo := repository.NewConfigRepository(db, "default-encryption-key")
	scriptVersionRepo := repository.NewScriptVersionRepository(db)
	healingLogRepo := repository.NewHealingLogRepository(db)
	vulnRepo := repository.NewVulnerabilityRepo(db)
	vulnScriptRepo := repository.NewVulnerabilityScriptRepository(db)
	customCVEQueryRepo := repository.NewCustomCVEQueryRepository(db)
	hostVulnerabilityScriptRepo := repository.NewHostVulnerabilityScriptRepository(db)
	alertRepo := repository.NewAlertRepository(db)
	blockRepo := repository.NewBlockRepository(db)
	blockPolicyRepo := repository.NewBlockPolicyRepository(db)
	sigmaRuleRepo := repository.NewSigmaRuleRepository(db)
	toolCallRepo := repository.NewToolCallRepository(db)
	llmAggregationRepo := repository.NewLLMAggregationRepository(db)
	runtimeEventRepo := repository.NewRuntimeEventRepository(db)
	notificationRepo := repository.NewNotificationRepository(db)
	authRepo := repository.NewAuthRepository(db)
	commandAuditRuleRepo := repository.NewCommandAuditRuleRepo(db)
	auditLogRepo := repository.NewAuditLogRepo(db)
	systemConfigRepo := repository.NewSystemConfigRepo(db)

	// V6.0 Assistant repositories
	assistantSessionRepo := repository.NewAssistantSessionRepository(db)
	assistantMessageRepo := repository.NewAssistantMessageRepository(db)
	assistantContextRefRepo := repository.NewAssistantContextRefRepository(db)
	assistantToolCallRepo := repository.NewAssistantToolCallRepository(db)
	assistantOperationRepo := repository.NewAssistantOperationRepository(db)
	assistantApprovalRepo := repository.NewAssistantApprovalRepository(db)
	assistantRecoveryRepo := repository.NewAssistantRecoveryRepository(db)
	assistantMemoryRepo := repository.NewAssistantMemoryRepository(db)
	assistantToolPolicyRepo := repository.NewAssistantToolPolicyRepository(db)
	assistantInvestigationReportRepo := repository.NewAssistantInvestigationReportRepository(db)
	assistantInvestigationEvidenceRepo := repository.NewAssistantInvestigationEvidenceRepository(db)
	externalMCPSourceRepo := repository.NewExternalMCPSourceRepository(db)
	externalMCPQueryLogRepo := repository.NewExternalMCPQueryLogRepository(db)
	agentGuardCatalogRepo := repository.NewAgentGuardCatalogRepository(db)
	agentGuardPolicyRepo := repository.NewAgentGuardPolicyRepository(db)
	agentGuardQueryRepo := repository.NewAgentGuardQueryRepository(db)
	agentGuardAnalysisRepo := repository.NewAgentGuardAnalysisRepository(db)
	agentGuardActionRepo := repository.NewAgentGuardActionRepository(db)
	agentGuardToolFindingRepo := repository.NewAgentGuardToolFindingRepository(db)
	agentSessionRepo := repository.NewAgentSessionRepository(db)
	agentSkillSnapshotStore := service.NewAgentSkillScanSnapshotStore(db)
	mcpPlatformRepo := repository.NewMCPPlatformRepository(db)

	if err := agentGuardCatalogRepo.VerifyBuiltinManifest(context.Background()); err != nil {
		if cfg.AgentGuard.Enabled {
			logger.Fatal("agent guard builtin manifest verification failed", zap.Error(err))
		}
		logger.Warn("agent guard builtin manifest is unavailable while feature is disabled", zap.Error(err))
	} else {
		logger.Info("agent guard builtin manifest verified")
	}

	var agentGuardScopeSigner *service.AgentGuardScopeSigner
	if strings.TrimSpace(cfg.AgentGuard.ScopeSigningKey) != "" {
		agentGuardScopeSigner, err = service.NewAgentGuardScopeSigner(cfg.AgentGuard.ScopeSigningKey)
		if err != nil {
			logger.Fatal("invalid agent guard scope signing configuration", zap.Error(err))
		}
	} else if cfg.AgentGuard.Enabled {
		logger.Fatal("agent guard scope signing key is required while feature is enabled")
	}
	logger.Info("agent guard control plane configured",
		zap.Bool("enabled", cfg.AgentGuard.Enabled),
		zap.Bool("policy_write_enabled", cfg.AgentGuard.Enabled && cfg.AgentGuard.PolicyWriteEnabled),
		zap.Bool("analysis_enabled", cfg.AgentGuard.Enabled && cfg.AgentGuard.AnalysisEnabled),
		zap.Bool("action_enabled", cfg.AgentGuard.Enabled && cfg.AgentGuard.ActionEnabled),
		zap.Bool("scope_signing_configured", agentGuardScopeSigner != nil),
	)

	// V5.7 Script Audit Services (must initialize before services that depend on it)
	blacklistChecker := checker.NewBlacklistChecker()
	scriptAuditService := service.NewScriptAuditService(blacklistChecker, auditLogRepo, configRepo, systemConfigRepo, commandAuditRuleRepo, cfg.LLM.TimeoutSeconds, cfg.LLM.MaxRetries)
	if err := scriptAuditService.ReloadRules(context.Background()); err != nil {
		logger.Warn("failed to load initial audit rules", zap.Error(err))
	}

	// Initialize services
	templateService := service.NewTemplateService(templateRepo, ruleRepo, configRepo, minioClient, redisClient, cfg.LLM.TimeoutSeconds, cfg.LLM.MaxRetries, 3)
	scriptGenService := service.NewScriptGenerationService(ruleRepo, scriptVersionRepo, configRepo, minioClient, cfg.LLM.TimeoutSeconds, cfg.LLM.MaxRetries, 2, scriptAuditService)
	taskService := service.NewTaskService(taskLogRepo, hostRepo, ruleRepo, healingLogRepo, redisClient, serverClient)
	taskService.SetAuditService(scriptAuditService)
	taskService.SetScriptGenService(scriptGenService)
	selfHealingService := service.NewSelfHealingService(healingLogRepo, scriptVersionRepo, configRepo, ruleRepo, taskLogRepo, minioClient, redisClient, cfg.LLM.TimeoutSeconds, cfg.LLM.MaxRetries, 3, scriptAuditService)
	selfHealingService.SetVulnerabilityScriptRepositories(vulnRepo, vulnScriptRepo)
	taskService.SetSelfHealingService(selfHealingService)
	selfHealingService.SetTaskRedispatcher(taskService)
	// V6.1: Auto-verify service for automatic detection-repair loop
	autoVerifyService := service.NewAutoVerifyService(taskLogRepo, ruleRepo, taskService)
	taskService.SetAutoVerifyService(autoVerifyService)
	// V5.8: Asset repository for vulnerability scanning
	assetCollectionRepo := repository.NewAssetCollectionRepository(db)
	weakPasswordRepo := repository.NewWeakPasswordRepository(db)
	vulnService := service.NewVulnerabilityService(vulnRepo, hostRepo, taskLogRepo, redisClient, configRepo, cfg.LLM.TimeoutSeconds, cfg.LLM.MaxRetries, serverClient, scriptAuditService, assetCollectionRepo)
	vulnService.SetTaskService(taskService)
	logger.Info("Vulnerability service initialized with asset repository for V5.8 asset-based scanning")
	// V6.1: Vulnerability auto fix+verify loop (POC_VERIFY <-> VULNERABILITY_FIX)
	vulnAutoVerifyService := service.NewVulnerabilityAutoVerifyService(vulnRepo, vulnScriptRepo, hostRepo, taskLogRepo, vulnService, taskService)
	taskService.SetVulnAutoVerifyService(vulnAutoVerifyService)
	customCVEService := service.NewCustomCVEService(vulnRepo, customCVEQueryRepo, configRepo, cfg.LLM.TimeoutSeconds, cfg.LLM.MaxRetries)
	hostVulnerabilityScriptService := service.NewHostVulnerabilityScriptService(hostVulnerabilityScriptRepo, vulnScriptRepo, vulnRepo, hostRepo, taskLogRepo, configRepo, scriptAuditService, cfg.LLM.TimeoutSeconds, cfg.LLM.MaxRetries, serverClient)
	hostVulnerabilityScriptService.SetTaskService(taskService)
	alertService := service.NewAlertService(alertRepo, blockPolicyRepo, blockRepo, serverClient)
	sigmaRuleService := service.NewSigmaRuleService(sigmaRuleRepo, serverClient)

	// AI Rule Config Services
	aiRuleConfigRepo := repository.NewAIRuleConfigRepository(db)
	aiRuleConfigService := service.NewAIRuleConfigService(aiRuleConfigRepo)
	ruleGenerationService := service.NewRuleGenerationService(
		aiRuleConfigService,
		configRepo,
		sigmaRuleRepo,
		alertRepo,
		notificationRepo,
		sigmaRuleService,
		serverClient,
		cfg.LLM.TimeoutSeconds,
		cfg.LLM.MaxRetries,
	)
	sigmaRuleUploadService := service.NewSigmaRuleUploadService(sigmaRuleRepo, serverClient)

	// Notification Service
	notificationSvc := service.NewNotificationService(notificationRepo)
	authService := service.NewAuthService(authRepo, redisClient)

	// V5.0 Runtime Detection Services
	wsService := service.NewWebSocketService()
	agentGuardActionService := service.NewAgentGuardActionService(
		agentGuardActionRepo,
		serverClient,
		cfg.AgentGuard.Enabled && cfg.AgentGuard.ActionEnabled,
		logger.Get().Named("agent_guard_action"),
	)
	_ = service.NewLLMAnalysisService(configRepo, cfg.LLM.TimeoutSeconds, cfg.LLM.MaxRetries)
	_ = service.NewBlockService(blockRepo, alertRepo)
	_ = service.NewRuleService(sigmaRuleRepo, kafkaProducer)
	websocketHandler := handler.NewWebSocketHandler(wsService)

	// AI Analysis Services
	// Initialize EmbeddingService for RAG vector search
	embeddingSvc := service.NewEmbeddingService(cfg.LLM.APIKey, cfg.LLM.BaseURL)
	vectorService := service.NewVectorService(db, embeddingSvc)
	aiSessionRepo := repository.NewAISessionRepository(db)
	aiMessageRepo := repository.NewAIMessageRepository(db)
	agentExecRepo := repository.NewAgentExecutionRepository(db)
	aiAutoBlockService := service.NewAIAutoBlockService(alertRepo, blockPolicyRepo, blockRepo, serverClient)
	aiAnalysisHandler := handler.NewAIAnalysisHandler(alertRepo, configRepo, vectorService, serverClient, aiSessionRepo, aiMessageRepo, agentExecRepo, blockPolicyRepo, blockRepo, aiAutoBlockService)

	// Start background workers
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var agentGuardWSConsumer *queue.KafkaConsumer
	var agentGuardToolRuleConsumer *queue.KafkaConsumer
	var agentSessionConsumer *queue.KafkaConsumer
	if cfg.AgentGuard.Enabled {
		groupID := strings.TrimSpace(cfg.Kafka.GroupID)
		if groupID == "" {
			groupID = "aegis-api-server"
		}
		agentGuardRealtimeHandler := service.NewAgentGuardRealtimeHandler(
			wsService,
			logger.Get().Named("agent_guard_realtime"),
		)
		agentGuardRealtimeHandler.SetActionStatusUpdater(agentGuardActionService)
		agentGuardWSConsumer = queue.NewKafkaConsumer(
			kafkaBrokers,
			"aegis.security.events",
			groupID+"-agent-guard-ws",
			agentGuardRealtimeHandler.HandleKafkaMessage,
			logger.Get().Named("agent_guard_realtime_consumer"),
		)
		go func() {
			if err := agentGuardWSConsumer.Start(ctx); err != nil && ctx.Err() == nil {
				logger.Error("agent_guard_realtime_consumer_failed", zap.Error(err))
			}
		}()
		logger.Info("agent_guard_realtime_consumer_started",
			zap.String("topic", "aegis.security.events"),
			zap.String("group_id", groupID+"-agent-guard-ws"),
		)

		agentGuardToolRuleHandler := service.NewAgentGuardToolRuleHandler(
			agentGuardToolFindingRepo,
			agentGuardCatalogRepo,
			wsService,
			logger.Get().Named("agent_guard_tool_rules"),
		)
		agentGuardToolRuleConsumer = queue.NewKafkaConsumer(
			kafkaBrokers,
			"aegis.security.events",
			groupID+"-agent-guard-tool-rules",
			agentGuardToolRuleHandler.HandleKafkaMessage,
			logger.Get().Named("agent_guard_tool_rule_consumer"),
		)
		go func() {
			if err := agentGuardToolRuleConsumer.Start(ctx); err != nil && ctx.Err() == nil {
				logger.Error("agent_guard_tool_rule_consumer_failed", zap.Error(err))
			}
		}()
		logger.Info("agent_guard_tool_rule_consumer_started",
			zap.String("topic", "aegis.security.events"),
			zap.String("group_id", groupID+"-agent-guard-tool-rules"),
			zap.String("rule_owner", "api-server"),
		)
	}
	templateService.StartWorkers(ctx)
	scriptGenService.StartWorkers(ctx)
	selfHealingService.StartWorkers(ctx)
	autoVerifyService.StartResultScanner(ctx)
	vulnAutoVerifyService.StartResultScanner(ctx)

	logger.Info("background workers started")

	// Detect server IP
	serverIP := ipdetect.DetectServerIP(cfg.Server.ExternalIP)

	logger.Info("server ports configured",
		zap.String("http_port", fmt.Sprintf("%d", cfg.Server.HTTPPort)),
		zap.String("grpc_port", fmt.Sprintf("%d", cfg.Server.GRPCPort)),
	)

	// Start AI rule auto-update service
	ruleGenerationService.Start(ctx)

	// Initialize handlers
	configHandler := handler.NewConfigHandler(configRepo, "default-encryption-key")
	hostHandler := handler.NewHostHandler(hostRepo, redisClient, serverClient)
	templateHandler := handler.NewTemplateHandler(templateRepo, ruleRepo, minioClient, redisClient, templateService, scriptGenService)
	taskHandler := handler.NewTaskHandler(taskService, taskLogRepo, healingLogRepo, scriptGenService, serverClient, ruleRepo, selfHealingService, auditLogRepo, vulnRepo)
	taskHandlerWithHealing := handler.NewTaskHandlerWithHealing(taskService, taskLogRepo, healingLogRepo, scriptGenService, serverClient, selfHealingService, ruleRepo, auditLogRepo, vulnRepo)
	agentHandler := handler.NewAgentHandler(serverClient, minioClient, serverIP, cfg.Server.HTTPPort, cfg.Server.AgentHubPort)
	ruleHandler := handler.NewRuleHandler(ruleRepo, taskLogRepo, scriptGenService)
	vulnerabilityHandler := handler.NewVulnerabilityHandler(vulnService, customCVEService, hostVulnerabilityScriptService)
	detectionHandler := handler.NewDetectionHandler(alertRepo, blockRepo, blockPolicyRepo, sigmaRuleRepo, toolCallRepo, alertService, sigmaRuleService, sigmaRuleUploadService, llmAggregationRepo, runtimeEventRepo, configRepo, serverClient, wsService, aiRuleConfigService, ruleGenerationService)

	// V5.8 Detection Package
	detectionPkgRepo := repository.NewDetectionPackageRepo(db)

	// Builder gRPC client
	builderAddr := os.Getenv("BUILDER_GRPC_ADDRESS")
	if builderAddr == "" {
		builderAddr = "builder:19096"
	}
	var builderSvcClient service.BuilderClient
	if bc, err := grpcclient.NewBuilderClient(builderAddr); err != nil {
		logger.Warn("failed to connect to builder gRPC, builds will be DB-only", zap.Error(err), zap.String("addr", builderAddr))
	} else {
		builderSvcClient = bc
		defer bc.Close()
		logger.Info("Builder gRPC client initialized", zap.String("addr", builderAddr))
	}

	// Build the base URL agents use to download detection-package artifacts
	// from MinIO.  When MINIO_ARTIFACT_BASE_URL / config value is set, use it
	// directly; otherwise derive from the MinIO endpoint.
	artifactBaseURL := cfg.MinIO.ArtifactBaseURL
	if artifactBaseURL == "" {
		scheme := "http"
		if cfg.MinIO.UseSSL {
			scheme = "https"
		}
		artifactBaseURL = fmt.Sprintf("%s://%s/aegis-releases", scheme, strings.TrimRight(cfg.MinIO.Endpoint, "/"))
	}
	detectionPkgService := service.NewDetectionPackageService(detectionPkgRepo, db, serverClient, builderSvcClient, artifactBaseURL)
	detectionPkgGenerationService := service.NewDetectionPackageGenerationService(
		configRepo,
		detectionPkgService,
		cfg.LLM.TimeoutSeconds,
		cfg.LLM.MaxRetries,
	)

	detectionPkgHandler := handler.NewDetectionPackageHandler(detectionPkgService, configRepo, cfg.LLM.TimeoutSeconds, cfg.LLM.MaxRetries)

	notificationHandler := handler.NewNotificationHandler(notificationSvc)
	roleRepo := repository.NewRoleRepo(db)
	authHandler := handler.NewAuthHandler(authService, roleRepo)
	commandAuditHandler := handler.NewCommandAuditHandler(commandAuditRuleRepo, systemConfigRepo, scriptAuditService)
	auditLogHandler := handler.NewAuditLogHandler(auditLogRepo)

	// V5.8 Intelligent Asset Collection (assetCollectionRepo already initialized above)
	assetCollectionService := service.NewAssetCollectionService(assetCollectionRepo, serverClient, logger.Get())
	assetQueryService := service.NewAssetQueryService(assetCollectionRepo, logger.Get())
	assetAnalysisService := service.NewAssetAnalysisService(assetCollectionRepo, configRepo, serverClient, logger.Get())
	assetCollectionService.SetAnalysisService(assetAnalysisService)
	assetHandler := handler.NewAssetHandler(assetCollectionService, assetQueryService, assetAnalysisService, logger.Get())
	logger.Info("Intelligent asset collection module initialized")

	// V6.1 Weak Password Detection
	weakPasswordService := service.NewWeakPasswordService(weakPasswordRepo, serverClient, logger.Get().Named("weak_password"))
	weakPasswordService.SetConfigRepository(configRepo, cfg.LLM.TimeoutSeconds, cfg.LLM.MaxRetries)
	weakPasswordHandler := handler.NewWeakPasswordHandler(weakPasswordService, logger.Get().Named("weak_password_handler"))
	agentGuardPolicyService := service.NewAgentGuardPolicyService(
		agentGuardCatalogRepo,
		agentGuardPolicyRepo,
		cfg.AgentGuard.Enabled && cfg.AgentGuard.PolicyWriteEnabled,
	)
	agentGuardBundleService := service.NewAgentGuardBundleService(
		agentGuardPolicyRepo,
		agentGuardCatalogRepo,
		serverClient,
		cfg.AgentGuard.Enabled && cfg.AgentGuard.PolicyWriteEnabled,
		cfg.AgentGuard.ToolAdapterEnabled,
		logger.Get().Named("agent_guard_bundle"),
	)
	agentGuardRuntimeSettingsRepo := repository.NewAgentGuardRuntimeSettingsRepository(systemConfigRepo)
	agentGuardRuntimeSettingsService := service.NewAgentGuardRuntimeSettingsService(
		agentGuardRuntimeSettingsRepo,
		serverClient,
		logger.Get().Named("agent_guard_runtime_settings"),
	)
	agentGuardAnalysisClient := service.NewConfiguredAgentGuardAnalysisClient(
		configRepo,
		cfg.LLM.TimeoutSeconds,
		cfg.LLM.MaxRetries,
	)
	agentGuardAnalysisService := service.NewAgentGuardAnalysisService(
		agentGuardAnalysisRepo,
		agentGuardAnalysisClient,
		cfg.AgentGuard.Enabled && cfg.AgentGuard.AnalysisEnabled,
		logger.Get().Named("agent_guard_analysis"),
	)
	agentGuardAnalysisService.Start(ctx)
	agentSessionAI := service.NewConfiguredAgentSessionAIClient(configRepo, cfg.LLM.TimeoutSeconds, cfg.LLM.MaxRetries)
	agentSessionService := service.NewAgentSessionService(agentSessionRepo, agentSessionAI, logger.Get().Named("agent_session"))
	agentSessionService.SetCollectionDispatcher(serverClient)
	agentConfigSecurityService := service.NewAgentConfigSecurityService(serverClient, logger.Get().Named("agent_config_security"))
	agentSkillSecurityService := service.NewAgentSkillSecurityService(serverClient, logger.Get().Named("agent_skill_security"), agentSkillSnapshotStore)
	agentSessionHandler := handler.NewAgentSessionHandler(agentSessionService, logger.Get().Named("agent_session_handler"))
	mcpPlatformService := service.NewMCPPlatformService(mcpPlatformRepo, logger.Get())
	mcpPlatformService.SetCatalogSigningKey(cfg.MCPPlatform.CatalogSigningKey)
	mcpPlatformHandler := handler.NewMCPPlatformHandler(mcpPlatformService, logger.Get())
	mcpPlatformHandler.SetRuntimeSecret(cfg.MCPPlatform.RuntimeSharedSecret)
	mcpPlatformHandler.SetPublicGatewayBaseURL(cfg.MCPPlatform.PublicGatewayBaseURL)
	logger.Info("mcp_platform_control_plane_configured")
	if cfg.AgentSession.Enabled {
		groupID := strings.TrimSpace(cfg.Kafka.GroupID)
		if groupID == "" {
			groupID = "aegis-api-server"
		}
		agentSessionConsumer = queue.NewKafkaConsumer(kafkaBrokers, "aegis.agent.sessions.v1", groupID+"-agent-sessions", agentSessionService.HandleKafkaMessage, logger.Get().Named("agent_session_consumer"))
		go func() {
			if err := agentSessionConsumer.Start(ctx); err != nil && ctx.Err() == nil {
				logger.Error("agent_session_consumer_failed", zap.Error(err))
			}
		}()
		logger.Info("agent_session_consumer_started", zap.String("topic", "aegis.agent.sessions.v1"), zap.String("group_id", groupID+"-agent-sessions"))
	}
	agentGuardHandler := handler.NewAgentGuardHandler(
		agentGuardCatalogRepo,
		agentGuardPolicyRepo,
		agentGuardQueryRepo,
		agentGuardPolicyService,
		agentGuardScopeSigner,
		logger.Get().Named("agent_guard_handler"),
	)
	agentGuardHandler.SetBundleService(agentGuardBundleService)
	agentGuardHandler.SetRuntimeSettingsService(agentGuardRuntimeSettingsService, agentGuardRuntimeSettingsService)
	agentGuardHandler.SetConfigScanner(agentConfigSecurityService)
	agentGuardHandler.SetSkillScanner(agentSkillSecurityService)
	agentGuardHandler.SetSkillInventoryReader(agentSkillSnapshotStore)
	agentGuardHandler.SetAnalysisService(agentGuardAnalysisService)
	agentGuardHandler.SetActionService(agentGuardActionService)
	logger.Info("Weak password detection module initialized")

	// V6.0 Assistant
	assistantLogger := logger.Get().Named("assistant")
	contextLoader := assistant.NewContextLoader(assistant.ContextLoaderDeps{
		HostRepo:       hostRepo,
		AlertRepo:      alertRepo,
		TaskRepo:       taskLogRepo,
		VulnRepo:       vulnRepo,
		ContextRefRepo: assistantContextRefRepo,
	})
	riskPolicy := assistant.NewRiskPolicy(assistant.RiskPolicyDeps{
		SystemConfig: systemConfigRepo,
	})
	toolRegistry := assistant.NewToolRegistry()
	// Register all assistant tools
	registerAssistantTools(
		toolRegistry,
		assistantLogger,
		hostRepo,
		alertRepo,
		taskLogRepo,
		vulnRepo,
		sigmaRuleRepo,
		blockPolicyRepo,
		blockRepo,
		configRepo,
		auditLogRepo,
		detectionPkgRepo,
		serverClient,
		assetCollectionRepo,
		assetCollectionService,
		assetQueryService,
		vulnService,
		customCVEService,
		hostVulnerabilityScriptService,
		weakPasswordService,
	)
	if cfg.AgentGuard.Enabled {
		if err := assistantTools.RegisterAgentGuardTools(toolRegistry, assistantTools.AgentGuardToolDeps{
			Query:         agentGuardQueryRepo,
			Catalog:       agentGuardCatalogRepo,
			Analysis:      agentGuardAnalysisService,
			Actions:       agentGuardActionService,
			Runtime:       agentGuardRuntimeSettingsService,
			ConfigScanner: agentConfigSecurityService,
			Conversations: agentSessionService,
		}); err != nil {
			logger.Warn("failed to register agent guard assistant tools", zap.Error(err))
		}
	} else {
		logger.Info("agent guard assistant tools disabled by configuration")
	}
	toolCatalog := assistant.NewToolCatalog(toolRegistry)
	toolPolicyService := assistant.NewToolPolicyService(assistant.ToolPolicyServiceDeps{
		PolicyRepo:   assistantToolPolicyRepo,
		Registry:     toolRegistry,
		SystemConfig: systemConfigRepo,
		Logger:       assistantLogger,
	})
	runManager := assistant.NewRunManager()
	approvalGate := assistant.NewApprovalGate(assistant.ApprovalGateDeps{
		ApprovalRepo:  assistantApprovalRepo,
		ToolCallRepo:  assistantToolCallRepo,
		PolicyService: toolPolicyService,
		RiskPolicy:    riskPolicy,
		Logger:        assistantLogger,
	})
	intentRouter := assistant.NewIntentRouter(assistantLogger)
	toolDispatcher := assistant.NewToolDispatcher(toolRegistry, approvalGate, assistantToolCallRepo, assistantSessionRepo, toolPolicyService, assistantLogger)
	recoveryManager := assistant.NewRecoveryManager(assistantRecoveryRepo, assistantLogger)
	recoveryManager.RegisterExecutor(
		"hook_allowlist",
		assistant.NewHookAllowlistRecoveryExecutor(detectionPkgService, assistantLogger),
	)
	toolDispatcher.SetRecoveryManager(recoveryManager)
	toolCapabilityMapper := assistant.NewToolCapabilityMapper(toolRegistry)
	toolDecisionEngine := assistant.NewToolDecisionEngine(assistant.ToolDecisionEngineDeps{
		Registry: toolRegistry,
		Mapper:   toolCapabilityMapper,
		Config:   assistant.DefaultToolDecisionConfigFromEnv(),
		Logger:   assistantLogger,
	})
	runtimeFactory := assistant.NewRuntimeFactory(assistant.RuntimeFactoryDeps{
		ConfigRepo:     configRepo,
		Catalog:        toolCatalog,
		ToolDispatcher: toolDispatcher,
		RunManager:     runManager,
		MemoryRepo:     assistantMemoryRepo,
		Logger:         assistantLogger,
	})
	intentRouter.SetLLMClientFactory(runtimeFactory.BuildLLMClient)
	intentDecomposer := assistant.NewIntentDecomposer(assistant.IntentDecomposerDeps{
		LLMClientFactory: runtimeFactory.BuildLLMClient,
		Logger:           assistantLogger,
	})
	orchestrator := assistant.NewOrchestrator(assistant.OrchestratorDeps{
		ConfigRepo:         configRepo,
		MessageRepo:        assistantMessageRepo,
		ToolCallRepo:       assistantToolCallRepo,
		SessionRepo:        assistantSessionRepo,
		ToolRegistry:       toolRegistry,
		IntentDecomposer:   intentDecomposer,
		ToolDecisionEngine: toolDecisionEngine,
		ToolDispatcher:     toolDispatcher,
		ApprovalGate:       approvalGate,
		ContextLoader:      contextLoader,
		IntentRouter:       intentRouter,
		RuntimeFactory:     runtimeFactory,
		RunManager:         runManager,
		RecoveryManager:    recoveryManager,
		Logger:             assistantLogger,
	})
	assistantService := assistant.NewService(assistant.ServiceDeps{
		SessionRepo:     assistantSessionRepo,
		MessageRepo:     assistantMessageRepo,
		ContextRefRepo:  assistantContextRefRepo,
		ToolCallRepo:    assistantToolCallRepo,
		ApprovalRepo:    assistantApprovalRepo,
		RecoveryManager: recoveryManager,
		MemoryRepo:      assistantMemoryRepo,
		ContextLoader:   contextLoader,
		Orchestrator:    orchestrator,
		RunManager:      runManager,
		Logger:          assistantLogger,
	})
	assistantFileUploadService := assistant.NewFileUploadService(assistant.FileUploadServiceDeps{
		ContextRepo:     assistantContextRefRepo,
		TemplateService: templateService,
		SigmaService:    sigmaRuleUploadService,
		Logger:          assistantLogger,
	})
	// V6.0 Investigation service
	investigationSvc := assistant.NewHostAttackInvestigationService(assistant.HostAttackInvestigationServiceDeps{
		ReportRepo:   assistantInvestigationReportRepo,
		EvidenceRepo: assistantInvestigationEvidenceRepo,
		HostRepo:     hostRepo,
		AlertRepo:    alertRepo,
		TaskRepo:     taskLogRepo,
		VulnRepo:     vulnRepo,
		BlockRepo:    blockRepo,
		Logger:       assistantLogger,
	})

	// V6.0 External MCP service
	mcpSvc := assistant.NewExternalMCPSourceService(assistant.ExternalMCPSourceServiceDeps{
		SourceRepo:   externalMCPSourceRepo,
		QueryLogRepo: externalMCPQueryLogRepo,
		Logger:       assistantLogger,
	})

	// V6.0 External MCP components
	mcpRedactor := assistant.NewExternalMCPRedactor(assistantLogger)
	mcpNormalizer := assistant.NewExternalMCPNormalizer(assistantLogger)
	mcpPromptProvider := assistant.NewExternalMCPPromptProvider(mcpRedactor)
	mcpClientFactory := assistant.NewExternalMCPClientFactory(assistantLogger)
	mcpQueryPlanner := assistant.NewExternalMCPQueryPlanner(mcpSvc, mcpPromptProvider, assistantLogger)

	// Register MCP tools. V6.3 uses a fixed, read-only Assistant facade over a
	// pre-authorized Client endpoint. The legacy V6.0 source tools remain
	// available only while the managed facade is disabled for migration.
	if cfg.MCPPlatform.AssistantMCPEnabled {
		gatewayClient, gatewayErr := assistant.NewMCPGatewayClient(assistant.MCPGatewayClientConfig{
			BaseURL:              cfg.MCPPlatform.GatewayBaseURL,
			ClientKey:            cfg.MCPPlatform.AssistantMCPClientKey,
			Token:                cfg.MCPPlatform.AssistantMCPClientToken,
			ContextSigningSecret: cfg.MCPPlatform.RuntimeSharedSecret,
			Timeout:              time.Duration(cfg.MCPPlatform.UpstreamTimeoutSec) * time.Second,
			Logger:               assistantLogger,
		})
		if gatewayErr != nil {
			logger.Error("managed MCP Assistant disabled because Client authorization is invalid", zap.Error(gatewayErr))
		} else if err := assistantTools.RegisterMCPAggregationTools(toolRegistry, assistantTools.MCPAggregationToolDeps{Gateway: gatewayClient, Invocations: mcpPlatformService, Logger: assistantLogger}); err != nil {
			logger.Error("failed to register managed MCP Assistant tools", zap.Error(err))
		} else {
			logger.Info("managed MCP Assistant tools registered", zap.Bool("client_authorization_configured", true))
		}
	}
	// Onboarding is a governed Assistant workflow backed by the MCP platform
	// service. It remains available even when the read-only aggregation facade
	// is disabled; the onboarding job itself performs endpoint validation,
	// discovery, security review, and approval before publication.
	if err := assistantTools.RegisterMCPOnboardingTool(toolRegistry, assistantTools.MCPOnboardingToolDeps{Platform: mcpPlatformService, Logger: assistantLogger}); err != nil {
		logger.Error("failed to register MCP onboarding Assistant tool", zap.Error(err))
	}
	if err := assistantTools.RegisterMCPOnboardingStatusTool(toolRegistry, assistantTools.MCPOnboardingToolDeps{Platform: mcpPlatformService, Logger: assistantLogger}); err != nil {
		logger.Error("failed to register MCP onboarding status Assistant tool", zap.Error(err))
	}
	if err := assistantTools.RegisterMCPClientAuthorizationTool(toolRegistry, assistantTools.MCPClientAuthorizationToolDeps{Platform: mcpPlatformService, PublicGatewayURL: cfg.MCPPlatform.PublicGatewayBaseURL, Logger: assistantLogger}); err != nil {
		logger.Error("failed to register MCP Client authorization Assistant tool", zap.Error(err))
	}
	if !cfg.MCPPlatform.AssistantMCPEnabled {
		if err := assistantTools.RegisterExternalMCPTools(toolRegistry, assistantTools.ExternalMCPToolDeps{
			SourceService:  mcpSvc,
			QueryPlanner:   mcpQueryPlanner,
			Normalizer:     mcpNormalizer,
			Redactor:       mcpRedactor,
			PromptProvider: mcpPromptProvider,
			Logger:         assistantLogger,
		}); err != nil {
			logger.Warn("failed to register external MCP tools", zap.Error(err))
		}
	}
	// Register remaining assistant tools (require services initialized above)
	// Agent tools
	if err := assistantTools.RegisterAgentTools(toolRegistry, assistantTools.AgentToolDeps{ServerClient: serverClient}); err != nil {
		logger.Warn("failed to register agent tools", zap.Error(err))
	}
	// Investigation tools
	if err := assistantTools.RegisterInvestigationTools(toolRegistry, assistantTools.InvestigationToolDeps{InvestigationService: investigationSvc}); err != nil {
		logger.Warn("failed to register investigation tools", zap.Error(err))
	}
	// System tools (Tool.Search, Context.Get, Session.Summarize)
	if err := assistantTools.RegisterSystemTools(toolRegistry, toolCatalog, assistantSessionRepo, contextLoader); err != nil {
		logger.Warn("failed to register system tools", zap.Error(err))
	}
	// Notification tools
	if err := assistantTools.RegisterNotificationTools(toolRegistry, assistantTools.NotificationToolDeps{}); err != nil {
		logger.Warn("failed to register notification tools", zap.Error(err))
	}
	// Baseline tools
	baselineToolDeps := assistantTools.BaselineToolDeps{
		TaskService:      taskService,
		TemplateRepo:     templateRepo,
		RuleRepo:         ruleRepo,
		ScriptGenService: scriptGenService,
		HostRepo:         hostRepo,
		ServerClient:     serverClient,
		OperationRepo:    assistantOperationRepo,
		TaskLogRepo:      taskLogRepo,
		Logger:           assistantLogger,
	}
	if err := assistantTools.RegisterBaselineTools(toolRegistry, baselineToolDeps); err != nil {
		logger.Warn("failed to register baseline tools", zap.Error(err))
	} else {
		assistantTools.NewBaselineOperationWorker(baselineToolDeps).Start(ctx)
	}
	// Detection write tools
	if err := assistantTools.RegisterDetectionWriteTools(toolRegistry, assistantTools.DetectionWriteToolDeps{AlertService: alertService}); err != nil {
		logger.Warn("failed to register detection write tools", zap.Error(err))
	}
	// Package write tools
	if err := assistantTools.RegisterPackageWriteTools(toolRegistry, assistantTools.PackageWriteToolDeps{
		PackageService:         detectionPkgService,
		PackageGenerator:       detectionPkgGenerationService,
		DraftGenerationTimeout: time.Duration(cfg.LLM.TimeoutSeconds) * time.Second,
	}); err != nil {
		logger.Warn("failed to register package write tools", zap.Error(err))
	}
	// Config tools
	if err := assistantTools.RegisterConfigTools(toolRegistry, assistantTools.ConfigToolDeps{SystemConfigRepo: systemConfigRepo, LLMConfigRepo: configRepo}); err != nil {
		logger.Warn("failed to register config tools", zap.Error(err))
	}
	// Sigma rule tools
	if err := assistantTools.RegisterSigmaRuleTools(toolRegistry, assistantTools.SigmaRuleToolDeps{
		SigmaRuleRepo:    sigmaRuleRepo,
		RuleGenService:   ruleGenerationService,
		ContextRefReader: assistantContextRefRepo,
		LifecycleService: sigmaRuleUploadService,
	}); err != nil {
		logger.Warn("failed to register sigma rule tools", zap.Error(err))
	}
	if err := toolRegistry.ValidateModelFacingEnglish(); err != nil {
		logger.Fatal("assistant tool English contract validation failed", zap.Error(err))
	}
	// Enforce a 1:1 capability->tool policy at startup using the resolved
	// capability (including synthetic capabilities), so Mapping can never select
	// multiple implementations for one capability. This catches collisions the
	// per-Register guard misses (tools with an empty Capability field that
	// synthesize the same capability from domain+operation).
	if err := toolRegistry.ValidateCapabilityUniqueness(); err != nil {
		logger.Fatal("assistant tool capability uniqueness validation failed", zap.Error(err))
	}
	assistantLogger.Info("assistant tool capability uniqueness validated", zap.Int("total", toolRegistry.Count()))

	assistantLogger.Info("all assistant tools registered", zap.Int("total", toolRegistry.Count()))

	_ = mcpClientFactory

	assistantHandler := handler.NewAssistantHandler(assistantService, approvalGate, toolDispatcher, toolPolicyService, assistantFileUploadService, investigationSvc, mcpSvc, assistantLogger)

	// Sync tool policies at startup
	if err := toolPolicyService.SyncCatalogTools(context.Background()); err != nil {
		logger.Warn("failed to sync assistant tool policies", zap.Error(err))
	}

	// Initialize HTTP router
	router := api.NewRouter(roleRepo, authService, authHandler, configHandler, hostHandler, templateHandler, taskHandler, taskHandlerWithHealing, agentHandler, ruleHandler, vulnerabilityHandler, detectionHandler, detectionPkgHandler, websocketHandler, notificationHandler, aiAnalysisHandler, commandAuditHandler, auditLogHandler, assetHandler, weakPasswordHandler, assistantHandler, agentGuardHandler, agentSessionHandler, mcpPlatformHandler)
	router.Setup()

	// Start HTTP server
	go func() {
		addr := fmt.Sprintf(":%d", cfg.Server.HTTPPort)
		logger.Info("HTTP server starting", zap.String("addr", addr))
		if err := router.Run(addr); err != nil {
			logger.Fatal("failed to start HTTP server", zap.Error(err))
		}
	}()

	// Start task timeout checker
	taskService.StartTimeoutChecker()

	logger.Info("api-server started successfully",
		zap.String("http_addr", fmt.Sprintf("http://localhost:%d", cfg.Server.HTTPPort)),
		zap.String("server_grpc_addr", serverAddr),
	)

	// Seed default block policies
	seed.SeedBlockPolicies(blockPolicyRepo)

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logger.Info("shutting down...")

	// Graceful shutdown
	cancel()
	if agentGuardWSConsumer != nil {
		if err := agentGuardWSConsumer.Close(); err != nil {
			logger.Warn("agent_guard_realtime_consumer_close_failed", zap.Error(err))
		}
	}
	if agentGuardToolRuleConsumer != nil {
		if err := agentGuardToolRuleConsumer.Close(); err != nil {
			logger.Warn("agent_guard_tool_rule_consumer_close_failed", zap.Error(err))
		}
	}
	if agentSessionConsumer != nil {
		if err := agentSessionConsumer.Close(); err != nil {
			logger.Warn("agent_session_consumer_close_failed", zap.Error(err))
		}
	}
	time.Sleep(2 * time.Second)

	kafkaProducer.Close()
	serverClient.Close()

	logger.Info("api-server stopped")
}

// registerAssistantTools 注册所有助手工具
func registerAssistantTools(
	registry *assistant.ToolRegistry,
	logger *zap.Logger,
	hostRepo *repository.HostRepository,
	alertRepo *repository.AlertRepository,
	taskLogRepo *repository.TaskLogRepository,
	vulnRepo *repository.VulnerabilityRepo,
	sigmaRuleRepo *repository.SigmaRuleRepository,
	blockPolicyRepo *repository.BlockPolicyRepository,
	blockRepo *repository.BlockRepository,
	configRepo *repository.ConfigRepository,
	auditLogRepo *repository.AuditLogRepo,
	detectionPkgRepo *repository.DetectionPackageRepo,
	serverClient *grpcclient.ServerClient,
	assetCollectionRepo *repository.AssetCollectionRepository,
	assetCollectionService *service.AssetCollectionService,
	assetQueryService *service.AssetQueryService,
	vulnService *service.VulnerabilityService,
	customCVEService *service.CustomCVEService,
	hostVulnerabilityScriptService *service.HostVulnerabilityScriptService,
	weakPasswordService *service.WeakPasswordService,
) {
	// Host tools
	if err := assistantTools.RegisterHostTools(registry, assistantTools.HostToolDeps{HostRepo: hostRepo, ServerClient: serverClient}); err != nil {
		logger.Warn("failed to register host tools", zap.Error(err))
	}
	// Detection tools
	if err := assistantTools.RegisterDetectionTools(registry, assistantTools.DetectionToolDeps{
		AlertRepo:     alertRepo,
		BlockRepo:     blockRepo,
		SigmaRuleRepo: sigmaRuleRepo,
	}); err != nil {
		logger.Warn("failed to register detection tools", zap.Error(err))
	}
	// Vulnerability tools
	if err := assistantTools.RegisterVulnerabilityTools(registry, assistantTools.VulnerabilityToolDeps{
		VulnRepo:          vulnRepo,
		AssetRepo:         assetCollectionRepo,
		VulnService:       vulnService,
		HostScriptService: hostVulnerabilityScriptService,
		CustomCVEService:  customCVEService,
	}); err != nil {
		logger.Warn("failed to register vulnerability tools", zap.Error(err))
	}
	// Asset tools
	if err := assistantTools.RegisterAssetTools(registry, assistantTools.AssetToolDeps{
		CollectionService: assetCollectionService,
		QueryService:      assetQueryService,
		AssetRepo:         assetCollectionRepo,
	}); err != nil {
		logger.Warn("failed to register asset tools", zap.Error(err))
	}
	// Weak password tools
	if err := assistantTools.RegisterWeakPasswordTools(registry, assistantTools.WeakPasswordToolDeps{Service: weakPasswordService}); err != nil {
		logger.Warn("failed to register weak password tools", zap.Error(err))
	}
	// Task tools
	if err := assistantTools.RegisterTaskTools(registry, assistantTools.TaskToolDeps{TaskLogRepo: taskLogRepo}); err != nil {
		logger.Warn("failed to register task tools", zap.Error(err))
	}
	// Block tools
	if err := assistantTools.RegisterBlockTools(registry, assistantTools.BlockToolDeps{BlockPolicyRepo: blockPolicyRepo}); err != nil {
		logger.Warn("failed to register block tools", zap.Error(err))
	}
	// Audit tools
	if err := assistantTools.RegisterAuditTools(registry, assistantTools.AuditToolDeps{AuditLogRepo: auditLogRepo}); err != nil {
		logger.Warn("failed to register audit tools", zap.Error(err))
	}
	// Package tools
	if err := assistantTools.RegisterPackageTools(registry, assistantTools.PackageToolDeps{PackageRepo: detectionPkgRepo}); err != nil {
		logger.Warn("failed to register package tools", zap.Error(err))
	}

	logger.Info("assistant tools registered", zap.Int("count", registry.Count()))
}
