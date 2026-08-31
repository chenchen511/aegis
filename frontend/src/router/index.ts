import { createRouter, createWebHistory } from 'vue-router'
import { getStoredAuth } from '@/utils/auth'
import { canCapability } from '@/utils/capabilities'
import Login from '../views/Login.vue'
import ForcePasswordChange from '../views/ForcePasswordChange.vue'
import Dashboard from '../views/Dashboard.vue'
import ModelSettings from '../views/settings/ModelSettings.vue'
import AgentInstall from '../views/settings/AgentInstall.vue'
import Workbench from '../views/Workbench.vue'
import TaskCenter from '../views/TaskCenter.vue'
import TaskDetail from '../views/TaskDetail.vue'
import Vulnerability from '../views/Vulnerability.vue'
import DetectionOverview from '../views/detection/Overview.vue'
import DetectionAlerts from '../views/detection/Alerts.vue'
import DetectionPolicies from '../views/detection/Policies.vue'
import DetectionRules from '../views/detection/Rules.vue'
import AIAnalysis from '../views/detection/AIAnalysis.vue'
import CommandAudit from '../views/settings/CommandAudit/index.vue'
import AuditLogs from '../views/settings/AuditLogs/index.vue'
import DetectionPackages from '../views/detection/DetectionPackages/index.vue'
import PackageDetail from '../views/detection/DetectionPackages/PackageDetail.vue'
import PackageEditor from '../views/detection/DetectionPackages/PackageEditor.vue'
import EBPFHooks from '../views/settings/EBPFHooks/index.vue'
import WeakPasswordIndex from '../views/detection/WeakPassword/Index.vue'
import WeakPasswordTaskDetail from '../views/detection/WeakPassword/TaskDetail.vue'
import WeakPasswordDictionaries from '../views/detection/WeakPassword/Dictionaries.vue'

const routes = [
  {
    path: '/login',
    name: 'Login',
    component: Login,
    meta: { titleKey: 'routes.login', public: true, authLayout: true }
  },
  {
    path: '/force-password-change',
    name: 'ForcePasswordChange',
    component: ForcePasswordChange,
    meta: { titleKey: 'routes.forcePasswordChange', authLayout: true, requiresAuth: true }
  },
  {
    path: '/',
    redirect: '/hosts'
  },
  {
    path: '/hosts',
    name: 'Hosts',
    component: Dashboard,
    meta: { titleKey: 'routes.hosts' }
  },
  // V5.8 智能资产采集
  {
    path: '/hosts/assets',
    name: 'AssetsOverview',
    component: () => import('../views/hosts/Assets/Overview.vue'),
    meta: { titleKey: 'routes.assetsOverview' }
  },
  {
    path: '/hosts/assets/software',
    name: 'AssetsSoftware',
    component: () => import('../views/hosts/Assets/Software.vue'),
    meta: { titleKey: 'routes.software' }
  },
  {
    path: '/hosts/assets/applications',
    name: 'AssetsApplications',
    component: () => import('../views/hosts/Assets/Applications.vue'),
    meta: { titleKey: 'routes.applications' }
  },
  {
    path: '/hosts/assets/databases',
    name: 'AssetsDatabases',
    component: () => import('../views/hosts/Assets/Applications.vue'),
    meta: { titleKey: 'routes.databases' },
    props: { defaultCategory: 'database' }
  },
  {
    path: '/hosts/assets/web-services',
    name: 'AssetsWebServices',
    component: () => import('../views/hosts/Assets/Applications.vue'),
    meta: { titleKey: 'routes.webServices' },
    props: { defaultCategory: 'web_service' }
  },
  {
    path: '/hosts/assets/web-frameworks',
    name: 'AssetsWebFrameworks',
    component: () => import('../views/hosts/Assets/Applications.vue'),
    meta: { titleKey: 'routes.webFrameworks' },
    props: { defaultCategory: 'web_framework' }
  },
  {
    path: '/hosts/assets/web-sites',
    name: 'AssetsWebSites',
    component: () => import('../views/hosts/Assets/Applications.vue'),
    meta: { titleKey: 'routes.webSites' },
    props: { defaultCategory: 'web_site' }
  },
  {
    path: '/hosts/assets/llm-services',
    name: 'AssetsLLMServices',
    component: () => import('../views/hosts/Assets/Applications.vue'),
    meta: { titleKey: 'routes.llmServices' },
    props: { defaultCategory: 'llm_service' }
  },
  {
    path: '/hosts/assets/ai-agents',
    name: 'AssetsAIAgents',
    component: () => import('../views/hosts/Assets/Applications.vue'),
    meta: { titleKey: 'routes.aiAgents' },
    props: { defaultCategory: 'ai_agent' }
  },
  {
    path: '/hosts/assets/mcp-servers',
    name: 'AssetsMCPServers',
    component: () => import('../views/hosts/Assets/Applications.vue'),
    meta: { titleKey: 'routes.mcpServers' },
    props: { defaultCategory: 'mcp_server' }
  },
  {
    path: '/hosts/assets/other-applications',
    name: 'AssetsOtherApplications',
    component: () => import('../views/hosts/Assets/Applications.vue'),
    meta: { titleKey: 'routes.otherApplications' },
    props: { defaultCategory: 'other' }
  },
  {
    path: '/hosts/assets/collections',
    name: 'AssetsCollections',
    redirect: '/hosts/assets',
    meta: { titleKey: 'routes.collections' }
  },
  {
    path: '/baseline',
    redirect: '/baseline/workbench',
    meta: { titleKey: 'routes.baseline' }
  },
  {
    path: '/baseline/workbench',
    name: 'BaselineWorkbench',
    component: Workbench,
    meta: { titleKey: 'routes.ruleManagement' }
  },
  {
    path: '/baseline/tasks',
    name: 'BaselineTasks',
    component: TaskCenter,
    meta: { titleKey: 'routes.baselineTasks' }
  },
  {
    path: '/baseline/tasks/:id',
    name: 'BaselineTaskDetail',
    component: TaskDetail,
    meta: { titleKey: 'routes.taskDetail' }
  },
  {
    path: '/vulnerability',
    name: 'Vulnerability',
    component: Vulnerability,
    meta: { titleKey: 'routes.vulnerability' }
  },
  {
    path: '/vulnerability/tasks',
    name: 'VulnerabilityTasks',
    component: TaskCenter,
    meta: { titleKey: 'routes.vulnerabilityTasks' }
  },
  {
    path: '/vulnerability/tasks/:id',
    name: 'VulnerabilityTaskDetail',
    component: TaskDetail,
    meta: { titleKey: 'routes.vulnerabilityTaskDetail' }
  },
  {
    path: '/detection/overview',
    name: 'DetectionOverview',
    component: DetectionOverview,
    meta: { titleKey: 'routes.securityOverview' }
  },
  {
    path: '/detection/alerts',
    name: 'DetectionAlerts',
    component: DetectionAlerts,
    meta: { titleKey: 'routes.alerts' }
  },
  {
    path: '/detection/ai-analysis',
    name: 'AIAnalysis',
    component: AIAnalysis,
    meta: { titleKey: 'routes.aiAnalysis' }
  },
  {
    path: '/detection/policies',
    name: 'DetectionPolicies',
    component: DetectionPolicies,
    meta: { titleKey: 'routes.blockingPolicies' }
  },
  {
    path: '/detection/rules',
    name: 'DetectionRules',
    component: DetectionRules,
    meta: { titleKey: 'routes.detectionRules' }
  },
  {
    path: '/detection/packages',
    name: 'DetectionPackages',
    component: DetectionPackages,
    meta: { titleKey: 'routes.detectionPackages' }
  },
  {
    path: '/detection/packages/new',
    name: 'DetectionPackageNew',
    component: PackageEditor,
    meta: { titleKey: 'routes.detectionPackageNew' }
  },
  {
    path: '/detection/packages/:id',
    name: 'DetectionPackageDetail',
    component: PackageDetail,
    meta: { titleKey: 'routes.detectionPackageDetail' }
  },
  {
    path: '/detection/packages/:id/edit',
    name: 'DetectionPackageEdit',
    component: PackageEditor,
    meta: { titleKey: 'routes.detectionPackageEdit' }
  },
  {
    path: '/detection/agent-guard',
    redirect: '/detection/agent-guard/events'
  },
  {
    path: '/detection/agent-guard/events',
    name: 'AgentGuardEvents',
    component: () => import('../views/detection/AgentGuard/EventProtection.vue'),
    meta: { titleKey: 'routes.agentGuardEvents', permission: 'agent_guard:read' }
  },
  {
    path: '/detection/agent-guard/escape',
    name: 'AgentGuardEscape',
    component: () => import('../views/detection/AgentGuard/EscapeProtection.vue'),
    meta: { titleKey: 'routes.agentGuardEscape', permission: 'agent_guard:read' }
  },
  {
    path: '/detection/agent-guard/configurations',
    name: 'AgentGuardConfigurations',
    component: () => import('../views/detection/AgentGuard/AgentConfigurationDetection.vue'),
    meta: { titleKey: 'routes.agentGuardConfigurations', permission: 'agent_guard:read' }
  },
  {
    path: '/detection/agent-skill-security',
    name: 'AgentSkillSecurity',
    component: () => import('../views/detection/AgentGuard/AgentSkillSecurity.vue'),
    meta: { titleKey: 'routes.agentSkillSecurity', permission: 'agent_guard:read' }
  },
  {
    path: '/detection/agent-sessions',
    redirect: '/detection/agent-guard/session-awareness'
  },
  {
    path: '/detection/agent-guard/session-awareness',
    name: 'AgentSessionAwareness',
    component: () => import('../views/detection/AgentSessionAwareness.vue'),
    meta: { titleKey: 'routes.agentSessionAwareness', permission: 'agent_guard:read' }
  },
  {
    path: '/risk/weak-password',
    name: 'WeakPassword',
    component: WeakPasswordIndex,
    meta: { titleKey: 'routes.weakPassword' }
  },
  {
    path: '/risk/weak-password/tasks/:id',
    name: 'WeakPasswordTaskDetail',
    component: WeakPasswordTaskDetail,
    meta: { titleKey: 'routes.weakPasswordTaskDetail' }
  },
  {
    path: '/risk/weak-password/dictionaries',
    name: 'WeakPasswordDictionaries',
    component: WeakPasswordDictionaries,
    meta: { titleKey: 'routes.weakPasswordDictionaries' }
  },
  {
    path: '/settings/command-audit',
    name: 'CommandAudit',
    component: CommandAudit,
    meta: { titleKey: 'routes.commandAudit' }
  },
  {
    path: '/settings/audit-logs',
    name: 'AuditLogs',
    component: AuditLogs,
    meta: { titleKey: 'routes.auditLogs' }
  },
  {
    path: '/settings',
    redirect: '/settings/models',
    meta: { titleKey: 'routes.settings' }
  },
  {
    path: '/settings/models',
    name: 'ModelSettings',
    component: ModelSettings,
    meta: { titleKey: 'routes.modelSettings' }
  },
  {
    path: '/settings/agent',
    name: 'AgentInstall',
    component: AgentInstall,
    meta: { titleKey: 'routes.agentInstall' }
  },
  {
    path: '/settings/ebpf-hooks',
    name: 'EBPFHooks',
    component: EBPFHooks,
    meta: { titleKey: 'routes.ebpfHooks' }
  },
  {
    path: '/settings/mcp-aggregation',
    name: 'MCPAggregationControl',
    component: () => import('../views/settings/MCPAggregationControl.vue'),
    meta: { titleKey: 'routes.mcpAggregationControl', permission: 'mcp:server:read' }
  },
  {
    path: '/settings/tool-policy',
    name: 'ToolPolicySettings',
    component: () => import('../views/settings/AssistantToolPolicySettings.vue'),
    meta: { titleKey: 'routes.toolPolicy' }
  },
  // V6.0 智能助手
  {
    path: '/assistant',
    name: 'Assistant',
    component: () => import('../views/assistant/AssistantWorkspace.vue'),
    meta: { titleKey: 'routes.assistant', requiresAuth: true }
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

router.beforeEach((to) => {
  const auth = getStoredAuth()

  if (to.path === '/login' && auth) {
    return auth.forcePasswordChange ? '/force-password-change' : '/hosts'
  }

  if (!to.meta.public && !auth) {
    return '/login'
  }

  if (auth?.forcePasswordChange && to.path !== '/force-password-change') {
    return '/force-password-change'
  }

  if (to.path === '/force-password-change' && auth && !auth.forcePasswordChange) {
    return '/hosts'
  }

  const requiredPermission = typeof to.meta.permission === 'string' ? to.meta.permission : ''
  if (requiredPermission && !hasFrontendPermission(auth?.role, requiredPermission)) {
    return '/hosts'
  }

  return true
})

function hasFrontendPermission(role: string | undefined, permission: string): boolean {
  if (!permission.startsWith('mcp:')) return true
  if (!canCapability(permission)) return false
  // The backend remains authoritative. This client-side check only prevents
  // navigation flicker for known Aegis roles; capability refresh/403 handling
  // is still performed by the API layer.
	return !role || role === 'admin' || role === 'security_developer' || role === 'security_analyst'
}

export default router
