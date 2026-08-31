<template>
  <el-config-provider :locale="elementLocale">
  <div v-if="isAuthLayout" class="auth-layout-wrapper">
    <LanguageSwitcher class="auth-language-switcher" />
    <router-view />
  </div>
  <el-container
    v-else
    class="app-container"
    :class="{
      'assistant-mode': isAssistantMode,
      'sidebar-collapsed': isSidebarCollapsed,
      'sidebar-labels-wrap': sidebarLayout.wrapMenuLabels,
    }"
    :style="{ '--aegis-sidebar-expanded-width': `${sidebarLayout.expandedWidth}px` }"
  >
    <!-- 普通模式才显示侧边栏 -->
    <el-aside
      v-if="!isAssistantMode"
      :width="isSidebarCollapsed ? '64px' : `${sidebarLayout.expandedWidth}px`"
      class="sidebar"
      :class="{ collapsed: isSidebarCollapsed }"
    >
      <div class="logo">
        <span class="logo-mark" aria-hidden="true">
          <span class="brand-shield"></span>
        </span>
        <div class="logo-copy">
          <span class="logo-text">Aegis</span>
          <span class="logo-subtitle">{{ t('app.brand.subtitle') }}</span>
        </div>
      </div>
      <el-menu
        :default-active="activeMenu"
        :router="true"
        :collapse="isSidebarCollapsed"
        :collapse-transition="false"
        class="sidebar-menu"
      >
        <el-menu-item index="/hosts">
          <el-icon><Monitor /></el-icon>
          <span>{{ t('app.menu.hosts') }}</span>
        </el-menu-item>

        <el-sub-menu index="assets">
          <template #title>
            <el-icon><Box /></el-icon>
            <span>{{ t('app.menu.assets') }}</span>
          </template>
          <el-menu-item index="/hosts/assets">
            <el-icon><DataBoard /></el-icon>
            <span>{{ t('app.menu.assetsOverview') }}</span>
          </el-menu-item>
          <el-menu-item index="/hosts/assets/software">
            <el-icon><Files /></el-icon>
            <span>{{ t('app.menu.software') }}</span>
          </el-menu-item>
          <el-menu-item index="/hosts/assets/applications">
            <el-icon><Grid /></el-icon>
            <span>{{ t('app.menu.applications') }}</span>
          </el-menu-item>
        </el-sub-menu>

        <el-sub-menu index="baseline">
          <template #title>
            <el-icon><Document /></el-icon>
            <span>{{ t('app.menu.baseline') }}</span>
          </template>
          <el-menu-item index="/baseline/workbench">
            <el-icon><SetUp /></el-icon>
            <span>{{ t('app.menu.ruleManagement') }}</span>
          </el-menu-item>
          <el-menu-item index="/baseline/tasks">
            <el-icon><List /></el-icon>
            <span>{{ t('app.menu.baselineTasks') }}</span>
          </el-menu-item>
        </el-sub-menu>

        <el-sub-menu index="vulnerability">
          <template #title>
            <el-icon><Warning /></el-icon>
            <span>{{ t('app.menu.vulnerability') }}</span>
          </template>
          <el-menu-item index="/vulnerability">
            <el-icon><SetUp /></el-icon>
            <span>{{ t('app.menu.vulnerabilityWorkbench') }}</span>
          </el-menu-item>
          <el-menu-item index="/vulnerability/tasks">
            <el-icon><List /></el-icon>
            <span>{{ t('app.menu.vulnerabilityTasks') }}</span>
          </el-menu-item>
        </el-sub-menu>

        <el-sub-menu index="detection">
          <template #title>
            <el-icon><DataAnalysis /></el-icon>
            <span>{{ t('app.menu.detection') }}</span>
          </template>
          <el-menu-item index="/detection/overview">
            <el-icon><DataAnalysis /></el-icon>
            <span>{{ t('app.menu.securityOverview') }}</span>
          </el-menu-item>
          <el-menu-item index="/detection/alerts">
            <el-icon><Bell /></el-icon>
            <span>{{ t('app.menu.alerts') }}</span>
          </el-menu-item>
          <el-menu-item index="/detection/ai-analysis">
            <el-icon><ChatDotRound /></el-icon>
            <span>{{ t('app.menu.aiAnalysis') }}</span>
          </el-menu-item>
          <el-menu-item index="/detection/policies">
            <el-icon><Operation /></el-icon>
            <span>{{ t('app.menu.blockingPolicies') }}</span>
          </el-menu-item>
          <el-menu-item index="/detection/rules">
            <el-icon><Tickets /></el-icon>
            <span>{{ t('app.menu.ruleManagement') }}</span>
          </el-menu-item>
          <el-menu-item index="/detection/packages">
            <el-icon><Box /></el-icon>
            <span>{{ t('app.menu.detectionPackages') }}</span>
          </el-menu-item>
        </el-sub-menu>

        <el-sub-menu index="agent-guard">
          <template #title>
            <el-icon><Connection /></el-icon>
            <span>{{ t('app.menu.agentGuard') }}</span>
          </template>
          <el-menu-item index="/detection/agent-guard/events">
            <el-icon><DataAnalysis /></el-icon>
            <span>{{ t('app.menu.agentGuardEvents') }}</span>
          </el-menu-item>
          <el-menu-item index="/detection/agent-guard/escape">
            <el-icon><Warning /></el-icon>
            <span>{{ t('app.menu.agentGuardEscape') }}</span>
          </el-menu-item>
          <el-menu-item index="/detection/agent-guard/configurations">
            <el-icon><Setting /></el-icon>
            <span>{{ t('app.menu.agentGuardConfigurations') }}</span>
          </el-menu-item>
          <el-menu-item index="/detection/agent-skill-security">
            <el-icon><DocumentChecked /></el-icon>
            <span>{{ t('app.menu.agentSkillSecurity') }}</span>
          </el-menu-item>
          <el-menu-item index="/detection/agent-guard/session-awareness">
            <el-icon><ChatDotRound /></el-icon>
            <span>{{ t('app.menu.agentSessionAwareness') }}</span>
          </el-menu-item>
        </el-sub-menu>

        <el-menu-item index="/risk/weak-password">
          <el-icon><Lock /></el-icon>
          <span>{{ t('app.menu.weakPassword') }}</span>
        </el-menu-item>

        <el-menu-item index="/settings/mcp-aggregation">
          <el-icon><Connection /></el-icon>
          <span>{{ t('app.menu.mcpAggregationControl') }}</span>
        </el-menu-item>

        <el-sub-menu index="settings">
          <template #title>
            <el-icon><Setting /></el-icon>
            <span>{{ t('app.menu.settings') }}</span>
          </template>
          <el-menu-item index="/settings/models">
            <el-icon><Setting /></el-icon>
            <span>{{ t('app.menu.modelSettings') }}</span>
          </el-menu-item>
          <el-menu-item index="/settings/agent">
            <el-icon><Operation /></el-icon>
            <span>{{ t('app.menu.agentInstall') }}</span>
          </el-menu-item>
          <el-menu-item index="/settings/command-audit">
            <el-icon><Tickets /></el-icon>
            <span>{{ t('app.menu.commandAudit') }}</span>
          </el-menu-item>
          <el-menu-item index="/settings/audit-logs">
            <el-icon><Document /></el-icon>
            <span>{{ t('app.menu.auditLogs') }}</span>
          </el-menu-item>
          <el-menu-item index="/settings/ebpf-hooks">
            <el-icon><Connection /></el-icon>
            <span>{{ t('app.menu.ebpfHooks') }}</span>
          </el-menu-item>
        </el-sub-menu>
      </el-menu>

      <div class="sidebar-footer">
        <template v-if="!isSidebarCollapsed">
          <span class="status-dot" />
          <span class="version">{{ t('app.sidebar.controlPlaneOnline') }}</span>
        </template>
        <el-tooltip :content="isSidebarCollapsed ? t('app.sidebar.expand') : t('app.sidebar.collapse')" placement="right">
          <el-button
            class="collapse-button"
            :icon="isSidebarCollapsed ? Expand : Fold"
            circle
            size="small"
            @click="isSidebarCollapsed = !isSidebarCollapsed"
          />
        </el-tooltip>
      </div>
    </el-aside>

    <el-container>
      <el-header class="app-header">
        <div class="header-left">
          <div class="route-kicker">Security Operations</div>
          <el-breadcrumb v-if="!isAssistantMode" separator="/">
            <el-breadcrumb-item v-for="item in breadcrumbs" :key="item.path">
              {{ item.title }}
            </el-breadcrumb-item>
          </el-breadcrumb>
          <div v-else class="assistant-title">
            <el-icon><MagicStick /></el-icon>
            <span>{{ t('app.header.assistantTitle') }}</span>
          </div>
        </div>
        <div class="header-right">
          <!-- 模式切换 -->
          <div class="mode-switch">
            <el-segmented
              v-model="currentMode"
              :options="modeOptions"
              size="small"
              @change="handleModeChange"
            />
          </div>
          <LanguageSwitcher />
          <NotificationBell />
          <el-tooltip :content="t('app.header.refresh')" placement="bottom">
            <el-button :icon="Refresh" circle size="small" @click="handleRefresh" />
          </el-tooltip>
          <UserProfileDropdown />
        </div>
      </el-header>

      <el-main class="app-main" :class="{ 'assistant-main': isAssistantMode }">
        <router-view />
      </el-main>
    </el-container>
  </el-container>
  </el-config-provider>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import { Monitor, Document, DocumentChecked, SetUp, List, Warning, Setting, Refresh, DataAnalysis, Bell, Operation, Tickets, ChatDotRound, Box, Connection, DataBoard, Files, Grid, MagicStick, Lock, Fold, Expand } from '@element-plus/icons-vue'
import NotificationBell from '@/components/notification/NotificationBell.vue'
import UserProfileDropdown from '@/components/UserProfileDropdown.vue'
import LanguageSwitcher from '@/components/common/LanguageSwitcher.vue'
import { clearStoredAuth, getStoredAuth } from '@/utils/auth'
import { createIdleLogout } from '@/utils/sessionTimeout'
import { elementLocale } from '@/i18n'
import { getSidebarLayout } from '@/utils/sidebarLayout'

const route = useRoute()
const router = useRouter()
const { t, locale } = useI18n()
const isSidebarCollapsed = ref(false)
const sidebarLayout = computed(() => getSidebarLayout(locale.value))
// 模式切换
const currentMode = ref<'normal' | 'assistant'>('normal')
const modeOptions = computed(() => [
  { label: t('app.mode.operationsAudit'), value: 'normal' },
  { label: t('app.mode.agentMode'), value: 'assistant' },
])

const isAssistantMode = computed(() => {
  return route.path === '/assistant' || currentMode.value === 'assistant'
})

function handleModeChange(mode: string | number) {
  if (mode === 'assistant') {
    router.push('/assistant')
  } else {
    router.push('/hosts')
  }
}

// 监听路由变化，同步模式
watch(() => route.path, (path) => {
  currentMode.value = path === '/assistant' ? 'assistant' : 'normal'
}, { immediate: true })

const activeMenu = computed(() => {
  return route.path
})

const breadcrumbs = computed(() => {
  const matched = route.matched.filter(item => item.meta && item.meta.titleKey)
  const crumbs = [{ path: '/', title: t('routes.home') }]

  matched.forEach(item => {
    crumbs.push({
      path: item.path,
      title: t(String(item.meta.titleKey || 'routes.home'))
    })
  })

  return crumbs
})

const isAuthLayout = computed(() => {
  return Boolean(route.meta.authLayout)
})

function setViewportContent(content: string) {
  const viewport = document.querySelector<HTMLMetaElement>('meta[name="viewport"]')
  if (viewport) {
    viewport.setAttribute('content', content)
  }
}

function syncViewportForLayout() {
  if (isAuthLayout.value) {
    setViewportContent('width=device-width, initial-scale=1.0')
    return
  }

  setViewportContent('width=1280')
}

function handleRefresh() {
  router.go(0)
}

const idleLogout = createIdleLogout({
  isEnabled: () => Boolean(getStoredAuth()) && !route.meta.authLayout,
  onTimeout: () => {
    clearStoredAuth()
    ElMessage.warning(t('app.session.idleLogout'))
    router.replace('/login')
  }
})

onMounted(() => {
  syncViewportForLayout()
  idleLogout.start()
})

onBeforeUnmount(() => {
  setViewportContent('width=device-width, initial-scale=1.0')
  idleLogout.stop()
})

watch(() => route.fullPath, () => {
  syncViewportForLayout()
  idleLogout.refresh()
}, { immediate: true })

watch([() => route.fullPath, locale], () => {
  const titleKey = String(route.meta.titleKey || 'routes.home')
  document.title = `${t(titleKey)} · Aegis`
}, { immediate: true })
</script>

<style scoped>
.auth-layout-wrapper {
  min-height: 100dvh;
  position: relative;
}

.auth-language-switcher {
  position: fixed;
  right: 24px;
  top: 20px;
  z-index: 20;
}

.app-container {
  --aegis-sidebar-expanded-width: 220px;
  height: 100dvh;
  min-width: var(--aegis-desktop-min-width);
  width: max(100vw, var(--aegis-desktop-min-width));
  background:
    linear-gradient(90deg, rgba(11, 18, 32, 0.98) 0 var(--aegis-sidebar-expanded-width), transparent var(--aegis-sidebar-expanded-width)),
    radial-gradient(circle at 80% 8%, rgba(34, 211, 238, 0.14), transparent 25%),
    linear-gradient(135deg, #edf5ff, #f8fafc);
}

.app-container.assistant-mode {
  background:
    radial-gradient(circle at 80% 8%, rgba(34, 211, 238, 0.14), transparent 25%),
    linear-gradient(135deg, #edf5ff, #f8fafc);
}

.app-container.sidebar-collapsed {
  background:
    linear-gradient(90deg, rgba(11, 18, 32, 0.98) 0 64px, transparent 64px),
    radial-gradient(circle at 80% 8%, rgba(34, 211, 238, 0.14), transparent 25%),
    linear-gradient(135deg, #edf5ff, #f8fafc);
}

.sidebar {
  position: relative;
  background:
    radial-gradient(circle at 20% 0%, rgba(34, 211, 238, 0.18), transparent 32%),
    linear-gradient(180deg, #0b1220 0%, #111827 52%, #0f172a 100%);
  display: flex;
  flex-direction: column;
  overflow: hidden;
  border-right: 1px solid rgba(148, 163, 184, 0.14);
  transition: width var(--aegis-transition);
}

.sidebar::after {
  content: "";
  position: absolute;
  inset: 0;
  pointer-events: none;
  background-image:
    linear-gradient(rgba(255, 255, 255, 0.035) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255, 255, 255, 0.035) 1px, transparent 1px);
  background-size: 26px 26px;
  opacity: 0.5;
}

.logo {
  position: relative;
  z-index: 1;
  height: 72px;
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 0 18px;
  border-bottom: 1px solid rgba(148, 163, 184, 0.14);
}

.sidebar.collapsed .logo {
  justify-content: center;
  padding: 0 12px;
}

.sidebar.collapsed .logo-copy {
  display: none;
}

.logo-mark {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 38px;
  height: 38px;
  border: 1px solid rgba(34, 211, 238, 0.38);
  border-radius: 8px;
  background: rgba(34, 211, 238, 0.1);
  box-shadow: 0 10px 28px rgba(34, 211, 238, 0.16);
}

.brand-shield {
  width: 24px;
  height: 28px;
  display: block;
  background-image: url('/aegis-brand-source.png');
  background-repeat: no-repeat;
  background-size: 1916px 804px;
  background-position: -23px -28px;
}

.logo-copy {
  display: flex;
  flex-direction: column;
  min-width: 0;
}

.logo-text {
  font-size: 18px;
  font-weight: 800;
  color: #fff;
  letter-spacing: 0.04em;
}

.logo-subtitle {
  color: rgba(226, 232, 240, 0.62);
  font-size: 12px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.sidebar-menu {
  position: relative;
  z-index: 1;
  flex: 1;
  border-right: none;
  overflow-y: auto;
  background: transparent;
}

.sidebar-menu:not(.el-menu--collapse) {
  width: var(--aegis-sidebar-expanded-width);
}

.sidebar-menu.el-menu--collapse {
  width: 64px;
}

.sidebar-footer {
  position: relative;
  z-index: 1;
  height: 48px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  padding: 0 10px;
  border-top: 1px solid rgba(148, 163, 184, 0.14);
}

.sidebar.collapsed .sidebar-footer {
  justify-content: center;
}

.collapse-button {
  color: rgba(226, 232, 240, 0.86);
  border-color: rgba(148, 163, 184, 0.22);
  background: rgba(15, 23, 42, 0.34);
}

.version {
  font-size: 12px;
  color: rgba(226, 232, 240, 0.72);
}

.status-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: #22c55e;
  box-shadow: 0 0 0 4px rgba(34, 197, 94, 0.14);
}

.app-header {
  height: 64px;
  background: rgba(255, 255, 255, 0.72);
  border-bottom: 1px solid rgba(15, 23, 42, 0.08);
  backdrop-filter: blur(18px);
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 24px;
}

.header-left {
  display: flex;
  flex-direction: column;
  gap: 4px;
  justify-content: center;
}

.route-kicker {
  color: #64748b;
  font-size: 11px;
  font-weight: 750;
  letter-spacing: 0.14em;
  text-transform: uppercase;
}

.assistant-title {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 16px;
  font-weight: 600;
  color: #303133;
}

.assistant-title .el-icon {
  color: #409eff;
}

.system-chip {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  height: 32px;
  padding: 0 12px;
  border: 1px solid rgba(34, 197, 94, 0.2);
  border-radius: 999px;
  color: #166534;
  background: rgba(240, 253, 244, 0.82);
  font-size: 12px;
  font-weight: 700;
}

.header-right {
  display: flex;
  align-items: center;
  gap: 12px;
}

.mode-switch {
  display: flex;
  align-items: center;
}

.app-main {
  position: relative;
  background:
    radial-gradient(circle at 8% 12%, rgba(34, 211, 238, 0.12), transparent 24%),
    radial-gradient(circle at 92% 0%, rgba(37, 99, 235, 0.1), transparent 22%),
    linear-gradient(135deg, rgba(241, 247, 253, 0.96), rgba(248, 250, 252, 0.94));
  padding: 24px;
  min-width: 0;
  max-width: 100%;
  overflow-y: auto;
  overflow-x: hidden;
}

.app-container > .el-container {
  min-width: 0;
  width: 0;
  flex: 1 1 auto;
}

.app-main.assistant-main {
  padding: 0;
  background: #f5f7fa;
  overflow: hidden;
  display: flex;
  flex-direction: column;
}

:deep(.el-menu) {
  border-right: none;
  background: transparent;
}

:deep(.el-menu-item),
:deep(.el-sub-menu__title) {
  height: 46px;
  line-height: 46px;
  margin: 4px 10px;
  border-radius: 12px;
  color: rgba(226, 232, 240, 0.78);
  transition: background 180ms ease, color 180ms ease, transform 180ms ease;
}

.sidebar.collapsed :deep(.el-menu-item),
.sidebar.collapsed :deep(.el-sub-menu__title) {
  margin: 4px 8px;
  padding: 0 14px !important;
  justify-content: center;
}

:deep(.el-menu-item:hover),
:deep(.el-sub-menu__title:hover) {
  background: rgba(34, 211, 238, 0.08) !important;
  color: #f8fafc !important;
  transform: translateX(2px);
}

:deep(.el-menu-item.is-active) {
  background: linear-gradient(135deg, rgba(37, 99, 235, 0.95), rgba(8, 145, 178, 0.95)) !important;
  color: #ffffff !important;
  box-shadow: 0 12px 28px rgba(37, 99, 235, 0.3);
}

:deep(.el-menu-item.is-active .el-icon) {
  color: #ffffff !important;
}

:deep(.el-menu-item.is-active span) {
  color: #ffffff !important;
}

:deep(.el-sub-menu .el-menu-item) {
  min-width: var(--aegis-sidebar-expanded-width);
  padding-left: 44px !important;
  background: rgba(15, 23, 42, 0.34) !important;
}

.sidebar-labels-wrap .sidebar:not(.collapsed) :deep(.el-sub-menu__title) {
  height: auto;
  min-height: 46px;
  padding-top: 8px;
  padding-bottom: 8px;
  line-height: 20px;
}

.sidebar-labels-wrap .sidebar:not(.collapsed) :deep(.el-sub-menu__title > span) {
  min-width: 0;
  max-width: calc(100% - 90px);
  white-space: normal;
  line-height: 20px;
}

:deep(.el-sub-menu .el-menu-item:hover) {
  background: rgba(34, 211, 238, 0.08) !important;
}

:deep(.el-sub-menu .el-menu-item.is-active) {
  background: linear-gradient(135deg, rgba(37, 99, 235, 0.95), rgba(8, 145, 178, 0.95)) !important;
  color: #ffffff !important;
}

:deep(.el-sub-menu.is-active > .el-sub-menu__title) {
  color: #67e8f9 !important;
}

:deep(.el-sub-menu.is-active > .el-sub-menu__title .el-icon) {
  color: #67e8f9 !important;
}

:deep(.el-segmented) {
  --el-segmented-bg-color: rgba(0, 0, 0, 0.04);
  --el-segmented-item-selected-bg-color: #409eff;
  --el-segmented-item-selected-color: #fff;
}
</style>
