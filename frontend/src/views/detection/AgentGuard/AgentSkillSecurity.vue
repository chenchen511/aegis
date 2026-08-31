<template>
  <div class="agent-skill-security page-shell">
    <section class="page-hero">
      <div>
        <h1>智能体 Skill 安全</h1>
        <p>获取 Codex、Claude Code、OpenClaw 的 Skill 完整原文，并检测投毒、提示词攻击和越狱能力。</p>
      </div>
      <div class="hero-actions">
        <el-button plain @click="rulesVisible = true">内置检测规则</el-button>
        <el-tag type="warning" effect="plain">原文不脱敏</el-tag>
      </div>
    </section>

    <el-alert
      title="扫描仅读取批准的 Agent Skill 根目录，不执行 Skill、脚本、命令或 URL；完整原文可能包含凭据、路径和命令，请确认访问权限。"
      type="warning"
      :closable="false"
      show-icon
    />

    <el-card class="scan-card">
      <el-form inline @submit.prevent="scanSelected">
        <el-form-item label="扫描主机">
          <el-select
            v-model="selectedHostIds"
            multiple
            filterable
            collapse-tags
            collapse-tags-tooltip
            clearable
            :loading="hostsLoading"
            :placeholder="hosts.length ? '选择已连接主机' : '暂无已连接主机'"
            class="host-select"
          >
            <el-option
              v-for="host in hosts"
              :key="host.id"
              :value="host.id"
              :label="hostLabel(host)"
              :disabled="!host.online"
            >
              <div class="host-option">
                <div class="stacked">
                  <strong>{{ host.hostname || host.id }}</strong>
                  <span>{{ host.ip || host.id }} · {{ host.agentTypes.join('、') || 'Agent' }}</span>
                </div>
                <el-tag size="small" :type="host.online ? 'success' : 'info'" effect="plain">
                  {{ host.online ? '在线' : '离线' }}
                </el-tag>
              </div>
            </el-option>
          </el-select>
        </el-form-item>
        <div class="scan-actions">
          <el-button
            type="primary"
            :loading="scanning"
            :disabled="!selectedConnectedHostIds.length"
            @click="scanSelected"
          >
            扫描选中（{{ selectedConnectedHostIds.length }}）
          </el-button>
          <el-button
            type="success"
            plain
            :loading="scanning"
            :disabled="!connectedHosts.length"
            @click="scanAll"
          >
            一键扫描全部已连接主机（{{ connectedHosts.length }}）
          </el-button>
          <el-button :loading="hostsLoading" @click="loadHosts">刷新主机</el-button>
        </div>
      </el-form>
      <div v-if="scanning" class="scan-progress">
        正在扫描 {{ completedHostCount }} / {{ scanningHostCount }} 台主机，请勿关闭页面。
      </div>
    </el-card>

    <el-alert
      v-if="hostsError"
      title="在线主机加载失败，请刷新后重试。"
      type="warning"
      :closable="false"
      class="scan-error"
    />

    <el-skeleton v-if="hostsLoading && !hosts.length" :rows="5" animated />
    <template v-if="hasScan">
      <div class="metric-grid">
        <div class="metric-card"><span>已存储主机</span><strong>{{ inventoryPage?.host_count || scanResults.length }}</strong></div>
        <div class="metric-card"><span>发现 Skill</span><strong>{{ skillCount }}</strong></div>
        <div class="metric-card"><span>安全发现</span><strong :class="{ danger: findingCount > 0 }">{{ findingCount }}</strong></div>
        <div class="metric-card"><span>扫描页</span><strong>{{ pageCount }}</strong></div>
      </div>

      <el-alert
        v-for="error in scanErrorsForDisplay"
        :key="`${error.stage}-${error.message}`"
        :title="`${error.stage}: ${error.message}`"
        type="warning"
        :closable="false"
        class="scan-error"
      />

      <el-card v-loading="inventoryLoading">
        <template #header>
          <div class="table-header">
            <strong>Skill 清单</strong>
            <span>{{ latestScannedAt || '-' }}</span>
          </div>
        </template>
        <el-empty v-if="!rows.length" description="未发现支持的 Skill" />
        <el-table v-else :data="skillPagination.items" stripe row-key="key" @row-click="openSkill">
          <el-table-column label="主机" min-width="190">
            <template #default="{ row }">
              <div class="stacked"><strong>{{ row.host.hostname || row.host.id }}</strong><span>{{ row.host.ip || row.host.id }}</span></div>
            </template>
          </el-table-column>
          <el-table-column label="Skill" min-width="190">
            <template #default="{ row }"><div class="stacked"><strong>{{ row.skill.name }}</strong><span>{{ row.skill.directory_name }}</span></div></template>
          </el-table-column>
          <el-table-column label="Agent" width="130"><template #default="{ row }">{{ row.agent.display_name }}</template></el-table-column>
          <el-table-column prop="skill.source_scope" label="来源" width="130" />
          <el-table-column label="风险" width="110"><template #default="{ row }"><el-tag :type="riskType(row.skill.risk)">{{ row.skill.risk }}</el-tag></template></el-table-column>
          <el-table-column label="发现" width="80" align="center"><template #default="{ row }">{{ row.skill.finding_count }}</template></el-table-column>
          <el-table-column prop="skill.frontmatter_state" label="Frontmatter" width="130" />
          <el-table-column label="操作" width="100" fixed="right"><template #default="{ row }"><el-button link type="primary" @click.stop="openSkill(row)">查看原文</el-button></template></el-table-column>
        </el-table>
        <el-pagination
          v-if="skillPagination.total > 0"
          class="skill-pagination"
          :current-page="skillPage"
          :page-size="skillPageSize"
          :page-sizes="[10, 20, 50]"
          layout="total, sizes, prev, pager, next, jumper"
          :total="skillPagination.total"
          @current-change="changeSkillPage"
          @size-change="changeSkillPageSize"
        />
      </el-card>
    </template>

    <el-drawer v-model="detailVisible" title="Skill 原文与检测证据" direction="rtl" size="min(1180px, 96vw)">
      <template v-if="selected">
        <el-descriptions :column="2" border>
          <el-descriptions-item label="主机">{{ selected.host.hostname || selected.host.id }}</el-descriptions-item>
          <el-descriptions-item label="主机 ID">{{ selected.host.id }}</el-descriptions-item>
          <el-descriptions-item label="名称">{{ selected.skill.name }}</el-descriptions-item>
          <el-descriptions-item label="Agent">{{ selected.agent.display_name }}</el-descriptions-item>
          <el-descriptions-item label="来源">{{ selected.skill.source_scope }}</el-descriptions-item>
          <el-descriptions-item label="路径">{{ selected.skill.skill_path }}</el-descriptions-item>
        </el-descriptions>
        <el-divider>原文与规则命中</el-divider>
        <div class="content-findings-layout">
          <section class="content-panel raw-panel">
            <div class="panel-heading"><strong>文件原文</strong><el-tag size="small" effect="plain">命中部分已标红</el-tag></div>
            <el-tabs v-model="activeFilePath" type="border-card">
              <el-tab-pane v-for="file in selected.skill.files" :key="file.relative_path" :label="file.relative_path" :name="file.relative_path">
                <el-alert v-if="file.content_status !== 'complete'" :title="`${file.content_status}: ${file.error || '内容不可用'}`" type="warning" :closable="false" />
                <pre v-else class="raw-content"><code><template v-for="(segment, index) in highlightSegments(file)" :key="`${file.relative_path}-${index}`"><span :class="{ 'hit-segment': segment.hit }" :title="segment.title">{{ segment.text }}</span></template></code></pre>
              </el-tab-pane>
            </el-tabs>
          </section>
          <section class="content-panel findings-panel">
            <div class="panel-heading"><strong>规则命中</strong><el-tag size="small" :type="selected.skill.findings?.length ? 'danger' : 'success'" effect="plain">{{ selected.skill.findings?.length || 0 }}</el-tag></div>
            <el-empty v-if="!selected.skill.findings?.length" description="未发现已知规则命中" />
            <el-collapse v-else>
              <el-collapse-item v-for="finding in selected.skill.findings" :key="`${finding.rule_key}-${finding.file_path}-${finding.start_byte}`" :name="`${finding.rule_key}-${finding.start_byte}`">
                <template #title><span class="finding-title">{{ finding.rule_key }} · {{ finding.severity }}</span></template>
                <p>{{ finding.reason }}</p>
                <div class="finding-meta">{{ finding.relative_path || finding.file_path }} · codepoint {{ finding.start_codepoint }}–{{ finding.end_codepoint }}</div>
                <pre class="evidence">{{ finding.evidence_excerpt }}</pre>
                <el-button link type="danger" @click="selectFinding(finding)">定位原文命中</el-button>
              </el-collapse-item>
            </el-collapse>
          </section>
        </div>
      </template>
    </el-drawer>

    <el-dialog v-model="rulesVisible" title="Agent Skill 内置安全规则" width="min(1000px, 94vw)">
      <el-table :data="rules" v-loading="rulesLoading" max-height="560">
        <el-table-column prop="rule_key" label="规则" width="180" />
        <el-table-column prop="name" label="名称" width="220" />
        <el-table-column prop="severity" label="级别" width="100" />
        <el-table-column prop="description" label="说明" min-width="300" />
      </el-table>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { listAgentGuardAgents } from '@/api/agentGuard'
import { listAgentSkillInventory, listAgentSkillRules, scanAgentSkills } from '@/api/agentSkill'
import type { AgentGuardAgentSummary } from '@/types/agentGuard'
import type { AgentSkill, AgentSkillAgent, AgentSkillFinding, AgentSkillRule, AgentSkillScanResult, AgentSkillFile, AgentSkillInventoryPage } from '@/types/agentSkill'
import { buildAgentSkillHighlightSegments } from './agentSkillPresentation'

interface SkillHostOption {
  id: string
  hostname: string
  ip: string
  online: boolean
  agentTypes: string[]
}

interface SkillRow {
  key: string
  host: SkillHostOption
  agent: AgentSkillAgent
  skill: AgentSkill
}

interface ScanError {
  stage: string
  message: string
}

const hosts = ref<SkillHostOption[]>([])
const selectedHostIds = ref<string[]>([])
const hostsLoading = ref(false)
const hostsError = ref(false)
const scanning = ref(false)
const hasScan = ref(false)
const scanningHostCount = ref(0)
const completedHostCount = ref(0)
const scanResults = ref<AgentSkillScanResult[]>([])
const scanErrors = ref<ScanError[]>([])
const inventoryPage = ref<AgentSkillInventoryPage | null>(null)
const inventoryLoading = ref(false)
const selected = ref<{ host: SkillHostOption; agent: AgentSkillAgent; skill: AgentSkill } | null>(null)
const activeFilePath = ref('')
const skillPage = ref(1)
const skillPageSize = ref(20)
const detailVisible = ref(false)
const rulesVisible = ref(false)
const rulesLoading = ref(false)
const rules = ref<AgentSkillRule[]>([])
const selectedHostStorageKey = 'aegis.agent-skill.selected-hosts'

const hostMap = computed(() => new Map(hosts.value.map(host => [host.id, host])))
const connectedHosts = computed(() => hosts.value.filter(host => host.online))
const selectedConnectedHostIds = computed(() => selectedHostIds.value.filter(id => hostMap.value.get(id)?.online))
const skillCount = computed(() => inventoryPage.value?.skill_count ?? scanResults.value.reduce((count, result) => count + result.skill_count, 0))
const findingCount = computed(() => inventoryPage.value?.finding_count ?? scanResults.value.reduce((count, result) => count + result.finding_count, 0))
const pageCount = computed(() => inventoryPage.value?.page_count ?? scanResults.value.reduce((count, result) => count + result.page_count, 0))
const latestScannedAt = computed(() => inventoryPage.value?.latest_scanned_at || scanResults.value.reduce((latest, result) => result.scanned_at > latest ? result.scanned_at : latest, ''))
const scanErrorsWithResult = computed<ScanError[]>(() => scanResults.value.flatMap(result => (result.errors || []).map(error => ({
  stage: `${hostLabel(hostMap.value.get(result.host_id) || fallbackHost(result.host_id))} · ${error.stage}`,
  message: error.message,
}))))
const allScanErrors = computed(() => [...scanErrors.value, ...scanErrorsWithResult.value])
const scanErrorsForDisplay = computed(() => allScanErrors.value)
const rows = computed<SkillRow[]>(() => {
  if (inventoryPage.value) {
    return inventoryPage.value.items.map(item => ({
      key: item.id,
      host: hostMap.value.get(item.host_id) || fallbackHost(item.host_id),
      agent: { ...item.agent, skills: [item.skill] },
      skill: item.skill,
    }))
  }
  return scanResults.value.flatMap(result => {
    const host = hostMap.value.get(result.host_id) || fallbackHost(result.host_id)
    return result.agents.flatMap(agent => agent.skills.map(skill => ({
      key: `${result.host_id}:${agent.agent_type}:${skill.skill_path}`,
      host,
      agent,
      skill,
    })))
  })
})
const skillPagination = computed(() => ({
  items: rows.value,
  total: inventoryPage.value?.total ?? rows.value.length,
}))

async function loadInventoryPage(page = skillPage.value, pageSize = skillPageSize.value) {
  inventoryLoading.value = true
  try {
    const result = await listAgentSkillInventory({ page, page_size: pageSize })
    inventoryPage.value = result
    skillPage.value = result.page || page
    skillPageSize.value = result.page_size || pageSize
    hasScan.value = result.host_count > 0 || result.total > 0
  } catch {
    // A scan can still be shown from its immediate response when an older
    // deployment has not applied the snapshot migration yet.
  } finally {
    inventoryLoading.value = false
  }
}

async function loadHosts() {
  hostsLoading.value = true
  hostsError.value = false
  try {
    const firstPage = await listAgentGuardAgents({ page: 1, page_size: 100 })
    const items: AgentGuardAgentSummary[] = [...(firstPage.items || [])]
    const total = Number(firstPage.total) || items.length
    for (let page = 2; items.length < total && page <= 20; page += 1) {
      const nextPage = await listAgentGuardAgents({ page, page_size: 100 })
      items.push(...(nextPage.items || []))
      if (!nextPage.items?.length) break
    }
    const unique = new Map<string, SkillHostOption>()
    for (const item of items) {
      const id = item.host?.id
      if (!id) continue
      const online = item.asset_status === 'running' || item.runtime_status === 'running' || item.running_instance_count > 0
      const current = unique.get(id)
      if (!current) {
        unique.set(id, {
          id,
          hostname: item.host.hostname || '',
          ip: item.host.ip || '',
          online,
          agentTypes: item.display_name ? [item.display_name] : [item.agent_type],
        })
        continue
      }
      current.online = current.online || online
      if (item.display_name && !current.agentTypes.includes(item.display_name)) current.agentTypes.push(item.display_name)
    }
    hosts.value = [...unique.values()].sort((left, right) => Number(right.online) - Number(left.online) || hostLabel(left).localeCompare(hostLabel(right)))
    selectedHostIds.value = selectedHostIds.value.filter(id => unique.has(id))
    if (!selectedHostIds.value.length) {
      try {
        const saved = JSON.parse(localStorage.getItem(selectedHostStorageKey) || '[]')
        if (Array.isArray(saved)) selectedHostIds.value = saved.filter((id): id is string => typeof id === 'string' && unique.has(id))
      } catch {
        // Ignore malformed browser state and keep the empty selection.
      }
    }
  } catch {
    hostsError.value = true
  } finally {
    hostsLoading.value = false
  }
}

async function scanSelected() {
  const ids = selectedConnectedHostIds.value
  if (!ids.length) {
    ElMessage.warning('请先选择至少一台在线主机')
    return
  }
  if (selectedHostIds.value.length !== ids.length) ElMessage.warning('已自动跳过离线主机')
  await scanHostIds(ids)
}

async function scanAll() {
  const ids = connectedHosts.value.map(host => host.id)
  if (!ids.length) {
    ElMessage.warning('暂无已连接主机')
    return
  }
  selectedHostIds.value = ids
  await scanHostIds(ids)
}

async function scanHostIds(ids: string[]) {
  const uniqueIds = [...new Set(ids)]
  scanning.value = true
  hasScan.value = true
  scanningHostCount.value = uniqueIds.length
  completedHostCount.value = 0
  scanResults.value = []
  scanErrors.value = []
  skillPage.value = 1
  const results: Array<AgentSkillScanResult | undefined> = new Array(uniqueIds.length)
  let cursor = 0
  const worker = async () => {
    while (cursor < uniqueIds.length) {
      const index = cursor
      cursor += 1
      const hostId = uniqueIds[index]
      try {
        results[index] = await scanAgentSkills(hostId)
      } catch (error) {
        scanErrors.value.push({ stage: `${hostLabel(hostMap.value.get(hostId) || fallbackHost(hostId))} 扫描`, message: errorMessage(error) })
      } finally {
        completedHostCount.value += 1
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(3, uniqueIds.length) }, () => worker()))
  scanResults.value = results.filter((result): result is AgentSkillScanResult => Boolean(result))
  scanning.value = false
  await loadInventoryPage(1, skillPageSize.value)
  if (!scanResults.value.length && scanErrors.value.length) ElMessage.error('所有主机扫描均失败')
}

function openSkill(row: SkillRow) {
  selected.value = row
  activeFilePath.value = (row.skill.files || [])[0]?.relative_path || ''
  detailVisible.value = true
}

function changeSkillPageSize(size: number) {
  skillPageSize.value = size
  skillPage.value = 1
  void loadInventoryPage(1, size)
}

function changeSkillPage(page: number) {
  skillPage.value = page
  void loadInventoryPage(page, skillPageSize.value)
}

function highlightSegments(file: AgentSkillFile) {
  const findings = (selected.value?.skill.findings || []).filter(finding => finding.relative_path === file.relative_path || finding.file_path === file.path)
  return buildAgentSkillHighlightSegments(file.content || '', findings)
}

function selectFinding(finding: AgentSkillFinding) {
  const path = finding.relative_path || selected.value?.skill.files.find(file => file.path === finding.file_path)?.relative_path
  if (path) activeFilePath.value = path
}

function hostLabel(host: SkillHostOption) {
  return `${host.hostname || host.id} (${host.ip || host.id})`
}

function fallbackHost(id: string): SkillHostOption {
  return { id, hostname: '', ip: '', online: false, agentTypes: [] }
}

function errorMessage(error: unknown) {
  return error instanceof Error && error.message ? error.message : '扫描请求失败'
}

function riskType(risk: string) {
  return risk === 'critical' ? 'danger' : risk === 'high' ? 'warning' : risk === 'medium' ? 'info' : 'success'
}

watch(rulesVisible, async visible => {
  if (!visible || rules.value.length) return
  rulesLoading.value = true
  try { rules.value = (await listAgentSkillRules()).items } finally { rulesLoading.value = false }
})

watch(selectedHostIds, value => {
  try { localStorage.setItem(selectedHostStorageKey, JSON.stringify(value)) } catch {
    // Browser storage can be disabled; server-side scan snapshots remain the source of truth.
  }
}, { deep: true })

onMounted(() => {
  void loadHosts()
  void loadInventoryPage()
})
</script>

<style scoped>
.scan-card { margin-top: 18px; }
.scan-actions { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
.host-select { width: min(520px, 42vw); }
.host-option { display: flex; align-items: center; justify-content: space-between; gap: 18px; width: 100%; }
.scan-progress { color: var(--el-color-primary); font-size: 13px; margin-top: 2px; }
.metric-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 16px; margin: 18px 0; }
.metric-card { padding: 18px; border-radius: 12px; background: var(--el-fill-color-light); display: flex; flex-direction: column; gap: 8px; }
.metric-card strong { font-size: 26px; }
.danger { color: var(--el-color-danger); }
.scan-error { margin: 8px 0; }
.table-header { display: flex; justify-content: space-between; align-items: center; }
.skill-pagination { justify-content: flex-end; margin-top: 18px; }
.stacked { display: flex; flex-direction: column; gap: 4px; }
.stacked span { color: var(--el-text-color-secondary); font-size: 12px; }
.content-findings-layout { display: grid; grid-template-columns: minmax(0, 1.35fr) minmax(320px, .85fr); gap: 18px; align-items: start; }
.content-panel { min-width: 0; border: 1px solid var(--el-border-color-light); border-radius: 10px; padding: 14px; background: var(--el-bg-color); }
.panel-heading { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 12px; }
.raw-content, .evidence { white-space: pre-wrap; word-break: break-word; max-height: 55vh; overflow: auto; padding: 14px; background: #111827; color: #e5e7eb; border-radius: 8px; font: 12px/1.6 ui-monospace, SFMono-Regular, Consolas, monospace; }
.raw-content code { font: inherit; }
.hit-segment { color: #fecaca; background: rgba(220, 38, 38, .42); text-decoration: underline wavy #f87171; text-decoration-thickness: 1px; }
.finding-title { color: var(--el-color-danger); font-weight: 600; }
.finding-meta { margin: 8px 0; color: var(--el-text-color-secondary); font-size: 12px; word-break: break-all; }
.findings-panel { max-height: 70vh; overflow: auto; }
@media (max-width: 1100px) { .host-select { width: min(420px, 38vw); } .content-findings-layout { grid-template-columns: 1fr; } .findings-panel { max-height: none; } }
@media (max-width: 800px) { .metric-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); } .host-select { width: 100%; } .scan-actions { width: 100%; } }
</style>
