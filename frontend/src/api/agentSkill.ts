import request from './index'
import type { AgentSkillInventoryPage, AgentSkillRule, AgentSkillScanResult } from '@/types/agentSkill'

export function scanAgentSkills(hostId: string): Promise<AgentSkillScanResult> {
  return request.get('/agent-guard/skills', { params: { host_id: hostId } })
}

export function listAgentSkillInventory(params: {
  host_ids?: string[]
  page?: number
  page_size?: number
} = {}): Promise<AgentSkillInventoryPage> {
  return request.get('/agent-guard/skills/inventory', {
    params: { page: 1, page_size: 20, ...params },
    paramsSerializer: { indexes: null },
  })
}

export function listAgentSkillRules(params: { page?: number; page_size?: number; keyword?: string } = {}): Promise<{ items: AgentSkillRule[]; total: number }> {
  return request.get('/agent-guard/skill-rules', { params: { page: 1, page_size: 100, ...params } })
}
