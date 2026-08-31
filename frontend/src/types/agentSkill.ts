export interface AgentSkillFinding {
  rule_key: string
  rule_version: number
  severity: string
  category: string
  file_path: string
  relative_path: string
  start_byte: number
  end_byte: number
  start_codepoint: number
  end_codepoint: number
  evidence_excerpt: string
  context: string
  polarity: string
  actionability: string
  target: string
  reason: string
  confidence: number
}

export interface AgentSkillFile {
  path: string
  relative_path: string
  kind: string
  encoding?: string
  size: number
  mode?: string
  owner_uid?: number
  owner_gid?: number
  executable: boolean
  symlink_state: string
  content_status: string
  content_digest?: string
  content?: string
  error?: string
  binary: boolean
  modified_at?: string
}

export interface AgentSkill {
  name: string
  directory_name: string
  qualified_name: string
  agent_type: string
  source_scope: string
  source_root: string
  skill_path: string
  relative_path: string
  directory_mode?: string
  owner_uid?: number
  owner_gid?: number
  precedence: number
  effective_state: string
  eligible: string
  frontmatter_state: string
  frontmatter_keys?: string[]
  files: AgentSkillFile[]
  finding_count: number
  risk: string
  findings?: AgentSkillFinding[]
}

export interface AgentSkillAgent {
  agent_type: string
  display_name: string
  skills: AgentSkill[]
}

export interface AgentSkillScanResult {
  schema: string
  host_id: string
  scanned_at: string
  agents: AgentSkillAgent[]
  errors: Array<{ stage: string; message: string }>
  skill_count: number
  finding_count: number
  page_count: number
}

export interface AgentSkillInventoryItem {
  id: string
  host_id: string
  scanned_at: string
  agent: {
    agent_type: string
    display_name: string
  }
  skill: AgentSkill
}

export interface AgentSkillInventoryPage {
  items: AgentSkillInventoryItem[]
  total: number
  page: number
  page_size: number
  host_count: number
  skill_count: number
  finding_count: number
  page_count: number
  latest_scanned_at?: string
  errors?: Array<{ stage: string; message: string }>
}

export interface AgentSkillRule {
  rule_key: string
  rule_version: number
  name: string
  category: string
  severity: string
  description: string
  source: string
  engine: string
  default_enabled: boolean
  default_action: string
  recommended_action: string
  immutable: boolean
  digest: string
  categories: string[]
}
