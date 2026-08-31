-- V6.4 Agent Skill inventory, revision and prompt-security evidence.
-- Raw Skill bytes remain in the encrypted content object store; PostgreSQL
-- keeps digests, provenance, state and bounded evidence only.

CREATE TABLE IF NOT EXISTS agent_skill_scan_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    requested_by VARCHAR(100),
    trigger_type VARCHAR(24) NOT NULL DEFAULT 'manual',
    agent_types JSONB NOT NULL DEFAULT '["codex","claude-code","openclaw"]'::jsonb,
    scope_filter JSONB NOT NULL DEFAULT '{}'::jsonb,
    content_mode VARCHAR(24) NOT NULL DEFAULT 'full_content',
    policy_version BIGINT NOT NULL DEFAULT 1,
    active_scope_digest VARCHAR(80) NOT NULL,
    status VARCHAR(24) NOT NULL DEFAULT 'queued',
    collection_coverage VARCHAR(32) NOT NULL DEFAULT 'unknown',
    current_cursor_encrypted BYTEA,
    current_page_index BIGINT NOT NULL DEFAULT 0,
    previous_page_digest VARCHAR(80),
    page_count BIGINT NOT NULL DEFAULT 0,
    skill_count BIGINT NOT NULL DEFAULT 0,
    revision_count BIGINT NOT NULL DEFAULT 0,
    finding_count BIGINT NOT NULL DEFAULT 0,
    bytes_received BIGINT NOT NULL DEFAULT 0,
    lease_owner VARCHAR(100),
    lease_expires_at TIMESTAMPTZ,
    attempt INT NOT NULL DEFAULT 0,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    error_code VARCHAR(100),
    error_message_safe TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_agent_skill_scan_jobs_host_status ON agent_skill_scan_jobs(host_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_skill_scan_jobs_lease ON agent_skill_scan_jobs(status, lease_expires_at);

CREATE TABLE IF NOT EXISTS agent_skill_scan_pages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES agent_skill_scan_jobs(id) ON DELETE CASCADE,
    page_index BIGINT NOT NULL,
    page_digest VARCHAR(80) NOT NULL,
    previous_page_digest VARCHAR(80),
    request_cursor_digest VARCHAR(80),
    next_cursor_encrypted BYTEA,
    payload_size BIGINT NOT NULL DEFAULT 0,
    skill_fragment_count INT NOT NULL DEFAULT 0,
    status VARCHAR(24) NOT NULL DEFAULT 'received',
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    error_code VARCHAR(100),
    UNIQUE(scan_id, page_index),
    UNIQUE(scan_id, page_digest)
);

CREATE TABLE IF NOT EXISTS agent_skill_scan_coverage (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES agent_skill_scan_jobs(id) ON DELETE CASCADE,
    agent_type VARCHAR(32) NOT NULL,
    scope VARCHAR(32),
    root TEXT,
    status VARCHAR(32) NOT NULL,
    reason_code VARCHAR(64),
    discovered_count BIGINT NOT NULL DEFAULT 0,
    collected_count BIGINT NOT NULL DEFAULT 0,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(scan_id, agent_type, scope, root)
);

CREATE TABLE IF NOT EXISTS agent_skills (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    subject_uid BIGINT NOT NULL,
    agent_type VARCHAR(32) NOT NULL CHECK (agent_type IN ('codex','claude-code','openclaw')),
    declared_name TEXT,
    directory_name TEXT NOT NULL,
    qualified_name TEXT,
    disappeared_at TIMESTAMPTZ,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(host_id, subject_uid, agent_type, directory_name)
);

CREATE TABLE IF NOT EXISTS agent_skill_revisions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    skill_id UUID NOT NULL REFERENCES agent_skills(id) ON DELETE CASCADE,
    revision_digest VARCHAR(80) NOT NULL,
    manifest_digest VARCHAR(80),
    source_scope VARCHAR(32) NOT NULL,
    source_root TEXT NOT NULL,
    absolute_skill_path TEXT NOT NULL,
    precedence INT NOT NULL DEFAULT 0,
    effective_state VARCHAR(24) NOT NULL DEFAULT 'unknown',
    eligible_state VARCHAR(24) NOT NULL DEFAULT 'unknown',
    frontmatter_parse_status VARCHAR(32) NOT NULL DEFAULT 'unknown',
    frontmatter_keys JSONB NOT NULL DEFAULT '[]'::jsonb,
    description TEXT,
    content_object_ref TEXT,
    content_object_digest VARCHAR(80),
    content_object_size BIGINT,
    content_key_version VARCHAR(64),
    extraction_status VARCHAR(32) NOT NULL DEFAULT 'complete',
    file_count BIGINT NOT NULL DEFAULT 0,
    content_bytes BIGINT NOT NULL DEFAULT 0,
    normalized_capabilities JSONB NOT NULL DEFAULT '{}'::jsonb,
    rule_status VARCHAR(24) NOT NULL DEFAULT 'pending',
    ai_status VARCHAR(24) NOT NULL DEFAULT 'not_requested',
    deterministic_risk VARCHAR(16) NOT NULL DEFAULT 'unknown',
    ai_risk VARCHAR(16) NOT NULL DEFAULT 'unknown',
    overall_risk VARCHAR(16) NOT NULL DEFAULT 'unknown',
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(skill_id, revision_digest)
);
CREATE INDEX IF NOT EXISTS idx_agent_skill_revisions_risk ON agent_skill_revisions(overall_risk, last_seen_at DESC);

CREATE TABLE IF NOT EXISTS agent_skill_revision_files (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    revision_id UUID NOT NULL REFERENCES agent_skill_revisions(id) ON DELETE CASCADE,
    file_key VARCHAR(128) NOT NULL,
    absolute_path TEXT NOT NULL,
    relative_path TEXT NOT NULL,
    path_digest VARCHAR(80) NOT NULL,
    kind VARCHAR(32) NOT NULL,
    language VARCHAR(32),
    encoding VARCHAR(32),
    size BIGINT NOT NULL DEFAULT 0,
    mode VARCHAR(16),
    owner_uid BIGINT,
    owner_gid BIGINT,
    executable BOOLEAN NOT NULL DEFAULT false,
    symlink_state VARCHAR(32) NOT NULL DEFAULT 'none',
    content_status VARCHAR(32) NOT NULL DEFAULT 'metadata_only',
    content_digest VARCHAR(80),
    object_offset BIGINT,
    object_length BIGINT,
    capability_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(revision_id, file_key),
    UNIQUE(revision_id, path_digest)
);

CREATE TABLE IF NOT EXISTS agent_skill_reference_edges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    revision_id UUID NOT NULL REFERENCES agent_skill_revisions(id) ON DELETE CASCADE,
    from_file_id UUID NOT NULL REFERENCES agent_skill_revision_files(id) ON DELETE CASCADE,
    to_file_id UUID REFERENCES agent_skill_revision_files(id) ON DELETE SET NULL,
    raw_target TEXT NOT NULL,
    edge_type VARCHAR(32) NOT NULL,
    depth INT NOT NULL DEFAULT 0,
    status VARCHAR(32) NOT NULL DEFAULT 'unresolved',
    target_digest VARCHAR(80),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(revision_id, from_file_id, raw_target, edge_type)
);

CREATE TABLE IF NOT EXISTS agent_skill_baselines (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    skill_id UUID NOT NULL REFERENCES agent_skills(id) ON DELETE CASCADE,
    revision_id UUID NOT NULL REFERENCES agent_skill_revisions(id) ON DELETE RESTRICT,
    source VARCHAR(32) NOT NULL,
    status VARCHAR(24) NOT NULL DEFAULT 'active',
    reason TEXT,
    created_by VARCHAR(100) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    superseded_at TIMESTAMPTZ,
    UNIQUE(skill_id, revision_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_skill_active_baseline ON agent_skill_baselines(skill_id) WHERE status = 'active';

CREATE TABLE IF NOT EXISTS agent_skill_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    revision_id UUID NOT NULL REFERENCES agent_skill_revisions(id) ON DELETE CASCADE,
    source VARCHAR(16) NOT NULL DEFAULT 'rule',
    rule_key VARCHAR(128) NOT NULL,
    rule_version BIGINT NOT NULL DEFAULT 1,
    category VARCHAR(64) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    confidence NUMERIC(5,4) NOT NULL DEFAULT 1,
    context VARCHAR(24),
    polarity VARCHAR(24),
    actionability VARCHAR(24),
    target VARCHAR(32),
    file_id UUID REFERENCES agent_skill_revision_files(id) ON DELETE SET NULL,
    span_id VARCHAR(128),
    start_byte BIGINT,
    end_byte BIGINT,
    start_codepoint BIGINT,
    end_codepoint BIGINT,
    evidence_excerpt TEXT,
    runtime_stage VARCHAR(32) NOT NULL DEFAULT 'capability_only',
    status VARCHAR(24) NOT NULL DEFAULT 'open',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(revision_id, rule_key, file_id, start_byte)
);
CREATE INDEX IF NOT EXISTS idx_agent_skill_findings_open ON agent_skill_findings(status, severity, created_at DESC);

CREATE TABLE IF NOT EXISTS agent_skill_scan_observations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES agent_skill_scan_jobs(id) ON DELETE CASCADE,
    skill_id UUID NOT NULL REFERENCES agent_skills(id) ON DELETE CASCADE,
    revision_id UUID NOT NULL REFERENCES agent_skill_revisions(id) ON DELETE RESTRICT,
    effective_state VARCHAR(24) NOT NULL,
    eligible_state VARCHAR(24) NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    observation_digest VARCHAR(80) NOT NULL,
    UNIQUE(scan_id, skill_id, revision_id)
);

CREATE TABLE IF NOT EXISTS agent_skill_rule_definitions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_key VARCHAR(128) NOT NULL,
    version BIGINT NOT NULL,
    name VARCHAR(255) NOT NULL,
    category VARCHAR(64) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    definition JSONB NOT NULL DEFAULT '{}'::jsonb,
    digest VARCHAR(80) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(rule_key, version)
);

INSERT INTO agent_skill_rule_definitions (rule_key, version, name, category, severity, definition, digest)
VALUES
 ('ASK-PROMPT-001', 1, '覆盖高优先级指令', 'prompt_injection', 'high', '{"engine":"agent_skill_static"}', 'builtin:ask-prompt-001-v1'),
 ('ASK-PROMPT-003', 1, '安全与审批绕过', 'approval_bypass', 'critical', '{"engine":"agent_skill_static"}', 'builtin:ask-prompt-003-v1'),
 ('ASK-PROMPT-004', 1, '越狱与限制移除', 'jailbreak', 'high', '{"engine":"agent_skill_static"}', 'builtin:ask-prompt-004-v1'),
 ('ASK-PROMPT-009', 1, '防御与审计规避', 'defense_evasion', 'critical', '{"engine":"agent_skill_static"}', 'builtin:ask-prompt-009-v1'),
 ('ASK-EXEC-002', 1, '下载后执行', 'download_execute', 'critical', '{"engine":"agent_skill_static"}', 'builtin:ask-exec-002-v1')
ON CONFLICT (rule_key, version) DO NOTHING;
