-- V6.4 durable latest Agent Skill scan snapshots.
-- The snapshot keeps the complete, non-redacted scan response so the UI can
-- restore the original content and findings after a browser refresh. The
-- row is replaced atomically per host; the normalized V6.4 tables remain the
-- source for future history/analytics queries.
CREATE TABLE IF NOT EXISTS agent_skill_scan_snapshots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    scanned_at TIMESTAMPTZ NOT NULL,
    payload JSONB NOT NULL,
    skill_count BIGINT NOT NULL DEFAULT 0,
    finding_count BIGINT NOT NULL DEFAULT 0,
    page_count BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(host_id)
);
CREATE INDEX IF NOT EXISTS idx_agent_skill_scan_snapshots_scanned_at
    ON agent_skill_scan_snapshots(scanned_at DESC);
