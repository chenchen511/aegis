package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// AgentSkillScanSnapshotStore stores the latest complete scan per host.
// Keeping one immutable JSON snapshot per host makes restoration lossless
// (including original file content and findings) while the API still exposes
// a bounded, server-side page of Skills.
type AgentSkillScanSnapshotStore struct {
	db *gorm.DB
}

type agentSkillScanSnapshotRow struct {
	ID           uuid.UUID      `gorm:"type:uuid;primaryKey"`
	HostID       uuid.UUID      `gorm:"type:uuid;not null;uniqueIndex"`
	ScannedAt    time.Time      `gorm:"column:scanned_at"`
	Payload      datatypes.JSON `gorm:"type:jsonb;not null"`
	SkillCount   int64          `gorm:"column:skill_count"`
	FindingCount int64          `gorm:"column:finding_count"`
	PageCount    int64          `gorm:"column:page_count"`
	CreatedAt    time.Time      `gorm:"column:created_at"`
	UpdatedAt    time.Time      `gorm:"column:updated_at"`
}

func (agentSkillScanSnapshotRow) TableName() string { return "agent_skill_scan_snapshots" }

func NewAgentSkillScanSnapshotStore(db *gorm.DB) *AgentSkillScanSnapshotStore {
	return &AgentSkillScanSnapshotStore{db: db}
}

func (r *AgentSkillScanSnapshotStore) SaveScan(ctx context.Context, result *AgentSkillScanResult) error {
	if r == nil || r.db == nil {
		return errors.New("agent skill snapshot store is unavailable")
	}
	if result == nil {
		return errors.New("agent skill scan result is nil")
	}
	hostID, err := uuid.Parse(strings.TrimSpace(result.HostID))
	if err != nil {
		return fmt.Errorf("host_id must be a UUID: %w", err)
	}
	payload, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("marshal agent skill scan snapshot: %w", err)
	}
	// PostgreSQL's ON CONFLICT keeps refreshes idempotent and ensures the UI
	// always restores the most recent completed scan for each host.
	payloadPlaceholder := "?::jsonb"
	timestampExpression := "now()"
	if r.db.Dialector.Name() != "postgres" {
		payloadPlaceholder = "?"
		timestampExpression = "CURRENT_TIMESTAMP"
	}
	statement := fmt.Sprintf(`
		INSERT INTO agent_skill_scan_snapshots
			(host_id, scanned_at, payload, skill_count, finding_count, page_count, created_at, updated_at)
		VALUES (?, ?, %s, ?, ?, ?, %s, %s)
		ON CONFLICT (host_id) DO UPDATE SET
			scanned_at = EXCLUDED.scanned_at,
			payload = EXCLUDED.payload,
			skill_count = EXCLUDED.skill_count,
			finding_count = EXCLUDED.finding_count,
			page_count = EXCLUDED.page_count,
			updated_at = %s
	`, payloadPlaceholder, timestampExpression, timestampExpression, timestampExpression)
	err = r.db.WithContext(ctx).Exec(statement, hostID, result.ScannedAt, string(payload), result.SkillCount, result.FindingCount, result.PageCount).Error
	if err != nil {
		return fmt.Errorf("save agent skill scan snapshot: %w", err)
	}
	return nil
}

func (r *AgentSkillScanSnapshotStore) ListInventory(ctx context.Context, query AgentSkillInventoryQuery) (*AgentSkillInventoryPage, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("agent skill snapshot store is unavailable")
	}
	page, pageSize := normalizeAgentSkillInventoryPage(query.Page, query.PageSize)
	var rows []agentSkillScanSnapshotRow
	db := r.db.WithContext(ctx).Model(&agentSkillScanSnapshotRow{}).Order("scanned_at DESC, host_id ASC")
	if len(query.HostIDs) > 0 {
		hostIDs := make([]uuid.UUID, 0, len(query.HostIDs))
		for _, raw := range query.HostIDs {
			id, err := uuid.Parse(strings.TrimSpace(raw))
			if err != nil {
				return nil, fmt.Errorf("host_id must be a UUID: %w", err)
			}
			hostIDs = append(hostIDs, id)
		}
		db = db.Where("host_id IN ?", hostIDs)
	}
	if err := db.Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("list agent skill scan snapshots: %w", err)
	}

	result := &AgentSkillInventoryPage{
		Items: make([]AgentSkillInventoryItem, 0),
		Page:  page, PageSize: pageSize,
		Errors: make([]AgentSkillScanError, 0),
	}
	allItems := make([]AgentSkillInventoryItem, 0)
	seenHosts := make(map[string]struct{}, len(rows))
	for _, row := range rows {
		var scan AgentSkillScanResult
		if err := json.Unmarshal(row.Payload, &scan); err != nil {
			return nil, fmt.Errorf("decode agent skill snapshot %s: %w", row.ID, err)
		}
		hostID := row.HostID.String()
		seenHosts[hostID] = struct{}{}
		if scan.HostID == "" {
			scan.HostID = hostID
		}
		if scan.ScannedAt.IsZero() {
			// The payload is authoritative, but retain a valid timestamp if an
			// older snapshot was written without one.
			scan.ScannedAt = row.ScannedAt
		}
		if result.LatestScannedAt == nil || scan.ScannedAt.After(*result.LatestScannedAt) {
			scannedAt := scan.ScannedAt
			result.LatestScannedAt = &scannedAt
		}
		result.SkillCount += scan.SkillCount
		result.FindingCount += scan.FindingCount
		result.PageCount += scan.PageCount
		result.Errors = append(result.Errors, scan.Errors...)
		for _, agent := range scan.Agents {
			for _, skill := range agent.Skills {
				allItems = append(allItems, AgentSkillInventoryItem{
					ID:        hostID + ":" + agent.AgentType + ":" + skill.SkillPath,
					HostID:    hostID,
					ScannedAt: scan.ScannedAt,
					Agent:     AgentSkillResultAgent{AgentType: agent.AgentType, DisplayName: agent.DisplayName},
					Skill:     skill,
				})
			}
		}
	}
	// Stable order is important when the user moves between pages while a
	// different host finishes scanning.
	sort.SliceStable(allItems, func(i, j int) bool {
		if allItems[i].HostID != allItems[j].HostID {
			return allItems[i].HostID < allItems[j].HostID
		}
		if allItems[i].Agent.AgentType != allItems[j].Agent.AgentType {
			return allItems[i].Agent.AgentType < allItems[j].Agent.AgentType
		}
		return allItems[i].Skill.SkillPath < allItems[j].Skill.SkillPath
	})
	result.Total = len(allItems)
	result.HostCount = len(seenHosts)
	start := (page - 1) * pageSize
	if start < result.Total {
		end := start + pageSize
		if end > result.Total {
			end = result.Total
		}
		result.Items = allItems[start:end]
	}
	return result, nil
}

func normalizeAgentSkillInventoryPage(page, pageSize int) (int, int) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}
	return page, pageSize
}
