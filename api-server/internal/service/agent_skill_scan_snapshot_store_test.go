package service

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestAgentSkillScanSnapshotStorePersistsAndPagesLatestSnapshot(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:agent-skill-snapshot-test?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&agentSkillScanSnapshotRow{}); err != nil {
		t.Fatal(err)
	}
	store := NewAgentSkillScanSnapshotStore(db)
	hostID := uuid.NewString()
	scan := &AgentSkillScanResult{
		HostID: hostID, ScannedAt: time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC),
		SkillCount: 2, FindingCount: 1, PageCount: 1,
		Agents: []AgentSkillResultAgent{{AgentType: "codex", DisplayName: "Codex", Skills: []AgentSkillResultSkill{
			{Name: "one", SkillPath: "/skills/one", Files: []AgentSkillResultFile{{RelativePath: "SKILL.md", Content: "safe"}}},
			{Name: "two", SkillPath: "/skills/two", Files: []AgentSkillResultFile{{RelativePath: "SKILL.md", Content: "unsafe"}}},
		}}},
	}
	if err := store.SaveScan(context.Background(), scan); err != nil {
		t.Fatal(err)
	}
	page, err := store.ListInventory(context.Background(), AgentSkillInventoryQuery{Page: 2, PageSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 2 || page.HostCount != 1 || len(page.Items) != 1 || page.Items[0].Skill.Name != "two" {
		t.Fatalf("unexpected persisted page: %+v", page)
	}

	// A second scan replaces the host's latest snapshot instead of duplicating
	// rows, which is what makes refresh deterministic.
	scan.Agents[0].Skills = scan.Agents[0].Skills[:1]
	scan.SkillCount = 1
	if err := store.SaveScan(context.Background(), scan); err != nil {
		t.Fatal(err)
	}
	page, err = store.ListInventory(context.Background(), AgentSkillInventoryQuery{Page: 1, PageSize: 20})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 || page.Items[0].Skill.Name != "one" {
		t.Fatalf("latest snapshot was not replaced: %+v", page)
	}
}
