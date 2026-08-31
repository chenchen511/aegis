package handler

import (
	"context"
	"net/http"
	"testing"

	"api-server/internal/service"
	"github.com/gin-gonic/gin"
)

type fakeAgentSkillInventoryReader struct {
	page  *service.AgentSkillInventoryPage
	query service.AgentSkillInventoryQuery
}

func (f *fakeAgentSkillInventoryReader) ListInventory(_ context.Context, query service.AgentSkillInventoryQuery) (*service.AgentSkillInventoryPage, error) {
	f.query = query
	return f.page, nil
}

type fakeAgentSkillScanner struct{}

func (fakeAgentSkillScanner) Scan(context.Context, string) (*service.AgentSkillScanResult, error) {
	return &service.AgentSkillScanResult{}, nil
}

func TestAgentSkillInventoryRouteUsesServerPagination(t *testing.T) {
	gin.SetMode(gin.TestMode)
	reader := &fakeAgentSkillInventoryReader{page: &service.AgentSkillInventoryPage{Page: 2, PageSize: 10, Total: 21}}
	handler := NewAgentGuardHandler(
		fakeAgentGuardCatalog{}, fakeAgentGuardPolicies{}, &fakeAgentGuardQuery{}, nil, nil, nil,
	)
	handler.SetSkillScanner(fakeAgentSkillScanner{})
	handler.SetSkillInventoryReader(reader)
	engine := gin.New()
	pass := func(c *gin.Context) { c.Next() }
	handler.RegisterRoutes(engine.Group("/api/v1"), pass, pass, pass, pass, pass, pass, pass, pass, pass, pass)

	response := serveAgentGuardRequest(engine, http.MethodGet, "/api/v1/agent-guard/skills/inventory?page=2&page_size=10", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", response.Code, response.Body.String())
	}
	if reader.query.Page != 2 || reader.query.PageSize != 10 {
		t.Fatalf("expected repository pagination, got %+v", reader.query)
	}
}
