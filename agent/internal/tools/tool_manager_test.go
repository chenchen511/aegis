package tools

import (
	"testing"
)

func TestToolManager_QueryHistoricalLogs(t *testing.T) {
	m := NewToolManager()

	// Test with valid time range parameters
	params := map[string]interface{}{
		"start_time": "2026-04-01T00:00:00Z",
		"end_time":   "2026-04-22T23:59:59Z",
		"filter":     "ssh",
	}

	result, err := m.Execute("QueryHistoricalLogs", params)
	if err != nil {
		t.Errorf("QueryHistoricalLogs returned error: %v", err)
		return
	}

	if result == nil {
		t.Error("QueryHistoricalLogs returned nil result")
		return
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Error("QueryHistoricalLogs result is not a map")
		return
	}

	if _, ok := resultMap["logs"]; !ok {
		t.Error("QueryHistoricalLogs result missing 'logs' field")
	}

	if _, ok := resultMap["count"]; !ok {
		t.Error("QueryHistoricalLogs result missing 'count' field")
	}

	t.Logf("QueryHistoricalLogs result: %+v", resultMap)
}

func TestToolManager_UnknownTool(t *testing.T) {
	m := NewToolManager()

	params := map[string]interface{}{}
	_, err := m.Execute("NonExistentTool", params)
	if err == nil {
		t.Error("Expected error for unknown tool, got nil")
		return
	}

	expectedErr := "unknown tool: NonExistentTool"
	if err.Error() != expectedErr {
		t.Errorf("Expected error '%s', got '%s'", expectedErr, err.Error())
	}
}

func TestToolManager_GetProcessTree(t *testing.T) {
	m := NewToolManager()

	params := map[string]interface{}{
		"pid": float64(1), // systemd process
	}

	result, err := m.Execute("GetProcessTree", params)
	if err != nil {
		t.Errorf("GetProcessTree returned error: %v", err)
		return
	}

	if result == nil {
		t.Error("GetProcessTree returned nil result")
		return
	}

	t.Logf("GetProcessTree result: %+v", result)
}

func TestToolManager_GetProcessTreeDefaultsToRootPID(t *testing.T) {
	m := NewToolManager()

	result, err := m.Execute("GetProcessTree", map[string]interface{}{})
	if err != nil {
		t.Errorf("GetProcessTree without pid returned error: %v", err)
		return
	}

	tree, ok := result.(*ProcessTree)
	if !ok {
		t.Fatalf("GetProcessTree result = %T, want *ProcessTree", result)
	}
	if tree.PID != 1 {
		t.Fatalf("GetProcessTree default PID = %d, want 1", tree.PID)
	}
}

func TestToolManager_GetNetworkConnections(t *testing.T) {
	m := NewToolManager()

	params := map[string]interface{}{
		"pid": float64(1),
	}

	result, err := m.Execute("GetNetworkConnections", params)
	if err != nil {
		t.Errorf("GetNetworkConnections returned error: %v", err)
		return
	}

	if result == nil {
		t.Error("GetNetworkConnections returned nil result")
		return
	}

	t.Logf("GetNetworkConnections result: %+v", result)
}

func TestToolManager_GetNetworkConnectionsAllowsMissingPID(t *testing.T) {
	m := NewToolManager()

	result, err := m.Execute("GetNetworkConnections", map[string]interface{}{})
	if err != nil {
		t.Errorf("GetNetworkConnections without pid returned error: %v", err)
		return
	}

	connections, ok := result.(*NetworkConnections)
	if !ok {
		t.Fatalf("GetNetworkConnections result = %T, want *NetworkConnections", result)
	}
	if connections.PID != 0 {
		t.Fatalf("GetNetworkConnections default PID = %d, want 0", connections.PID)
	}
}

func TestToolManager_AcceptsNumericStringPID(t *testing.T) {
	m := NewToolManager()

	result, err := m.Execute("GetNetworkConnections", map[string]interface{}{"pid": "1"})
	if err != nil {
		t.Errorf("GetNetworkConnections with string pid returned error: %v", err)
		return
	}

	connections, ok := result.(*NetworkConnections)
	if !ok {
		t.Fatalf("GetNetworkConnections result = %T, want *NetworkConnections", result)
	}
	if connections.PID != 1 {
		t.Fatalf("GetNetworkConnections PID = %d, want 1", connections.PID)
	}
}

func TestToolManagerAgentSkillScanValidatesPagingArguments(t *testing.T) {
	m := NewToolManager()
	if _, err := m.Execute("AgentSkillScan", map[string]interface{}{}); err == nil {
		t.Fatal("expected missing skill host id")
	}
	if _, err := m.Execute("AgentSkillScan", map[string]interface{}{"host_id": "host-1", "path": "/etc"}); err == nil {
		t.Fatal("expected arbitrary path to be rejected")
	}
	if _, err := m.Execute("AgentSkillScan", map[string]interface{}{"host_id": "host-1", "limit": 0}); err == nil {
		t.Fatal("expected invalid skill page limit")
	}
	if _, err := m.Execute("AgentSkillScan", map[string]interface{}{"host_id": "host-1", "offset": -1}); err == nil {
		t.Fatal("expected invalid skill page offset")
	}
}
