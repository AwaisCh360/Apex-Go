package agents_graph

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/AwaisCh360/Apex/apex/skills"
	"github.com/google/uuid"
)

// AllStatuses must be kept in sync with the Status constants in core/agents.go
// and the equivalent Python Status type.
var AllStatuses = []string{
	"running", "waiting", "completed", "crashed", "stopped", "failed", "budget_paused",
}

var logger = log.New(os.Stderr, "[agents_graph] ", log.LstdFlags)

var ActiveStatuses = map[string]bool{
	"running": true,
	"waiting": true,
}

// RunContextWrapper stub to preserve public interface
type RunContextWrapper struct {
	Context   map[string]interface{}
	TurnInput []interface{}
}

// Coordinator interface stub for local dependencies
type Coordinator interface {
	GraphSnapshot() (parentOf map[string]*string, statuses map[string]string, names map[string]string, other interface{}, err error)
	Send(targetAgentID string, message map[string]interface{}) (bool, error)
	ConsumePending(agentID string, includeItems bool) (int, []interface{}, error)
	MarkRunning(agentID string) error
	ParkWaiting(agentID string, waitKind string) error
	WaitForMessage(ctx context.Context, agentID string) error
	GetStatus(agentID string) (string, error)
	ClaimParentNotice(agentID string) (bool, error)
	SetStatus(agentID string, status string) error
	CancelDescendantsGraceful(targetAgentID string) ([]string, error)
	RequestStop(agentID string) error
	GetParentOf(agentID string) *string
	GetName(agentID string) string
}

func coordinatorFromContext(inner map[string]interface{}) Coordinator {
	if c, ok := inner["coordinator"].(Coordinator); ok {
		return c
	}
	return nil
}

func notifyParentOnTerminal(coordinator Coordinator, agentID string, status string) error {
	if n, ok := coordinator.(interface {
		NotifyParentOnTerminal(agentID string, status string) error
	}); ok {
		return n.NotifyParentOnTerminal(agentID, status)
	}
	return nil
}

func validateRequestedSkills(skillsList []string) string {
	return skills.ValidateRequestedSkills(skillsList, 5)
}

func _ctx(ctx RunContextWrapper) map[string]interface{} {
	if ctx.Context != nil {
		return ctx.Context
	}
	return make(map[string]interface{})
}

func renderCompletionReport(agentName, agentID, task string, success bool, resultSummary string, findings, recommendations []string) string {
	status := "FAILED"
	if success {
		status = "SUCCESS"
	}
	completionTime := time.Now().UTC().Format(time.RFC3339)

	var lines []string
	lines = append(lines, fmt.Sprintf("== Completion report from %s (%s) ==", agentName, agentID))
	lines = append(lines, fmt.Sprintf("Status: %s", status))
	lines = append(lines, fmt.Sprintf("Time: %s", completionTime))
	if task != "" {
		lines = append(lines, fmt.Sprintf("Task: %s", task))
	}
	lines = append(lines, "")
	lines = append(lines, "Summary:")
	if resultSummary != "" {
		lines = append(lines, resultSummary)
	} else {
		lines = append(lines, "(none)")
	}

	if len(findings) > 0 {
		lines = append(lines, "")
		lines = append(lines, "Findings:")
		for _, f := range findings {
			lines = append(lines, fmt.Sprintf("- %s", f))
		}
	}

	if len(recommendations) > 0 {
		lines = append(lines, "")
		lines = append(lines, "Recommendations:")
		for _, r := range recommendations {
			lines = append(lines, fmt.Sprintf("- %s", r))
		}
	}
	return strings.Join(lines, "\n")
}

func ViewAgentGraph(ctx context.Context, runCtx RunContextWrapper) (string, error) {
	inner := _ctx(runCtx)
	coordinator := coordinatorFromContext(inner)
	me, _ := inner["agent_id"].(string)

	if coordinator == nil {
		b, _ := json.Marshal(map[string]interface{}{"success": false, "error": "Agent coordinator not initialized in context"})
		return string(b), nil
	}

	parentOf, statuses, names, _, err := coordinator.GraphSnapshot()
	if err != nil {
		b, _ := json.Marshal(map[string]interface{}{"success": false, "error": err.Error()})
		return string(b), nil
	}

	var lines []string
	var render func(aid string, depth int)
	render = func(aid string, depth int) {
		status := "?"
		if s, ok := statuses[aid]; ok {
			status = s
		}
		marker := ""
		if aid == me {
			marker = "  ← you"
		}
		name := aid
		if n, ok := names[aid]; ok {
			name = n
		}
		indent := strings.Repeat("  ", depth)
		lines = append(lines, fmt.Sprintf("%s- %s (%s) [%s]%s", indent, name, aid, status, marker))

		for child, p := range parentOf {
			if p != nil && *p == aid {
				render(child, depth+1)
			}
		}
	}

	var roots []string
	for aid, p := range parentOf {
		if p == nil {
			roots = append(roots, aid)
		}
	}

	for _, root := range roots {
		render(root, 0)
	}

	counts := make(map[string]int)
	for _, status := range statuses {
		counts[status]++
	}

	summary := map[string]interface{}{
		"total": len(parentOf),
	}
	for _, s := range AllStatuses {
		if val, exists := counts[s]; exists {
			summary[s] = val
		} else {
			summary[s] = 0
		}
	}

	graphStructure := strings.Join(lines, "\n")
	if graphStructure == "" {
		graphStructure = "(no agents)"
	}

	resp := map[string]interface{}{
		"success":         true,
		"graph_structure": graphStructure,
		"summary":         summary,
	}
	b, _ := json.Marshal(resp)
	return string(b), nil
}

func SendMessageToAgent(ctx context.Context, runCtx RunContextWrapper, targetAgentID, message, messageType, priority string) (string, error) {
	if messageType == "" {
		messageType = "information"
	}
	if priority == "" {
		priority = "normal"
	}

	inner := _ctx(runCtx)
	coordinator := coordinatorFromContext(inner)
	me, _ := inner["agent_id"].(string)

	if coordinator == nil || me == "" {
		b, _ := json.Marshal(map[string]interface{}{"success": false, "error": "Agent coordinator or agent_id missing in context"})
		return string(b), nil
	}

	if targetAgentID == me {
		b, _ := json.Marshal(map[string]interface{}{
			"success": false,
			"error":   "Cannot send a message to yourself; use `think` to record a private note, or `agent_finish` / `finish_scan` to terminate",
		})
		return string(b), nil
	}

	msgID := "msg_" + uuid.New().String()[:8]
	msg := map[string]interface{}{
		"id":       msgID,
		"from":     me,
		"content":  message,
		"type":     messageType,
		"priority": priority,
	}

	delivered, err := coordinator.Send(targetAgentID, msg)
	if !delivered || err != nil {
		b, _ := json.Marshal(map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("Target agent '%s' not found or message delivery failed", targetAgentID),
		})
		return string(b), nil
	}

	b, _ := json.Marshal(map[string]interface{}{
		"success":         true,
		"message_id":      msgID,
		"target_agent_id": targetAgentID,
		"delivery_status": "delivered",
	})
	return string(b), nil
}

func sessionItemsPayload(items []interface{}) []map[string]interface{} {
	var payload []map[string]interface{}
	for _, item := range items {
		if dict, ok := item.(map[string]interface{}); ok {
			role, _ := dict["role"].(string)
			content, _ := dict["content"].(string)
			payload = append(payload, map[string]interface{}{
				"role":    role,
				"content": content,
			})
		} else {
			payload = append(payload, map[string]interface{}{
				"content": fmt.Sprintf("%v", item),
			})
		}
	}
	return payload
}

func WaitForAgents(ctx context.Context, runCtx RunContextWrapper, reason string, timeoutSeconds int) (string, error) {
	if timeoutSeconds <= 0 {
		timeoutSeconds = 300
	}
	if timeoutSeconds > 300 {
		timeoutSeconds = 300
	}
	inner := _ctx(runCtx)
	coordinator := coordinatorFromContext(inner)
	me, _ := inner["agent_id"].(string)
	interactive, _ := inner["interactive"].(bool)

	if coordinator == nil || me == "" {
		b, _ := json.Marshal(map[string]interface{}{"success": false, "error": "Agent coordinator or agent_id missing in context"})
		return string(b), nil
	}

	status, _ := coordinator.GetStatus(me)
	if status == "stopped" {
		b, _ := json.Marshal(map[string]interface{}{
			"success":      true,
			"wait_outcome": "stopped",
			"reason":       reason,
			"note":         "Wait ended because this agent is stopped.",
		})
		return string(b), nil
	}

	pending, items, _ := coordinator.ConsumePending(me, true)
	if pending > 0 {
		coordinator.MarkRunning(me)
		b, _ := json.Marshal(map[string]interface{}{
			"success":          true,
			"wait_outcome":     "message_arrived",
			"pending_messages": pending,
			"messages":         sessionItemsPayload(items),
			"reason":           reason,
		})
		return string(b), nil
	}

	if interactive {
		coordinator.ParkWaiting(me, "agents")
		b, _ := json.Marshal(map[string]interface{}{
			"success":      true,
			"wait_outcome": "waiting",
			"reason":       reason,
			"note":         "Agent parked; execution will resume when a message arrives.",
		})
		return string(b), nil
	}

	coordinator.ParkWaiting(me, "agents")

	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		coordinator.WaitForMessage(timeoutCtx, me)
		close(done)
	}()

	select {
	case <-done:
	case <-timeoutCtx.Done():
		coordinator.MarkRunning(me)
		b, _ := json.Marshal(map[string]interface{}{
			"success":         true,
			"wait_outcome":    "timeout",
			"timeout_seconds": timeoutSeconds,
			"reason":          reason,
			"note":            "No messages within timeout — continue work or call agent_finish.",
		})
		return string(b), nil
	}

	status, _ = coordinator.GetStatus(me)
	if status == "stopped" {
		b, _ := json.Marshal(map[string]interface{}{
			"success":      true,
			"wait_outcome": "stopped",
			"reason":       reason,
			"note":         "Wait ended because this agent is stopped.",
		})
		return string(b), nil
	}

	pending, items, _ = coordinator.ConsumePending(me, true)
	coordinator.MarkRunning(me)
	b, _ := json.Marshal(map[string]interface{}{
		"success":          true,
		"wait_outcome":     "message_arrived",
		"pending_messages": pending,
		"messages":         sessionItemsPayload(items),
		"reason":           reason,
	})
	return string(b), nil
}

func CreateAgent(ctx context.Context, runCtx RunContextWrapper, name, task string, inheritContext bool, skills []string) (string, error) {
	inner := _ctx(runCtx)
	coordinator := coordinatorFromContext(inner)
	parentID, _ := inner["agent_id"].(string)

	var spawner func(parentCtx map[string]interface{}, name, task string, skills []string, parentHistory []interface{}) (map[string]interface{}, error)
	if s, ok := inner["spawn_child_agent"].(func(map[string]interface{}, string, string, []string, []interface{}) (map[string]interface{}, error)); ok {
		spawner = s
	}

	if coordinator == nil || parentID == "" {
		b, _ := json.Marshal(map[string]interface{}{"success": false, "error": "Agent coordinator or agent_id missing in context"})
		return string(b), nil
	}

	if spawner == nil {
		b, _ := json.Marshal(map[string]interface{}{
			"success": false,
			"error":   "Scan runner did not provide a child-agent spawner in context",
		})
		return string(b), nil
	}

	if skills == nil {
		skills = []string{}
	}
	skillError := validateRequestedSkills(skills)
	if skillError != "" {
		b, _ := json.Marshal(map[string]interface{}{"success": false, "error": skillError, "agent_id": nil})
		return string(b), nil
	}

	var parentHistory []interface{}
	if inheritContext && runCtx.TurnInput != nil {
		parentHistory = runCtx.TurnInput
	}

	result, err := spawner(inner, name, task, skills, parentHistory)
	if err != nil {
		logger.Printf("create_agent: scan runner failed to spawn child '%s': %v", name, err)
		b, _ := json.Marshal(map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("child spawn failed: %v", err),
		})
		return string(b), nil
	}

	logger.Printf("create_agent: spawned %v (%s) parent=%s skills=%d task_len=%d", result["agent_id"], name, parentID, len(skills), len(task))

	b, _ := json.Marshal(result)
	return string(b), nil
}

func AgentFinish(ctx context.Context, runCtx RunContextWrapper, resultSummary string, findings []string, success, reportToParent bool, finalRecommendations []string) (string, error) {
	inner := _ctx(runCtx)
	coordinator := coordinatorFromContext(inner)
	me, _ := inner["agent_id"].(string)

	if coordinator == nil || me == "" {
		b, _ := json.Marshal(map[string]interface{}{"success": false, "error": "Agent coordinator or agent_id missing in context"})
		return string(b), nil
	}

	parentID, ok := inner["parent_id"].(string)
	if !ok || parentID == "" {
		b, _ := json.Marshal(map[string]interface{}{
			"success": false,
			"error":   "agent_finish is for subagents. Root/main agents must call finish_scan instead",
		})
		return string(b), nil
	}

	parentNotified := false
	claimed, _ := coordinator.ClaimParentNotice(me)
	if reportToParent && claimed {
		agentName := coordinator.GetName(me)
		if agentName == "" {
			agentName = me
		}

		task, _ := inner["task"].(string)

		report := renderCompletionReport(
			agentName,
			me,
			task,
			success,
			resultSummary,
			findings,
			finalRecommendations,
		)

		msgID := "report_" + uuid.New().String()[:8]
		coordinator.Send(parentID, map[string]interface{}{
			"id":       msgID,
			"from":     me,
			"content":  report,
			"type":     "completion",
			"priority": "high",
		})
		parentNotified = true
	}

	coordinator.SetStatus(me, "completed")
	if !parentNotified {
		notifyParentOnTerminal(coordinator, me, "completed")
	}

	logger.Printf("agent_finish: %s success=%t findings=%d parent_notified=%t", me, success, len(findings), parentNotified)

	hasRecs := false
	if len(finalRecommendations) > 0 {
		hasRecs = true
	}

	b, _ := json.Marshal(map[string]interface{}{
		"success":             true,
		"agent_completed":     true,
		"parent_notified":     parentNotified,
		"agent_id":            me,
		"summary":             resultSummary,
		"findings_count":      len(findings),
		"has_recommendations": hasRecs,
	})
	return string(b), nil
}

func StopAgent(ctx context.Context, runCtx RunContextWrapper, targetAgentID string, cascade bool, reason string) (string, error) {
	inner := _ctx(runCtx)
	coordinator := coordinatorFromContext(inner)
	me, _ := inner["agent_id"].(string)

	if coordinator == nil || me == "" {
		b, _ := json.Marshal(map[string]interface{}{"success": false, "error": "Agent coordinator or agent_id missing in context"})
		return string(b), nil
	}
	if targetAgentID == me {
		b, _ := json.Marshal(map[string]interface{}{
			"success": false,
			"error":   "Cannot stop yourself; call agent_finish or finish_scan instead",
		})
		return string(b), nil
	}

	_, statuses, _, _, err := coordinator.GraphSnapshot()
	if err != nil {
		b, _ := json.Marshal(map[string]interface{}{"success": false, "error": err.Error()})
		return string(b), nil
	}

	currentStatus, ok := statuses[targetAgentID]
	if !ok {
		b, _ := json.Marshal(map[string]interface{}{"success": false, "error": fmt.Sprintf("Unknown agent_id: %s", targetAgentID)})
		return string(b), nil
	}

	if !ActiveStatuses[currentStatus] {
		b, _ := json.Marshal(map[string]interface{}{
			"success":         false,
			"error":           fmt.Sprintf("Agent %s is already '%s'; stop_agent only acts on running/waiting agents — use view_agent_graph to find still-active descendants and stop them individually, or send_message_to_agent if you want to wake this one with new instructions", targetAgentID, currentStatus),
			"target_agent_id": targetAgentID,
			"current_status":  currentStatus,
		})
		return string(b), nil
	}

	var stopped []string
	if cascade {
		stopped, _ = coordinator.CancelDescendantsGraceful(targetAgentID)
	} else {
		coordinator.RequestStop(targetAgentID)
		stopped = []string{targetAgentID}
	}

	var orphaned []string
	for _, aid := range stopped {
		p := coordinator.GetParentOf(aid)
		if p != nil && *p != me {
			orphaned = append(orphaned, aid)
		}
	}

	for _, aid := range orphaned {
		notifyParentOnTerminal(coordinator, aid, "stopped")
	}

	logger.Printf("stop_agent: target=%s cascade=%t reason=%q", targetAgentID, cascade, reason)

	b, _ := json.Marshal(map[string]interface{}{
		"success":         true,
		"target_agent_id": targetAgentID,
		"cascade":         cascade,
		"reason":          reason,
		"note":            "Cancellation is graceful — current turn completes first.",
	})
	return string(b), nil
}
