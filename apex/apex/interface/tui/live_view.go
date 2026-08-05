package tui

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

type AgentCallKey struct {
	AgentID string
	CallID  string
}

type TuiLiveView struct {
	Agents                    map[string]map[string]any
	Events                    []map[string]any
	nextEventID               int
	openAssistantEventByAgent map[string]map[string]any
	toolEventByAgentAndCallID map[string]map[string]any
	userInstruction           *string
	userInstructionAt         *string
	userInstructionShown      bool
}

func NewTuiLiveView() *TuiLiveView {
	return &TuiLiveView{
		Agents:                    make(map[string]map[string]any),
		Events:                    make([]map[string]any, 0),
		nextEventID:               1,
		openAssistantEventByAgent: make(map[string]map[string]any),
		toolEventByAgentAndCallID: make(map[string]map[string]any),
	}
}

func (tv *TuiLiveView) SetUserInstruction(text *string, timestamp *string) {
	if tv.userInstructionShown || text == nil || strings.TrimSpace(*text) == "" {
		return
	}
	t := strings.TrimSpace(*text)
	tv.userInstruction = &t
	tv.userInstructionAt = timestamp
	tv.FlushUserInstruction()
}

func (tv *TuiLiveView) FlushUserInstruction() bool {
	if tv.userInstructionShown || tv.userInstruction == nil {
		return false
	}
	var rootID *string
	for agentID, agent := range tv.Agents {
		if agent["parent_id"] == nil {
			id := agentID
			rootID = &id
			break
		}
	}
	if rootID == nil {
		return false
	}
	tv.userInstructionShown = true
	tv.appendEvent(
		*rootID,
		"chat",
		map[string]any{
			"role":    "user",
			"content": *tv.userInstruction,
			"metadata": map[string]any{
				"source": "user_instruction",
			},
		},
		tv.userInstructionAt,
	)
	return true
}

func (tv *TuiLiveView) HydrateFromRunDir(runDir string) {
	tv.loadUserInstruction(runDir)
	stateDir := runtimeStateDir(runDir)
	agentsPath := filepath.Join(stateDir, "agents.json")
	if _, err := os.Stat(agentsPath); os.IsNotExist(err) {
		return
	}
	data, err := os.ReadFile(agentsPath)
	if err != nil {
		return
	}
	var agentsData map[string]any
	if err := json.Unmarshal(data, &agentsData); err != nil {
		return
	}

	statuses, _ := agentsData["statuses"].(map[string]any)
	names, _ := agentsData["names"].(map[string]any)
	parentOf, _ := agentsData["parent_of"].(map[string]any)

	if statuses == nil {
		return
	}

	for agentID, status := range statuses {
		name := agentID
		if n, ok := names[agentID].(string); ok {
			name = n
		}
		var parentID string
		if p, ok := parentOf[agentID].(string); ok {
			parentID = p
		}
		statusStr := fmt.Sprintf("%v", status)
		tv.UpsertAgent(agentID, name, parentID, statusStr, "")
	}

	tv.FlushUserInstruction()
	agentIDs := make([]string, 0, len(statuses))
	for id := range statuses {
		agentIDs = append(agentIDs, id)
	}
	tv.hydrateSDKSessionHistory(runDir, agentIDs)
}

func (tv *TuiLiveView) loadUserInstruction(runDir string) {
	data, err := os.ReadFile(filepath.Join(runDir, "run.json"))
	if err != nil {
		return
	}
	var record map[string]any
	if err := json.Unmarshal(data, &record); err != nil {
		return
	}

	instruction, ok := record["user_instruction"].(string)
	if !ok {
		return
	}
	var startTimeStr *string
	if st, ok := record["start_time"].(string); ok {
		startTimeStr = &st
	}
	tv.SetUserInstruction(&instruction, startTimeStr)
}

func (tv *TuiLiveView) hydrateSDKSessionHistory(runDir string, agentIDs []string) {
	tasked := make(map[string]bool)
	anyIDs := make([]any, len(agentIDs))
	for i, id := range agentIDs {
		anyIDs[i] = id
	}
	history := LoadSessionHistory(runDir, anyIDs)
	for _, h := range history {
		firstUserTurn := !tasked[h.AgentID]
		role, _ := h.Data["role"].(string)
		typ, _ := h.Data["type"].(string)
		if role == "user" && (typ == "" || typ == "message") {
			tasked[h.AgentID] = true
		}
		tv.ingestSessionHistoryItem(h.AgentID, h.Data, h.CreatedAt, firstUserTurn)
	}
}

func (tv *TuiLiveView) UpsertAgent(agentID string, name string, parentID string, status string, errorMessage string) bool {
	now := time.Now().UTC().Format(time.RFC3339)
	current, exists := tv.Agents[agentID]
	changed := false
	if !exists {
		n := agentID
		if name != "" {
			n = name
		}
		s := "running"
		if status != "" {
			s = status
		}
		var pID any = nil
		if parentID != "" {
			pID = parentID
		}
		current = map[string]any{
			"id":         agentID,
			"name":       n,
			"parent_id":  pID,
			"status":     s,
			"created_at": now,
			"updated_at": now,
		}
		tv.Agents[agentID] = current
		changed = true
	} else {
		if name != "" {
			current["name"] = name
			changed = true
		}
		if parentID != "" {
			current["parent_id"] = parentID
			changed = true
		} else if _, ok := current["parent_id"]; !ok {
			current["parent_id"] = nil
			changed = true
		}
		if status != "" {
			current["status"] = status
			changed = true
		}
		if errorMessage != "" {
			current["error_message"] = errorMessage
			changed = true
		}
		current["updated_at"] = now
	}
	return changed
}

func (tv *TuiLiveView) RecordAgentError(agentID string, errorMsg string) {
	tv.appendEvent(
		agentID,
		"chat",
		map[string]any{
			"role":    "assistant",
			"content": fmt.Sprintf("An error occurred: %s\nI'm now waiting for new instructions.", errorMsg),
			"metadata": map[string]any{
				"source": "agent_error",
			},
		},
		nil,
	)
}

func (tv *TuiLiveView) RecordUserMessage(agentID string, content string) {
	tv.appendEvent(
		agentID,
		"chat",
		map[string]any{
			"role":    "user",
			"content": content,
			"metadata": map[string]any{
				"source": "tui_user",
			},
		},
		nil,
	)
}

func (tv *TuiLiveView) IngestSDKEvent(agentID string, event any) {
	eventType, _ := rawField(event, "type", "").(string)
	if eventType == "raw_response_event" {
		tv.ingestRawResponseEvent(agentID, rawField(event, "data", nil))
		return
	}
	if eventType != "run_item_stream_event" {
		return
	}

	item := rawField(event, "item", nil)
	itemType, _ := rawField(item, "type", "").(string)
	if itemType == "message_output_item" {
		tv.recordAssistantMessage(agentID, sdkMessageText(item), true)
	} else if itemType == "tool_call_item" {
		tv.recordToolCall(agentID, item)
	} else if itemType == "tool_call_output_item" {
		tv.recordToolOutput(agentID, item)
	}
}

func (tv *TuiLiveView) EventsForAgent(agentID string) []map[string]any {
	var result []map[string]any
	for _, event := range tv.Events {
		if event["agent_id"] == agentID {
			result = append(result, event)
		}
	}
	return result
}

func (tv *TuiLiveView) HasEventsForAgent(agentID string) bool {
	for _, event := range tv.Events {
		if event["agent_id"] == agentID {
			return true
		}
	}
	return false
}

func (tv *TuiLiveView) ingestRawResponseEvent(agentID string, data any) {
	dataType, _ := rawField(data, "type", "").(string)
	if dataType == "response.output_text.delta" {
		delta, _ := rawField(data, "delta", "").(string)
		if delta != "" {
			tv.recordAssistantMessage(agentID, delta, false)
		}
	}
}

func (tv *TuiLiveView) ingestSessionHistoryItem(agentID string, item map[string]any, timestamp string, firstUserTurn bool) {
	itemType, _ := item["type"].(string)
	role, _ := item["role"].(string)

	if (role == "user" || role == "assistant") && (itemType == "" || itemType == "message") {
		content := sessionMessageText(item)
		if content == "" {
			return
		}
		if role == "user" && (firstUserTurn || isInternalAgentTurn(content)) {
			return
		}
		tv.appendEvent(
			agentID,
			"chat",
			map[string]any{
				"role":    role,
				"content": content,
				"metadata": map[string]any{
					"source": "sdk_session",
				},
			},
			&timestamp,
		)
		return
	}

	if itemType == "function_call" {
		callID := ""
		if cID, ok := item["call_id"].(string); ok && cID != "" {
			callID = cID
		} else if id, ok := item["id"].(string); ok && id != "" {
			callID = id
		}
		toolName := "tool"
		if n, ok := item["name"].(string); ok && n != "" {
			toolName = n
		}
		tv.recordToolCallData(
			agentID,
			map[string]any{
				"call_id":   callID,
				"tool_name": toolName,
				"args":      parseJSONObject(item["arguments"]),
			},
			&timestamp,
		)
		return
	}

	if itemType == "function_call_output" {
		callID := ""
		if cID, ok := item["call_id"].(string); ok && cID != "" {
			callID = cID
		} else if id, ok := item["id"].(string); ok && id != "" {
			callID = id
		}
		tv.recordToolOutputData(
			agentID,
			map[string]any{
				"call_id":   callID,
				"tool_name": "tool",
				"output":    item["output"],
			},
			&timestamp,
		)
	}
}

func (tv *TuiLiveView) recordAssistantMessage(agentID string, content string, final bool) {
	if content == "" {
		return
	}
	existing, ok := tv.openAssistantEventByAgent[agentID]
	if !ok {
		event := tv.appendEvent(
			agentID,
			"chat",
			map[string]any{
				"role":    "assistant",
				"content": content,
				"metadata": map[string]any{
					"source":    "sdk_stream",
					"streaming": !final,
				},
			},
			nil,
		)
		if !final {
			tv.openAssistantEventByAgent[agentID] = event
		}
		return
	}

	data := existing["data"].(map[string]any)
	if final {
		data["content"] = content
		metadata := data["metadata"].(map[string]any)
		metadata["streaming"] = false
		delete(tv.openAssistantEventByAgent, agentID)
	} else {
		prevContent, _ := data["content"].(string)
		data["content"] = prevContent + content
	}
	bumpEvent(existing, nil)
}

func (tv *TuiLiveView) recordToolCall(agentID string, item any) {
	tv.recordToolCallData(agentID, sdkToolCallData(item), nil)
}

func (tv *TuiLiveView) recordToolCallData(agentID string, call map[string]any, timestamp *string) {
	callID, _ := call["call_id"].(string)
	eventKey := agentID + "|" + callID
	existing, ok := tv.toolEventByAgentAndCallID[eventKey]
	toolData := map[string]any{
		"tool_name": call["tool_name"],
		"args":      call["args"],
		"status":    "running",
		"agent_id":  agentID,
		"call_id":   callID,
	}
	if !ok {
		event := tv.appendEvent(agentID, "tool", toolData, timestamp)
		tv.toolEventByAgentAndCallID[eventKey] = event
	} else {
		data := existing["data"].(map[string]any)
		for k, v := range toolData {
			data[k] = v
		}
		bumpEvent(existing, timestamp)
	}
}

func (tv *TuiLiveView) recordToolOutput(agentID string, item any) {
	tv.recordToolOutputData(agentID, sdkToolOutputData(item), nil)
}

func (tv *TuiLiveView) recordToolOutputData(agentID string, output map[string]any, timestamp *string) {
	callID, _ := output["call_id"].(string)
	eventKey := agentID + "|" + callID
	event, ok := tv.toolEventByAgentAndCallID[eventKey]
	if !ok {
		event = tv.appendEvent(
			agentID,
			"tool",
			map[string]any{
				"tool_name": output["tool_name"],
				"args":      map[string]any{},
				"status":    "completed",
				"agent_id":  agentID,
				"call_id":   callID,
			},
			timestamp,
		)
		tv.toolEventByAgentAndCallID[eventKey] = event
	}

	result := normalizeImageResult(parseJSONValue(output["output"]))
	data := event["data"].(map[string]any)
	data["result"] = result
	data["status"] = toolStatusFromResult(result)
	bumpEvent(event, timestamp)
}

func (tv *TuiLiveView) appendEvent(agentID string, eventType string, data map[string]any, timestamp *string) map[string]any {
	ts := time.Now().UTC().Format(time.RFC3339)
	if timestamp != nil {
		ts = *timestamp
	}
	event := map[string]any{
		"id":        fmt.Sprintf("%s_%d", eventType, tv.nextEventID),
		"type":      eventType,
		"agent_id":  agentID,
		"timestamp": ts,
		"version":   0,
		"data":      data,
	}
	tv.nextEventID++
	tv.Events = append(tv.Events, event)
	return event
}

func bumpEvent(event map[string]any, timestamp *string) {
	version, _ := event["version"].(int)
	event["version"] = version + 1
	ts := time.Now().UTC().Format(time.RFC3339)
	if timestamp != nil {
		ts = *timestamp
	}
	event["timestamp"] = ts
}

func sdkToolCallData(item any) map[string]any {
	raw := rawField(item, "raw_item", nil)

	callIDStr := ""
	if c := rawField(raw, "call_id", nil); c != nil {
		callIDStr = fmt.Sprintf("%v", c)
	} else if id := rawField(raw, "id", nil); id != nil {
		callIDStr = fmt.Sprintf("%v", id)
	} else {
		callIDStr = fmt.Sprintf("%p", item)
	}

	toolNameStr := "tool"
	if n := rawField(raw, "name", nil); n != nil {
		toolNameStr = fmt.Sprintf("%v", n)
	} else if t := rawField(raw, "type", nil); t != nil {
		toolNameStr = fmt.Sprintf("%v", t)
	} else if title := rawField(item, "title", nil); title != nil {
		toolNameStr = fmt.Sprintf("%v", title)
	}

	return map[string]any{
		"call_id":   callIDStr,
		"tool_name": toolNameStr,
		"args":      parseJSONObject(rawField(raw, "arguments", nil)),
	}
}

func sdkToolOutputData(item any) map[string]any {
	raw := rawField(item, "raw_item", nil)

	callIDStr := ""
	if c := rawField(raw, "call_id", nil); c != nil {
		callIDStr = fmt.Sprintf("%v", c)
	} else if id := rawField(raw, "id", nil); id != nil {
		callIDStr = fmt.Sprintf("%v", id)
	} else {
		callIDStr = fmt.Sprintf("%p", item)
	}

	toolNameStr := "tool"
	if n := rawField(raw, "name", nil); n != nil {
		toolNameStr = fmt.Sprintf("%v", n)
	} else if t := rawField(raw, "type", nil); t != nil {
		toolNameStr = fmt.Sprintf("%v", t)
	}

	output := rawField(item, "output", nil)
	if output == nil {
		output = rawField(raw, "output", nil)
	}

	return map[string]any{
		"call_id":   callIDStr,
		"tool_name": toolNameStr,
		"output":    output,
	}
}

func sdkMessageText(item any) string {
	raw := rawField(item, "raw_item", nil)
	return messageContentText(rawField(raw, "content", []any{}))
}

func sessionMessageText(item map[string]any) string {
	content, _ := item["content"]
	if content == nil {
		content = ""
	}
	return messageContentText(content)
}

var internalTurnPrefixes = []string{
	"[Message from ",
	"== Inherited context from parent",
	"Your previous message ended a turn without a tool call.",
	"Your previous response ended the autonomous Apex run without a lifecycle tool call.",
	"[NOTICE] Turn budget:",
	"[URGENT] Turn budget:",
	"[CRITICAL] Turn budget:",
	"[NOTICE] Scan cost budget:",
	"[URGENT] Scan cost budget:",
	"[CRITICAL] Scan cost budget:",
}

func isInternalAgentTurn(content string) bool {
	content = strings.TrimLeft(content, " \t\r\n")
	for _, prefix := range internalTurnPrefixes {
		if strings.HasPrefix(content, prefix) {
			return true
		}
	}
	return false
}

func messageContentText(content any) string {
	var parts []string
	var contentItems []any
	if slice, ok := content.([]any); ok {
		contentItems = slice
	} else {
		contentItems = []any{content}
	}

	for _, part := range contentItems {
		if s, ok := part.(string); ok {
			parts = append(parts, s)
			continue
		}
		text := rawField(part, "text", nil)
		if s, ok := text.(string); ok {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, "")
}

func rawField(raw any, key string, defaultVal any) any {
	if raw == nil {
		return defaultVal
	}
	if m, ok := raw.(map[string]any); ok {
		if val, exists := m[key]; exists {
			return val
		}
		return defaultVal
	}
	v := reflect.ValueOf(raw)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() == reflect.Struct {
		// Try to find the field, maybe with uppercase first letter
		field := v.FieldByName(key)
		if !field.IsValid() {
			titleKey := strings.ToUpper(key[:1]) + key[1:]
			field = v.FieldByName(titleKey)
		}
		if field.IsValid() && field.CanInterface() {
			return field.Interface()
		}
	}
	return defaultVal
}

func parseJSONObject(value any) map[string]any {
	parsed := parseJSONValue(value)
	if m, ok := parsed.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func parseJSONValue(value any) any {
	s, ok := value.(string)
	if !ok {
		return value
	}
	var parsed any
	if err := json.Unmarshal([]byte(s), &parsed); err != nil {
		return value
	}
	return parsed
}

func normalizeImageResult(result any) any {
	imageURL := imageUrlFromResult(result)
	if imageURL == nil {
		return result
	}
	return map[string]any{
		"type":      "image",
		"image_url": *imageURL,
	}
}

func imageUrlFromResult(result any) *string {
	if slice, ok := result.([]any); ok {
		for _, block := range slice {
			url := imageUrlFromResult(block)
			if url != nil {
				return url
			}
		}
		return nil
	}
	// Support for ToolOutputImage shape directly without reflection
	if m, ok := result.(map[string]any); ok {
		if _, ok := m["image_url"]; ok {
			// This covers both ToolOutputImage JSON shapes and nested dicts
			if typ, ok := m["type"].(string); !ok || (typ == "image" || typ == "input_image" || typ == "output_image") {
				if url, ok := m["image_url"].(string); ok && strings.HasPrefix(url, "data:image/") {
					return &url
				}
			}
		}
	}
	
	// Support dynamic ToolOutputImage type definition if present via reflection as a fallback
	if url, ok := rawField(result, "image_url", nil).(string); ok {
		if strings.HasPrefix(url, "data:image/") {
			return &url
		}
	}
	if url, ok := rawField(result, "ImageUrl", nil).(string); ok {
		if strings.HasPrefix(url, "data:image/") {
			return &url
		}
	}
	if url, ok := rawField(result, "ImageURL", nil).(string); ok {
		if strings.HasPrefix(url, "data:image/") {
			return &url
		}
	}
	return nil
}

func toolStatusFromResult(result any) string {
	if m, ok := result.(map[string]any); ok {
		if success, ok := m["success"].(bool); ok && !success {
			return "failed"
		}
	}
	return "completed"
}

// ---- STUBS ----
// We provide these stubs to make the file compile, since the original python
// imported them from other packages not yet translated to Go.

func (tv *TuiLiveView) GetAgents() map[string]map[string]any {
	return tv.Agents
}

func (tv *TuiLiveView) GetEvents() []map[string]any {
	return tv.Events
}

func (tv *TuiLiveView) SetEvents(events []map[string]any) {
	tv.Events = events
}

func (tv *TuiLiveView) CleanupEventReferences(eventID string) {
	for k, v := range tv.openAssistantEventByAgent {
		if id, ok := v["id"].(string); ok && id == eventID {
			delete(tv.openAssistantEventByAgent, k)
		}
	}
	for k, v := range tv.toolEventByAgentAndCallID {
		if id, ok := v["id"].(string); ok && id == eventID {
			delete(tv.toolEventByAgentAndCallID, k)
		}
	}
}
