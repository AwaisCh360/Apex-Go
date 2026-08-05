package report

import (
	"encoding/json"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

// LLMUsageLedger aggregates SDK Usage objects and attaches best-effort cost estimates.
type LLMUsageLedger struct {
	TotalUsage    *Usage
	AgentUsage    map[string]*Usage
	AgentMetadata map[string]map[string]string
	totalCost     float64
	// When True, tokens are still tracked but cost stays $0 — the run is on a
	// model subscription, so there is no metered per-token charge to report.
	ZeroCost bool
}

func NewLLMUsageLedger() *LLMUsageLedger {
	return &LLMUsageLedger{
		TotalUsage:    NewUsage(),
		AgentUsage:    make(map[string]*Usage),
		AgentMetadata: make(map[string]map[string]string),
	}
}

func (l *LLMUsageLedger) Record(agentID string, usage *Usage, agentName string, model string) bool {
	if usage == nil || !usageHasActivity(usage) {
		return false
	}

	normalizedAgentID := "unknown"
	if agentID != "" {
		normalizedAgentID = agentID
	}

	l.TotalUsage.Add(usage)

	if _, ok := l.AgentUsage[normalizedAgentID]; !ok {
		l.AgentUsage[normalizedAgentID] = NewUsage()
	}
	l.AgentUsage[normalizedAgentID].Add(usage)

	if _, ok := l.AgentMetadata[normalizedAgentID]; !ok {
		l.AgentMetadata[normalizedAgentID] = make(map[string]string)
	}
	metadata := l.AgentMetadata[normalizedAgentID]

	if agentName != "" {
		metadata["agent_name"] = agentName
	}
	if model != "" {
		metadata["model"] = model
	}

	if !l.ZeroCost && !isLitellmRouted(model) {
		estimated := estimateLitellmCost(usage, model)
		if estimated != nil {
			l.totalCost += *estimated
		}
	}

	return true
}

func (l *LLMUsageLedger) RecordObservedCost(cost float64) {
	if l.ZeroCost {
		return
	}
	if cost > 0 {
		l.totalCost += cost
	}
}

func (l *LLMUsageLedger) TotalCost() float64 {
	return roundCost(l.totalCost)
}

func (l *LLMUsageLedger) ToRecord() map[string]any {
	record := SerializeUsage(l.TotalUsage)
	if record == nil {
		record = make(map[string]any)
	}
	record["cost"] = roundCost(l.totalCost)
	
	agentsList := make([]map[string]any, 0)
	
	agentTokens := make(map[string]float64)
	var totalTokens float64 = 0
	
	var agentIDs []string
	for aid, u := range l.AgentUsage {
		agentIDs = append(agentIDs, aid)
		toks := float64(resolveTotalTokens(u))
		agentTokens[aid] = toks
		totalTokens += toks
	}
	
	sort.Strings(agentIDs)
	
	for _, agentID := range agentIDs {
		usage := l.AgentUsage[agentID]
		metadata := l.AgentMetadata[agentID]
		
		var agentCost float64 = 0
		if totalTokens > 0 {
			agentCost = l.totalCost * (agentTokens[agentID] / totalTokens)
		}
		
		agentRecord := SerializeUsage(usage)
		if agentRecord == nil {
			agentRecord = make(map[string]any)
		}
		
		agentRecord["agent_id"] = agentID
		
		aName := agentID
		if n, ok := metadata["agent_name"]; ok && n != "" {
			aName = n
		}
		agentRecord["agent_name"] = aName
		
		if m, ok := metadata["model"]; ok {
			agentRecord["model"] = m
		} else {
			agentRecord["model"] = nil
		}
		
		agentRecord["cost"] = roundCost(agentCost)
		agentsList = append(agentsList, agentRecord)
	}
	
	record["agents"] = agentsList
	return record
}

func (l *LLMUsageLedger) Hydrate(rawUsage any) {
	l.TotalUsage = NewUsage()
	l.AgentUsage = make(map[string]*Usage)
	l.AgentMetadata = make(map[string]map[string]string)
	l.totalCost = 0.0

	rawMap, ok := rawUsage.(map[string]any)
	if !ok {
		return
	}

	if t, err := DeserializeUsage(rawMap); err == nil && t != nil {
		l.TotalUsage = t
	} else {
		l.TotalUsage = NewUsage()
	}

	l.totalCost = floatOrZero(rawMap["cost"])

	if agents, ok := rawMap["agents"].([]any); ok {
		for _, rawAgentAny := range agents {
			rawAgent, ok := rawAgentAny.(map[string]any)
			if !ok {
				continue
			}
			agentIDAny := rawAgent["agent_id"]
			var agentID string
			if aidStr, ok := agentIDAny.(string); ok {
				agentID = strings.TrimSpace(aidStr)
			}
			if agentID == "" {
				continue
			}

			u, err := DeserializeUsage(rawAgent)
			if err != nil || u == nil {
				u = NewUsage()
			}
			l.AgentUsage[agentID] = u

			metadata := make(map[string]string)
			if agentName, ok := rawAgent["agent_name"].(string); ok && agentName != "" {
				metadata["agent_name"] = agentName
			}
			if model, ok := rawAgent["model"].(string); ok && model != "" {
				metadata["model"] = model
			}
			l.AgentMetadata[agentID] = metadata
		}
	}
}

func resolveTotalTokens(usage *Usage) int {
	if usage == nil {
		return 0
	}
	total := usage.TotalTokens
	if total < 0 {
		total = 0
	}
	if total > 0 {
		return total
	}
	prompt := intOrZero(usage.InputTokens)
	completion := intOrZero(usage.OutputTokens)
	return prompt + completion
}

func isLitellmRouted(model string) bool {
	if model == "" {
		return false
	}
	name := strings.ToLower(strings.TrimSpace(model))
	if !strings.Contains(name, "/") {
		return false
	}
	return !strings.HasPrefix(name, "openai/")
}

func usageHasActivity(usage *Usage) bool {
	if usage == nil {
		return false
	}
	return usage.Requests != 0 || usage.InputTokens != 0 || usage.OutputTokens != 0 || usage.TotalTokens != 0 || len(usage.RequestUsageEntries) > 0
}

func estimateLitellmCost(usage *Usage, model string) *float64 {
	litellmModel := litellmModelName(model)
	if litellmModel == "" {
		return nil
	}

	entries := usage.RequestUsageEntries
	if len(entries) == 0 {
		return estimateLitellmEntryCost(usage, litellmModel)
	}

	var total float64 = 0
	estimatedAny := false

	for _, entry := range entries {
		cost := estimateLitellmEntryCost(entry, litellmModel)
		if cost != nil {
			total += *cost
			estimatedAny = true
		}
	}

	if estimatedAny {
		return &total
	}
	return nil
}

func estimateLitellmEntryCost(entry any, model string) *float64 {
	promptTokens := intOrZero(getField(entry, "InputTokens"))
	completionTokens := intOrZero(getField(entry, "OutputTokens"))
	totalTokens := intOrZero(getField(entry, "TotalTokens"))

	if totalTokens <= 0 {
		totalTokens = promptTokens + completionTokens
	}
	if totalTokens <= 0 {
		return nil
	}

	usagePayload := map[string]any{
		"prompt_tokens":     promptTokens,
		"completion_tokens": completionTokens,
		"total_tokens":      totalTokens,
	}

	promptDetails := detailsToMap(getField(entry, "InputTokensDetails"))
	completionDetails := detailsToMap(getField(entry, "OutputTokensDetails"))

	if len(promptDetails) > 0 {
		usagePayload["prompt_tokens_details"] = promptDetails
	}
	if len(completionDetails) > 0 {
		usagePayload["completion_tokens_details"] = completionDetails
	}

	candidates := []string{model}
	if strings.Contains(model, "/") {
		parts := strings.SplitN(model, "/", 2)
		if len(parts) == 2 {
			candidates = append(candidates, parts[1])
		}
	}

	for _, candidate := range candidates {
		cost, err := CompletionCost(map[string]any{
			"model": candidate,
			"usage": usagePayload,
		}, model)
		if err == nil && cost >= 0 {
			return &cost
		}
	}

	return nil
}

func litellmModelName(model string) string {
	if model == "" {
		return ""
	}
	normalized := strings.TrimSpace(model)
	prefixes := []string{"litellm/", "any-llm/", "openai/"}
	for _, prefix := range prefixes {
		if strings.HasPrefix(normalized, prefix) {
			normalized = strings.TrimPrefix(normalized, prefix)
			break
		}
	}
	return normalized
}

func detailsToMap(details any) map[string]any {
	if details == nil {
		return make(map[string]any)
	}

	if list, ok := details.([]any); ok {
		for _, item := range list {
			result := detailsToMap(item)
			if len(result) > 0 {
				return result
			}
		}
		return make(map[string]any)
	}
	
	if m, ok := details.(map[string]any); ok {
		res := make(map[string]any)
		for k, v := range m {
			if v != nil {
				res[k] = v
			}
		}
		return res
	}

	b, err := json.Marshal(details)
	if err == nil {
		var m map[string]any
		if err := json.Unmarshal(b, &m); err == nil {
			res := make(map[string]any)
			for k, v := range m {
				if v != nil {
					res[k] = v
				}
			}
			return res
		}
	}

	return make(map[string]any)
}

func intOrZero(value any) int {
	if value == nil {
		return 0
	}
	switch v := value.(type) {
	case int:
		if v > 0 { return v } else { return 0 }
	case int32:
		if v > 0 { return int(v) } else { return 0 }
	case int64:
		if v > 0 { return int(v) } else { return 0 }
	case float32:
		if v > 0 { return int(v) } else { return 0 }
	case float64:
		if v > 0 { return int(v) } else { return 0 }
	case string:
		if i, err := strconv.Atoi(v); err == nil {
			if i > 0 { return i } else { return 0 }
		}
	}
	return 0
}

func floatOrZero(value any) float64 {
	if value == nil {
		return 0.0
	}
	var res float64
	switch v := value.(type) {
	case float64:
		res = v
	case float32:
		res = float64(v)
	case int:
		res = float64(v)
	case int32:
		res = float64(v)
	case int64:
		res = float64(v)
	case string:
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			res = f
		}
	}
	if res >= 0 {
		return res
	}
	return 0.0
}

func roundCost(cost float64) float64 {
	if cost < 0 {
		cost = 0.0
	}
	multiplier := math.Pow(10, 10)
	return math.Round(cost*multiplier) / multiplier
}

func getField(obj any, fieldName string) any {
	if obj == nil {
		return nil
	}
	
	if u, ok := obj.(*Usage); ok {
		switch fieldName {
		case "InputTokens": return u.InputTokens
		case "OutputTokens": return u.OutputTokens
		case "TotalTokens": return u.TotalTokens
		case "InputTokensDetails": return nil
		case "OutputTokensDetails": return nil
		}
		return nil
	}
	
	if m, ok := obj.(map[string]any); ok {
		snake := toSnakeCase(fieldName)
		if val, ok := m[snake]; ok {
			return val
		}
		if val, ok := m[fieldName]; ok {
		    return val
		}
	}
	
	v := reflect.ValueOf(obj)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() == reflect.Struct {
		f := v.FieldByName(fieldName)
		if f.IsValid() && f.CanInterface() {
			return f.Interface()
		}
	}
	return nil
}

func toSnakeCase(s string) string {
    switch s {
    case "InputTokens": return "input_tokens"
    case "OutputTokens": return "output_tokens"
    case "TotalTokens": return "total_tokens"
    case "InputTokensDetails": return "input_tokens_details"
    case "OutputTokensDetails": return "output_tokens_details"
    }
    return s
}

// -----------------------------------------------------------------------------
// Stubs for missing dependencies
// -----------------------------------------------------------------------------

type Usage struct {
	Requests            int
	InputTokens         int
	OutputTokens        int
	TotalTokens         int
	RequestUsageEntries []any
}

func NewUsage() *Usage {
	return &Usage{}
}

func (u *Usage) Add(other *Usage) {
	if other == nil {
		return
	}
	u.Requests += other.Requests
	u.InputTokens += other.InputTokens
	u.OutputTokens += other.OutputTokens
	u.TotalTokens += other.TotalTokens
	u.RequestUsageEntries = append(u.RequestUsageEntries, other.RequestUsageEntries...)
}

func DeserializeUsage(raw any) (*Usage, error) {
	u := &Usage{}
	if rawMap, ok := raw.(map[string]any); ok {
		if val, ok := rawMap["requests"].(float64); ok {
			u.Requests = int(val)
		}
		if val, ok := rawMap["input_tokens"].(float64); ok {
			u.InputTokens = int(val)
		}
		if val, ok := rawMap["output_tokens"].(float64); ok {
			u.OutputTokens = int(val)
		}
		if val, ok := rawMap["total_tokens"].(float64); ok {
			u.TotalTokens = int(val)
		}
		if entries, ok := rawMap["request_usage_entries"].([]any); ok {
			u.RequestUsageEntries = entries
		}
	}
	return u, nil
}

func SerializeUsage(u *Usage) map[string]any {
	if u == nil {
		return map[string]any{}
	}
	return map[string]any{
		"requests":              u.Requests,
		"input_tokens":          u.InputTokens,
		"output_tokens":         u.OutputTokens,
		"total_tokens":          u.TotalTokens,
		"request_usage_entries": u.RequestUsageEntries,
	}
}

func CompletionCost(completionResponse map[string]any, model string) (float64, error) {
	// This replaces litellm.completion_cost.
	// Prices are per 1M tokens (input, output).
	// Unmapped models will default to $0 cost, which may lead to inaccurate cost reporting for those models.
	pricing := map[string][2]float64{
		// OpenAI
		"gpt-4":                      {30, 60},
		"gpt-4-turbo":                {10, 30},
		"gpt-4o":                     {5, 15},
		"gpt-4o-mini":                {0.15, 0.60},
		"gpt-3.5-turbo":              {0.50, 1.50},
		// Anthropic
		"claude-3-opus-20240229":     {15, 75},
		"claude-3-sonnet-20240229":   {3, 15},
		"claude-3-haiku-20240307":    {0.25, 1.25},
		"claude-3-5-sonnet-20240620": {3, 15},
		"claude-3-5-sonnet-20241022": {3, 15},
		"claude-3-5-haiku-20241022":  {1, 5},
		// Google
		"gemini-1.5-pro":             {3.50, 10.50},
		"gemini-1.5-flash":           {0.075, 0.30},
		"gemini-1.0-pro":             {0.50, 1.50},
		// Meta Llama
		"llama-3.1-405b":             {3, 3}, // rough estimate
		"llama-3.1-70b":              {0.70, 0.90},
		"llama-3.1-8b":               {0.05, 0.08},
		// Mistral
		"mistral-large-2407":         {2, 6},
		"mistral-nemo":               {0.15, 0.15},
	}

	modelBase := model
	if strings.Contains(model, "/") {
		parts := strings.SplitN(model, "/", 2)
		modelBase = parts[1]
	}

	costInfo, ok := pricing[modelBase]
	if !ok {
		return 0, nil // Unmapped models cost 0
	}

	var inputTokens, outputTokens float64
	if inToks, ok := completionResponse["prompt_tokens"].(int); ok {
		inputTokens = float64(inToks)
	} else if inToks, ok := completionResponse["prompt_tokens"].(float64); ok {
		inputTokens = inToks
	}
	if outToks, ok := completionResponse["completion_tokens"].(int); ok {
		outputTokens = float64(outToks)
	} else if outToks, ok := completionResponse["completion_tokens"].(float64); ok {
		outputTokens = outToks
	}

	return (inputTokens/1000000.0)*costInfo[0] + (outputTokens/1000000.0)*costInfo[1], nil
}
