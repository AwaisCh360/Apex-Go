package report

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/AwaisCh360/Apex/apex/config"
	"github.com/AwaisCh360/Apex/apex/llm"
)

const DedupeSystemPrompt = `You are an expert vulnerability report deduplication judge.
Your task is to determine if a candidate vulnerability report describes the SAME vulnerability
as any existing report.

CRITICAL DEDUPLICATION RULES:

1. SAME VULNERABILITY means:
   - Same root cause (e.g., "missing input validation" not just "SQL injection")
   - Same affected component/endpoint/file (exact match or clear overlap)
   - Same exploitation method or attack vector
   - Would be fixed by the same code change/patch

2. NOT DUPLICATES if:
   - Different endpoints even with same vulnerability type (e.g., SQLi in /login vs /search)
   - Different parameters in same endpoint (e.g., XSS in 'name' vs 'comment' field)
   - Different root causes (e.g., stored XSS vs reflected XSS in same field)
   - Different severity levels due to different impact
   - One is authenticated, other is unauthenticated

3. ARE DUPLICATES even if:
   - Titles are worded differently
   - Descriptions have different level of detail
   - PoC uses different payloads but exploits same issue
   - One report is more thorough than another
   - Minor variations in technical analysis

4. DEPENDENCY-CVE reports use package identity:
   - Same CVE and same package/ecosystem is a duplicate
   - Same CVE but different package/ecosystem is NOT a duplicate
   - Same package/ecosystem but different CVE is NOT a duplicate

COMPARISON GUIDELINES:
- Focus on the technical root cause, not surface-level similarities
- Same vulnerability type (SQLi, XSS) doesn't mean duplicate - location matters
- Consider the fix: would fixing one also fix the other?
- When uncertain, lean towards NOT duplicate

FIELDS TO ANALYZE:
- title, description: General vulnerability info
- target, endpoint, method: Exact location of vulnerability
- technical_analysis: Root cause details
- poc_description: How it's exploited
- impact: What damage it can cause

Respond with a single JSON object and nothing else:

{
  "is_duplicate": true,
  "duplicate_id": "vuln-0001",
  "confidence": 0.95,
  "reason": "Both reports describe SQL injection in /api/login via the username parameter"
}

Or, if not a duplicate:

{
  "is_duplicate": false,
  "duplicate_id": "",
  "confidence": 0.90,
  "reason": "Different endpoints: candidate is /api/search, existing is /api/login"
}

Rules:
- ` + "``is_duplicate``" + ` is a boolean.
- ` + "``duplicate_id``" + ` is the exact id from existing reports, or "" if not a duplicate.
- ` + "``confidence``" + ` is a number between 0 and 1.
- ` + "``reason``" + ` is a specific explanation mentioning endpoint/parameter/root cause.
- Output ONLY the JSON object — no surrounding prose, no code fences.`

func ConfigureSDKModelDefaults(settings *config.Settings) {}

// --- END STUBS ---

func dedupeModelSettings(dedupe config.DedupeSettings, mainLLM config.LlmSettings, modelName string, requestTimeout int) llm.ModelSettings {
	apiKey := strings.TrimSpace(dedupe.APIKey)
	if apiKey == "" && strings.TrimSpace(dedupe.Model) == "" {
		apiKey = strings.TrimSpace(mainLLM.APIKey)
	}

	apiBase := strings.TrimSpace(dedupe.APIBase)
	if apiBase == "" && strings.TrimSpace(dedupe.Model) == "" {
		apiBase = strings.TrimSpace(mainLLM.APIBase)
	}

	reasoningEffort := strings.TrimSpace(dedupe.ReasoningEffort)
	if reasoningEffort == "" {
		reasoningEffort = strings.TrimSpace(mainLLM.ReasoningEffort)
	}

	extraHeaders := make(map[string]string)
	if strings.TrimSpace(dedupe.Model) != "" {
		for k, v := range dedupe.ExtraHeaders {
			extraHeaders[k] = v
		}
	} else {
		for k, v := range mainLLM.ExtraHeaders {
			extraHeaders[k] = v
		}
	}

	return llm.ModelSettings{
		Temperature:     0.0,
		MaxTokens:       0,
		APIKey:          apiKey,
		APIBase:         apiBase,
		ReasoningEffort: reasoningEffort,
		ExtraHeaders:    extraHeaders,
		Timeout:         requestTimeout,
	}
}

func prepareReportForComparison(report map[string]any) map[string]any {
	relevantFields := []string{
		"id", "title", "description", "impact", "target", "technical_analysis",
		"poc_description", "endpoint", "method", "cve", "dependency_metadata",
	}
	cleaned := make(map[string]any)
	for _, field := range relevantFields {
		if val, ok := report[field]; ok && val != nil {
			if strVal, isStr := val.(string); isStr {
				if len(strVal) > 8000 {
					val = strVal[:8000] + "...[truncated]"
				}
			}
			cleaned[field] = val
		}
	}
	return cleaned
}

func dependencyIdentity(report map[string]any) (string, string, string, bool) {
	metaRaw, hasMeta := report["dependency_metadata"]
	if !hasMeta {
		return "", "", "", false
	}
	meta, isMap := metaRaw.(map[string]any)
	if !isMap {
		return "", "", "", false
	}

	rawCVE, hasCVE := report["cve"]
	rawPackage, hasPackage := meta["package_name"]
	if !hasCVE || !hasPackage || rawCVE == nil || rawPackage == nil {
		return "", "", "", false
	}

	cve := strings.ToUpper(strings.TrimSpace(fmt.Sprintf("%v", rawCVE)))

	ecosystem := ""
	if eco, ok := meta["package_ecosystem"]; ok && eco != nil {
		ecosystem = strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", eco)))
	}

	packageName := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", rawPackage)))

	if cve == "" || packageName == "" {
		return "", "", "", false
	}
	return cve, ecosystem, packageName, true
}

func reportCVE(report map[string]any) string {
	raw, ok := report["cve"]
	if !ok || raw == nil {
		return ""
	}
	return strings.ToUpper(strings.TrimSpace(fmt.Sprintf("%v", raw)))
}

func isAllowedBoundary(b byte) bool {
	if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_' {
		return true
	}
	if b == '@' || b == '.' || b == '/' || b == '-' {
		return true
	}
	return false
}

func containsWithBoundaries(haystack, needle string) bool {
	if needle == "" {
		return false
	}
	haystackBytes := []byte(haystack)
	needleBytes := []byte(needle)

	idx := 0
	for {
		i := bytes.Index(haystackBytes[idx:], needleBytes)
		if i == -1 {
			return false
		}

		matchStart := idx + i
		matchEnd := matchStart + len(needleBytes)

		validBefore := true
		if matchStart > 0 {
			if isAllowedBoundary(haystackBytes[matchStart-1]) {
				validBefore = false
			}
		}

		validAfter := true
		if matchEnd < len(haystackBytes) {
			if isAllowedBoundary(haystackBytes[matchEnd]) {
				validAfter = false
			}
		}

		if validBefore && validAfter {
			return true
		}

		idx = matchStart + 1
	}
}

func legacyReportMentionsPackage(report map[string]any, ecosystem, packageName string) bool {
	fields := []string{
		"title", "description", "impact", "target", "technical_analysis",
		"poc_description", "evidence",
	}
	var haystackBuilder strings.Builder
	for _, field := range fields {
		if val, ok := report[field]; ok && val != nil {
			haystackBuilder.WriteString(fmt.Sprintf("%v ", val))
		}
	}
	haystack := strings.ToLower(haystackBuilder.String())

	if !containsWithBoundaries(haystack, packageName) {
		return false
	}
	if ecosystem == "" {
		return true
	}
	return containsWithBoundaries(haystack, ecosystem)
}

func getShortID(report map[string]any) string {
	raw, ok := report["id"]
	if !ok || raw == nil {
		return ""
	}
	str := fmt.Sprintf("%v", raw)
	if len(str) > 64 {
		return str[:64]
	}
	return str
}

func checkDependencyDuplicate(candidate map[string]any, existingReports []map[string]any) map[string]any {
	cve, ecosystem, packageName, ok := dependencyIdentity(candidate)
	if !ok {
		return nil
	}

	foundLegacySameCVE := false
	for _, report := range existingReports {
		repCVE, repEcosystem, repPackageName, repOk := dependencyIdentity(report)
		if repOk {
			if repCVE != cve || repPackageName != packageName {
				continue
			}
			if repEcosystem == ecosystem {
				return map[string]any{
					"is_duplicate": true,
					"duplicate_id": getShortID(report),
					"confidence":   1.0,
					"reason":       "Same dependency CVE/package identity",
				}
			}
			if repEcosystem == "" || ecosystem == "" {
				return map[string]any{
					"is_duplicate": true,
					"duplicate_id": getShortID(report),
					"confidence":   1.0,
					"reason":       "Same dependency CVE/package identity with missing ecosystem",
				}
			}
			continue
		}

		if reportCVE(report) != cve {
			continue
		}
		foundLegacySameCVE = true
		if legacyReportMentionsPackage(report, ecosystem, packageName) {
			return map[string]any{
				"is_duplicate": true,
				"duplicate_id": getShortID(report),
				"confidence":   1.0,
				"reason":       "Same dependency CVE/package identity in legacy report",
			}
		}
	}

	if foundLegacySameCVE {
		return nil
	}

	packageLabel := packageName
	if ecosystem != "" {
		packageLabel = ecosystem + "/" + packageName
	}
	return map[string]any{
		"is_duplicate": false,
		"duplicate_id": "",
		"confidence":   1.0,
		"reason":       fmt.Sprintf("No existing dependency report for %s in %s", cve, packageLabel),
	}
}

func parseDedupeResponse(content string) (map[string]any, error) {
	text := strings.TrimSpace(content)
	if strings.HasPrefix(text, "```") {
		text = strings.TrimLeft(text, "`")
		if strings.HasPrefix(strings.ToLower(text), "json") {
			text = text[4:]
		}
		text = strings.TrimSpace(text)
	}

	start := strings.Index(text, "{")
	end := strings.LastIndex(text, "}")
	if start == -1 || end == -1 || end <= start {
		preview := content
		if len(preview) > 500 {
			preview = preview[:500]
		}
		return nil, fmt.Errorf("No JSON object found in dedupe response: %s", preview)
	}

	jsonText := text[start : end+1]
	var parsed map[string]any
	if err := json.Unmarshal([]byte(jsonText), &parsed); err != nil {
		return nil, err
	}

	duplicateID := ""
	if rawID, ok := parsed["duplicate_id"]; ok && rawID != nil {
		duplicateID = fmt.Sprintf("%v", rawID)
		if len(duplicateID) > 64 {
			duplicateID = duplicateID[:64]
		}
	}

	reason := ""
	if rawReason, ok := parsed["reason"]; ok && rawReason != nil {
		reason = fmt.Sprintf("%v", rawReason)
		if len(reason) > 500 {
			reason = reason[:500]
		}
	}

	confidence := 0.0
	if rawConf, ok := parsed["confidence"]; ok {
		switch v := rawConf.(type) {
		case float64:
			confidence = v
		case int:
			confidence = float64(v)
		case string:
			fmt.Sscanf(v, "%f", &confidence)
		}
	}

	isDuplicate := false
	if rawDup, ok := parsed["is_duplicate"]; ok {
		if b, ok := rawDup.(bool); ok {
			isDuplicate = b
		}
	}

	return map[string]any{
		"is_duplicate": isDuplicate,
		"duplicate_id": duplicateID,
		"confidence":   confidence,
		"reason":       reason,
	}, nil
}

func extractText(response *llm.ModelResponse) string {
	if response == nil {
		return ""
	}
	return response.ExtractText()
}

func CheckDuplicate(candidate map[string]any, existingReports []map[string]any) map[string]any {
	if len(existingReports) == 0 {
		return map[string]any{
			"is_duplicate": false,
			"duplicate_id": "",
			"confidence":   1.0,
			"reason":       "No existing reports to compare against",
		}
	}

	if dependencyDuplicate := checkDependencyDuplicate(candidate, existingReports); dependencyDuplicate != nil {
		return dependencyDuplicate
	}

	// Make sure we have a valid LLM setup
	settings := config.LoadSettings()
	dedupe := settings.Dedupe
	modelName := strings.TrimSpace(dedupe.Model)
	if modelName == "" {
		modelName = settings.Llm.Model
	}
	if modelName == "" {
		return map[string]any{
			"is_duplicate": false,
			"duplicate_id": "",
			"confidence":   0.0,
			"reason":       "No LLM model configured; skipping dedupe check",
		}
	}

	candidateCleaned := prepareReportForComparison(candidate)
	var existingCleaned []map[string]any
	for _, r := range existingReports {
		existingCleaned = append(existingCleaned, prepareReportForComparison(r))
	}

	comparisonData := map[string]any{
		"candidate":        candidateCleaned,
		"existing_reports": existingCleaned,
	}

	comparisonJSON, err := json.MarshalIndent(comparisonData, "", "  ")
	if err != nil {
		log.Printf("Error during vulnerability deduplication check: %v", err)
		return map[string]any{
			"is_duplicate": false,
			"duplicate_id": "",
			"confidence":   0.0,
			"reason":       fmt.Sprintf("Deduplication check failed: %v", err),
			"error":        err.Error(),
		}
	}

	userMsg := fmt.Sprintf("Compare this candidate vulnerability against existing reports:\n\n%s\n\nRespond with ONLY the JSON object described in the system prompt.", string(comparisonJSON))

	ConfigureSDKModelDefaults(settings)
	resolvedModel := strings.TrimSpace(modelName)
	provider := llm.NewApexProvider().GetModel(resolvedModel)

	ctx := context.Background()
	ms := dedupeModelSettings(dedupe, settings.Llm, resolvedModel, settings.Llm.Timeout)

	response, err := provider.GetResponse(ctx, DedupeSystemPrompt, userMsg, ms)
	if err != nil {
		log.Printf("Error during vulnerability deduplication check: %v", err)
		return map[string]any{
			"is_duplicate": false,
			"duplicate_id": "",
			"confidence":   0.0,
			"reason":       fmt.Sprintf("Deduplication check failed: %v", err),
			"error":        err.Error(),
		}
	}

	reportState := GetGlobalReportState()
	if reportState != nil && response.Usage != nil {
		u := &Usage{
			InputTokens:  response.Usage.PromptTokens,
			OutputTokens: response.Usage.CompletionTokens,
			TotalTokens:  response.Usage.TotalTokens,
		}
		reportState.RecordSDKUsage("dedupe", u, "dedupe", resolvedModel)
	}

	content := extractText(response)
	if content == "" {
		return map[string]any{
			"is_duplicate": false,
			"duplicate_id": "",
			"confidence":   0.0,
			"reason":       "Empty response from LLM",
		}
	}

	result, err := parseDedupeResponse(content)
	if err != nil {
		log.Printf("Error during vulnerability deduplication check: %v", err)
		return map[string]any{
			"is_duplicate": false,
			"duplicate_id": "",
			"confidence":   0.0,
			"reason":       fmt.Sprintf("Deduplication check failed: %v", err),
			"error":        err.Error(),
		}
	}

	reasonLog := ""
	if r, ok := result["reason"].(string); ok {
		reasonLog = r
		if len(reasonLog) > 100 {
			reasonLog = reasonLog[:100]
		}
	}

	log.Printf("Deduplication check: is_duplicate=%v, confidence=%.2f, reason=%s",
		result["is_duplicate"], result["confidence"], reasonLog)

	return result
}
