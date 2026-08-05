package viewer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings")

// Local stub for core/paths
func RunRecordPath(child string) string {
	return filepath.Join(child, "run.json")
}

var TerminalStatuses = map[string]bool{
	"completed":   true,
	"stopped":     true,
	"failed":      true,
	"interrupted": true,
}

var KnownSeverities = []string{"critical", "high", "medium", "low"}

// SeverityCounts buckets vulnerabilities into critical/high/medium/low counts.
// Mirrors the SPA's ``severityCounts``: severities are lowercased and
// trimmed, and anything outside the four known buckets (``info``,
// ``informational``, ``unknown``, missing, ...) folds into ``low`` so the
// shared UI renders cleanly.
func SeverityCounts(vulns []any) map[string]int {
	counts := make(map[string]int)
	for _, sev := range KnownSeverities {
		counts[sev] = 0
	}
	for _, vuln := range vulns {
		severity := ""
		if vMap, ok := vuln.(map[string]any); ok {
			if raw, exists := vMap["severity"]; exists && raw != nil {
				if s, isStr := raw.(string); isStr {
					severity = strings.ToLower(strings.TrimSpace(s))
				} else {
					severity = strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", raw)))
				}
			}
		}
		if _, exists := counts[severity]; !exists {
			severity = "low"
		}
		counts[severity]++
	}
	return counts
}

// BuildRunState returns the agent graph + full per-agent event/message stream.
// Reuses the shared ``TuiLiveView`` projection so the viewer and the TUI
// share one parser for ``agents.json`` + ``agents.db`` and never drift.
func BuildRunState(runDir string) map[string]any {
	// Local stub for BuildRunState since live_view is unported
	agents := make([]any, 0)
	events := make([]any, 0)
	return map[string]any{
		"agents": agents,
		"events": events,
	}
}

// ReadRunSummary returns the ``run.json`` record plus a computed ``finished`` flag.
func ReadRunSummary(runDir string) map[string]any {
	recordData := loadJSON(RunRecordPath(runDir), map[string]any{})
	record, ok := recordData.(map[string]any)
	if !ok {
		record = make(map[string]any)
	}

	statusStr := ""
	if statusRaw, exists := record["status"]; exists {
		if s, isStr := statusRaw.(string); isStr {
			statusStr = s
		}
	}

	finished := false
	if TerminalStatuses[statusStr] {
		if endTime, exists := record["end_time"]; exists && endTime != nil {
			switch v := endTime.(type) {
			case string:
				finished = v != ""
			case bool:
				finished = v
			case float64:
				finished = v != 0
			case int:
				finished = v != 0
			default:
				finished = true
			}
		}
	}

	result := make(map[string]any)
	for k, v := range record {
		result[k] = v
	}
	result["finished"] = finished
	return result
}

// PrimaryTarget returns the first target's original string from a run record, or nil.
func PrimaryTarget(record map[string]any) *string {
	targetsInfo, ok := record["targets_info"]
	if !ok {
		return nil
	}

	targets, ok := targetsInfo.([]any)
	if !ok {
		return nil
	}

	for _, entryRaw := range targets {
		entry, ok := entryRaw.(map[string]any)
		if !ok {
			continue
		}
		originalRaw, ok := entry["original"]
		if !ok {
			continue
		}
		originalStr, ok := originalRaw.(string)
		if ok && originalStr != "" {
			return &originalStr
		}
	}
	return nil
}

// ReadVulnerabilities returns the ``vulnerabilities.json`` list (empty until a scan writes it).
func ReadVulnerabilities(runDir string) []any {
	path := filepath.Join(runDir, "vulnerabilities.json")
	data := loadJSON(path, []any{})
	if list, ok := data.([]any); ok {
		return list
	}
	return []any{}
}

// ReadReportMarkdown returns the executive report markdown (empty until a scan writes it).
func ReadReportMarkdown(runDir string) string {
	reportPath := filepath.Join(runDir, "penetration_test_report.md")
	data, err := os.ReadFile(reportPath)
	if err != nil {
		return ""
	}
	return string(data)
}

func loadJSON(path string, defaultVal any) any {
	data, err := os.ReadFile(path)
	if err != nil {
		return defaultVal
	}
	var result any
	if err := json.Unmarshal(data, &result); err != nil {
		return defaultVal
	}
	return result
}
