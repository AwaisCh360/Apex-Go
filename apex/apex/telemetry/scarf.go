package telemetry

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/AwaisCh360/Apex/apex/config"
	"github.com/AwaisCh360/Apex/apex/report"
)

var (
	scarfEndpoint = "https://apex.gateway.scarf.sh"
)

func scarfIsEnabled() bool {
	cfg := config.LoadSettings()
	return cfg.Telemetry.Enabled
}

func scarfSend(event string, properties map[string]interface{}) bool {
	if !scarfIsEnabled() {
		return false
	}

	version := "unknown"
	if v, ok := properties["apex_version"]; ok {
		version = fmt.Sprintf("%v", v)
	}
	delete(properties, "apex_version")

	path := fmt.Sprintf("/%s/%s", url.PathEscape(event), url.PathEscape(version))

	q := url.Values{}
	for k, v := range properties {
		if v == nil {
			q.Add(k, "")
		} else {
			q.Add(k, fmt.Sprintf("%v", v))
		}
	}

	reqURL := scarfEndpoint + path
	if len(q) > 0 {
		reqURL += "?" + q.Encode()
	}

	client := &http.Client{
		Timeout: ReadTimeout,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: ConnectTimeout,
			}).DialContext,
		},
	}
	resp, err := client.Post(reqURL, "application/json", nil)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

func ScarfStart(model string, scanMode string, isWhitebox bool, interactive bool, hasInstructions bool, authMode string) {
	if authMode == "" {
		authMode = "api_key"
	}
	if model == "" {
		model = "unknown"
	}
	if scanMode == "" {
		scanMode = "unknown"
	}
	scanType := "blackbox"
	if isWhitebox {
		scanType = "whitebox"
	}

	props := baseProps()
	props["session"] = SESSION_ID
	props["model"] = model
	props["auth_mode"] = authMode
	props["scan_mode"] = scanMode
	props["scan_type"] = scanType
	props["interactive"] = interactive
	props["has_instructions"] = hasInstructions
	props["first_run"] = isFirstRun()

	scarfSend("scan_started", props)
}

func ScarfFinding(severity string, cwe string, isCve bool) {
	if cwe == "" {
		cwe = "unknown"
	}
	props := baseProps()
	props["session"] = SESSION_ID
	props["severity"] = severity
	props["cwe"] = cwe
	props["is_cve"] = isCve
	scarfSend("finding_reported", props)
}

func ScarfSkillLoaded(skillName string) {
	props := baseProps()
	props["session"] = SESSION_ID
	props["skill"] = skillName
	scarfSend("skill_loaded", props)
}

func ScarfEnd(reportState *report.ReportState, exitReason string) {
	if reportState.ScarfScanEndedSent {
		return
	}
	if reportState.ScanEndedExitReason == "" {
		reportState.ScanEndedExitReason = exitReason
	}

	vulnerabilitiesCounts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	for _, v := range reportState.VulnerabilityReports {
		sev := "info"
		if s, ok := v["severity"].(string); ok && s != "" {
			sev = s
		}
		vulnerabilitiesCounts[sev]++
	}

	var duration float64 = 0
	if reportState.StartTime != "" {
		start, err := time.Parse(time.RFC3339, reportState.StartTime)
		if err == nil {
			endStr := reportState.EndTime
			if endStr == "" {
				endStr = time.Now().Format(time.RFC3339)
			}
			end, err := time.Parse(time.RFC3339, endStr)
			if err == nil {
				duration = end.Sub(start).Seconds()
			}
		}
	}

	props := baseProps()
	props["session"] = SESSION_ID

	if reportState.RunRecord != nil {
		if am, ok := reportState.RunRecord["auth_mode"].(string); ok {
			props["auth_mode"] = am
		} else {
			props["auth_mode"] = "api_key"
		}
	} else {
		props["auth_mode"] = "api_key"
	}

	props["exit_reason"] = reportState.ScanEndedExitReason
	props["duration_seconds"] = int(duration)
	props["vulnerabilities_total"] = len(reportState.VulnerabilityReports)
	for k, v := range vulnerabilitiesCounts {
		props["vulnerabilities_"+k] = v
	}

	usage := reportState.GetTotalLLMUsage()
	if usage != nil {
		if v, ok := usage["requests"]; ok {
			props["llm_requests"] = v
		}
		if v, ok := usage["input_tokens"]; ok {
			props["llm_input_tokens"] = v
		}
		if v, ok := usage["output_tokens"]; ok {
			props["llm_output_tokens"] = v
		}
		if v, ok := usage["total_tokens"]; ok {
			props["llm_tokens"] = v
		}
		if v, ok := usage["cost"]; ok {
			props["llm_cost"] = v
		}
	}

	reportState.ScarfScanEndedSent = scarfSend("scan_ended", props)
}

func ScarfError(errorType string) {
	props := baseProps()
	props["session"] = SESSION_ID
	props["error_type"] = errorType
	scarfSend("error", props)
}
