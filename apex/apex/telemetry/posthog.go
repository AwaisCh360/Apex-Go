package telemetry

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"time"

	"github.com/AwaisCh360/Apex/apex/config"
	"github.com/AwaisCh360/Apex/apex/report"
)

var (
	posthogAPIKey = "phc_7rO3XRuNT5sgSKAl6HDIrWdSGh1COzxw0vxVIAR6vVZ"
	posthogHost   = "https://us.i.posthog.com"
)

func posthogIsEnabled() bool {
	cfg := config.LoadSettings()
	return cfg.Telemetry.Enabled
}

func posthogSend(event string, properties map[string]interface{}) bool {
	if !posthogIsEnabled() {
		return false
	}

	payload := map[string]interface{}{
		"api_key":     posthogAPIKey,
		"event":       event,
		"distinct_id": SESSION_ID,
		"properties":  properties,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return false
	}

	client := &http.Client{
		Timeout: ReadTimeout,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: ConnectTimeout,
			}).DialContext,
		},
	}
	resp, err := client.Post(posthogHost+"/capture/", "application/json", bytes.NewBuffer(body))
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

func PosthogStart(model string, scanMode string, isWhitebox bool, interactive bool, hasInstructions bool, authMode string) {
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
	props["model"] = model
	props["auth_mode"] = authMode
	props["scan_mode"] = scanMode
	props["scan_type"] = scanType
	props["interactive"] = interactive
	props["has_instructions"] = hasInstructions
	props["first_run"] = isFirstRun()

	posthogSend("scan_started", props)
}

func PosthogFinding(severity string, cwe string, isCve bool) {
	if cwe == "" {
		cwe = "unknown"
	}
	props := baseProps()
	props["severity"] = severity
	props["cwe"] = cwe
	props["is_cve"] = isCve
	posthogSend("finding_reported", props)
}

func PosthogSkillLoaded(skillName string) {
	props := baseProps()
	props["skill"] = skillName
	posthogSend("skill_loaded", props)
}

func PosthogEnd(reportState *report.ReportState, exitReason string) {
	if reportState.PosthogScanEndedSent {
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

	reportState.PosthogScanEndedSent = posthogSend("scan_ended", props)
}

func PosthogViewerOpened(source string, live bool) {
	props := baseProps()
	props["source"] = source
	props["live"] = live
	posthogSend("viewer_opened", props)
}

func PosthogViewerCtaClicked(cta string, surface string) {
	props := baseProps()
	if len(cta) > 64 {
		cta = cta[:64]
	}
	props["cta"] = cta
	if surface != "" {
		if len(surface) > 64 {
			surface = surface[:64]
		}
		props["surface"] = surface
	}
	posthogSend("viewer_cta_clicked", props)
}

func PosthogViewerEmailEvent(step string, purpose string) {
	validSteps := map[string]bool{"email_submitted": true, "email_verified": true, "report_sent": true, "work_email_required": true}
	if !validSteps[step] {
		return
	}
	props := baseProps()
	if purpose != "" {
		props["purpose"] = purpose
	}
	posthogSend("viewer_"+step, props)
}

func PosthogViewerFeedbackSubmitted() {
	posthogSend("viewer_feedback_submitted", baseProps())
}

func PosthogViewerAgentSteered() {
	posthogSend("viewer_agent_steered", baseProps())
}

func PosthogError(errorType string) {
	props := baseProps()
	props["error_type"] = errorType
	posthogSend("error", props)
}
