package report

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/AwaisCh360/Apex/apex/config"
)

var (
	globalReportState *ReportState
	globalStateMu     sync.RWMutex
)

func GetGlobalReportState() *ReportState {
	globalStateMu.RLock()
	defer globalStateMu.RUnlock()
	return globalReportState
}

func SetGlobalReportState(reportState *ReportState) {
	globalStateMu.Lock()
	defer globalStateMu.Unlock()
	globalReportState = reportState
	StreamedOpenRouterCostsInst.Clear()
}

func ApexVersion() string {
	return "0.0.1" // Best-effort package version
}

func parseRepoFullName(uri string) string {
	text := strings.TrimSpace(uri)
	text = strings.TrimSuffix(text, ".git")
	if text == "" {
		return ""
	}
	if strings.Contains(text, "@") && strings.Contains(strings.SplitN(text, "@", 2)[1], ":") {
		parts := strings.SplitN(text, "@", 2)
		parts2 := strings.SplitN(parts[1], ":", 2)
		text = parts2[1]
	} else if strings.Contains(text, "://") {
		parts := strings.SplitN(text, "://", 2)
		hostAndPath := parts[1]
		if strings.Contains(hostAndPath, "/") {
			parts2 := strings.SplitN(hostAndPath, "/", 2)
			text = parts2[1]
		} else {
			text = hostAndPath
		}
	}
	parts := strings.Split(text, "/")
	var validParts []string
	for _, p := range parts {
		if p != "" {
			validParts = append(validParts, p)
		}
	}
	if len(validParts) >= 2 {
		return validParts[len(validParts)-2] + "/" + validParts[len(validParts)-1]
	}
	return ""
}

func gitHead(repoPath string) (string, string) {
	info, err := os.Stat(repoPath)
	if err != nil || !info.IsDir() {
		return "", ""
	}

	runGit := func(args ...string) string {
		cmdArgs := append([]string{"-C", repoPath}, args...)
		cmd := exec.Command("git", cmdArgs...)
		out, err := cmd.Output()
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(out))
	}

	commit := runGit("rev-parse", "HEAD")
	branch := runGit("rev-parse", "--abbrev-ref", "HEAD")
	if branch == "HEAD" {
		branch = ""
	}
	if commit == "" {
		return "", ""
	}
	return commit, branch
}

type ReportState struct {
	RunName                    string
	RunID                      string
	StartTime                  string
	EndTime                    string
	VulnerabilityReports       []map[string]interface{}
	FinalScanResult            string
	ScanResults                map[string]interface{}
	ScanConfig                 map[string]interface{}
	llmUsage                   *LLMUsageLedger
	RunRecord                  map[string]interface{}
	runDir                     string
	savedVulnIDs               map[string]bool
	CaidoURL                   string
	VulnerabilityFoundCallback func(map[string]interface{})
	sarifRepoCtx               map[string]interface{}
	sarifRepoCtxReady          bool
	PosthogScanEndedSent       bool
	ScarfScanEndedSent         bool
	ScanEndedExitReason        string
	mu                         sync.Mutex
}

func NewReportState(runName string) *ReportState {
	runID := runName
	if runID == "" {
		runID = fmt.Sprintf("run-%d", time.Now().UnixNano()) // stub uuid
	}
	authMode := AuthMode(LoadSettingsModel())
	llmUsage := NewLLMUsageLedger()
	llmUsage.ZeroCost = (authMode == "subscription")

	rs := &ReportState{
		RunName:              runName,
		RunID:                runID,
		StartTime:            time.Now().UTC().Format(time.RFC3339),
		VulnerabilityReports: make([]map[string]interface{}, 0),
		llmUsage:             llmUsage,
		savedVulnIDs:         make(map[string]bool),
		RunRecord: map[string]interface{}{
			"run_id":       runID,
			"run_name":     runName,
			"start_time":   time.Now().UTC().Format(time.RFC3339),
			"end_time":     nil,
			"status":       "running",
			"auth_mode":    authMode,
			"targets_info": []interface{}{},
		},
	}
	rs.RunRecord["llm_usage"] = rs.buildLLMUsageRecord()
	return rs
}

func (rs *ReportState) GetRunDir() string {
	if rs.runDir == "" {
		runDirName := rs.RunName
		if runDirName == "" {
			runDirName = rs.RunID
		}
		rs.runDir = runDirFor(runDirName)
		os.MkdirAll(rs.runDir, 0755)
	}
	return rs.runDir
}

func (rs *ReportState) HydrateFromRunDir() error {
	runDir := rs.GetRunDir()

	record, err := ReadRunRecord(rs.runDir)
	if err == nil && record != nil {
		if val, ok := record["status"].(string); ok {
			rs.RunRecord["status"] = val
		}
		if st, ok := record["start_time"].(string); ok {
			rs.StartTime = st
		}
		if et, ok := record["end_time"].(string); ok {
			rs.EndTime = et
		}
		if sr, ok := record["scan_results"].(map[string]interface{}); ok {
			rs.ScanResults = sr
			rs.FinalScanResult = rs.formatFinalScanResult(sr)
		}
		rs.hydrateLLMUsage(record["llm_usage"])
	}

	jsonPath := filepath.Join(runDir, "vulnerabilities.json")
	if _, err := os.Stat(jsonPath); err == nil {
		content, err := os.ReadFile(jsonPath)
		if err != nil {
			return fmt.Errorf("vulnerabilities.json at %s is corrupt (%v); refusing to start fresh", jsonPath, err)
		}
		var rawReports []interface{}
		if err := json.Unmarshal(content, &rawReports); err != nil {
			return fmt.Errorf("vulnerabilities.json at %s is corrupt (%v); refusing to start fresh", jsonPath, err)
		}

		for _, raw := range rawReports {
			if rMap, ok := raw.(map[string]interface{}); ok {
				rs.VulnerabilityReports = append(rs.VulnerabilityReports, rMap)
				if rid, ok := rMap["id"].(string); ok {
					rs.savedVulnIDs[rid] = true
				}
			}
		}
	}
	return nil
}

type AddVulnerabilityReportArgs struct {
	Title              string
	Severity           string
	Description        string
	Impact             string
	Target             string
	TechnicalAnalysis  *string
	PocDescription     string
	PocScriptCode      string
	RemediationSteps   string
	Evidence           string
	Assumptions        string
	FixEffort          string
	Cvss               *float64
	CvssBreakdown      map[string]string
	Endpoint           *string
	Method             *string
	Cve                *string
	Cwe                *string
	CodeLocations      []map[string]interface{}
	FixPrBody          *string
	FindingClass       string
	DependencyMetadata map[string]string
	AgentId            *string
	AgentName          *string
}

func (rs *ReportState) AddVulnerabilityReport(args AddVulnerabilityReportArgs) (string, error) {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	reportID := fmt.Sprintf("vuln-%04d", len(rs.VulnerabilityReports)+1)
	report := map[string]interface{}{
		"id":        reportID,
		"title":     strings.TrimSpace(args.Title),
		"severity":  strings.ToLower(strings.TrimSpace(args.Severity)),
		"timestamp": time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
	}

	if args.Description != "" { report["description"] = strings.TrimSpace(args.Description) }
	if args.Impact != "" { report["impact"] = strings.TrimSpace(args.Impact) }
	if args.Target != "" { report["target"] = strings.TrimSpace(args.Target) }
	if args.TechnicalAnalysis != nil && *args.TechnicalAnalysis != "" { report["technical_analysis"] = strings.TrimSpace(*args.TechnicalAnalysis) }
	if args.PocDescription != "" { report["poc_description"] = strings.TrimSpace(args.PocDescription) }
	if args.PocScriptCode != "" { report["poc_script_code"] = strings.TrimSpace(args.PocScriptCode) }
	if args.RemediationSteps != "" { report["remediation_steps"] = strings.TrimSpace(args.RemediationSteps) }
	if args.Evidence != "" { report["evidence"] = strings.TrimSpace(args.Evidence) }
	if args.Assumptions != "" { report["assumptions"] = strings.TrimSpace(args.Assumptions) }
	if args.FixEffort != "" { report["fix_effort"] = strings.ToLower(strings.TrimSpace(args.FixEffort)) }
	if args.Cvss != nil { report["cvss"] = *args.Cvss }
	if args.CvssBreakdown != nil { report["cvss_breakdown"] = args.CvssBreakdown }
	if args.Endpoint != nil && *args.Endpoint != "" { report["endpoint"] = strings.TrimSpace(*args.Endpoint) }
	if args.Method != nil && *args.Method != "" { report["method"] = strings.TrimSpace(*args.Method) }
	if args.Cve != nil && *args.Cve != "" { report["cve"] = strings.TrimSpace(*args.Cve) }
	if args.Cwe != nil && *args.Cwe != "" { report["cwe"] = strings.TrimSpace(*args.Cwe) }
	if args.CodeLocations != nil { report["code_locations"] = args.CodeLocations }
	if args.FixPrBody != nil && *args.FixPrBody != "" { report["fix_pr_body"] = strings.TrimSpace(*args.FixPrBody) }

	findingClass := "dynamic"
	if args.FindingClass != "" { findingClass = args.FindingClass }
	report["finding_class"] = strings.ToLower(strings.TrimSpace(findingClass))

	if args.DependencyMetadata != nil { report["dependency_metadata"] = args.DependencyMetadata }
	if args.AgentId != nil && *args.AgentId != "" { if args.AgentId != nil { report["agent_id"] = *args.AgentId } }
	if args.AgentName != nil && *args.AgentName != "" { if args.AgentName != nil { report["agent_name"] = *args.AgentName } }

	rs.VulnerabilityReports = append(rs.VulnerabilityReports, report)

	
	cweStr := ""
	if args.Cwe != nil { cweStr = *args.Cwe }
	posthog.Finding(args.Severity, cweStr, args.Cve != nil && *args.Cve != "")

	scarf.Finding(args.Severity, cweStr, args.Cve != nil && *args.Cve != "")

	if rs.VulnerabilityFoundCallback != nil {
		rs.VulnerabilityFoundCallback(report)
	}

	rs.saveRunData(false, "")
	return reportID, nil
}

func (rs *ReportState) GetExistingVulnerabilities() []map[string]interface{} {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	res := make([]map[string]interface{}, len(rs.VulnerabilityReports))
	for i, r := range rs.VulnerabilityReports {
		res[i] = r
	}
	return res
}

func (rs *ReportState) RecordSDKUsage(agentID string, usage *Usage, agentName string, model string) {
	if rs.llmUsage.Record(agentID, usage, agentName, model) {
		rs.SaveRunData()
	}
}

func (rs *ReportState) RecordObservedLLMCost(cost float64) {
	rs.llmUsage.RecordObservedCost(cost)
}

func (rs *ReportState) GetTotalLLMUsage() map[string]interface{} {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if u, ok := rs.RunRecord["llm_usage"].(map[string]interface{}); ok && u != nil {
		return u
	}
	return rs.buildLLMUsageRecord()
}

func (rs *ReportState) GetTotalLLMCost() float64 {
	return rs.llmUsage.TotalCost()
}

func (rs *ReportState) UpdateScanFinalFields(executiveSummary, methodology, technicalAnalysis, recommendations string) {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	rs.ScanResults = map[string]interface{}{
		"scan_completed":     true,
		"executive_summary":  strings.TrimSpace(executiveSummary),
		"methodology":        strings.TrimSpace(methodology),
		"technical_analysis": strings.TrimSpace(technicalAnalysis),
		"recommendations":    strings.TrimSpace(recommendations),
		"success":            true,
	}

	rs.FinalScanResult = rs.formatFinalScanResult(rs.ScanResults)
	rs.RunRecord["scan_results"] = rs.ScanResults

	rs.saveRunData(true, "")
	posthog.End(rs, "finished_by_tool")
	scarf.End(rs, "finished_by_tool")
}

func (rs *ReportState) SetScanConfig(config map[string]interface{}) {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	rs.ScanConfig = config
	rs.RunRecord["status"] = "running"
	rs.RunRecord["end_time"] = nil
	delete(rs.RunRecord, "scan_results")
	rs.EndTime = ""
	rs.ScanResults = nil
	rs.FinalScanResult = ""

	if targets, ok := config["targets"]; ok { rs.RunRecord["targets_info"] = targets } else { rs.RunRecord["targets_info"] = []interface{}{} }
	if inst, ok := config["user_instructions"]; ok { rs.RunRecord["instruction"] = inst } else { rs.RunRecord["instruction"] = "" }
	if mode, ok := config["scan_mode"]; ok { rs.RunRecord["scan_mode"] = mode } else { rs.RunRecord["scan_mode"] = "deep" }
	if scope, ok := config["diff_scope"]; ok { rs.RunRecord["diff_scope"] = scope } else { rs.RunRecord["diff_scope"] = map[string]interface{}{"active": false} }
	if nonInt, ok := config["non_interactive"]; ok { rs.RunRecord["non_interactive"] = nonInt } else { rs.RunRecord["non_interactive"] = false }
	if locs, ok := config["local_sources"]; ok { rs.RunRecord["local_sources"] = locs } else { rs.RunRecord["local_sources"] = []interface{}{} }
	if sm, ok := config["scope_mode"]; ok { rs.RunRecord["scope_mode"] = sm } else { rs.RunRecord["scope_mode"] = "auto" }
	if db, ok := config["diff_base"]; ok { rs.RunRecord["diff_base"] = db }
}

func (rs *ReportState) SaveRunData() {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.saveRunData(false, "")
}

func (rs *ReportState) saveRunData(markComplete bool, status string) {
	if markComplete {
		rs.EndTime = time.Now().UTC().Format(time.RFC3339)
		rs.RunRecord["end_time"] = rs.EndTime
		rs.RunRecord["status"] = "completed"
	} else if status != "" {
		if rs.RunRecord["status"] != "completed" {
			currStatus, _ := rs.RunRecord["status"].(string)
			if status == "stopped" && (currStatus == "failed" || currStatus == "interrupted") {
				status = currStatus
			}
			if rs.EndTime == "" {
				rs.EndTime = time.Now().UTC().Format(time.RFC3339)
			}
			rs.RunRecord["end_time"] = rs.EndTime
			rs.RunRecord["status"] = status
		}
	}

	rs.syncLLMUsageRecord()
	rs.saveArtifacts()
}

func (rs *ReportState) Cleanup(status string) {
	if status == "" {
		status = "stopped"
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.saveRunData(false, status)
}

func (rs *ReportState) formatFinalScanResult(scanResults map[string]interface{}) string {
	execSum, _ := scanResults["executive_summary"].(string)
	meth, _ := scanResults["methodology"].(string)
	tech, _ := scanResults["technical_analysis"].(string)
	rec, _ := scanResults["recommendations"].(string)

	return fmt.Sprintf("# Executive Summary\n\n%s\n\n# Methodology\n\n%s\n\n# Technical Analysis\n\n%s\n\n# Recommendations\n\n%s\n",
		strings.TrimSpace(execSum),
		strings.TrimSpace(meth),
		strings.TrimSpace(tech),
		strings.TrimSpace(rec),
	)
}

func (rs *ReportState) saveArtifacts() {
	runDir := rs.GetRunDir()
	os.MkdirAll(runDir, 0755)

	if rs.FinalScanResult != "" {
		WriteExecutiveReport(runDir, rs.FinalScanResult)
	}

	if len(rs.VulnerabilityReports) > 0 {
		WriteVulnerabilities(runDir, rs.VulnerabilityReports, rs.savedVulnIDs)
	}

	_, _ = WriteSARIF(runDir, rs.VulnerabilityReports, ApexVersion(), rs.sarifRepositoryContext(), "report.sarif")
	WriteRunRecord(runDir, rs.RunRecord)
}

func (rs *ReportState) sarifRepositoryContext() map[string]interface{} {
	if !rs.sarifRepoCtxReady {
		rs.sarifRepoCtx = rs.deriveRepositoryContext()
		rs.sarifRepoCtxReady = true
	}
	return rs.sarifRepoCtx
}

func (rs *ReportState) deriveRepositoryContext() map[string]interface{} {
	targetsRaw := rs.RunRecord["targets_info"]
	targets, ok := targetsRaw.([]interface{})
	if !ok {
		return nil
	}

	var repoTargets []map[string]interface{}
	for _, tRaw := range targets {
		if t, ok := tRaw.(map[string]interface{}); ok {
			if t["type"] == "repository" {
				repoTargets = append(repoTargets, t)
			}
		}
	}
	if len(repoTargets) != 1 {
		return nil
	}
	target := repoTargets[0]
	details, ok := target["details"].(map[string]interface{})
	if !ok {
		return nil
	}
	uriRaw, _ := details["target_repo"].(string)
	uri := strings.TrimSpace(uriRaw)
	if uri == "" {
		return nil
	}

	context := map[string]interface{}{"repositoryUri": uri}
	fullName := parseRepoFullName(uri)
	if fullName != "" {
		context["repositoryFullName"] = fullName
	}
	clonedRaw, _ := details["cloned_repo_path"].(string)
	cloned := strings.TrimSpace(clonedRaw)
	if cloned != "" {
		commit, branch := gitHead(cloned)
		if commit != "" {
			context["commitSha"] = commit
		}
		if branch != "" {
			context["branch"] = branch
			context["ref"] = fmt.Sprintf("refs/heads/%s", branch)
		}
	}
	return context
}

func (rs *ReportState) syncLLMUsageRecord() {
	rs.RunRecord["llm_usage"] = rs.buildLLMUsageRecord()
}

func (rs *ReportState) buildLLMUsageRecord() map[string]interface{} {
	return rs.llmUsage.ToRecord()
}

func (rs *ReportState) hydrateLLMUsage(rawUsage interface{}) {
	rs.llmUsage.Hydrate(rawUsage)
	rs.syncLLMUsageRecord()
}

func openrouterStreamCost(usage interface{}) *float64 {
	usageMap, ok := usage.(map[string]interface{})
	if !ok {
		return nil
	}

	var total float64
	costFound := false

	if cost, ok := usageMap["cost"].(float64); ok && cost > 0 {
		total += cost
		costFound = true
	}

	if isByok, ok := usageMap["is_byok"].(bool); ok && isByok {
		if costDetails, ok := usageMap["cost_details"].(map[string]interface{}); ok {
			if upstream, ok := costDetails["upstream_inference_cost"].(float64); ok && upstream > 0 {
				total += upstream
				costFound = true
			}
		}
	}

	if !costFound || total <= 0 {
		return nil
	}
	return &total
}

func responseID(completionResponse interface{}) string {
	if cr, ok := completionResponse.(map[string]interface{}); ok {
		if id, ok := cr["id"].(string); ok {
			return id
		}
	}
	return ""
}

type StreamedOpenRouterCosts struct {
	costs map[string]float64
	mu    sync.Mutex
}

func NewStreamedOpenRouterCosts() *StreamedOpenRouterCosts {
	return &StreamedOpenRouterCosts{costs: make(map[string]float64)}
}

func (s *StreamedOpenRouterCosts) Remember(responseId interface{}, usage interface{}) {
	cost := openrouterStreamCost(usage)
	idStr, _ := responseId.(string)
	if cost == nil || idStr == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.costs[idStr] = *cost
}

func (s *StreamedOpenRouterCosts) Take(completionResponse interface{}) *float64 {
	idStr := responseID(completionResponse)
	if idStr == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if cost, ok := s.costs[idStr]; ok {
		delete(s.costs, idStr)
		return &cost
	}
	return nil
}

func (s *StreamedOpenRouterCosts) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.costs = make(map[string]float64)
}

var StreamedOpenRouterCostsInst = NewStreamedOpenRouterCosts()

func LitellmCostCallback(kwargs map[string]interface{}, completionResponse interface{}, startTime interface{}, endTime interface{}) {
	var cost *float64

	if rc, ok := kwargs["response_cost"].(float64); ok && rc > 0 {
		cost = &rc
	}

	if cost == nil {
		if cr, ok := completionResponse.(map[string]interface{}); ok {
			if hp, ok := cr["_hidden_params"].(map[string]interface{}); ok {
				if rc, ok := hp["response_cost"].(float64); ok && rc > 0 {
					cost = &rc
				} else if headers, ok := hp["additional_headers"].(map[string]interface{}); ok {
					if raw, ok := headers["llm_provider-x-litellm-response-cost"].(string); ok {
						var parsed float64
						if _, err := fmt.Sscanf(raw, "%f", &parsed); err == nil && parsed > 0 {
							cost = &parsed
						}
					}
				}
			}
		}
	}

	if cost == nil {
		cost = usageReportedCost(completionResponse)
	}

	if cost == nil {
		cost = StreamedOpenRouterCostsInst.Take(completionResponse)
	}

	if cost == nil {
		cost = estimateResponseCost(kwargs, completionResponse)
	}

	if cost == nil || *cost <= 0 {
		return
	}
	rs := GetGlobalReportState()
	if rs == nil {
		return
	}
	rs.RecordObservedLLMCost(*cost)
}

func usageReportedCost(completionResponse interface{}) *float64 {
	cr, ok := completionResponse.(map[string]interface{})
	if !ok {
		return nil
	}
	usage, ok := cr["usage"].(map[string]interface{})
	if !ok {
		return nil
	}

	var total float64
	costFound := false

	if cost, ok := usage["cost"].(float64); ok && cost > 0 {
		total += cost
		costFound = true
	}

	if isByok, _ := usage["is_byok"].(bool); isByok {
		if costDetails, ok := usage["cost_details"].(map[string]interface{}); ok {
			if upstream, ok := costDetails["upstream_inference_cost"].(float64); ok && upstream > 0 {
				total += upstream
				costFound = true
			}
		}
	}

	if !costFound || total <= 0 {
		return nil
	}
	return &total
}

func estimateResponseCost(kwargs map[string]interface{}, completionResponse interface{}) *float64 {
	cr, ok := completionResponse.(map[string]interface{})
	if !ok {
		return nil
	}
	model, _ := kwargs["model"].(string)
	if model == "" {
		model, _ = cr["model"].(string)
	}

	usagePayload := usagePayload(completionResponse)
	if usagePayload == nil {
		return nil
	}

	cost, err := CompletionCost(usagePayload, model)
	if err != nil || cost <= 0 {
		return nil
	}
	return &cost
}

func usagePayload(completionResponse interface{}) map[string]interface{} {
	cr, ok := completionResponse.(map[string]interface{})
	if !ok {
		return nil
	}
	usage, ok := cr["usage"].(map[string]interface{})
	if !ok {
		return nil
	}

	if tt, _ := usage["total_tokens"].(float64); tt == 0 {
		pt, _ := usage["prompt_tokens"].(float64)
		ct, _ := usage["completion_tokens"].(float64)
		if pt == 0 && ct == 0 {
			return nil
		}
	}
	return usage
}

// ----------------------------------------------------------------------------
// Stubs for missing dependencies so the file compiles
// ----------------------------------------------------------------------------

func runDirFor(runName string) string {
	base, _ := os.Getwd()
	return filepath.Join(base, "apex_runs", runName)
}

func AuthMode(model string) string { return config.AuthMode(model) }
func LoadSettingsModel() string    { return config.LoadSettings().Llm.Model }

// PostHog and Scarf telemetry clients are intentionally stubbed out.
// They require external dependencies that are not currently ported to Go.
// A full telemetry package should be implemented in the future if this
// behavior needs to be restored to match Python precisely.

type PosthogStub struct{}
func (p *PosthogStub) Finding(severity string, cwe string, isCve bool) {}
func (p *PosthogStub) End(state *ReportState, exitReason string) {}
var posthog = &PosthogStub{}

type ScarfStub struct{}
func (s *ScarfStub) Finding(severity string, cwe string, isCve bool) {}
func (s *ScarfStub) End(state *ReportState, exitReason string) {}
var scarf = &ScarfStub{}
