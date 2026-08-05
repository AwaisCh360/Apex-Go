package reporting

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// -----------------------------------------------------------------------------
// Core interfaces / pluggable dependencies
// -----------------------------------------------------------------------------

type RunContextWrapper interface {
	GetContext() map[string]interface{}
}

type NamesProvider interface {
	GetNames() map[string]string
}

type AddVulnerabilityReportArgs struct {
	Title              string
	Severity           string
	Description        string
	Impact             string
	Target             string
	TechnicalAnalysis  *string
	PocDescription     *string
	PocScriptCode      *string
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

type GlobalReportState interface {
	GetExistingVulnerabilities() []map[string]interface{}
	AddVulnerabilityReport(args AddVulnerabilityReportArgs) (string, error)
}

var (
	GlobalState        GlobalReportState
	CheckDuplicateFunc func(candidate map[string]interface{}, existing []map[string]interface{}) map[string]interface{}
	logger             = log.Default()
)

func getGlobalReportState() GlobalReportState {
	return GlobalState
}

func checkDuplicate(
	candidate map[string]interface{},
	existing []map[string]interface{},
) map[string]interface{} {
	if CheckDuplicateFunc != nil {
		return CheckDuplicateFunc(candidate, existing)
	}

	// Default no-duplicate behavior. Replace by setting CheckDuplicateFunc.
	return map[string]interface{}{
		"is_duplicate": false,
	}
}

// -----------------------------------------------------------------------------
// Regexes
// -----------------------------------------------------------------------------

var (
	cveExtractRe  = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)
	cveValidateRe = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	cweExtractRe  = regexp.MustCompile(`CWE-\d+`)
	cweValidateRe = regexp.MustCompile(`^CWE-\d+$`)
)

// -----------------------------------------------------------------------------
// Constants / validation metadata
// -----------------------------------------------------------------------------

const reportDescriptionPreviewChars = 280

var requiredFieldsOrder = []string{
	"title",
	"description",
	"impact",
	"target",
	"technical_analysis",
	"poc_description",
	"poc_script_code",
	"remediation_steps",
	"evidence",
	"assumptions",
}

var requiredFieldMessages = map[string]string{
	"title":              "Title cannot be empty",
	"description":        "Description cannot be empty",
	"impact":             "Impact cannot be empty",
	"target":             "Target cannot be empty",
	"technical_analysis": "Technical analysis cannot be empty",
	"poc_description":    "PoC description cannot be empty",
	"poc_script_code":    "PoC script/code is REQUIRED - provide the actual exploit/payload",
	"remediation_steps":  "Remediation steps cannot be empty",
	"evidence":           "Evidence cannot be empty - provide concrete proof of the finding",
	"assumptions":        "Assumptions cannot be empty - state exploitability prerequisites",
}

var cvssMetricOrder = []string{
	"attack_vector",
	"attack_complexity",
	"privileges_required",
	"user_interaction",
	"scope",
	"confidentiality",
	"integrity",
	"availability",
}

var cvssValidValues = map[string][]string{
	"attack_vector":       {"N", "A", "L", "P"},
	"attack_complexity":   {"L", "H"},
	"privileges_required": {"N", "L", "H"},
	"user_interaction":    {"N", "R"},
	"scope":               {"U", "C"},
	"confidentiality":     {"N", "L", "H"},
	"integrity":           {"N", "L", "H"},
	"availability":        {"N", "L", "H"},
}

var validFixEffort = map[string]bool{
	"trivial": true,
	"low":     true,
	"medium":  true,
	"high":    true,
}

var severityRankOrder = []string{
	"critical",
	"high",
	"medium",
	"low",
	"info",
	"none",
}

var severityOrder = map[string]int{
	"critical": 0,
	"high":     1,
	"medium":   2,
	"low":      3,
	"info":     4,
	"none":     5,
}

var validSeverities = map[string]bool{
	"critical": true,
	"high":     true,
	"medium":   true,
	"low":      true,
	"info":     true,
	"none":     true,
}

var validFindingClasses = map[string]bool{
	"dynamic":        true,
	"dependency_cve": true,
}

var reportSummaryFields = []string{
	"id",
	"title",
	"severity",
	"cvss",
	"finding_class",
	"cve",
	"cwe",
	"target",
	"endpoint",
	"method",
	"fix_effort",
	"agent_name",
	"timestamp",
}

var depSeverityFromCVSS = []struct {
	min   float64
	max   float64
	label string
}{
	{9.0, 10.0, "critical"},
	{7.0, 9.0, "high"},
	{4.0, 7.0, "medium"},
	{0.0, 4.0, "low"},
}

// CVSS v3.1 base metric weights.
var (
	cvssAVWeights = map[string]float64{
		"N": 0.85,
		"A": 0.62,
		"L": 0.55,
		"P": 0.20,
	}
	cvssACWeights = map[string]float64{
		"L": 0.77,
		"H": 0.44,
	}
	cvssUIWeights = map[string]float64{
		"N": 0.85,
		"R": 0.62,
	}
	cvssCIAWeights = map[string]float64{
		"N": 0.0,
		"L": 0.22,
		"H": 0.56,
	}
)

// -----------------------------------------------------------------------------
// Public tool argument structs
// -----------------------------------------------------------------------------

type CreateVulnerabilityReportArgs struct {
	Title             string                   `json:"title"`
	Description       string                   `json:"description"`
	Impact            string                   `json:"impact"`
	Target            string                   `json:"target"`
	TechnicalAnalysis string                   `json:"technical_analysis"`
	PocDescription    string                   `json:"poc_description"`
	PocScriptCode     string                   `json:"poc_script_code"`
	RemediationSteps  string                   `json:"remediation_steps"`
	Evidence          string                   `json:"evidence"`
	Assumptions       string                   `json:"assumptions"`
	FixEffort         string                   `json:"fix_effort"`
	CvssBreakdown     map[string]*string       `json:"cvss_breakdown"`
	Endpoint          *string                  `json:"endpoint"`
	Method            *string                  `json:"method"`
	Cve               *string                  `json:"cve"`
	Cwe               *string                  `json:"cwe"`
	CodeLocations     []map[string]interface{} `json:"code_locations"`
	FixPrBody         *string                  `json:"fix_pr_body"`
}

type CreateDependencyReportArgs struct {
	Title             string   `json:"title"`
	Description       string   `json:"description"`
	Target            string   `json:"target"`
	Cve               string   `json:"cve"`
	PackageName       string   `json:"package_name"`
	InstalledVersion  string   `json:"installed_version"`
	AdvisoryCvss      *float64 `json:"advisory_cvss"`
	Impact            string   `json:"impact"`
	RemediationSteps  string   `json:"remediation_steps"`
	Assumptions       string   `json:"assumptions"`
	PackageEcosystem  string   `json:"package_ecosystem"`
	FixedVersion      *string  `json:"fixed_version"`
	Cwe               *string  `json:"cwe"`
	TechnicalAnalysis *string  `json:"technical_analysis"`
	FixEffort         *string  `json:"fix_effort"`
}

type ListReportsArgs struct {
	Severity       *string `json:"severity"`
	FindingClass   *string `json:"finding_class"`
	Target         *string `json:"target"`
	Search         *string `json:"search"`
	IncludeDetails bool    `json:"include_details"`
}

type GetReportArgs struct {
	ReportId string `json:"report_id"`
}

// -----------------------------------------------------------------------------
// Public tool entrypoints
// -----------------------------------------------------------------------------

func CreateVulnerabilityReport(ctx RunContextWrapper, args CreateVulnerabilityReportArgs) string {
	agentID, agentName := callerIdentity(ctx)

	result := doCreate(
		args.Title,
		args.Description,
		args.Impact,
		args.Target,
		args.TechnicalAnalysis,
		args.PocDescription,
		args.PocScriptCode,
		args.RemediationSteps,
		args.Evidence,
		args.Assumptions,
		args.FixEffort,
		args.CvssBreakdown,
		args.Endpoint,
		args.Method,
		args.Cve,
		args.Cwe,
		args.CodeLocations,
		args.FixPrBody,
		agentID,
		agentName,
	)

	return toJSONString(result)
}

func CreateDependencyReport(ctx RunContextWrapper, args CreateDependencyReportArgs) string {
	agentID, agentName := callerIdentity(ctx)

	fixEffort := "low"
	if args.FixEffort != nil {
		fixEffort = *args.FixEffort
	}

	result := doCreateDependency(
		args.Title,
		args.Description,
		args.Target,
		args.Cve,
		args.PackageName,
		args.InstalledVersion,
		args.Impact,
		args.RemediationSteps,
		args.Assumptions,
		args.PackageEcosystem,
		args.FixedVersion,
		args.Cwe,
		args.AdvisoryCvss,
		args.TechnicalAnalysis,
		fixEffort,
		agentID,
		agentName,
	)

	return toJSONString(result)
}

func ListReports(ctx RunContextWrapper, args ListReportsArgs) string {
	agentID, _ := callerIdentity(ctx)

	result := doListReports(
		args.Severity,
		args.FindingClass,
		args.Target,
		args.Search,
		args.IncludeDetails,
		agentID,
	)

	return toJSONString(result)
}

func GetReport(ctx RunContextWrapper, args GetReportArgs) string {
	agentID, _ := callerIdentity(ctx)

	result := doGetReport(args.ReportId, agentID)

	return toJSONString(result)
}

// -----------------------------------------------------------------------------
// Dynamic vulnerability creation
// -----------------------------------------------------------------------------

func doCreate(
	title, description, impact, target, technicalAnalysis, pocDescription,
	pocScriptCode, remediationSteps, evidence, assumptions, fixEffort string,
	cvssBreakdown map[string]*string,
	endpoint, method, cve, cwe *string,
	codeLocations []map[string]interface{},
	fixPrBody *string,
	agentID, agentName *string,
) map[string]interface{} {
	var errors []string

	fields := map[string]string{
		"title":              title,
		"description":        description,
		"impact":             impact,
		"target":             target,
		"technical_analysis": technicalAnalysis,
		"poc_description":    pocDescription,
		"poc_script_code":    pocScriptCode,
		"remediation_steps":  remediationSteps,
		"evidence":           evidence,
		"assumptions":        assumptions,
	}

	for _, name := range requiredFieldsOrder {
		if strings.TrimSpace(fields[name]) == "" {
			errors = append(errors, requiredFieldMessages[name])
		}
	}

	fixEffort = strings.ToLower(strings.TrimSpace(fixEffort))
	if !validFixEffort[fixEffort] {
		errors = append(errors, fmt.Sprintf(
			"Invalid fix_effort: %s. Must be one of: %s",
			pythonReprString(fixEffort),
			pythonStringList(sortedBoolMapKeys(validFixEffort)),
		))
	}

	if len(cvssBreakdown) == 0 {
		errors = append(errors, "cvss_breakdown: must be an object with the 8 CVSS metrics")
		cvssBreakdown = map[string]*string{}
	} else {
		for _, name := range cvssMetricOrder {
			valid := cvssValidValues[name]
			valuePtr := cvssBreakdown[name]

			valueOK := false
			valueDisplay := "None"

			if valuePtr != nil {
				valueDisplay = *valuePtr
				valueOK = containsString(valid, *valuePtr)
			}

			if !valueOK {
				errors = append(errors, fmt.Sprintf(
					"Invalid %s: %s. Must be one of: %s",
					name,
					valueDisplay,
					pythonStringList(valid),
				))
			}
		}
	}

	parsedLocations := normalizeCodeLocations(codeLocations)
	if parsedLocations != nil {
		errors = append(errors, validateCodeLocations(parsedLocations)...)
	}

	var parsedCVE, parsedCWE string
	var stateCve, stateCwe *string

	if cve != nil {
		if *cve != "" {
			parsedCVE = extractCVE(*cve)
			if err := validateCVE(parsedCVE); err != nil {
				errors = append(errors, *err)
			} else {
				stateCve = &parsedCVE
			}
		} else {
			stateCve = cve
		}
	}

	if cwe != nil {
		if *cwe != "" {
			parsedCWE = extractCWE(*cwe)
			if err := validateCWE(parsedCWE); err != nil {
				errors = append(errors, *err)
			} else {
				stateCwe = &parsedCWE
			}
		} else {
			stateCwe = cwe
		}
	}

	if len(errors) > 0 {
		return map[string]interface{}{
			"success": false,
			"error":   "Validation failed",
			"errors":  errors,
		}
	}

	cvssBreakdownStrings := cvssBreakdownToStrings(cvssBreakdown)
	cvssScore, severity, _, err := calculateCVSS(cvssBreakdownStrings)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   "Validation failed",
			"errors":  []string{err.Error()},
		}
	}

	reportState := getGlobalReportState()
	if reportState == nil {
		logger.Printf("No global report state; vulnerability report not persisted")
		return map[string]interface{}{
			"success": true,
			"message": fmt.Sprintf("Vulnerability report '%s' created (not persisted)", title),
			"warning": "Report could not be persisted - report state unavailable",
		}
	}

	existing := reportState.GetExistingVulnerabilities()

	candidate := map[string]interface{}{
		"title":              title,
		"description":        description,
		"impact":             impact,
		"target":             target,
		"technical_analysis": technicalAnalysis,
		"poc_description":    pocDescription,
		"poc_script_code":    pocScriptCode,
		"endpoint":           optionalString(endpoint),
		"method":             optionalString(method),
	}

	dedupe := checkDuplicate(candidate, existing)

	if isTruthy(dedupe["is_duplicate"]) {
		dupID := dedupeDuplicateID(dedupe)
		dupTitle := dynamicDuplicateTitle(existing, dupID)

		return map[string]interface{}{
			"success": false,
			"error": fmt.Sprintf(
				"Potential duplicate of '%s' (id=%s...) — do not re-report the same vulnerability",
				duplicateTitleText(dupTitle),
				substrRunes(dupID, 0, 8),
			),
			"duplicate_of":    dupID,
			"duplicate_title": dupTitle,
			"confidence":      dedupeValueOrDefault(dedupe, "confidence", 0.0),
			"reason":          dedupeValueOrDefault(dedupe, "reason", ""),
		}
	}

	reportID, stateErr := reportState.AddVulnerabilityReport(AddVulnerabilityReportArgs{
		Title:              title,
		Description:        description,
		Severity:           severity,
		Impact:             impact,
		Target:             target,
		TechnicalAnalysis:  &technicalAnalysis,
		PocDescription:     &pocDescription,
		PocScriptCode:      &pocScriptCode,
		RemediationSteps:   remediationSteps,
		Evidence:           evidence,
		Assumptions:        assumptions,
		FixEffort:          fixEffort,
		Cvss:               &cvssScore,
		CvssBreakdown:      cvssBreakdownStrings,
		Endpoint:           endpoint,
		Method:             method,
		Cve:                stateCve,
		Cwe:                stateCwe,
		CodeLocations:      parsedLocations,
		FixPrBody:          fixPrBody,
		FindingClass:       "dynamic",
		DependencyMetadata: nil,
		AgentId:            agentID,
		AgentName:          agentName,
	})
	if stateErr != nil {
		logger.Printf("create_vulnerability_report persistence failed: %v", stateErr)
		return map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("Failed to create vulnerability report: %v", stateErr),
		}
	}

	logger.Printf(
		"Vulnerability report created: id=%s severity=%s cvss=%.1f title=%s",
		reportID,
		severity,
		cvssScore,
		title,
	)

	return map[string]interface{}{
		"success":    true,
		"message":    fmt.Sprintf("Vulnerability report '%s' created successfully", title),
		"report_id":  reportID,
		"severity":   severity,
		"cvss_score": cvssScore,
	}
}

// -----------------------------------------------------------------------------
// Dependency vulnerability creation
// -----------------------------------------------------------------------------

func doCreateDependency(
	title, description, target, cve, packageName, installedVersion, impact,
	remediationSteps, assumptions string,
	packageEcosystem string,
	fixedVersion *string,
	cwe *string,
	advisoryCvss *float64,
	technicalAnalysis *string,
	fixEffort string,
	agentID, agentName *string,
) map[string]interface{} {
	var errors []string

	requiredOrder := []string{
		"title",
		"description",
		"target",
		"package_name",
		"installed_version",
		"package_ecosystem",
		"impact",
		"remediation_steps",
		"assumptions",
	}

	requiredValues := map[string]string{
		"title":              title,
		"description":        description,
		"target":             target,
		"package_name":       packageName,
		"installed_version":  installedVersion,
		"package_ecosystem":  packageEcosystem,
		"impact":             impact,
		"remediation_steps":  remediationSteps,
		"assumptions":        assumptions,
	}

	for _, name := range requiredOrder {
		if strings.TrimSpace(requiredValues[name]) == "" {
			errors = append(errors, fmt.Sprintf("%s cannot be empty", name))
		}
	}

	parsedCVE := extractCVE(cve)
	if err := validateCVE(parsedCVE); err != nil {
		errors = append(errors, *err)
	}

	var parsedCWE string
	var stateCwe *string

	if cwe != nil {
		if *cwe != "" {
			parsedCWE = extractCWE(*cwe)
			if err := validateCWE(parsedCWE); err != nil {
				errors = append(errors, *err)
			} else {
				stateCwe = &parsedCWE
			}
		} else {
			stateCwe = cwe
		}
	}

	fixEffort = strings.ToLower(strings.TrimSpace(fixEffort))
	if !validFixEffort[fixEffort] {
		errors = append(errors, fmt.Sprintf(
			"Invalid fix_effort: %s. Must be one of: %s",
			pythonReprString(fixEffort),
			pythonStringList(sortedBoolMapKeys(validFixEffort)),
		))
	}

	if advisoryCvss == nil {
		errors = append(errors, "advisory_cvss is required: read the published advisory base score (0.0-10.0) off the advisory (trivy CVSS / NVD / GHSA). Severity is derived solely from it — do not omit it or the finding cannot be rated.")
	} else if *advisoryCvss < 0.0 || *advisoryCvss > 10.0 {
		errors = append(errors, fmt.Sprintf(
			"advisory_cvss must be between 0.0 and 10.0, got %s",
			pythonStr(*advisoryCvss),
		))
	}

	if len(errors) > 0 {
		return map[string]interface{}{
			"success": false,
			"error":   "Validation failed",
			"errors":  errors,
		}
	}

	cvssScore, severity := dependencySeverity(advisoryCvss)

	dependencyMetadata := buildDependencyMetadata(
		packageName,
		installedVersion,
		packageEcosystem,
		fixedVersion,
	)

	evidence := buildDependencyEvidence(
		parsedCVE,
		strings.TrimSpace(packageName),
		strings.TrimSpace(installedVersion),
		fixedVersion,
	)

	reportState := getGlobalReportState()
	if reportState == nil {
		logger.Printf("No global report state; dependency report not persisted")
		return map[string]interface{}{
			"success": true,
			"message": fmt.Sprintf("Dependency finding '%s' created (not persisted)", title),
			"warning": "Report could not be persisted - report state unavailable",
		}
	}

	existing := reportState.GetExistingVulnerabilities()

	candidate := map[string]interface{}{
		"title":               title,
		"description":         description,
		"target":              target,
		"cve":                 parsedCVE,
		"dependency_metadata": dependencyMetadata,
		"technical_analysis":  optionalString(technicalAnalysis),
	}

	dedupe := checkDuplicate(candidate, existing)

	if isTruthy(dedupe["is_duplicate"]) {
		dupID := dedupeDuplicateID(dedupe)

		return map[string]interface{}{
			"success": false,
			"error": fmt.Sprintf(
				"Potential duplicate (id=%s...) — do not re-report the same dependency finding",
				substrRunes(dupID, 0, 8),
			),
			"duplicate_of": dupID,
			"confidence":   dedupeValueOrDefault(dedupe, "confidence", 0.0),
			"reason":       dedupeValueOrDefault(dedupe, "reason", ""),
		}
	}

	var cvssPtr *float64
	if advisoryCvss != nil {
		cvssPtr = &cvssScore
	}

	reportID, stateErr := reportState.AddVulnerabilityReport(AddVulnerabilityReportArgs{
		Title:              title,
		Description:        description,
		Severity:           severity,
		Impact:             impact,
		Target:             target,
		TechnicalAnalysis:  technicalAnalysis,
		PocDescription:     nil,
		PocScriptCode:      nil,
		RemediationSteps:   remediationSteps,
		Evidence:           evidence,
		Assumptions:        assumptions,
		FixEffort:          fixEffort,
		Cvss:               cvssPtr,
		CvssBreakdown:      nil,
		Endpoint:           nil,
		Method:             nil,
		Cve:                &parsedCVE,
		Cwe:                stateCwe,
		CodeLocations:      nil,
		FixPrBody:          nil,
		FindingClass:       "dependency_cve",
		DependencyMetadata: dependencyMetadata,
		AgentId:            agentID,
		AgentName:          agentName,
	})
	if stateErr != nil {
		logger.Printf("create_dependency_report persistence failed: %v", stateErr)
		return map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("Failed to create dependency report: %v", stateErr),
		}
	}

	logger.Printf(
		"Dependency report created: id=%s cve=%s package=%s severity=%s",
		reportID,
		parsedCVE,
		packageName,
		severity,
	)

	return map[string]interface{}{
		"success":   true,
		"message":   fmt.Sprintf("Dependency finding '%s' created successfully", title),
		"report_id": reportID,
		"severity":  severity,
		"cve":       parsedCVE,
	}
}

func dependencySeverity(advisoryCvss *float64) (float64, string) {
	if advisoryCvss == nil {
		return 0.0, "info"
	}

	score := *advisoryCvss
	if score < 0.0 {
		score = 0.0
	}
	if score > 10.0 {
		score = 10.0
	}

	for _, d := range depSeverityFromCVSS {
		if (score >= d.min && score < d.max) || (d.max == 10.0 && score == 10.0) {
			return score, d.label
		}
	}

	return score, "none"
}

func buildDependencyMetadata(
	packageName, installedVersion, packageEcosystem string,
	fixedVersion *string,
) map[string]string {
	metadata := map[string]string{
		"package_name":      strings.TrimSpace(packageName),
		"installed_version": strings.TrimSpace(installedVersion),
	}

	if strings.TrimSpace(packageEcosystem) != "" {
		metadata["package_ecosystem"] = strings.TrimSpace(packageEcosystem)
	}

	if fixedVersion != nil && strings.TrimSpace(*fixedVersion) != "" {
		metadata["fixed_version"] = strings.TrimSpace(*fixedVersion)
	}

	return metadata
}

func buildDependencyEvidence(
	cve, packageName, installedVersion string,
	fixedVersion *string,
) string {
	evidence := fmt.Sprintf(
		"Advisory evidence: `%s` applies to `%s` at installed version `%s`.",
		cve,
		packageName,
		installedVersion,
	)

	if fixedVersion != nil && strings.TrimSpace(*fixedVersion) != "" {
		evidence += fmt.Sprintf(" The advisory is fixed in `%s`.", strings.TrimSpace(*fixedVersion))
	}

	return evidence
}

// -----------------------------------------------------------------------------
// Report listing / retrieval
// -----------------------------------------------------------------------------

func doListReports(
	severity, findingClass, target, search *string,
	includeDetails bool,
	callerAgentID *string,
) map[string]interface{} {
	var errors []string

	var sevPtr, fcPtr *string

	if severity != nil {
		s := strings.ToLower(strings.TrimSpace(*severity))
		if s != "" {
			if !validSeverities[s] {
				errors = append(errors, fmt.Sprintf(
					"Invalid severity: %s. Must be one of: %s",
					pythonReprString(s),
					pythonStringList(sortedBoolMapKeys(validSeverities)),
				))
			} else {
				sevPtr = &s
			}
		}
	}

	if findingClass != nil {
		fc := strings.ToLower(strings.TrimSpace(*findingClass))
		if fc != "" {
			if !validFindingClasses[fc] {
				errors = append(errors, fmt.Sprintf(
					"Invalid finding_class: %s. Must be one of: %s",
					pythonReprString(fc),
					pythonStringList(sortedBoolMapKeys(validFindingClasses)),
				))
			} else {
				fcPtr = &fc
			}
		}
	}

	if len(errors) > 0 {
		return map[string]interface{}{
			"success": false,
			"error":   "Validation failed",
			"errors":  errors,
		}
	}

	reportState := getGlobalReportState()
	if reportState == nil {
		return map[string]interface{}{
			"success":         true,
			"reports":         []interface{}{},
			"filtered_count":  0,
			"total_count":     0,
			"severity_counts": map[string]int{},
			"warning":         "Report state unavailable - no reports have been filed yet",
		}
	}

	var tgt, srch *string
	if target != nil {
		t := strings.TrimSpace(*target)
		if t != "" {
			tgt = &t
		}
	}
	if search != nil {
		s := strings.TrimSpace(*search)
		if s != "" {
			srch = &s
		}
	}

	allReports := reportState.GetExistingVulnerabilities()
	matched := []map[string]interface{}{}

	for _, r := range allReports {
		if reportMatchesFilters(r, sevPtr, fcPtr, tgt, srch) {
			matched = append(matched, r)
		}
	}

	sort.SliceStable(matched, func(i, j int) bool {
		ri := reportSeverityRank(matched[i])
		rj := reportSeverityRank(matched[j])

		if ri != rj {
			return ri < rj
		}

		idi := pyReportString(matched[i], "id", "")
		idj := pyReportString(matched[j], "id", "")

		return idi < idj
	})

	reports := []map[string]interface{}{}

	for _, r := range matched {
		if includeDetails {
			rCopy := copyReportMap(r)
			reports = append(reports, markAuthorship(rCopy, r, callerAgentID))
		} else {
			reports = append(reports, toReportSummaryEntry(r, callerAgentID))
		}
	}

	return map[string]interface{}{
		"success":         true,
		"reports":         reports,
		"filtered_count":  len(reports),
		"total_count":     len(allReports),
		"severity_counts": severityCounts(allReports),
	}
}

func doGetReport(reportID string, callerAgentID *string) map[string]interface{} {
	reportID = strings.TrimSpace(reportID)

	if reportID == "" {
		return map[string]interface{}{
			"success": false,
			"error":   "report_id cannot be empty",
			"report":  nil,
		}
	}

	reportState := getGlobalReportState()
	if reportState == nil {
		return map[string]interface{}{
			"success": false,
			"error":   "Report state unavailable - no reports have been filed yet",
			"report":  nil,
		}
	}

	for _, r := range reportState.GetExistingVulnerabilities() {
		if id, ok := r["id"].(string); ok && id == reportID {
			rCopy := copyReportMap(r)
			return map[string]interface{}{
				"success": true,
				"report":  markAuthorship(rCopy, r, callerAgentID),
			}
		}
	}

	return map[string]interface{}{
		"success": false,
		"error":   fmt.Sprintf("Report with id '%s' not found", reportID),
		"report":  nil,
	}
}

func reportMatchesFilters(
	report map[string]interface{},
	severity, findingClass, target, search *string,
) bool {
	if severity != nil {
		sev := strings.ToLower(pyReportString(report, "severity", ""))
		if sev != *severity {
			return false
		}
	}

	if findingClass != nil {
		fc := strings.ToLower(pyReportString(report, "finding_class", "dynamic"))
		if fc != *findingClass {
			return false
		}
	}

	if target != nil {
		tgtLower := strings.ToLower(*target)
		haystack := strings.ToLower(
			pyReportString(report, "target", "") + " " + pyReportString(report, "endpoint", ""),
		)
		if !strings.Contains(haystack, tgtLower) {
			return false
		}
	}

	if search != nil {
		searchLower := strings.ToLower(*search)

		title := strings.ToLower(pyReportString(report, "title", ""))
		desc := strings.ToLower(pyReportString(report, "description", ""))

		if !strings.Contains(title, searchLower) && !strings.Contains(desc, searchLower) {
			return false
		}
	}

	return true
}

func reportSeverityRank(report map[string]interface{}) int {
	sev := strings.ToLower(pyReportString(report, "severity", ""))

	if rank, ok := severityOrder[sev]; ok {
		return rank
	}

	return 99
}

func markAuthorship(
	entry, report map[string]interface{},
	callerAgentID *string,
) map[string]interface{} {
	if callerAgentID != nil {
		if id, ok := report["agent_id"].(string); ok && id == *callerAgentID {
			entry["by_you"] = true
		}
	}

	return entry
}

func toReportSummaryEntry(
	report map[string]interface{},
	callerAgentID *string,
) map[string]interface{} {
	entry := map[string]interface{}{}

	for _, field := range reportSummaryFields {
		if val, ok := report[field]; ok && val != nil {
			entry[field] = val
		}
	}

	description := strings.TrimSpace(pyReportString(report, "description", ""))
	if description != "" {
		runes := []rune(description)

		if len(runes) > reportDescriptionPreviewChars {
			cut := string(runes[:reportDescriptionPreviewChars])
			cut = strings.TrimRightFunc(cut, unicode.IsSpace)
			entry["description_preview"] = cut + "..."
		} else {
			entry["description_preview"] = description
		}
	}

	return markAuthorship(entry, report, callerAgentID)
}

func severityCounts(reports []map[string]interface{}) map[string]int {
	counts := map[string]int{}

	for _, report := range reports {
		sev := strings.ToLower(pyReportString(report, "severity", ""))
		if sev == "" {
			sev = "none"
		}

		counts[sev]++
	}

	res := map[string]int{}

	for _, sev := range severityRankOrder {
		if c, ok := counts[sev]; ok && c > 0 {
			res[sev] = c
		}
	}

	return res
}

// -----------------------------------------------------------------------------
// Caller identity
// -----------------------------------------------------------------------------

func callerIdentity(ctx RunContextWrapper) (*string, *string) {
	if ctx == nil || ctx.GetContext() == nil {
		return nil, nil
	}

	inner := ctx.GetContext()

	var agentID, agentName *string

	if idVal, ok := inner["agent_id"]; ok {
		if id, ok := idVal.(string); ok {
			agentID = &id
		}
	}

	if coord, ok := inner["coordinator"]; ok && coord != nil {
		names := getNamesFromCoordinator(coord)

		if agentID != nil && names != nil {
			if name, ok := names[*agentID]; ok {
				agentName = &name
			}
		}
	}

	return agentID, agentName
}

func getNamesFromCoordinator(coord interface{}) map[string]string {
	if coord == nil {
		return nil
	}

	if provider, ok := coord.(NamesProvider); ok {
		return provider.GetNames()
	}

	if m, ok := coord.(map[string]interface{}); ok {
		if namesVal, hasNames := m["names"]; hasNames {
			return toStringMap(namesVal)
		}
	}

	if m, ok := coord.(map[string]string); ok {
		return m
	}

	rv := reflect.ValueOf(coord)
	for rv.Kind() == reflect.Ptr || rv.Kind() == reflect.Interface {
		if rv.IsNil() {
			return nil
		}
		rv = rv.Elem()
	}

	if rv.Kind() == reflect.Struct {
		field := rv.FieldByName("Names")
		if !field.IsValid() {
			field = rv.FieldByName("names")
		}

		if field.IsValid() && field.CanInterface() {
			return toStringMap(field.Interface())
		}
	}

	if rv.Kind() == reflect.Map {
		if rv.Type().Key().Kind() == reflect.String {
			if namesVal := rv.MapIndex(reflect.ValueOf("names")); namesVal.IsValid() && namesVal.CanInterface() {
				return toStringMap(namesVal.Interface())
			}
			if namesVal := rv.MapIndex(reflect.ValueOf("Names")); namesVal.IsValid() && namesVal.CanInterface() {
				return toStringMap(namesVal.Interface())
			}
		}

		if rv.CanInterface() {
			return toStringMap(rv.Interface())
		}
	}

	return nil
}

func toStringMap(v interface{}) map[string]string {
	if v == nil {
		return nil
	}

	switch m := v.(type) {
	case map[string]string:
		return m

	case map[string]interface{}:
		res := make(map[string]string, len(m))
		for k, val := range m {
			if s, ok := val.(string); ok {
				res[k] = s
			}
		}
		return res
	}

	rv := reflect.ValueOf(v)
	for rv.Kind() == reflect.Ptr || rv.Kind() == reflect.Interface {
		if rv.IsNil() {
			return nil
		}
		rv = rv.Elem()
	}

	if rv.Kind() == reflect.Map {
		res := map[string]string{}

		iter := rv.MapRange()
		for iter.Next() {
			if !iter.Key().CanInterface() || !iter.Value().CanInterface() {
				continue
			}

			key := fmt.Sprint(iter.Key().Interface())

			if s, ok := iter.Value().Interface().(string); ok {
				res[key] = s
			}
		}

		return res
	}

	return nil
}

// -----------------------------------------------------------------------------
// Code location normalization / validation
// -----------------------------------------------------------------------------

func validateFilePath(p string) *string {
	if strings.TrimSpace(p) == "" {
		err := "file path cannot be empty"
		return &err
	}

	if strings.HasPrefix(p, "/") {
		err := fmt.Sprintf("file path must be relative, got absolute: '%s'", p)
		return &err
	}

	for _, part := range strings.Split(p, "/") {
		if part == ".." {
			err := fmt.Sprintf("file path must not contain '..': '%s'", p)
			return &err
		}
	}

	return nil
}

func normalizeCodeLocations(raw []map[string]interface{}) []map[string]interface{} {
	if len(raw) == 0 {
		return nil
	}

	var cleaned []map[string]interface{}

	for _, loc := range raw {
		normalized := map[string]interface{}{}

		for _, field := range []string{
			"file",
			"start_line",
			"end_line",
			"snippet",
			"label",
			"fix_before",
			"fix_after",
		} {
			val, ok := loc[field]
			if !ok || val == nil {
				continue
			}

			if field == "start_line" || field == "end_line" {
				if i, ok := normalizeInt(val); ok {
					normalized[field] = i
				}
				continue
			}

			text := pythonStr(val)

			if field == "snippet" || field == "fix_before" || field == "fix_after" {
				text = strings.Trim(text, "\n ")
			} else {
				text = strings.TrimSpace(text)
			}

			if text != "" {
				normalized[field] = text
			}
		}

		fileVal, fileOk := normalized["file"]
		_, startOk := normalized["start_line"]

		if fileOk && startOk && pythonStr(fileVal) != "" {
			cleaned = append(cleaned, normalized)
		}
	}

	if len(cleaned) == 0 {
		return nil
	}

	return cleaned
}

func normalizeInt(v interface{}) (int, bool) {
	switch x := v.(type) {
	case int:
		return x, true

	case int64:
		return int(x), true

	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return 0, false
		}
		return int(x), true

	case string:
		if i, err := strconv.Atoi(strings.TrimSpace(x)); err == nil {
			return i, true
		}

	case bool:
		if x {
			return 1, true
		}
		return 0, true

	case json.Number:
		if i, err := x.Int64(); err == nil {
			return int(i), true
		}

		if f, err := x.Float64(); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
			return int(f), true
		}
	}

	return 0, false
}

func validateCodeLocations(locations []map[string]interface{}) []string {
	var errors []string

	for i, loc := range locations {
		fileStr := pyReportString(loc, "file", "")

		if err := validateFilePath(fileStr); err != nil {
			errors = append(errors, fmt.Sprintf("code_locations[%d]: %s", i, *err))
		}

		startLine, startOk := loc["start_line"].(int)
		if !startOk || startLine < 1 {
			errors = append(errors, fmt.Sprintf("code_locations[%d]: start_line must be a positive integer", i))
		}

		endLineVal, endOk := loc["end_line"]
		if !endOk {
			errors = append(errors, fmt.Sprintf("code_locations[%d]: end_line is required", i))
			continue
		}

		endLine, isInt := endLineVal.(int)
		if !isInt || endLine < 1 {
			errors = append(errors, fmt.Sprintf("code_locations[%d]: end_line must be a positive integer", i))
			continue
		}

		if startOk && endLine < startLine {
			errors = append(errors, fmt.Sprintf(
				"code_locations[%d]: end_line (%d) must be >= start_line (%d)",
				i,
				endLine,
				startLine,
			))
		}
	}

	return errors
}

// -----------------------------------------------------------------------------
// CVE / CWE helpers
// -----------------------------------------------------------------------------

func extractCVE(cve string) string {
	match := cveExtractRe.FindString(cve)
	if match != "" {
		return match
	}

	return strings.TrimSpace(cve)
}

func validateCVE(cve string) *string {
	if !cveValidateRe.MatchString(cve) {
		err := fmt.Sprintf("invalid CVE format: '%s' (expected 'CVE-YYYY-NNNNN')", cve)
		return &err
	}

	return nil
}

func extractCWE(cwe string) string {
	match := cweExtractRe.FindString(cwe)
	if match != "" {
		return match
	}

	return strings.TrimSpace(cwe)
}

func validateCWE(cwe string) *string {
	if !cweValidateRe.MatchString(cwe) {
		err := fmt.Sprintf("invalid CWE format: '%s' (expected 'CWE-NNN')", cwe)
		return &err
	}

	return nil
}

// -----------------------------------------------------------------------------
// CVSS v3.1 calculation
// -----------------------------------------------------------------------------

func calculateCVSS(breakdown map[string]string) (float64, string, string, error) {
	vector := fmt.Sprintf(
		"CVSS:3.1/AV:%s/AC:%s/PR:%s/UI:%s/S:%s/C:%s/I:%s/A:%s",
		breakdown["attack_vector"],
		breakdown["attack_complexity"],
		breakdown["privileges_required"],
		breakdown["user_interaction"],
		breakdown["scope"],
		breakdown["confidentiality"],
		breakdown["integrity"],
		breakdown["availability"],
	)

	fail := func() (float64, string, string, error) {
		return 0.0, "info", vector, fmt.Errorf("Failed to calculate CVSS for validated vector: %s", vector)
	}

	av, ok := cvssAVWeights[breakdown["attack_vector"]]
	if !ok {
		return fail()
	}

	ac, ok := cvssACWeights[breakdown["attack_complexity"]]
	if !ok {
		return fail()
	}

	ui, ok := cvssUIWeights[breakdown["user_interaction"]]
	if !ok {
		return fail()
	}

	scope := breakdown["scope"]
	if scope != "U" && scope != "C" {
		return fail()
	}

	var pr float64

	switch breakdown["privileges_required"] {
	case "N":
		pr = 0.85
	case "L":
		if scope == "C" {
			pr = 0.68
		} else {
			pr = 0.62
		}
	case "H":
		if scope == "C" {
			pr = 0.50
		} else {
			pr = 0.27
		}
	default:
		return fail()
	}

	c, ok := cvssCIAWeights[breakdown["confidentiality"]]
	if !ok {
		return fail()
	}

	i, ok := cvssCIAWeights[breakdown["integrity"]]
	if !ok {
		return fail()
	}

	a, ok := cvssCIAWeights[breakdown["availability"]]
	if !ok {
		return fail()
	}

	iss := 1 - ((1 - c) * (1 - i) * (1 - a))

	var impact float64
	if scope == "U" {
		impact = 6.42 * iss
	} else {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}

	exploitability := 8.22 * av * ac * pr * ui

	var score float64
	if impact <= 0 {
		score = 0.0
	} else if scope == "U" {
		score = cvssRoundup(math.Min(impact+exploitability, 10.0))
	} else {
		score = cvssRoundup(math.Min(1.08*(impact+exploitability), 10.0))
	}

	severity := cvssBaseSeverity(score)
	if severity == "none" {
		severity = "info"
	}

	return score, severity, vector, nil
}

func cvssRoundup(input float64) float64 {
	intInput := int(math.Round(input * 100000))

	if intInput%10000 == 0 {
		return float64(intInput) / 100000.0
	}

	return float64(intInput/10000+1) / 10.0
}

func cvssBaseSeverity(score float64) string {
	if score == 0.0 {
		return "none"
	}
	if score < 4.0 {
		return "low"
	}
	if score < 7.0 {
		return "medium"
	}
	if score < 9.0 {
		return "high"
	}

	return "critical"
}

// -----------------------------------------------------------------------------
// JSON helpers
// -----------------------------------------------------------------------------

func toJSONString(v interface{}) string {
	sanitized := sanitizeJSON(v)

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)

	if err := enc.Encode(sanitized); err != nil {
		return `{"success":false,"error":"failed to marshal JSON response"}`
	}

	return strings.TrimRight(buf.String(), "\n")
}

func sanitizeJSON(v interface{}) interface{} {
	switch x := v.(type) {
	case nil:
		return nil

	case map[string]interface{}:
		res := make(map[string]interface{}, len(x))
		for k, val := range x {
			res[k] = sanitizeJSON(val)
		}
		return res

	case []interface{}:
		res := make([]interface{}, len(x))
		for i, val := range x {
			res[i] = sanitizeJSON(val)
		}
		return res

	case []map[string]interface{}:
		res := make([]interface{}, len(x))
		for i, val := range x {
			res[i] = sanitizeJSON(val)
		}
		return res

	case []string:
		res := make([]interface{}, len(x))
		for i, val := range x {
			res[i] = val
		}
		return res

	case map[string]string:
		res := make(map[string]interface{}, len(x))
		for k, val := range x {
			res[k] = val
		}
		return res

	case bool, string, int, int64, float64, json.Number:
		return x

	case time.Time:
		return x

	default:
		rv := reflect.ValueOf(v)

		if !rv.IsValid() {
			return nil
		}

		switch rv.Kind() {
		case reflect.Ptr, reflect.Interface:
			if rv.IsNil() {
				return nil
			}
			return sanitizeJSON(rv.Elem().Interface())

		case reflect.Slice, reflect.Array:
			res := make([]interface{}, rv.Len())
			for i := 0; i < rv.Len(); i++ {
				item := rv.Index(i)
				if item.CanInterface() {
					res[i] = sanitizeJSON(item.Interface())
				} else {
					res[i] = nil
				}
			}
			return res

		case reflect.Map:
			res := make(map[string]interface{})

			iter := rv.MapRange()
			for iter.Next() {
				if !iter.Key().CanInterface() || !iter.Value().CanInterface() {
					continue
				}

				key := fmt.Sprint(iter.Key().Interface())
				res[key] = sanitizeJSON(iter.Value().Interface())
			}

			return res

		case reflect.Struct:
			if _, ok := v.(json.Marshaler); ok {
				return v
			}
			return fmt.Sprint(v)

		default:
			return fmt.Sprint(v)
		}
	}
}

// -----------------------------------------------------------------------------
// Python-compatible string/format helpers
// -----------------------------------------------------------------------------

func pythonStr(v interface{}) string {
	switch x := v.(type) {
	case nil:
		return "None"

	case bool:
		if x {
			return "True"
		}
		return "False"

	case string:
		return x

	case int:
		return strconv.Itoa(x)

	case int64:
		return strconv.FormatInt(x, 10)

	case float64:
		s := strconv.FormatFloat(x, 'g', -1, 64)
		if !strings.ContainsAny(s, ".e") {
			s += ".0"
		}
		return s

	case json.Number:
		return x.String()

	default:
		return fmt.Sprint(v)
	}
}

func pyReportString(report map[string]interface{}, key string, missingDefault string) string {
	v, ok := report[key]
	if !ok {
		return missingDefault
	}

	if v == nil {
		return "None"
	}

	return pythonStr(v)
}

func pythonReprString(s string) string {
	escaped := strings.ReplaceAll(s, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `'`, `\'`)

	return "'" + escaped + "'"
}

func pythonStringList(items []string) string {
	quoted := make([]string, len(items))

	for i, item := range items {
		quoted[i] = pythonReprString(item)
	}

	return "[" + strings.Join(quoted, ", ") + "]"
}

func sortedBoolMapKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))

	for k := range m {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	return keys
}

// -----------------------------------------------------------------------------
// Generic helpers
// -----------------------------------------------------------------------------

func optionalString(p *string) interface{} {
	if p == nil {
		return nil
	}

	return *p
}

func containsString(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}

	return false
}

func cvssBreakdownToStrings(b map[string]*string) map[string]string {
	res := make(map[string]string, len(b))

	for k, v := range b {
		if v != nil {
			res[k] = *v
		}
	}

	return res
}

func isTruthy(v interface{}) bool {
	switch x := v.(type) {
	case bool:
		return x

	case string:
		return x != ""

	case int:
		return x != 0

	case int64:
		return x != 0

	case float64:
		return x != 0

	case json.Number:
		if f, err := x.Float64(); err == nil {
			return f != 0
		}
		return false

	case nil:
		return false

	case []interface{}:
		return len(x) > 0

	case map[string]interface{}:
		return len(x) > 0

	default:
		return true
	}
}

func dedupeDuplicateID(dedupe map[string]interface{}) string {
	if dedupe == nil {
		return ""
	}

	if v, ok := dedupe["duplicate_id"]; ok && v != nil {
		return fmt.Sprint(v)
	}

	return ""
}

func dedupeValueOrDefault(dedupe map[string]interface{}, key string, def interface{}) interface{} {
	if dedupe == nil {
		return def
	}

	if v, ok := dedupe[key]; ok {
		return v
	}

	return def
}

func dynamicDuplicateTitle(existing []map[string]interface{}, duplicateID string) interface{} {
	for _, r := range existing {
		if id, ok := r["id"].(string); ok && id == duplicateID {
			if title, exists := r["title"]; exists {
				if title == nil {
					return nil
				}
				if s, ok := title.(string); ok {
					return s
				}
				return fmt.Sprint(title)
			}

			return "Unknown"
		}
	}

	return ""
}

func duplicateTitleText(v interface{}) string {
	if v == nil {
		return "None"
	}

	return fmt.Sprint(v)
}

func substrRunes(s string, start, length int) string {
	runes := []rune(s)

	if start < 0 {
		start = 0
	}

	if start >= len(runes) {
		return ""
	}

	end := start + length
	if end > len(runes) {
		end = len(runes)
	}

	return string(runes[start:end])
}

func copyReportMap(r map[string]interface{}) map[string]interface{} {
	c := make(map[string]interface{}, len(r))

	for k, v := range r {
		c[k] = v
	}

	return c
}