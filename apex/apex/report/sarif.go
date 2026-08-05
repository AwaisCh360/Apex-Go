package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

type Dict = map[string]interface{}

var logger = log.New(os.Stdout, "[report] ", log.LstdFlags)

const (
	SARIFSchema          = "https://json.schemastore.org/sarif-2.1.0.json"
	SARIFVersion         = "2.1.0"
	ToolName             = "Apex"
	ToolInformationURI   = "https://apex.ai"
	SyntheticLocationURI = "SECURITY.md"
)

var severityToLevel = map[string]string{
	"critical":      "error",
	"high":          "error",
	"medium":        "warning",
	"low":           "note",
	"info":          "note",
	"informational": "note",
}

var severityToScore = map[string]string{
	"critical":      "9.5",
	"high":          "8.0",
	"medium":        "5.5",
	"low":           "3.0",
	"info":          "1.0",
	"informational": "1.0",
}

var cweToStride = map[string][]string{
	"287":  {"S"},
	"290":  {"S"},
	"294":  {"S"},
	"306":  {"S", "E"},
	"345":  {"S", "T"},
	"346":  {"S"},
	"352":  {"T", "S"},
	"384":  {"S"},
	"521":  {"S"},
	"613":  {"S"},
	"640":  {"S"},
	"259":  {"S", "I"},
	"798":  {"S", "I"},
	"1391": {"S"},
	"20":   {"T"},
	"73":   {"T", "I"},
	"78":   {"T", "E"},
	"79":   {"T", "I"},
	"89":   {"T"},
	"91":   {"T"},
	"94":   {"T", "E"},
	"434":  {"T"},
	"502":  {"T", "E"},
	"915":  {"E", "T"},
	"918":  {"T", "I"},
	"1336": {"T", "E"},
	"117":  {"R"},
	"223":  {"R"},
	"778":  {"R"},
	"200":  {"I"},
	"201":  {"I"},
	"209":  {"I"},
	"256":  {"I"},
	"311":  {"I"},
	"319":  {"I"},
	"327":  {"I"},
	"328":  {"I"},
	"522":  {"I"},
	"525":  {"I"},
	"532":  {"I"},
	"538":  {"I"},
	"598":  {"I"},
	"400":  {"D"},
	"770":  {"D"},
	"1333": {"D"},
	"269":  {"E"},
	"284":  {"E"},
	"285":  {"E"},
	"639":  {"E"},
	"732":  {"E"},
	"862":  {"E"},
	"863":  {"E"},
	"1220": {"E"},
	"22":   {"T", "I"},
	"611":  {"I", "T"},
}

var defaultStrideLegs = []string{"T", "I"}

var vulnClassKeywords = []string{
	"missing authentication",
	"missing authorization",
	"broken access control",
	"incorrect authorization",
	"default credentials",
	"hardcoded credentials",
	"hardcoded secret",
	"hardcoded password",
	"default admin",
	"default password",
	"session fixation",
	"open redirect",
	"path traversal",
	"directory traversal",
	"command injection",
	"sql injection",
	"code injection",
	"template injection",
	"xpath injection",
	"ldap injection",
	"log injection",
	"header injection",
	"csv injection",
	"prompt injection",
	"deserialization",
	"ssrf",
	"xss",
	"csrf",
	"xxe",
	"race condition",
	"toctou",
	"information disclosure",
	"insecure direct object reference",
	"idor",
	"bola",
	"bfla",
	"cross-tenant",
	"cross-project",
	"tenant bypass",
	"auth bypass",
	"rate limiting",
	"rate limit",
	"weak cryptography",
	"weak hash",
	"weak random",
	"insecure random",
	"tls verification",
	"certificate verification",
	"denial of service",
	"regex denial of service",
	"redos",
	"supply chain",
}

var reWords = regexp.MustCompile(`[a-z0-9]+`)

func stringValue(val interface{}) string {
	if val == nil {
		return ""
	}
	if s, ok := val.(string); ok {
		return strings.TrimSpace(s)
	}
	return ""
}

func intValue(val interface{}) (int, bool) {
	if val == nil {
		return 0, false
	}
	switch v := val.(type) {
	case int:
		return v, true
	case float64:
		return int(v), true
	}
	return 0, false
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func strideLegsForCWE(cwe string) []string {
	if cwe == "" {
		return defaultStrideLegs
	}
	var digits []rune
	for _, r := range cwe {
		if unicode.IsDigit(r) {
			digits = append(digits, r)
		}
	}
	if len(digits) == 0 {
		return defaultStrideLegs
	}
	if legs, ok := cweToStride[string(digits)]; ok {
		return legs
	}
	return defaultStrideLegs
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

func BuildSARIFReport(vulnerabilityReports []Dict, toolVersion string, repositoryContext Dict) Dict {
	rulesByID := make(map[string]Dict)
	ruleIndexByID := make(map[string]int)
	var results []Dict
	syntheticLocationCount := 0
	var droppedUnsafeLocationFindings []Dict
	var rulesList []Dict

	for _, report := range vulnerabilityReports {
		locations, isSynthetic, droppedLocationCount := buildLocations(report)
		if isSynthetic {
			syntheticLocationCount++
		}
		if droppedLocationCount > 0 {
			droppedUnsafeLocationFindings = append(droppedUnsafeLocationFindings, droppedLocationSummary(report, droppedLocationCount))
		}

		ruleIDStr := ruleID(report)
		if _, exists := rulesByID[ruleIDStr]; !exists {
			ruleIndexByID[ruleIDStr] = len(rulesList)
			rule := buildRule(ruleIDStr, report)
			rulesByID[ruleIDStr] = rule
			rulesList = append(rulesList, rule)
		}
		results = append(results, buildResult(ruleIDStr, ruleIndexByID[ruleIDStr], report, locations, isSynthetic))
	}

	driver := Dict{
		"name":           ToolName,
		"informationUri": ToolInformationURI,
	}
	if len(rulesList) > 0 {
		driver["rules"] = rulesList
	} else {
		driver["rules"] = []Dict{}
	}
	if toolVersion != "" {
		driver["version"] = toolVersion
	}

	if results == nil {
		results = []Dict{}
	}

	run := Dict{
		"tool":    Dict{"driver": driver},
		"results": results,
	}

	runProperties := make(Dict)
	if syntheticLocationCount > 0 {
		runProperties["syntheticLocationCount"] = syntheticLocationCount
	}
	if len(droppedUnsafeLocationFindings) > 0 {
		sum := 0
		for _, f := range droppedUnsafeLocationFindings {
			if c, ok := intValue(f["droppedLocationCount"]); ok {
				sum += c
			}
		}
		runProperties["droppedUnsafeLocationCount"] = sum
		runProperties["droppedUnsafeLocationFindings"] = droppedUnsafeLocationFindings
	}
	if len(runProperties) > 0 {
		run["properties"] = runProperties
	}

	if repositoryContext != nil {
		applyRepositoryContext(run, repositoryContext)
	}

	return Dict{
		"version": SARIFVersion,
		"$schema": SARIFSchema,
		"runs":    []Dict{run},
	}
}

func WriteSARIFReport(outputPath string, vulnerabilityReports []Dict, toolVersion string, repositoryContext Dict) error {
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	sarif := BuildSARIFReport(vulnerabilityReports, toolVersion, repositoryContext)

	pid := os.Getpid()
	tmpPath := fmt.Sprintf("%s.%d.tmp", outputPath, pid)

	f, err := os.Create(tmpPath)
	if err != nil {
		return err
	}

	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	// ensure_ascii=False in python translates nicely as Go JSON encoding preserves Unicode by default
	if err := encoder.Encode(sarif); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return err
	}
	f.WriteString("\n")
	f.Close()

	return os.Rename(tmpPath, outputPath)
}

func WriteSARIF(runDir string, reports []Dict, toolVersion string, repositoryContext Dict, filename string) (string, error) {
	if filename == "" {
		filename = "findings.sarif"
	}
	out := filepath.Join(runDir, filename)
	err := WriteSARIFReport(out, reports, toolVersion, repositoryContext)
	if err == nil {
		logger.Printf("Wrote SARIF 2.1.0 report: %s (%d results)", out, len(reports))
	}
	return out, err
}

func BuildSARIFDocument(reports []Dict, toolVersion string, repositoryContext Dict) Dict {
	return BuildSARIFReport(reports, toolVersion, repositoryContext)
}

// ---------------------------------------------------------------------------
// Repository provenance
// ---------------------------------------------------------------------------

func applyRepositoryContext(run Dict, context Dict) {
	fullName := stringValue(context["repositoryFullName"])
	uri := stringValue(context["repositoryUri"])
	commit := stringValue(context["commitSha"])
	branch := stringValue(context["branch"])
	ref := stringValue(context["ref"])

	if fullName != "" {
		run["automationDetails"] = Dict{"id": fmt.Sprintf("apex/%s", fullName)}
	}

	if uri != "" {
		provenance := Dict{"repositoryUri": uri}
		if commit != "" {
			provenance["revisionId"] = commit
		}
		if branch != "" {
			provenance["branch"] = branch
		}
		run["versionControlProvenance"] = []Dict{provenance}
	}

	var properties Dict
	if p, ok := run["properties"].(Dict); ok {
		properties = p
	} else if p, ok := run["properties"].(map[string]interface{}); ok {
		properties = Dict(p)
	} else {
		properties = make(Dict)
	}

	if fullName != "" {
		properties["repository"] = fullName
	}
	if ref != "" {
		properties["ref"] = ref
	}
	if commit != "" {
		properties["commit_sha"] = commit
	}

	if len(properties) > 0 {
		run["properties"] = properties
	} else {
		delete(run, "properties")
	}
}

// ---------------------------------------------------------------------------
// Rule + result builders
// ---------------------------------------------------------------------------

func buildRule(ruleID string, report Dict) Dict {
	title := stringValue(report["title"])
	if title == "" {
		title = ruleID
	}
	fullDescription := stringValue(report["description"])
	if fullDescription == "" {
		fullDescription = title
	}
	helpTxt := helpText(report, fullDescription)

	rule := Dict{
		"id":                   ruleID,
		"name":                 ruleName(ruleID, title),
		"shortDescription":     Dict{"text": title},
		"fullDescription":      Dict{"text": fullDescription},
		"defaultConfiguration": Dict{"level": sarifLevel(report["severity"])},
		"help":                 Dict{"text": helpTxt, "markdown": helpTxt},
	}

	properties := Dict{
		"security-severity": securitySeverity(report),
	}
	tags := ruleTags(ruleID, report)
	if len(tags) > 0 {
		properties["tags"] = tags
	}
	rule["properties"] = properties

	if helpURI := helpURIFor(ruleID); helpURI != "" {
		rule["helpUri"] = helpURI
	}

	return rule
}

func buildResult(ruleID string, ruleIndex int, report Dict, locations []Dict, isSynthetic bool) Dict {
	title := stringValue(report["title"])
	if title == "" {
		title = ruleID
	}
	description := stringValue(report["description"])
	messageText := title
	if description != "" {
		messageText = fmt.Sprintf("%s\n\n%s", title, description)
	}

	result := Dict{
		"ruleId":    ruleID,
		"ruleIndex": ruleIndex,
		"level":     sarifLevel(report["severity"]),
		"message":   Dict{"text": messageText},
	}
	if len(locations) > 0 {
		result["locations"] = locations
	}

	if fixes := buildFixes(report); len(fixes) > 0 {
		result["fixes"] = fixes
	}

	fp := primaryFingerprint(ruleID, report, locations, isSynthetic)
	if fp != "" {
		result["partialFingerprints"] = Dict{"primaryLocationLineHash": fp}
	}

	classFp := classFingerprint(ruleID, report)
	result["properties"] = resultProperties(report, classFp, isSynthetic)

	return result
}

func resultProperties(report Dict, classFingerprint string, isSynthetic bool) Dict {
	properties := Dict{
		"security-severity": securitySeverity(report),
	}
	if classFingerprint != "" {
		properties["apex_vuln_class_hash"] = classFingerprint
	}
	if isSynthetic {
		properties["synthetic_location"] = true
	}

	apex := make(Dict)
	keys := []string{
		"id", "severity", "cvss", "timestamp", "target", "endpoint",
		"method", "cve", "cwe", "impact", "technical_analysis", "remediation_steps",
	}
	for _, k := range keys {
		val := report[k]
		if val != nil {
			if s, ok := val.(string); ok {
				if strings.TrimSpace(s) == "" {
					continue
				}
			}
			apex[k] = val
		}
	}

	pocDescription := stringValue(report["poc_description"])
	pocScript := stringValue(report["poc_script_code"])
	if pocDescription != "" || pocScript != "" {
		poc := make(Dict)
		if pocDescription != "" {
			poc["description"] = pocDescription
		}
		if pocScript != "" {
			poc["script_available"] = true
		}
		apex["poc"] = poc
	}

	if len(apex) > 0 {
		properties["apex"] = apex
	}

	return properties
}

func buildFixes(report Dict) []Dict {
	var rawLocations []interface{}
	if rl, ok := report["code_locations"].([]interface{}); ok {
		rawLocations = rl
	} else if rld, ok := report["code_locations"].([]Dict); ok {
		for _, v := range rld {
			rawLocations = append(rawLocations, v)
		}
	} else if rlmap, ok := report["code_locations"].([]map[string]interface{}); ok {
		for _, v := range rlmap {
			rawLocations = append(rawLocations, v)
		}
	} else {
		return nil
	}

	var artifactChanges []Dict
	for _, rawLoc := range rawLocations {
		var loc map[string]interface{}
		if m, ok := rawLoc.(map[string]interface{}); ok {
			loc = m
		} else if d, ok := rawLoc.(Dict); ok {
			loc = map[string]interface{}(d)
		} else {
			continue
		}

		filePath := stringValue(loc["file"])
		fixBefore := stringValue(loc["fix_before"])
		fixAfter := stringValue(loc["fix_after"])
		startLine, slOk := intValue(loc["start_line"])

		if filePath == "" || fixBefore == "" || fixAfter == "" {
			continue
		}
		if !slOk || startLine < 1 {
			continue
		}
		uri := sarifURI(filePath)
		if uri == "" {
			continue
		}

		deletedRegion := Dict{"startLine": startLine}
		endLine, elOk := intValue(loc["end_line"])
		if elOk && endLine >= startLine {
			deletedRegion["endLine"] = endLine
		}

		artifactChanges = append(artifactChanges, Dict{
			"artifactLocation": Dict{"uri": uri},
			"replacements": []Dict{
				{
					"deletedRegion":   deletedRegion,
					"insertedContent": Dict{"text": fixAfter},
				},
			},
		})
	}

	if len(artifactChanges) == 0 {
		return nil
	}

	fix := Dict{"artifactChanges": artifactChanges}
	remediation := stringValue(report["remediation_steps"])
	if remediation != "" {
		fix["description"] = Dict{"text": remediation, "markdown": remediation}
	}
	return []Dict{fix}
}

// ---------------------------------------------------------------------------
// Location handling
// ---------------------------------------------------------------------------

func syntheticLocation() Dict {
	return Dict{
		"physicalLocation": Dict{
			"artifactLocation": Dict{"uri": SyntheticLocationURI},
		},
	}
}

func buildLocations(report Dict) ([]Dict, bool, int) {
	physical, droppedCount := buildPhysicalLocations(report["code_locations"])
	isSynthetic := len(physical) == 0

	var locations []Dict
	if len(physical) > 0 {
		locations = append(locations, physical...)
	} else {
		locations = append(locations, syntheticLocation())
	}

	endpoint := stringValue(report["endpoint"])
	if endpoint != "" {
		locations = append(locations, Dict{
			"logicalLocations": []Dict{
				{"fullyQualifiedName": endpoint, "kind": "endpoint"},
			},
		})
	} else if isSynthetic {
		resource := stringValue(report["target"])
		if resource == "" {
			resource = stringValue(report["title"])
		}
		if resource != "" {
			locations = append(locations, Dict{
				"logicalLocations": []Dict{
					{"fullyQualifiedName": resource, "kind": "resource"},
				},
			})
		}
	}

	return locations, isSynthetic, droppedCount
}

func buildPhysicalLocations(rawLocations interface{}) ([]Dict, int) {
	var locsInf []interface{}
	if rl, ok := rawLocations.([]interface{}); ok {
		locsInf = rl
	} else if rld, ok := rawLocations.([]Dict); ok {
		for _, v := range rld {
			locsInf = append(locsInf, v)
		}
	} else if rlmap, ok := rawLocations.([]map[string]interface{}); ok {
		for _, v := range rlmap {
			locsInf = append(locsInf, v)
		}
	} else {
		return nil, 0
	}

	var locations []Dict
	droppedCount := 0

	for _, rawLoc := range locsInf {
		var loc map[string]interface{}
		if m, ok := rawLoc.(map[string]interface{}); ok {
			loc = m
		} else if d, ok := rawLoc.(Dict); ok {
			loc = map[string]interface{}(d)
		} else {
			droppedCount++
			continue
		}

		filePath := stringValue(loc["file"])
		startLine, slOk := intValue(loc["start_line"])

		if filePath == "" || !slOk || startLine < 1 {
			droppedCount++
			continue
		}

		uri := sarifURI(filePath)
		if uri == "" {
			droppedCount++
			continue
		}

		region := Dict{"startLine": startLine}
		endLine, elOk := intValue(loc["end_line"])
		if elOk && endLine >= startLine {
			region["endLine"] = endLine
		}

		snippet := stringValue(loc["snippet"])
		if snippet != "" {
			region["snippet"] = Dict{"text": snippet}
		}

		physicalLoc := Dict{
			"artifactLocation": Dict{"uri": uri},
			"region":           region,
		}
		entry := Dict{"physicalLocation": physicalLoc}

		label := stringValue(loc["label"])
		if label != "" {
			entry["message"] = Dict{"text": label}
		}

		locations = append(locations, entry)
	}

	return locations, droppedCount
}

func sarifURI(filePath string) string {
	uri := strings.ReplaceAll(filePath, "\\", "/")
	if uri == "" || strings.HasPrefix(uri, "/") {
		return ""
	}
	parts := strings.Split(uri, "/")
	if len(parts) == 0 {
		return ""
	}
	if strings.Contains(parts[0], ":") {
		return ""
	}
	for _, part := range parts {
		if part == ".." {
			return ""
		}
	}
	return uri
}

// ---------------------------------------------------------------------------
// Rule ID resolution + CWE normalisation
// ---------------------------------------------------------------------------

func ruleID(report Dict) string {
	cwe := stringValue(report["cwe"])
	if cwe != "" {
		if norm := normaliseCWE(cwe); norm != "" {
			return norm
		}
	}
	cve := stringValue(report["cve"])
	if cve != "" {
		return cve
	}
	findingID := stringValue(report["id"])
	if findingID != "" {
		return findingID
	}
	title := stringValue(report["title"])
	if title == "" {
		title = "apex-finding"
	}
	return slugify(title)
}

func normaliseCWE(value string) string {
	var digits []rune
	for _, c := range value {
		if unicode.IsDigit(c) {
			digits = append(digits, c)
		}
	}
	if len(digits) == 0 {
		return ""
	}
	return "CWE-" + string(digits)
}

func primaryFingerprint(ruleIDStr string, report Dict, locations []Dict, isSynthetic bool) string {
	primaryPhysical := firstPhysicalLocation(locations)
	uri := ""
	var startLine *int

	if primaryPhysical != nil {
		if artLoc, ok := primaryPhysical["artifactLocation"].(Dict); ok {
			uri = stringValue(artLoc["uri"])
		} else if artLoc, ok := primaryPhysical["artifactLocation"].(map[string]interface{}); ok {
			uri = stringValue(artLoc["uri"])
		}

		if region, ok := primaryPhysical["region"].(Dict); ok {
			if sl, slOk := intValue(region["startLine"]); slOk && sl >= 1 {
				val := sl
				startLine = &val
			}
		} else if region, ok := primaryPhysical["region"].(map[string]interface{}); ok {
			if sl, slOk := intValue(region["startLine"]); slOk && sl >= 1 {
				val := sl
				startLine = &val
			}
		}
	}

	method := stringValue(report["method"])
	endpoint := stringValue(report["endpoint"])
	route := ""
	if method != "" || endpoint != "" {
		route = strings.TrimSpace(fmt.Sprintf("%s %s", strings.ToUpper(method), endpoint))
	}

	if uri == "" && route == "" {
		return ""
	}

	parts := []string{fmt.Sprintf("rule:%s", ruleIDStr)}
	if uri != "" {
		parts = append(parts, fmt.Sprintf("uri:%s", uri))
		if startLine != nil {
			parts = append(parts, fmt.Sprintf("line:%d", *startLine))
		}
	}
	if route != "" {
		parts = append(parts, fmt.Sprintf("route:%s", route))
	}

	if isSynthetic {
		title := stringValue(report["title"])
		if title != "" {
			parts = append(parts, fmt.Sprintf("synth_class:%s", classKeyword(title)))
		}
	}

	composite := strings.Join(parts, "|")
	hash := sha256.Sum256([]byte(composite))
	return hex.EncodeToString(hash[:])
}

func firstPhysicalLocation(locations []Dict) Dict {
	for _, loc := range locations {
		if phys, ok := loc["physicalLocation"].(Dict); ok {
			return phys
		} else if phys, ok := loc["physicalLocation"].(map[string]interface{}); ok {
			return Dict(phys)
		}
	}
	return nil
}

func classFingerprint(ruleIDStr string, report Dict) string {
	title := stringValue(report["title"])
	keyword := ""
	if title != "" {
		keyword = classKeyword(title)
	}
	if keyword == "" {
		return ""
	}
	composite := fmt.Sprintf("rule:%s|class:%s", ruleIDStr, keyword)
	hash := sha256.Sum256([]byte(composite))
	return hex.EncodeToString(hash[:])
}

func classKeyword(title string) string {
	if title == "" {
		return ""
	}
	lower := strings.ToLower(title)
	for _, kw := range vulnClassKeywords {
		if strings.Contains(lower, kw) {
			return kw
		}
	}
	words := reWords.FindAllString(lower, -1)
	if len(words) > 5 {
		words = words[:5]
	}
	return strings.Join(words, " ")
}

func ruleName(ruleIDStr string, title string) string {
	if title != "" {
		return title
	}
	return strings.ReplaceAll(ruleIDStr, "-", "_")
}

func ruleTags(ruleIDStr string, report Dict) []string {
	var tags []string
	tags = append(tags, "security")

	if strings.HasPrefix(ruleIDStr, "CWE-") {
		tags = append(tags, ruleIDStr)
	}

	cve := stringValue(report["cve"])
	if cve != "" && !contains(tags, cve) {
		tags = append(tags, cve)
	}

	cweStr := stringValue(report["cwe"])
	for _, leg := range strideLegsForCWE(cweStr) {
		tag := fmt.Sprintf("stride:%s", leg)
		if !contains(tags, tag) {
			tags = append(tags, tag)
		}
	}
	return tags
}

func helpURIFor(ruleIDStr string) string {
	if strings.HasPrefix(ruleIDStr, "CWE-") {
		return fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html", strings.TrimPrefix(ruleIDStr, "CWE-"))
	}
	return ""
}

// ---------------------------------------------------------------------------
// Severity + help text
// ---------------------------------------------------------------------------

func sarifLevel(severity interface{}) string {
	norm := strings.ToLower(stringValue(severity))
	if lvl, ok := severityToLevel[norm]; ok {
		return lvl
	}
	return "note"
}

func securitySeverity(report Dict) string {
	cvss := report["cvss"]
	if cvss != nil {
		switch v := cvss.(type) {
		case string:
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				return fmt.Sprintf("%.1f", f)
			}
		case float64:
			return fmt.Sprintf("%.1f", v)
		}
	}

	norm := "info"
	if sev := stringValue(report["severity"]); sev != "" {
		norm = strings.ToLower(sev)
	}
	if score, ok := severityToScore[norm]; ok {
		return score
	}
	return "1.0"
}

func helpText(report Dict, fallback string) string {
	var sections []string
	if desc := stringValue(report["description"]); desc != "" {
		sections = append(sections, desc)
	}
	if impact := stringValue(report["impact"]); impact != "" {
		sections = append(sections, impact)
	}
	if remediation := stringValue(report["remediation_steps"]); remediation != "" {
		sections = append(sections, remediation)
	}

	if len(sections) > 0 {
		return strings.Join(sections, "\n\n")
	}
	return fallback
}

// ---------------------------------------------------------------------------
// Summaries for unsafe-location findings
// ---------------------------------------------------------------------------

func droppedLocationSummary(report Dict, droppedLocationCount int) Dict {
	summary := Dict{"droppedLocationCount": droppedLocationCount}
	if id := stringValue(report["id"]); id != "" {
		summary["id"] = id
	}
	if title := stringValue(report["title"]); title != "" {
		summary["title"] = title
	}
	return summary
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

func slugify(value string) string {
	var chars []rune
	for _, char := range value {
		if unicode.IsLetter(char) || unicode.IsDigit(char) {
			chars = append(chars, unicode.ToLower(char))
		} else {
			chars = append(chars, '-')
		}
	}

	parts := strings.Split(string(chars), "-")
	var validParts []string
	for _, p := range parts {
		if p != "" {
			validParts = append(validParts, p)
		}
	}

	slug := strings.Join(validParts, "-")
	if slug == "" {
		return "apex-finding"
	}
	return slug
}
