package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	severityOrder = map[string]int{
		"critical": 0,
		"high":     1,
		"medium":   2,
		"low":      3,
		"info":     4,
	}

	fenceRe       = regexp.MustCompile("(?s)^```([^\\n`]*)\\r?\\n(.*)\\r?\\n?```$")
	backtickRunRe = regexp.MustCompile("`+")
)

// STUBS for missing dependencies
type Lexer interface{}

func getLexerByName(language string) (Lexer, error) {
	return nil, fmt.Errorf("ClassNotFound")
}

func guessLexer(code string) (Lexer, error) {
	return nil, fmt.Errorf("ClassNotFound")
}

type textLexer struct{}

func isTextLexer(l Lexer) bool {
	_, ok := l.(*textLexer)
	return ok
}

type pyLexer struct {
	aliases []string
}

func getAliases(l Lexer) []string {
	if p, ok := l.(*pyLexer); ok {
		return p.aliases
	}
	return nil
}

func runRecordPath(runDir string) string {
	return filepath.Join(runDir, "run.json")
}

// END STUBS

func SafeFence(content string) string {
	longest := 0
	matches := backtickRunRe.FindAllString(content, -1)
	for _, m := range matches {
		if len(m) > longest {
			longest = len(m)
		}
	}
	length := longest + 1
	if length < 3 {
		length = 3
	}
	return strings.Repeat("`", length)
}

func ParseFencedCode(raw string) (string, string) {
	match := fenceRe.FindStringSubmatch(strings.TrimSpace(raw))
	if match == nil {
		return "", raw
	}
	info := strings.TrimSpace(match[1])
	language := ""
	if info != "" {
		language = strings.Split(info, " ")[0]
	}
	return language, match[2]
}

func ResolveLexer(language string, code string) Lexer {
	if language != "" {
		if lexer, err := getLexerByName(language); err == nil {
			return lexer
		}
	}
	lexer, err := guessLexer(code)
	if err != nil || isTextLexer(lexer) {
		return &pyLexer{} // Fallback to python lexer
	}
	return lexer
}

// GuessLanguageName attempts to determine the programming language of a code snippet.
// It acts as a lightweight replacement for Python's pygments.lexers.guess_lexer.
// Language detection is best-effort and uses simple substring heuristics.
// If the language cannot be determined, it safely falls back to "python".
// This heuristic approach is acceptable for Markdown rendering purposes, as
// pulling in a full Go syntax highlighter like chroma is often unnecessary overhead.
func GuessLanguageName(code string) string {
	if strings.Contains(code, "package ") && strings.Contains(code, "func ") {
		return "go"
	}
	if strings.Contains(code, "import React") || strings.Contains(code, "console.log(") {
		return "javascript"
	}
	if strings.Contains(code, "def ") && strings.Contains(code, "self") {
		return "python"
	}
	if strings.Contains(code, "<?php") {
		return "php"
	}
	if strings.Contains(code, "public class ") && strings.Contains(code, "public static void main") {
		return "java"
	}
	if strings.Contains(code, "#include <") {
		return "cpp"
	}
	
	lexer, err := guessLexer(code)
	if err != nil || isTextLexer(lexer) {
		return "python"
	}
	aliases := getAliases(lexer)
	if len(aliases) == 0 {
		return "python"
	}
	return aliases[0]
}

func ReadRunRecord(runDir string) (map[string]any, error) {
	path := runRecordPath(runDir)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return make(map[string]any), nil
	}

	dataBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("run.json at %s is unreadable: %w", path, err)
	}

	var data map[string]any
	if err := json.Unmarshal(dataBytes, &data); err != nil {
		return nil, fmt.Errorf("run.json at %s is not an object: %w", path, err)
	}

	return data, nil
}

func WriteRunRecord(runDir string, runRecord map[string]any) error {
	dataBytes, err := json.MarshalIndent(runRecord, "", "  ")
	if err != nil {
		return err
	}
	return AtomicWriteText(runRecordPath(runDir), string(dataBytes))
}

func WriteExecutiveReport(runDir string, finalScanResult string) error {
	path := filepath.Join(runDir, "penetration_test_report.md")

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = fmt.Fprintf(f, "# Security Penetration Test Report\n\n**Generated:** %s\n\n%s\n", time.Now().UTC().Format("2006-01-02 15:04:05 UTC"), finalScanResult)
	return err
}

func WriteVulnerabilities(runDir string, vulnerabilityReports []map[string]any, savedVulnIds map[string]bool) (int, error) {
	vulnDir := filepath.Join(runDir, "vulnerabilities")
	if err := os.MkdirAll(vulnDir, 0755); err != nil {
		return 0, err
	}

	var newReports []map[string]any
	for _, report := range vulnerabilityReports {
		id, ok := report["id"].(string)
		if !ok {
			id = "unknown"
		}
		if !savedVulnIds[id] {
			newReports = append(newReports, report)
		}
	}

	for _, report := range newReports {
		id, _ := report["id"].(string)
		if id == "" {
			id = "unknown"
		}

		path := filepath.Join(vulnDir, id+".md")
		err := AtomicWriteText(path, RenderVulnerabilityMd(report))
		if err != nil {
			return 0, err
		}
		savedVulnIds[id] = true
	}

	sortedReports := make([]map[string]any, len(vulnerabilityReports))
	copy(sortedReports, vulnerabilityReports)

	sort.Slice(sortedReports, func(i, j int) bool {
		sevI, _ := sortedReports[i]["severity"].(string)
		sevJ, _ := sortedReports[j]["severity"].(string)

		orderI, ok := severityOrder[sevI]
		if !ok {
			orderI = 5
		}
		orderJ, ok := severityOrder[sevJ]
		if !ok {
			orderJ = 5
		}

		if orderI != orderJ {
			return orderI < orderJ
		}

		tsI, _ := sortedReports[i]["timestamp"].(string)
		tsJ, _ := sortedReports[j]["timestamp"].(string)
		return tsI < tsJ
	})

	csvPath := filepath.Join(runDir, "vulnerabilities.csv")
	var csvBuf strings.Builder
	csvWriter := csv.NewWriter(&csvBuf)
	csvWriter.UseCRLF = true

	_ = csvWriter.Write([]string{"id", "title", "severity", "timestamp", "file"})

	for _, report := range sortedReports {
		id, _ := report["id"].(string)
		title, _ := report["title"].(string)
		severity, _ := report["severity"].(string)
		timestamp, _ := report["timestamp"].(string)

		_ = csvWriter.Write([]string{
			id,
			title,
			strings.ToUpper(severity),
			timestamp,
			fmt.Sprintf("vulnerabilities/%s.md", id),
		})
	}
	csvWriter.Flush()

	if err := AtomicWriteText(csvPath, csvBuf.String()); err != nil {
		return 0, err
	}

	jsonBytes, err := json.MarshalIndent(vulnerabilityReports, "", "  ")
	if err != nil {
		return 0, err
	}

	if err := AtomicWriteText(filepath.Join(runDir, "vulnerabilities.json"), string(jsonBytes)); err != nil {
		return 0, err
	}

	return len(newReports), nil
}

func AtomicWriteText(path string, payload string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	tmpFile, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}

	tmpPath := tmpFile.Name()

	if _, err := tmpFile.WriteString(payload); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return err
	}

	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}

	return os.Rename(tmpPath, path)
}

func RenderVulnerabilityMd(report map[string]any) string {
	getString := func(k string) string {
		v, ok := report[k].(string)
		if !ok {
			return ""
		}
		return v
	}

	getStringDef := func(k string, def string) string {
		v, ok := report[k].(string)
		if !ok || v == "" {
			return def
		}
		return v
	}

	title := getStringDef("title", "Untitled Vulnerability")
	id := getStringDef("id", "unknown")
	severity := getStringDef("severity", "unknown")
	timestamp := getStringDef("timestamp", "unknown")

	var lines []string
	lines = append(lines, fmt.Sprintf("# %s\n", title))
	lines = append(lines, fmt.Sprintf("**ID:** %s", id))
	lines = append(lines, fmt.Sprintf("**Severity:** %s", strings.ToUpper(severity)))
	lines = append(lines, fmt.Sprintf("**Found:** %s", timestamp))

	depMeta, _ := report["dependency_metadata"].(map[string]any)
	if depMeta == nil {
		depMeta = make(map[string]any)
	}

	getDepMetaString := func(k string) string {
		if v, ok := depMeta[k].(string); ok {
			return v
		}
		return ""
	}

	type metaPair struct {
		Label string
		Value string
	}
	metadata := []metaPair{
		{"Target", getString("target")},
		{"Package", getDepMetaString("package_name")},
		{"Ecosystem", getDepMetaString("package_ecosystem")},
		{"Installed Version", getDepMetaString("installed_version")},
		{"Fixed Version", getDepMetaString("fixed_version")},
		{"Endpoint", getString("endpoint")},
		{"Method", getString("method")},
		{"CVE", getString("cve")},
		{"CWE", getString("cwe")},
	}

	if cvss, ok := report["cvss"]; ok && cvss != nil {
		metadata = append(metadata, metaPair{"CVSS", fmt.Sprintf("%v", cvss)})
	}

	if fixEffort, ok := report["fix_effort"]; ok && fixEffort != nil && fmt.Sprintf("%v", fixEffort) != "" {
		effortStr := fmt.Sprintf("%v", fixEffort)
		words := strings.Fields(effortStr)
		for i, w := range words {
			if len(w) > 0 {
				words[i] = strings.ToUpper(w[:1]) + strings.ToLower(w[1:])
			}
		}
		effortStr = strings.Join(words, " ")
		metadata = append(metadata, metaPair{"Fix Effort", effortStr})
	}

	for _, item := range metadata {
		if item.Value != "" {
			lines = append(lines, fmt.Sprintf("**%s:** %s", item.Label, item.Value))
		}
	}

	lines = append(lines, "")
	lines = append(lines, "## Description\n")
	desc := getStringDef("description", "No description provided.")
	lines = append(lines, desc)
	lines = append(lines, "")

	if evidence, ok := report["evidence"]; ok && evidence != nil {
		lines = append(lines, "## Evidence\n")
		lines = append(lines, fmt.Sprintf("%v", evidence))
		lines = append(lines, "")
	}

	if impact, ok := report["impact"]; ok && impact != nil {
		lines = append(lines, "## Impact\n")
		lines = append(lines, fmt.Sprintf("%v", impact))
		lines = append(lines, "")
	}

	if techAnalysis, ok := report["technical_analysis"]; ok && techAnalysis != nil {
		lines = append(lines, "## Technical Analysis\n")
		lines = append(lines, fmt.Sprintf("%v", techAnalysis))
		lines = append(lines, "")
	}

	pocDesc, _ := report["poc_description"]
	pocCode, _ := report["poc_script_code"]

	if (pocDesc != nil && fmt.Sprintf("%v", pocDesc) != "") || (pocCode != nil && fmt.Sprintf("%v", pocCode) != "") {
		lines = append(lines, "## Proof of Concept\n")
		if pocDesc != nil && fmt.Sprintf("%v", pocDesc) != "" {
			lines = append(lines, fmt.Sprintf("%v", pocDesc))
			lines = append(lines, "")
		}
		if pocCode != nil && fmt.Sprintf("%v", pocCode) != "" {
			pocCodeStr := fmt.Sprintf("%v", pocCode)
			language, code := ParseFencedCode(pocCodeStr)
			fenceLang := language
			if fenceLang == "" {
				fenceLang = GuessLanguageName(code)
			}
			fence := SafeFence(code)
			lines = append(lines, fmt.Sprintf("%s%s", fence, fenceLang))
			lines = append(lines, code)
			lines = append(lines, fence)
			lines = append(lines, "")
		}
	}

	if codeLocs, ok := report["code_locations"].([]any); ok && len(codeLocs) > 0 {
		lines = append(lines, "## Code Analysis\n")
		for i, locAny := range codeLocs {
			loc, ok := locAny.(map[string]any)
			if !ok {
				continue
			}
			fileRef, ok := loc["file"].(string)
			if !ok || fileRef == "" {
				fileRef = "unknown"
			}

			lineRef := ""
			startLine, hasStart := loc["start_line"]
			if hasStart && startLine != nil {
				endLine, hasEnd := loc["end_line"]
				if hasEnd && endLine != nil && fmt.Sprintf("%v", endLine) != fmt.Sprintf("%v", startLine) {
					lineRef = fmt.Sprintf(" (lines %v-%v)", startLine, endLine)
				} else {
					lineRef = fmt.Sprintf(" (line %v)", startLine)
				}
			}

			lines = append(lines, fmt.Sprintf("**Location %d:** `%s`%s", i+1, fileRef, lineRef))

			if label, ok := loc["label"]; ok && label != nil && fmt.Sprintf("%v", label) != "" {
				lines = append(lines, fmt.Sprintf("  %v", label))
			}

			if snippet, ok := loc["snippet"]; ok && snippet != nil && fmt.Sprintf("%v", snippet) != "" {
				snippetStr := fmt.Sprintf("%v", snippet)
				fence := SafeFence(snippetStr)
				lines = append(lines, fmt.Sprintf("  %s", fence))

				snippetLines := strings.Split(strings.ReplaceAll(snippetStr, "\r\n", "\n"), "\n")
				for _, ln := range snippetLines {
					lines = append(lines, fmt.Sprintf("  %s", ln))
				}
				lines = append(lines, fmt.Sprintf("  %s", fence))
			}

			fixBefore, hasFixBefore := loc["fix_before"]
			fixAfter, hasFixAfter := loc["fix_after"]

			if (hasFixBefore && fixBefore != nil && fmt.Sprintf("%v", fixBefore) != "") ||
				(hasFixAfter && fixAfter != nil && fmt.Sprintf("%v", fixAfter) != "") {
				lines = append(lines, "\n  **Suggested Fix:**")
				lines = append(lines, "```diff")

				if hasFixBefore && fixBefore != nil && fmt.Sprintf("%v", fixBefore) != "" {
					fixBeforeLines := strings.Split(strings.ReplaceAll(fmt.Sprintf("%v", fixBefore), "\r\n", "\n"), "\n")
					for _, ln := range fixBeforeLines {
						lines = append(lines, fmt.Sprintf("- %s", ln))
					}
				}

				if hasFixAfter && fixAfter != nil && fmt.Sprintf("%v", fixAfter) != "" {
					fixAfterLines := strings.Split(strings.ReplaceAll(fmt.Sprintf("%v", fixAfter), "\r\n", "\n"), "\n")
					for _, ln := range fixAfterLines {
						lines = append(lines, fmt.Sprintf("+ %s", ln))
					}
				}

				lines = append(lines, "```")
			}
			lines = append(lines, "")
		}
	}

	if remSteps, ok := report["remediation_steps"]; ok && remSteps != nil && fmt.Sprintf("%v", remSteps) != "" {
		lines = append(lines, "## Remediation\n")
		lines = append(lines, fmt.Sprintf("%v", remSteps))
		lines = append(lines, "")
	}

	if assumptions, ok := report["assumptions"]; ok && assumptions != nil && fmt.Sprintf("%v", assumptions) != "" {
		lines = append(lines, "## Assumptions\n")
		lines = append(lines, fmt.Sprintf("%v", assumptions))
		lines = append(lines, "")
	}

	return strings.Join(lines, "\n")
}
