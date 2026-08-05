package viewer

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/jung-kurt/gofpdf"
	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
)

const (
	INK      = "#000000"
	TEXT     = "#1a1a1a"
	MUTED    = "#666666"
	FAINT    = "#999999"
	BORDER   = "#e5e5e5"
	LIGHT_BG = "#f7f7f7"
)

var severityOrder = []string{"critical", "high", "medium", "low"}
var severityColors = map[string]string{
	"critical": "#dc2626",
	"high":     "#ea580c",
	"medium":   "#ca8a04",
	"low":      "#2563eb",
}

func hexColor(pdf *gofpdf.Fpdf, hexStr string) {
	var r, g, b int
	fmt.Sscanf(hexStr, "#%02x%02x%02x", &r, &g, &b)
	pdf.SetTextColor(r, g, b)
}

func hexFillColor(pdf *gofpdf.Fpdf, hexStr string) {
	var r, g, b int
	fmt.Sscanf(hexStr, "#%02x%02x%02x", &r, &g, &b)
	pdf.SetFillColor(r, g, b)
}

func hexDrawColor(pdf *gofpdf.Fpdf, hexStr string) {
	var r, g, b int
	fmt.Sscanf(hexStr, "#%02x%02x%02x", &r, &g, &b)
	pdf.SetDrawColor(r, g, b)
}

func GeneratePassword() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func EncryptPDF(pdfBytes []byte, password string) ([]byte, error) {
	conf := model.NewAESConfiguration(password, password, 256)
	rs := bytes.NewReader(pdfBytes)
	var out bytes.Buffer
	err := api.Encrypt(rs, &out, conf)
	if err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

type RunSummary struct {
	RunName       string        `json:"run_name"`
	ScanMode      string        `json:"scan_mode"`
	Status        string        `json:"status"`
	StartTime     string        `json:"start_time"`
	EndTime       string        `json:"end_time"`
	TargetsInfo   []interface{} `json:"targets_info"`
	ScanResults   struct {
		ExecutiveSummary string `json:"executive_summary"`
		Methodology      string `json:"methodology"`
		TechnicalAnalysis string `json:"technical_analysis"`
		Recommendations  string `json:"recommendations"`
	} `json:"scan_results"`
}

type Vulnerability struct {
	Title             string      `json:"title"`
	Severity          string      `json:"severity"`
	CVSS              interface{} `json:"cvss"`
	Target            string      `json:"target"`
	Endpoint          string      `json:"endpoint"`
	Method            string      `json:"method"`
	Description       string      `json:"description"`
	Impact            string      `json:"impact"`
	TechnicalAnalysis string      `json:"technical_analysis"`
	PoCDescription    string      `json:"poc_description"`
	PoCScriptCode     string      `json:"poc_script_code"`
	Evidence          string      `json:"evidence"`
	RemediationSteps  interface{} `json:"remediation_steps"`
}

func BuildEncryptedReport(runDir string) ([]byte, string, string, error) {
	summaryPath := filepath.Join(runDir, "run.json")
	var record RunSummary
	if b, err := os.ReadFile(summaryPath); err == nil {
		json.Unmarshal(b, &record)
	}

	runName := record.RunName
	if runName == "" {
		runName = filepath.Base(runDir)
	}

	pdfBytes, err := GenerateReportPDF(runDir)
	if err != nil {
		return nil, "", "", err
	}

	password := GeneratePassword()
	encrypted, err := EncryptPDF(pdfBytes, password)
	if err != nil {
		return nil, "", "", err
	}

	filename := fmt.Sprintf("apex-report-%s.pdf", runName)
	return encrypted, password, filename, nil
}

func parseTime(raw string) (time.Time, bool) {
	if raw == "" {
		return time.Time{}, false
	}
	tstr := strings.ReplaceAll(raw, " UTC", "Z")
	tstr = strings.ReplaceAll(tstr, " ", "T")
	if strings.HasSuffix(tstr, "Z") {
		tstr = tstr[:len(tstr)-1] + "+00:00"
	}
	t, err := time.Parse(time.RFC3339, tstr)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

func fmtTime(raw string) string {
	t, ok := parseTime(raw)
	if !ok {
		return "n/a"
	}
	return t.Format("2006-01-02 15:04 UTC")
}

func duration(start, end string) string {
	s, ok1 := parseTime(start)
	e, ok2 := parseTime(end)
	if !ok1 || !ok2 {
		return "n/a"
	}
	d := e.Sub(s)
	if d < 0 {
		return "n/a"
	}
	secs := int(d.Seconds())
	hours := secs / 3600
	rem := secs % 3600
	mins := rem / 60
	secs = rem % 60
	if hours > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, mins, secs)
	}
	if mins > 0 {
		return fmt.Sprintf("%dm %ds", mins, secs)
	}
	return fmt.Sprintf("%ds", secs)
}

func primaryTarget(record RunSummary) string {
	for _, t := range record.TargetsInfo {
		if m, ok := t.(map[string]interface{}); ok {
			if orig, ok := m["original"].(string); ok && orig != "" {
				return orig
			}
		}
	}
	return "unknown target"
}

func GenerateReportPDF(runDir string) ([]byte, error) {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(20, 22, 20)
	pdf.SetAutoPageBreak(true, 24)

	pdf.SetFooterFunc(func() {
		if pdf.PageNo() > 1 {
			pdf.SetY(-14)
			pdf.SetFont("Helvetica", "", 8)
			hexColor(pdf, FAINT)
			pdf.CellFormat(0, 10, fmt.Sprintf("Page %d", pdf.PageNo()), "", 0, "C", false, 0, "")
		}
	})

	var record RunSummary
	b, err := os.ReadFile(filepath.Join(runDir, "run.json"))
	if err == nil {
		json.Unmarshal(b, &record)
	}
	runName := record.RunName
	if runName == "" {
		runName = filepath.Base(runDir)
	}

	var vulns []Vulnerability
	if b, err := os.ReadFile(filepath.Join(runDir, "vulnerabilities.json")); err == nil {
		json.Unmarshal(b, &vulns)
	}

	counts := make(map[string]int)
	for _, v := range vulns {
		sev := strings.ToLower(strings.TrimSpace(v.Severity))
		if sev != "critical" && sev != "high" && sev != "medium" && sev != "low" {
			sev = "low"
		}
		counts[sev]++
	}

	pdf.AddPage()
	
	s := 10.58
	hexFillColor(pdf, INK)
	pdf.Rect(20, 22, s, s, "F")
	hexColor(pdf, "#ffffff")
	pdf.SetFont("Helvetica", "B", 17)
	pdf.Text(20+s/2-3, 22+s/2+2, "S")

	hexColor(pdf, INK)
	pdf.SetFont("Helvetica", "B", 17)
	pdf.SetXY(20+s+4, 22)
	pdf.CellFormat(0, s, "Apex", "", 1, "L", false, 0, "")

	pdf.Ln(150 * 0.352778)
	
	hexColor(pdf, MUTED)
	pdf.SetFont("Helvetica", "B", 9)
	pdf.CellFormat(0, 4.2, "PENETRATION TEST REPORT", "", 1, "L", false, 0, "")
	
	pdf.Ln(20 * 0.352778)

	hexColor(pdf, INK)
	pdf.SetFont("Helvetica", "B", 34)
	pdf.CellFormat(0, 13.4, "Security Assessment", "", 1, "L", false, 0, "")
	
	hexColor(pdf, MUTED)
	pdf.SetFont("Helvetica", "", 13)
	target := primaryTarget(record)
	pdf.CellFormat(0, 6.35, target, "", 1, "L", false, 0, "")
	
	pdf.Ln(28 * 0.352778)

	meta := [][]string{
		{"TARGET", target},
		{"RUN", runName},
		{"SCAN MODE", record.ScanMode},
		{"STATUS", record.Status},
		{"STARTED", fmtTime(record.StartTime)},
		{"COMPLETED", fmtTime(record.EndTime)},
		{"DURATION", duration(record.StartTime, record.EndTime)},
	}

	for _, m := range meta {
		val := m[1]
		if val == "" {
			val = "n/a"
		}
		pdf.SetFont("Helvetica", "B", 8)
		hexColor(pdf, MUTED)
		y := pdf.GetY()
		pdf.CellFormat(38, 5, m[0], "", 0, "L", false, 0, "")
		
		pdf.SetFont("Helvetica", "", 10.5)
		hexColor(pdf, TEXT)
		pdf.CellFormat(0, 5, val, "", 1, "L", false, 0, "")
		
		hexDrawColor(pdf, BORDER)
		pdf.SetLineWidth(0.5 * 0.352778)
		if m[0] != "DURATION" {
			pdf.Line(20, pdf.GetY()+1, 20+170, pdf.GetY()+1)
		}
		pdf.Ln(2)
		_ = y
	}

	pdf.Ln(90 * 0.352778)

	hexFillColor(pdf, INK)
	hexColor(pdf, "#ffffff")
	pdf.SetFont("Helvetica", "B", 9)
	pdf.SetX((210 - 120*0.352778) / 2)
	pdf.CellFormat(120*0.352778, 10, "CONFIDENTIAL", "", 1, "C", true, 0, "")

	pdf.AddPage()
	
	hexColor(pdf, INK)
	pdf.SetFont("Helvetica", "B", 18)
	pdf.CellFormat(0, 8, "Executive Summary", "", 1, "L", false, 0, "")
	hexDrawColor(pdf, BORDER)
	pdf.SetLineWidth(0.352778)
	pdf.Line(20, pdf.GetY(), 190, pdf.GetY())
	pdf.Ln(6)

	colW := (170.0) / 4.0
	yGrid := pdf.GetY()
	for i, name := range severityOrder {
		x := 20.0 + float64(i)*colW
		
		hexFillColor(pdf, severityColors[name])
		pdf.Rect(x, yGrid, colW, 1, "F")
		
		hexDrawColor(pdf, BORDER)
		pdf.Rect(x, yGrid, colW, 20, "D")

		pdf.SetXY(x, yGrid+4)
		hexColor(pdf, severityColors[name])
		pdf.SetFont("Helvetica", "B", 30)
		pdf.CellFormat(colW, 10, fmt.Sprintf("%d", counts[name]), "", 2, "C", false, 0, "")
		
		hexColor(pdf, MUTED)
		pdf.SetFont("Helvetica", "B", 8)
		pdf.CellFormat(colW, 4, strings.ToUpper(name), "", 0, "C", false, 0, "")
	}
	pdf.SetY(yGrid + 25)

	hexColor(pdf, TEXT)
	pdf.SetFont("Helvetica", "", 10)
	pdf.CellFormat(0, 5, fmt.Sprintf("%d total findings across this assessment.", len(vulns)), "", 1, "L", false, 0, "")
	
	if record.ScanResults.ExecutiveSummary != "" {
		pdf.Ln(6)
		writeMarkdown(pdf, record.ScanResults.ExecutiveSummary)
	}

	for _, tuple := range [][]string{
		{"Methodology", record.ScanResults.Methodology},
		{"Technical Analysis", record.ScanResults.TechnicalAnalysis},
		{"Recommendations", record.ScanResults.Recommendations},
	} {
		if tuple[1] != "" {
			pdf.Ln(7)
			hexColor(pdf, INK)
			pdf.SetFont("Helvetica", "B", 18)
			pdf.CellFormat(0, 8, tuple[0], "", 1, "L", false, 0, "")
			hexDrawColor(pdf, BORDER)
			pdf.Line(20, pdf.GetY(), 190, pdf.GetY())
			pdf.Ln(4)
			writeMarkdown(pdf, tuple[1])
		}
	}

	pdf.AddPage()
	hexColor(pdf, INK)
	pdf.SetFont("Helvetica", "B", 18)
	pdf.CellFormat(0, 8, "Findings", "", 1, "L", false, 0, "")
	hexDrawColor(pdf, BORDER)
	pdf.Line(20, pdf.GetY(), 190, pdf.GetY())
	pdf.Ln(6)

	if len(vulns) == 0 {
		hexColor(pdf, TEXT)
		pdf.SetFont("Helvetica", "", 10)
		pdf.CellFormat(0, 5, "No findings were recorded for this run.", "", 1, "L", false, 0, "")
	} else {
		for i, v := range vulns {
			title := v.Title
			if title == "" {
				title = "Untitled finding"
			}
			sev := strings.ToLower(strings.TrimSpace(v.Severity))
			if sev == "" {
				sev = "low"
			}

			if pdf.GetY() > 250 {
				pdf.AddPage()
			}

			hexColor(pdf, INK)
			pdf.SetFont("Helvetica", "B", 13)
			pdf.MultiCell(0, 6, fmt.Sprintf("%d. %s", i+1, title), "", "L", false)
			
			pdf.Ln(2)
			
			hexFillColor(pdf, severityColors[sev])
			if severityColors[sev] == "" {
				hexFillColor(pdf, MUTED)
			}
			hexColor(pdf, "#ffffff")
			pdf.SetFont("Helvetica", "B", 9)
			bw := float64(len(sev))*2.3 + 10.0
			pdf.CellFormat(bw, 6, strings.ToUpper(sev), "", 0, "C", true, 0, "")
			
			pdf.SetX(pdf.GetX() + 4)
			
			var metas []string
			if v.CVSS != nil {
				metas = append(metas, fmt.Sprintf("CVSS %v", v.CVSS))
			}
			if v.Target != "" { metas = append(metas, "Target "+v.Target) }
			if v.Endpoint != "" { metas = append(metas, "Endpoint "+v.Endpoint) }
			if v.Method != "" { metas = append(metas, "Method "+v.Method) }
			
			if len(metas) > 0 {
				hexColor(pdf, MUTED)
				pdf.SetFont("Helvetica", "", 9)
				pdf.CellFormat(0, 6, strings.Join(metas, "  "), "", 1, "L", false, 0, "")
			} else {
				pdf.Ln(6)
			}

			fieldBlock(pdf, "Description", v.Description, false)
			fieldBlock(pdf, "Impact", v.Impact, false)
			fieldBlock(pdf, "Technical analysis", v.TechnicalAnalysis, false)
			fieldBlock(pdf, "Proof of concept", v.PoCDescription, false)
			fieldBlock(pdf, "PoC script", stripCodeFence(v.PoCScriptCode), true)
			fieldBlock(pdf, "Evidence", stripCodeFence(v.Evidence), true)
			
			var rem string
			if l, ok := v.RemediationSteps.([]interface{}); ok {
				var ss []string
				for _, r := range l {
					ss = append(ss, fmt.Sprintf("%v", r))
				}
				rem = strings.Join(ss, "\n")
			} else if s, ok := v.RemediationSteps.(string); ok {
				rem = s
			}
			fieldBlock(pdf, "Remediation", rem, false)
			
			pdf.Ln(8)
		}
	}

	var buf bytes.Buffer
	err = pdf.Output(&buf)
	return buf.Bytes(), err
}

func stripCodeFence(val string) string {
	val = strings.TrimSpace(val)
	if strings.HasPrefix(val, "```") {
		lines := strings.Split(val, "\n")
		if len(lines) > 2 && strings.HasPrefix(lines[len(lines)-1], "```") {
			return strings.Join(lines[1:len(lines)-1], "\n")
		}
	}
	return val
}

func fieldBlock(pdf *gofpdf.Fpdf, label, value string, code bool) {
	if strings.TrimSpace(value) == "" {
		return
	}
	pdf.Ln(4)
	hexColor(pdf, MUTED)
	pdf.SetFont("Helvetica", "B", 8.5)
	pdf.CellFormat(0, 4, strings.ToUpper(label), "", 1, "L", false, 0, "")
	
	if code {
		pdf.Ln(2)
		hexColor(pdf, TEXT)
		hexFillColor(pdf, LIGHT_BG)
		hexDrawColor(pdf, BORDER)
		pdf.SetLineWidth(0.3)
		pdf.SetFont("Courier", "", 8)
		
		x, y := pdf.GetXY()
		lines := pdf.SplitLines([]byte(value), 166)
		h := float64(len(lines)) * 4.0
		if y+h > 270 {
			pdf.AddPage()
			x, y = pdf.GetXY()
		}
		
		pdf.Rect(x, y, 170, h+4, "FD")
		pdf.SetXY(x+2, y+2)
		for _, l := range lines {
			pdf.CellFormat(166, 4, string(l), "", 2, "L", false, 0, "")
		}
		pdf.SetXY(20, y+h+4)
	} else {
		writeMarkdown(pdf, value)
	}
}

var headingRe = regexp.MustCompile(`^(#{1,6})\s+(.*)$`)
var orderedRe = regexp.MustCompile(`^(\d+)\.\s+(.*)$`)
var unorderedRe = regexp.MustCompile(`^[-*+]\s+(.*)$`)
var mdBold = regexp.MustCompile(`\*\*(.*?)\*\*|__(.*?)__`)

func writeMarkdown(pdf *gofpdf.Fpdf, md string) {
	lines := strings.Split(strings.ReplaceAll(md, "\r\n", "\n"), "\n")
	
	if len(lines) > 0 {
		if headingRe.MatchString(strings.TrimSpace(lines[0])) {
			lines = lines[1:]
		}
	}
	
	inCode := false
	var codeLines []string
	
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "```") {
			if inCode {
				fieldBlock(pdf, "", strings.Join(codeLines, "\n"), true)
				codeLines = nil
				inCode = false
			} else {
				inCode = true
			}
			continue
		}
		if inCode {
			codeLines = append(codeLines, raw)
			continue
		}
		
		if line == "" {
			pdf.Ln(2)
			continue
		}
		
		if m := headingRe.FindStringSubmatch(line); m != nil {
			pdf.Ln(3)
			hexColor(pdf, INK)
			pdf.SetFont("Helvetica", "B", 11)
			pdf.MultiCell(0, 5, m[2], "", "L", false)
			pdf.Ln(1)
			continue
		}
		
		if m := orderedRe.FindStringSubmatch(line); m != nil {
			hexColor(pdf, TEXT)
			pdf.SetFont("Helvetica", "", 10)
			pdf.SetX(25)
			text := mdBold.ReplaceAllString(m[2], "$1$2")
			pdf.MultiCell(0, 5, m[1]+". "+text, "", "L", false)
			continue
		}
		
		if m := unorderedRe.FindStringSubmatch(line); m != nil {
			hexColor(pdf, TEXT)
			pdf.SetFont("Helvetica", "", 10)
			pdf.SetX(25)
			text := mdBold.ReplaceAllString(m[1], "$1$2")
			pdf.MultiCell(0, 5, string(rune(149))+" "+text, "", "L", false)
			continue
		}
		
		hexColor(pdf, TEXT)
		pdf.SetFont("Helvetica", "", 10)
		text := mdBold.ReplaceAllString(line, "$1$2")
		pdf.MultiCell(0, 5, text, "", "L", false)
	}
}
