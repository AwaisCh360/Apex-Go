package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/AwaisCh360/Apex/apex/config"
	"github.com/AwaisCh360/Apex/apex/core"
	"github.com/AwaisCh360/Apex/apex/report"
)

var logger = log.New(os.Stderr, "[cli] ", log.LstdFlags)

type LiveUI struct {
	mu           sync.Mutex
	lastLines    int
	reportState  *report.ReportState
	startupPhase *[]string
}

func (l *LiveUI) Render() {
	l.mu.Lock()
	defer l.mu.Unlock()
	
	text := "Penetration test in progress...\n\n"
	if !HasModelResponse(l.reportState) {
		text += fmt.Sprintf("%s...\n\n", (*l.startupPhase)[0])
	}
	stats := BuildLiveStatsText(l.reportState)
	if stats != "" {
		text += stats
	}

	l.clear()
	fmt.Print(text)
	l.lastLines = strings.Count(text, "\n")
	if !strings.HasSuffix(text, "\n") {
		l.lastLines++
	}
}

func (l *LiveUI) Clear() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.clear()
}

func (l *LiveUI) clear() {
	if l.lastLines > 0 {
		fmt.Printf("\033[%dA\033[J", l.lastLines)
		l.lastLines = 0
	}
}

func (l *LiveUI) DisplayVulnerability(r map[string]interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.clear()
	
	id, _ := r["id"].(string)
	if id == "" {
		id = "unknown"
	}
	fmt.Printf("\n[%s]\n%s\n\n", id, FormatVulnerabilityReport(r))
}

// Stubs for utils and runner dependencies
func ResolveSandboxImage() string {
	settings := config.LoadSettings()
	if settings.Runtime.Image == "" {
		panic("apex_image is not configured")
	}
	return settings.Runtime.Image
}

func FormatVulnerabilityReport(report map[string]interface{}) string {
	return fmt.Sprintf("%v", report)
}
func BuildLiveStatsText(rs *report.ReportState) string { return "" }
func HasModelResponse(rs *report.ReportState) bool { return false }
func SessionManagerCleanup(runName string) {}

func RunCLI(args *CliArgs) error {
	fmt.Println("\n[APEX] Penetration test initiated")
	
	targetsText := ""
	if len(args.TargetsInfo) == 1 {
		if orig, ok := args.TargetsInfo[0]["original"].(string); ok {
			targetsText = orig
		}
	} else {
		targetsText = fmt.Sprintf("%d targets", len(args.TargetsInfo))
		for _, t := range args.TargetsInfo {
			if orig, ok := t["original"].(string); ok {
				targetsText += "\n        " + orig
			}
		}
	}
	fmt.Printf("Target  %s\n", targetsText)
	
	runName := "unknown"
	if args.RunName != nil { runName = *args.RunName }
	fmt.Printf("Output  apex_runs/%s\n\n", runName)
	fmt.Println("Vulnerabilities will be displayed in real-time.")
	fmt.Println()

	scanConfig := map[string]interface{}{
		"scan_id":            runName,
		"targets":            args.TargetsInfo,
		"run_name":           runName,
		"diff_scope":         args.DiffScope,
		"scan_mode":          args.ScanMode,
		"non_interactive":    args.NonInteractive,
		"local_sources":      args.LocalSources,
		"scope_mode":         args.ScopeMode,
	}
	if args.Instruction != nil {
		scanConfig["user_instructions"] = *args.Instruction
	} else {
		scanConfig["user_instructions"] = ""
	}
	if args.DiffBase != nil {
		scanConfig["diff_base"] = *args.DiffBase
	}
	if args.UserExplicitInstruction != nil {
		scanConfig["resume_instruction"] = *args.UserExplicitInstruction
	} else {
		scanConfig["resume_instruction"] = ""
	}

	reportState := report.NewReportState(runName)
	reportState.HydrateFromRunDir()
	reportState.SetScanConfig(scanConfig)
	reportState.SaveRunData()

	reportState.VulnerabilityFoundCallback = func(report map[string]interface{}) {
		id, _ := report["id"].(string)
		if id == "" { id = "unknown" }
		fmt.Printf("\n[%s]\n%s\n\n", id, FormatVulnerabilityReport(report))
	}

	cleanupOnExit := func() {
		reportState.Cleanup("")
	}
	defer cleanupOnExit()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		<-sigChan
		reportState.Cleanup("interrupted")
		os.Exit(1)
	}()

	report.SetGlobalReportState(reportState)

	startupPhase := []string{"Starting up"}
	noteStartupPhase := func(phase string) {
		startupPhase[0] = phase
	}

	fmt.Println()
	fmt.Println("Penetration test in progress...")

	liveUI := &LiveUI{
		reportState:  reportState,
		startupPhase: &startupPhase,
	}

	reportState.VulnerabilityFoundCallback = func(r map[string]interface{}) {
		liveUI.DisplayVulnerability(r)
	}

	stopUpdates := make(chan struct{})
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopUpdates:
				return
			case <-ticker.C:
				liveUI.Render()
			}
		}
	}()

	defer func() {
		close(stopUpdates)
		liveUI.Clear()
		SessionManagerCleanup(runName)
	}()

	logger.Printf("CLI launching scan: run_name=%s targets=%d interactive=%v", runName, len(args.TargetsInfo), !args.NonInteractive)


	interactive := !args.NonInteractive
	_, err := core.RunApexScan(
		scanConfig,
		&runName,
		ResolveSandboxImage(),
		args.LocalSources,
		nil,
		interactive,
		args.MaxTurns,
		args.MaxBudgetUSD,
		nil,
		true, // cleanupOnExit
		nil,  // eventSink
		nil,  // rootInstructionsOverride
		nil,  // extraSystemPromptContext
		noteStartupPhase,
	)

	if err != nil {
		fmt.Printf("\nError during penetration test: %v\n", err)
		return err
	}

	if reportState.FinalScanResult != "" {
		fmt.Println("\n[APEX] Penetration test summary")
		fmt.Println(reportState.FinalScanResult)
		fmt.Println()
	}

	return nil
}
