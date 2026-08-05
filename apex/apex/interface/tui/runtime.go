package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/AwaisCh360/Apex/apex/utils"
)

// -- Stubs for missing dependencies to ensure compilation --

type Namespace struct {
	RunName                 string
	TargetsInfo             []map[string]interface{}
	Instruction             string
	DiffScope               string
	ScanMode                string
	LocalSources            []string
	ScopeMode               string
	DiffBase                string
	UserExplicitInstruction string
	WorkspaceMount          string
	WorkspaceSubdir         string
	MaxBudgetUSD            float64
	MaxTurns                int
	UserInstruction         *string
	Target                  []string
	TargetList              []interface{}
}

func (n *Namespace) Update(other *Namespace) {
	*n = *other
}

type AgentCoordinator struct{}
func (c *AgentCoordinator) MarkShuttingDown() {}
func (c *AgentCoordinator) GraphSnapshot() (map[string]string, map[string]string, map[string]string, map[string]string, error) { return nil, nil, nil, nil, nil }

type ReportState struct {
	RunRecord                  map[string]interface{}
	VulnerabilityReports       []interface{}
	VulnerabilityFoundCallback func(interface{})
}
func NewReportState(runName string) *ReportState {
	return &ReportState{ RunRecord: make(map[string]interface{}), VulnerabilityReports: []interface{}{} }
}
func (r *ReportState) HydrateFromRunDir()                 {}
func (r *ReportState) SetScanConfig(config map[string]interface{}) {}
func (r *ReportState) SaveRunData()                       {}
func (r *ReportState) GetRunDir() string                  { return "" }
func (r *ReportState) GetTotalLLMUsage() map[string]interface{} { return nil }

type TuiController struct {
	ScanMode       string
	Instruction    string
	MaxBudgetUSD   float64
	MaxTurns       int
	ScopeMode      string
	DiffBase       string
	Targets        []string
	WorkspaceMount string
	ScanState      string
	Error          string
	SetupMode      bool
}
func NewTuiController(args *Namespace, lv *TuiLiveView, coord *AgentCoordinator, onStart func(bool) error, onQuit func()) *TuiController { return &TuiController{} }
func (c *TuiController) SetRuntime(reportState *ReportState) {}
func (c *TuiController) NotifyChanged()                      {}
func (c *TuiController) FailPreparation(err string)          {}
func (c *TuiController) CloseViewer()                        {}
func (c *TuiController) BeginPreparation()                   {}

type TuiBackendServer struct { Activated bool }
func NewTuiBackendServer(c *TuiController) *TuiBackendServer { return &TuiBackendServer{} }
func (s *TuiBackendServer) Start(conn net.Conn) error { return nil }
func (s *TuiBackendServer) Close() error              { return nil }

func SetGlobalReportState(rs *ReportState)   {}

func LoadSettings() struct {
	LLM struct { Model string }
	Runtime struct { Image string }
} { return struct{LLM struct{Model string}; Runtime struct{Image string}}{} }
func PreflightModelConnection(model string) error { return nil }
func BuildTargetsInfo(args *Namespace)       {}
func PrepareRun(args *Namespace)             {}
func TelemetryStart(args *Namespace)         {}
func PersistCurrent()                        {}
func RunApexScan(config map[string]interface{}, id, image string, localSources []string, coord *AgentCoordinator, interactive bool, maxTurns int, maxBudget float64, eventSink func(string, interface{})) error { return nil }

type BudgetExceededError struct{}

func (e *BudgetExceededError) Error() string { return "Budget Exceeded" }

// -- End of stubs --

type GoTuiPreActivationError struct {
	Msg string
}

func (e *GoTuiPreActivationError) Error() string {
	return e.Msg
}

type GoTuiRuntime struct {
	args                 *Namespace
	liveView             *TuiLiveView
	coordinator          *AgentCoordinator
	reportState          *ReportState
	scanConfig           map[string]interface{}
	scanTask             context.CancelFunc
	scanDone             chan struct{}
	scanError            error
	lastSyncFingerprint  string
	errorNotedAgents     map[string]bool
	controller           *TuiController
	server               *TuiBackendServer
	ctx                  context.Context
	cancel               context.CancelFunc
}

func NewGoTuiRuntime(args *Namespace) *GoTuiRuntime {
	ctx, cancel := context.WithCancel(context.Background())
	rt := &GoTuiRuntime{
		args:             args,
		liveView:         &TuiLiveView{},
		coordinator:      &AgentCoordinator{},
		scanConfig:       make(map[string]interface{}),
		errorNotedAgents: make(map[string]bool),
		ctx:              ctx,
		cancel:           cancel,
	}
	rt.controller = NewTuiController(args, rt.liveView, rt.coordinator, rt.StartFromSetup, rt.Quit)
	rt.server = NewTuiBackendServer(rt.controller)
	return rt
}

func (r *GoTuiRuntime) InitRunState() {
	r.scanConfig = map[string]interface{}{
		"scan_id":            r.args.RunName,
		"targets":            r.args.TargetsInfo,
		"user_instructions":  r.args.Instruction,
		"run_name":           r.args.RunName,
		"diff_scope":         r.args.DiffScope,
		"scan_mode":          r.args.ScanMode,
		"non_interactive":    false,
		"local_sources":      r.args.LocalSources,
		"scope_mode":         r.args.ScopeMode,
		"diff_base":          r.args.DiffBase,
		"resume_instruction": r.args.UserExplicitInstruction,
		"workspace_mount":    r.args.WorkspaceMount,
		"workspace_subdir":   r.args.WorkspaceSubdir,
	}
	r.reportState = NewReportState(r.scanConfig["run_name"].(string))
	r.reportState.HydrateFromRunDir()
	r.reportState.SetScanConfig(r.scanConfig)
	r.reportState.SaveRunData()
	SetGlobalReportState(r.reportState)
	r.liveView.HydrateFromRunDir(r.reportState.GetRunDir())
	r.controller.SetRuntime(r.reportState)
	r.reportState.VulnerabilityFoundCallback = func(_ interface{}) {
		r.controller.NotifyChanged()
	}
	r.controller.NotifyChanged()
}

func (r *GoTuiRuntime) StartFromSetup(verify bool) error {
	candidate := *r.args
	candidate.ScanMode = r.controller.ScanMode
	candidate.Instruction = r.controller.Instruction
	instr := r.controller.Instruction
	if instr == "" {
		candidate.UserInstruction = nil
	} else {
		candidate.UserInstruction = &instr
	}
	candidate.MaxBudgetUSD = r.controller.MaxBudgetUSD
	candidate.MaxTurns = r.controller.MaxTurns
	candidate.ScopeMode = r.controller.ScopeMode
	candidate.DiffBase = r.controller.DiffBase

	var existingTargets []string
	for _, target := range candidate.TargetsInfo {
		if orig, ok := target["original"].(string); ok && orig != "" {
			existingTargets = append(existingTargets, orig)
		}
	}

	targetsChanged := fmt.Sprintf("%v", r.controller.Targets) != fmt.Sprintf("%v", existingTargets)
	settings := LoadSettings()
	model := settings.LLM.Model

	if verify {
		if err := PreflightModelConnection(model); err != nil {
			log.Printf("Go TUI setup model preflight failed: %v", err)
			return fmt.Errorf("Model connection failed: %w", err)
		}
	}

	candidate.WorkspaceMount = r.controller.WorkspaceMount
	if targetsChanged {
		candidate.Target = append([]string{}, r.controller.Targets...)
		candidate.TargetList = []interface{}{}
		BuildTargetsInfo(&candidate)
	}

	PrepareRun(&candidate)
	TelemetryStart(&candidate)

	r.args.Update(&candidate)
	r.InitRunState()
	r.StartScan()
	return nil
}

func (r *GoTuiRuntime) PrepareAndStart() {
	settings := LoadSettings()
	model := settings.LLM.Model
	if err := PreflightModelConnection(model); err != nil {
		log.Printf("Go TUI scan preparation failed: %v", err)
		r.controller.FailPreparation(err.Error())
		return
	}
	PersistCurrent()
	PrepareRun(r.args)
	TelemetryStart(r.args)

	r.controller.ScanState = "running"
	r.InitRunState()
	r.StartScan()
}

func (r *GoTuiRuntime) StartScan() {
	if r.scanDone == nil {
		r.scanDone = make(chan struct{})
		ctx, cancel := context.WithCancel(r.ctx)
		r.scanTask = cancel
		go func() {
			defer close(r.scanDone)
			r.runScan(ctx)
		}()
	}
}

func (r *GoTuiRuntime) runScan(ctx context.Context) {
	settings := LoadSettings()
	image := settings.Runtime.Image
	if image == "" {
		image = "apex-sandbox:latest"
	}

	defer func() {
		if _, err := r.syncAgentState(); err != nil {
			log.Printf("Go TUI agent-state sync failed: %v", err)
			r.controller.Error = fmt.Sprintf("Agent-state sync failed: %v", err)
		}
		r.controller.NotifyChanged()
	}()

	err := RunApexScan(
		r.scanConfig,
		r.scanConfig["run_name"].(string),
		image,
		r.args.LocalSources,
		r.coordinator,
		true,
		r.args.MaxTurns,
		r.args.MaxBudgetUSD,
		r.CaptureEvent,
	)

	if err != nil {
		if _, ok := err.(*BudgetExceededError); ok || err == context.Canceled {
			reportStatus := ""
			if r.reportState != nil {
				if s, ok := r.reportState.RunRecord["status"].(string); ok {
					reportStatus = s
				}
			}
			if reportStatus == "completed" {
				r.controller.ScanState = "completed"
			} else {
				r.controller.ScanState = "stopped"
			}
		} else {
			log.Printf("Go TUI scan failed: %v", err)
			r.scanError = err
			r.controller.Error = err.Error()
			r.controller.ScanState = "failed"
		}
	} else {
		if _, err := r.syncAgentState(); err != nil {
			log.Printf("Go TUI agent-state sync failed: %v", err)
			r.controller.Error = fmt.Sprintf("Agent-state sync failed: %v", err)
		}
		if r.controller.ScanState == "running" {
			r.controller.ScanState = "stopped"
		}
	}
}

func (r *GoTuiRuntime) CaptureEvent(agentID string, event interface{}) {
	r.liveView.IngestSDKEvent(agentID, event)
	r.controller.NotifyChanged()
}

func (r *GoTuiRuntime) syncAgentState() (bool, error) {
	parentOf, statuses, names, errors, err := r.coordinator.GraphSnapshot()
	if err != nil {
		return false, err
	}
	changed := false
	for agentID, status := range statuses {
		errMsg := errors[agentID]
		name := names[agentID]
		if name == "" {
			name = agentID
		}
		parentID := parentOf[agentID]

		upserted := r.liveView.UpsertAgent(agentID, name, parentID, status, errMsg)
		if upserted {
			changed = true
		}

		if (status == "failed" || status == "crashed") && errMsg != "" {
			if !r.errorNotedAgents[agentID] {
				r.errorNotedAgents[agentID] = true
				r.liveView.RecordAgentError(agentID, errMsg)
				changed = true
			}
		} else {
			delete(r.errorNotedAgents, agentID)
		}
	}

	if r.liveView.FlushUserInstruction() {
		changed = true
	}

	var rootID string
	for id, parent := range parentOf {
		if parent == "" {
			rootID = id
			break
		}
	}

	rootStatus := ""
	if rootID != "" {
		rootStatus = statuses[rootID]
	}

	reportStatus := ""
	if r.reportState != nil {
		if s, ok := r.reportState.RunRecord["status"].(string); ok {
			reportStatus = s
		}
	}

	scanState := r.controller.ScanState
	if rootStatus == "failed" || rootStatus == "crashed" {
		scanState = "failed"
		if rootID != "" && errors[rootID] != "" {
			r.controller.Error = errors[rootID]
		}
	} else if scanState != "failed" {
		if reportStatus == "completed" {
			scanState = "completed"
		} else if rootStatus == "stopped" {
			scanState = "stopped"
		} else if rootStatus == "completed" {
			scanState = "failed"
			r.controller.Error = "Scan ended without a completed report"
		}
	}

	if scanState != r.controller.ScanState {
		r.controller.ScanState = scanState
		changed = true
	}

	return changed, nil
}

func (r *GoTuiRuntime) runtimeSyncFingerprint() string {
	usage := make(map[string]interface{})
	var vulnerabilities []interface{}

	if r.reportState != nil {
		usage = r.reportState.GetTotalLLMUsage()
		for i, v := range r.reportState.VulnerabilityReports {
			if vMap, ok := v.(map[string]interface{}); ok {
				if id, exists := vMap["id"]; exists {
					vulnerabilities = append(vulnerabilities, id)
				} else {
					vulnerabilities = append(vulnerabilities, i)
				}
			} else {
				vulnerabilities = append(vulnerabilities, i)
			}
		}
	}

	data := map[string]interface{}{
		"scan_state":      r.controller.ScanState,
		"usage":           usage,
		"vulnerabilities": vulnerabilities,
	}
	b, _ := json.Marshal(data)
	return string(b)
}

func (r *GoTuiRuntime) SyncState(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(500 * time.Millisecond):
			if r.scanDone != nil {
				select {
				case <-r.scanDone:
					// scan task done
				default:
					changed, err := r.syncAgentState()
					if err != nil {
						log.Printf("Go TUI agent-state sync failed: %v", err)
						r.controller.Error = fmt.Sprintf("Agent-state sync failed: %v", err)
						changed = true
					}
					fingerprint := r.runtimeSyncFingerprint()
					if fingerprint != r.lastSyncFingerprint {
						r.lastSyncFingerprint = fingerprint
						changed = true
					}
					if changed {
						r.controller.NotifyChanged()
					}
				}
			}
		}
	}
}

func (r *GoTuiRuntime) Quit() {
	r.controller.CloseViewer()
	r.coordinator.MarkShuttingDown()
	if r.scanTask != nil {
		r.scanTask()
	}
}

func BinaryCommand() ([]string, error) {
	source := TUISourceDir()
	goModPath := filepath.Join(source, "go.mod")
	if _, err := os.Stat(goModPath); err == nil {
		if _, err := exec.LookPath("go"); err == nil {
			return []string{"go", "run", "./cmd/apex-tui"}, nil
		}
	}

	packaged := utils.GetApexResourcePath("bin", TUIExecutable())
	if _, err := os.Stat(packaged); err == nil {
		return []string{packaged}, nil
	}

	return nil, fmt.Errorf("Bubble Tea TUI binary not found. Reinstall Apex from an official platform wheel.")
}

func (r *GoTuiRuntime) Run() error {
	originalStdout := os.Stdout
	originalStderr := os.Stderr
	outputSink, err := os.OpenFile(os.DevNull, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer outputSink.Close()

	os.Stdout = outputSink
	os.Stderr = outputSink
	defer func() {
		os.Stdout = originalStdout
		os.Stderr = originalStderr
	}()

	var backendSocket net.Conn
	var process *exec.Cmd

	env := ChildEnvironment()
	if env == nil {
		env = make(map[string]string)
	}
	env["APEX_VERSION"] = PackageVersion()

	command, err := BinaryCommand()
	if err != nil {
		return err
	}

	cwd := ""
	if len(command) >= 2 && command[0] == "go" && command[1] == "run" {
		cwd = TUISourceDir()
		fmt.Fprintln(originalStdout, "\x1b[2mCompiling the TUI from source (cached after the first run)....\x1b[0m")
	}

	process, backendSocket, err = LaunchTUIProcess(r.ctx, command, env, cwd)
	if err != nil {
		return &GoTuiPreActivationError{Msg: err.Error()}
	}
	defer func() {
		if backendSocket != nil {
			backendSocket.Close()
		}
		r.cancel()
		r.Quit()
		r.server.Close()
	}()

	if err := r.server.Start(backendSocket); err != nil {
		TerminateProcess(process)
		if !r.server.Activated {
			return &GoTuiPreActivationError{Msg: err.Error()}
		}
		return err
	}

	if !r.controller.SetupMode {
		r.controller.BeginPreparation()
		go r.PrepareAndStart()
	}

	go r.SyncState(r.ctx)

	returnCode := WaitProcess(r.ctx, process)
	err = CheckReturnCode(returnCode)
	if err != nil {
		TerminateProcess(process)
		return err
	}

	if r.scanError != nil {
		return r.scanError
	}

	return nil
}

func RunGoTui(args *Namespace) error {
	rt := NewGoTuiRuntime(args)
	return rt.Run()
}
