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

	"github.com/useapex/apex/tui/backend"
	"github.com/AwaisCh360/Apex/apex/core"
	"github.com/AwaisCh360/Apex/apex/report"
	"github.com/AwaisCh360/Apex/apex/utils"
)

// -- Stubs for missing dependencies to ensure compilation --

type Namespace struct {
	RunName                 string
	TargetsInfo             []map[string]interface{}
	Instruction             string
	DiffScope               string
	ScanMode                string
	LocalSources            []map[string]interface{}
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


type Callbacks struct {
	LoadSettings             func() (model string, image string)
	PreflightModelConnection func(model string) error
	BuildTargetsInfo         func(args *Namespace)
	PrepareRun               func(args *Namespace)
	TelemetryStart           func(args *Namespace)
	PersistCurrent           func()
	RunApexScan              func(config map[string]interface{}, id, image string, localSources []map[string]interface{}, coord *core.AgentCoordinator, interactive bool, maxTurns int, maxBudget float64, eventSink func(string, interface{})) error
}

var GlobalCallbacks *Callbacks

type GoTuiPreActivationError struct {
	Msg string
}

func (e *GoTuiPreActivationError) Error() string {
	return e.Msg
}

type GoTuiRuntime struct {
	args                 *Namespace
	liveView             *TuiLiveView
	coordinator          *core.AgentCoordinator
	reportState          *report.ReportState
	scanConfig           map[string]interface{}
	scanTask             context.CancelFunc
	scanDone             chan struct{}
	scanError            error
	lastSyncFingerprint  string
	errorNotedAgents     map[string]bool
	controller           *backend.TuiController
	server               *backend.TuiBackendServer
	realServer           *backend.TuiBackendServer
	realController       *backend.TuiController
	ctx                  context.Context
	cancel               context.CancelFunc
}

func NewGoTuiRuntime(args *Namespace) *GoTuiRuntime {
	ctx, cancel := context.WithCancel(context.Background())
	rt := &GoTuiRuntime{
		args:             args,
		liveView:         &TuiLiveView{},
		coordinator:      core.NewAgentCoordinator(),
		scanConfig:       make(map[string]interface{}),
		errorNotedAgents: make(map[string]bool),
		ctx:              ctx,
		cancel:           cancel,
	}

	// For now, we will create the REAL backend server to handle the IPC protocol!
	// We need to map our stub Namespace to backend.Args
	bArgs := &backend.Args{
		NeedsSetup: false,
	}
	realController := backend.NewTuiController(
		bArgs,
		nil, // liveView (can be nil)
		nil, // coordinator
		nil, // reportState
		nil, // onStart
		nil, // onQuit
		nil, // onChange
	)
	rt.realController = realController
	
	// Create the REAL server!
	rt.realServer = backend.NewTuiBackendServer(realController)

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
	r.reportState = report.NewReportState(r.scanConfig["run_name"].(string))
	r.reportState.HydrateFromRunDir()
	r.reportState.SetScanConfig(r.scanConfig)
	r.reportState.SaveRunData()
	report.SetGlobalReportState(r.reportState)
	r.liveView.HydrateFromRunDir(r.reportState.GetRunDir())
	r.realController.SetRuntime(r.reportState, r.ctx)
	r.reportState.VulnerabilityFoundCallback = func(_ map[string]interface{}) {
		r.realController.NotifyChanged()
	}
	r.realController.NotifyChanged()
}

func (r *GoTuiRuntime) StartFromSetup(verify bool) error {
	candidate := *r.args
	candidate.ScanMode = r.realController.ScanMode
	candidate.Instruction = r.realController.Instruction
	instr := r.realController.Instruction
	if instr == "" {
		candidate.UserInstruction = nil
	} else {
		candidate.UserInstruction = &instr
	}
	if r.realController.MaxBudgetUSD != nil {
		candidate.MaxBudgetUSD = *r.realController.MaxBudgetUSD
	}
	candidate.MaxTurns = r.realController.MaxTurns
	candidate.ScopeMode = r.realController.ScopeMode
	if r.realController.DiffBase != nil {
		candidate.DiffBase = *r.realController.DiffBase
	}

	var existingTargets []string
	for _, target := range candidate.TargetsInfo {
		if orig, ok := target["original"].(string); ok && orig != "" {
			existingTargets = append(existingTargets, orig)
		}
	}

	targetsChanged := fmt.Sprintf("%v", r.realController.Targets) != fmt.Sprintf("%v", existingTargets)
	var model string
	if GlobalCallbacks != nil && GlobalCallbacks.LoadSettings != nil {
		model, _ = GlobalCallbacks.LoadSettings()
	}

	if verify {
		if GlobalCallbacks != nil && GlobalCallbacks.PreflightModelConnection != nil {
			if err := GlobalCallbacks.PreflightModelConnection(model); err != nil {
				log.Printf("Go TUI setup model preflight failed: %v", err)
				return fmt.Errorf("Model connection failed: %w", err)
			}
		}
	}

	if r.realController.WorkspaceMount != nil {
		candidate.WorkspaceMount = *r.realController.WorkspaceMount
	}
	if targetsChanged {
		candidate.Target = append([]string{}, r.realController.Targets...)
		candidate.TargetList = []interface{}{}
		if GlobalCallbacks != nil && GlobalCallbacks.BuildTargetsInfo != nil {
			GlobalCallbacks.BuildTargetsInfo(&candidate)
		}
	}

	if GlobalCallbacks != nil && GlobalCallbacks.PrepareRun != nil {
		GlobalCallbacks.PrepareRun(&candidate)
	}
	if GlobalCallbacks != nil && GlobalCallbacks.TelemetryStart != nil {
		GlobalCallbacks.TelemetryStart(&candidate)
	}

	r.args.Update(&candidate)
	r.InitRunState()
	r.StartScan()
	return nil
}

func (r *GoTuiRuntime) PrepareAndStart() {
	var model string
	if GlobalCallbacks != nil && GlobalCallbacks.LoadSettings != nil {
		model, _ = GlobalCallbacks.LoadSettings()
	}
	if GlobalCallbacks != nil && GlobalCallbacks.PreflightModelConnection != nil {
		if err := GlobalCallbacks.PreflightModelConnection(model); err != nil {
			log.Printf("Go TUI scan preparation failed: %v", err)
			r.realController.FailPreparation(err.Error())
			return
		}
	}
	if GlobalCallbacks != nil && GlobalCallbacks.PersistCurrent != nil {
		GlobalCallbacks.PersistCurrent()
	}
	if GlobalCallbacks != nil && GlobalCallbacks.PrepareRun != nil {
		GlobalCallbacks.PrepareRun(r.args)
	}
	if GlobalCallbacks != nil && GlobalCallbacks.TelemetryStart != nil {
		GlobalCallbacks.TelemetryStart(r.args)
	}

	r.realController.ScanState = "running"
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
	var image string
	if GlobalCallbacks != nil && GlobalCallbacks.LoadSettings != nil {
		_, image = GlobalCallbacks.LoadSettings()
	}
	if image == "" {
		image = "apex-sandbox:latest"
	}

	defer func() {
		if _, err := r.syncAgentState(); err != nil {
			log.Printf("Go TUI agent-state sync failed: %v", err)
			errStr := fmt.Sprintf("Agent-state sync failed: %v", err)
			r.realController.Error = &errStr
		}
		r.realController.NotifyChanged()
	}()

	var err error
	if GlobalCallbacks != nil && GlobalCallbacks.RunApexScan != nil {
		err = GlobalCallbacks.RunApexScan(
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
	}

	if err != nil {
		if _, ok := err.(*core.BudgetExceededError); ok || err == context.Canceled {
			// Expected termination
		} else {
			errStr := err.Error()
			r.realController.Error = &errStr
			r.realController.ScanState = "failed"
		}
	} else {
		if _, err := r.syncAgentState(); err != nil {
			log.Printf("Go TUI agent-state sync failed: %v", err)
			errStr := fmt.Sprintf("Agent-state sync failed: %v", err)
			r.realController.Error = &errStr
		}
		if r.realController.ScanState == "running" {
			r.realController.ScanState = "stopped"
		}
	}
}

func (r *GoTuiRuntime) CaptureEvent(agentID string, event interface{}) {
	r.liveView.IngestSDKEvent(agentID, event)
	r.realController.NotifyChanged()
}

func (r *GoTuiRuntime) syncAgentState() (bool, error) {
	snap, err := r.coordinator.Snapshot()
	if err != nil {
		return false, err
	}
	statuses, _ := snap["statuses"].(map[string]interface{})
	parentOf, _ := snap["parent_of"].(map[string]interface{})
	names, _ := snap["names"].(map[string]interface{})
	errors, _ := snap["errors"].(map[string]interface{})

	changed := false
	for agentID, statusIf := range statuses {
		status, _ := statusIf.(string)
		errMsgIf := errors[agentID]
		var errMsg string
		if errMsgIf != nil {
			errMsg, _ = errMsgIf.(string)
		}
		var parentStr string
		parentIf := parentOf[agentID]
		if parentIf != nil {
			parentStr, _ = parentIf.(string)
		}
		nameStr, _ := names[agentID].(string)
		parentID := parentStr

		upserted := r.liveView.UpsertAgent(agentID, nameStr, parentID, status, errMsg)
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
		if val, ok := statuses[rootID].(string); ok {
			rootStatus = val
		}
	}

	reportStatus := ""
	if r.reportState != nil {
		if s, ok := r.reportState.RunRecord["status"].(string); ok {
			reportStatus = s
		}
	}

	scanState := r.realController.ScanState
	if (r.realController.ScanState == "failed" || r.realController.ScanState == "crashed") && rootID != "" {
		if errVal, ok := errors[rootID].(string); ok {
			r.realController.Error = &errVal
		}
	} else if scanState != "failed" {
		if reportStatus == "completed" {
			scanState = "completed"
		} else if rootStatus == "stopped" {
			scanState = "stopped"
		} else if r.realController.ScanState != "finished" {
			msg := "Scan ended without a completed report"
			r.realController.Error = &msg
		}
	}

	if scanState != r.realController.ScanState {
		r.realController.ScanState = scanState
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
			if id, exists := v["id"]; exists {
				vulnerabilities = append(vulnerabilities, id)
			} else {
				vulnerabilities = append(vulnerabilities, i)
			}
		}
	}

	data := map[string]interface{}{
		"scan_state":      r.realController.ScanState,
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
						errStr := fmt.Sprintf("Agent-state sync failed: %v", err)
						r.realController.Error = &errStr
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
	exe, err := os.Executable()
	if err == nil {
		localPath := filepath.Join(filepath.Dir(exe), TUIExecutable())
		if _, err := os.Stat(localPath); err == nil {
			return []string{localPath}, nil
		}
	}

	if path, err := exec.LookPath(TUIExecutable()); err == nil {
		return []string{path}, nil
	}

	packaged := utils.GetApexResourcePath("bin", TUIExecutable())
	if _, err := os.Stat(packaged); err == nil {
		return []string{packaged}, nil
	}

	source := TUISourceDir()
	goModPath := filepath.Join(source, "go.mod")
	if _, err := os.Stat(goModPath); err == nil {
		if _, err := exec.LookPath("go"); err == nil {
			// WARNING: go run does not pass ExtraFiles. We must build and run.
			tmpBin := filepath.Join(os.TempDir(), "apex-tui-dev")
			buildCmd := exec.Command("go", "build", "-o", tmpBin, "./cmd/apex-tui")
			buildCmd.Dir = source
			if err := buildCmd.Run(); err == nil {
				return []string{tmpBin}, nil
			}
		}
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

	process, backendSocket, err = LaunchTUIProcess(r.ctx, command, env, cwd, os.Stdin, originalStdout, originalStderr)
	if err != nil {
		return &GoTuiPreActivationError{Msg: err.Error()}
	}
	defer func() {
		if backendSocket != nil {
			backendSocket.Close()
		}
		r.cancel()
		r.Quit()
		if r.realServer != nil {
			r.realServer.Close()
		}
	}()

	startErr := r.realServer.Start(backendSocket)

	if startErr != nil {
		TerminateProcess(process)
		if !r.realServer.Activated {
			return &GoTuiPreActivationError{Msg: startErr.Error()}
		}
		return startErr
	}

	if !r.realController.Args.NeedsSetup {
		// r.realController.BeginPreparation()
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
