package backend

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
)

// Stubs for types that are presumably defined elsewhere in the package.
// If they are already defined, these can be removed.
type Args struct {
	NeedsSetup   bool
	TargetsInfo  []interface{}
	Instruction  interface{}
	ScanMode     string
	MaxBudgetUSD interface{}
	MaxTurns     interface{}
	ScopeMode    string
	DiffBase     interface{}
}



type ReportState struct {
	CaidoURL             *string
	VulnerabilityReports []map[string]interface{}
	RunRecord            map[string]interface{}
}

func (r *ReportState) GetTotalLLMUsage() map[string]interface{} { return nil }
func (r *ReportState) GetRunDir() string                        { return "" }

type Coordinator interface {
	Send(agentID string, msg map[string]interface{}) (bool, error)
	CancelDescendantsGraceful(agentID string) (bool, error)
}

var (
	DefaultMaxTurns            = 100
	scanModes                  = map[string]bool{"deep": true}
	scopeModes                 = map[string]bool{"auto": true}
	stoppableAgentStatuses     = map[string]bool{"running": true, "waiting": true, "budget_paused": true}
)

func isSubscriptionRun(r *ReportState) bool { 
	if r != nil && r.RunRecord != nil {
		if sub, ok := r.RunRecord["subscription"].(bool); ok {
			return sub
		}
	}
	return false 
}

type llmSettingsStub struct{ Model string }
type configSettingsStub struct{ Llm llmSettingsStub }

func loadSettings() *configSettingsStub {
	model := os.Getenv("APEX_LLM")
	// If not set, Python settings loader would fallback, but for this parity check we rely on env or empty
	return &configSettingsStub{Llm: llmSettingsStub{Model: model}}
}

func isRecommendedOrFrontierModel(m string) bool {
	m = strings.ToLower(m)
	return strings.Contains(m, "claude-3-5-sonnet") || strings.Contains(m, "gpt-4") || strings.Contains(m, "o1") || strings.Contains(m, "o3")
}

func viewerOpenedTelemetry(source string, live bool) {
	// In the future this should call telemetry.ViewerOpened
}

// Controller Callbacks
type ChangeCallback func()
type StartCallback func(bool) error
type QuitCallback func() error

type TuiController struct {
	mu sync.Mutex

	Args        *Args
	LiveView    *TuiLiveView
	Coordinator Coordinator
	ReportState *ReportState
	ScanCtx     context.Context

	SetupMode       bool
	ScanStarted     bool
	StartInProgress bool
	ScanState       string
	Targets         []string
	Instruction     string
	ScanMode        string
	MaxBudgetUSD    *float64
	MaxTurns        int
	ScopeMode       string
	DiffBase        *string

	WorkspaceMount        *string
	PendingWorkspaceMount *string
	PendingVerify         bool

	Messages      []map[string]string
	NextMessageID int
	Error         *string
	ViewerStatus  string
	ViewerURL     *string
	ViewerHTTPD   interface{}

	onStart  StartCallback
	onQuit   QuitCallback
	onChange ChangeCallback
}

func NewTuiController(
	args *Args,
	liveView *TuiLiveView,
	coordinator Coordinator,
	reportState *ReportState,
	onStart StartCallback,
	onQuit QuitCallback,
	onChange ChangeCallback,
) *TuiController {
	if liveView == nil {
		liveView = NewTuiLiveView(nil)
	}

	setupMode := args.NeedsSetup
	scanStarted := !setupMode
	scanState := "setup"
	if !setupMode {
		scanState = "running"
	}

	var targets []string
	for _, t := range args.TargetsInfo {
		if m, ok := t.(map[string]interface{}); ok {
			if orig, ok := m["original"].(string); ok && orig != "" {
				targets = append(targets, orig)
			}
		}
	}

	instruction := ""
	if s, ok := args.Instruction.(string); ok {
		instruction = strings.TrimSpace(s)
	}

	scanMode := "deep"
	if _, ok := scanModes[args.ScanMode]; ok {
		scanMode = args.ScanMode
	}

	var maxBudgetUSD *float64
	switch v := args.MaxBudgetUSD.(type) {
	case float64:
		if v > 0 && !math.IsNaN(v) && !math.IsInf(v, 0) {
			val := v
			maxBudgetUSD = &val
		}
	case float32:
		if v > 0 && !math.IsNaN(float64(v)) && !math.IsInf(float64(v), 0) {
			val := float64(v)
			maxBudgetUSD = &val
		}
	case int:
		if v > 0 {
			val := float64(v)
			maxBudgetUSD = &val
		}
	}

	maxTurns := DefaultMaxTurns
	if v, ok := args.MaxTurns.(int); ok && v > 0 {
		maxTurns = v
	}

	scopeMode := "auto"
	if _, ok := scopeModes[args.ScopeMode]; ok {
		scopeMode = args.ScopeMode
	}

	var diffBase *string
	if v, ok := args.DiffBase.(string); ok {
		trimmed := strings.TrimSpace(v)
		diffBase = &trimmed
	}

	return &TuiController{
		Args:          args,
		LiveView:      liveView,
		Coordinator:   coordinator,
		ReportState:   reportState,
		SetupMode:     setupMode,
		ScanStarted:   scanStarted,
		ScanState:     scanState,
		Targets:       targets,
		Instruction:   instruction,
		ScanMode:      scanMode,
		MaxBudgetUSD:  maxBudgetUSD,
		MaxTurns:      maxTurns,
		ScopeMode:     scopeMode,
		DiffBase:      diffBase,
		PendingVerify: true,
		Messages:      []map[string]string{},
		NextMessageID: 1,
		ViewerStatus:  "idle",
		onStart:       onStart,
		onQuit:        onQuit,
		onChange:      onChange,
	}
}

func (c *TuiController) SetChangeCallback(callback ChangeCallback) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onChange = callback
}

func (c *TuiController) NotifyChanged() {
	c.mu.Lock()
	cb := c.onChange
	c.mu.Unlock()
	if cb != nil {
		cb()
	}
}

func (c *TuiController) SetRuntime(reportState *ReportState, scanCtx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if reportState != nil {
		c.ReportState = reportState
	}
	if scanCtx != nil {
		c.ScanCtx = scanCtx
	}
}

func (c *TuiController) BeginPreparation() {
	c.mu.Lock()
	c.ScanState = "preparing"
	c.mu.Unlock()
	c.NotifyChanged()
}

func (c *TuiController) FailPreparation(detail string) {
	c.mu.Lock()
	c.ScanState = "failed"
	c.Error = &detail
	c.mu.Unlock()
	c.NotifyChanged()
}

func (c *TuiController) EnterSetup() {
	c.mu.Lock()
	c.SetupMode = true
	c.ScanStarted = false
	c.ScanState = "setup"
	c.mu.Unlock()
	c.NotifyChanged()
}

func (c *TuiController) AddMessage(text string, level string) {
	if level == "" {
		level = "info"
	}
	c.mu.Lock()
	c.appendMessage(text, level)
	c.mu.Unlock()
	c.NotifyChanged()
}

func (c *TuiController) appendMessage(text, level string) {
	c.Messages = append(c.Messages, map[string]string{
		"id":    fmt.Sprintf("message-%d", c.NextMessageID),
		"text":  SanitizeTerminalText(text),
		"level": SanitizeTerminalText(level),
	})
	c.NextMessageID++
	if len(c.Messages) > 200 {
		c.Messages = c.Messages[len(c.Messages)-200:]
	}
}

func (c *TuiController) Snapshot() map[string]interface{} {
	c.mu.Lock()
	defer c.mu.Unlock()

	model := ""
	settings := loadSettings()
	if settings != nil {
		model = strings.TrimSpace(settings.Llm.Model)
	}

	usage := make(map[string]interface{})
	if c.ReportState != nil {
		usage = c.ReportState.GetTotalLLMUsage()
	}
	subscription := false
	if c.ReportState != nil {
		subscription = isSubscriptionRun(c.ReportState)
	}
	modelWarning := ""
	if model != "" && !isRecommendedOrFrontierModel(model) {
		modelWarning = fmt.Sprintf("%s is not a recommended frontier model; pentest quality could be degraded", model)
	}

	cwd, _ := os.Getwd()
	pendingMount := ""
	if c.PendingWorkspaceMount != nil {
		pendingMount = *c.PendingWorkspaceMount
	}

	caidoURL := ""
	if c.ReportState != nil && c.ReportState.CaidoURL != nil {
		caidoURL = *c.ReportState.CaidoURL
	}

	targetsProj := []interface{}{}
	limit := len(c.Targets)
	if limit > 16 {
		limit = 16
	}
	for i := 0; i < limit; i++ {
		targetsProj = append(targetsProj, TerminalProjectionWithOpts(c.Targets[i], 128, 20))
	}

	var messagesProj []interface{}
	msgStart := len(c.Messages) - 10
	if msgStart < 0 {
		msgStart = 0
	}
	for i := msgStart; i < len(c.Messages); i++ {
		msg := c.Messages[i]
		idStr := msg["id"]
		if len(idStr) > 64 {
			idStr = idStr[:64]
		}
		levelStr := msg["level"]
		if len(levelStr) > 32 {
			levelStr = levelStr[:32]
		}
		messagesProj = append(messagesProj, map[string]interface{}{
			"id":    idStr,
			"text":  TerminalProjectionWithOpts(msg["text"], 256, 20),
			"level": levelStr,
		})
	}

	var viewerURL interface{}
	if c.ViewerURL != nil {
		viewerURL = TerminalProjectionWithOpts(*c.ViewerURL, 1024, 20)
	}

	var errorProj interface{}
	if c.Error != nil {
		errorProj = TerminalProjectionWithOpts(*c.Error, 2048, 20)
	}
	var diffBaseProj interface{}
	if c.DiffBase != nil {
		diffBaseProj = TerminalProjectionWithOpts(*c.DiffBase, 256, 20)
	}

	state := map[string]interface{}{
		"setup_mode":      c.SetupMode,
		"scan_started":    c.ScanStarted,
		"scan_state":      c.ScanState,
		"targets":         targetsProj,
		"target_count":    len(c.Targets),
		"working_dir":     cwd,
		"pending_mount":   pendingMount,
		"instruction":     TerminalProjectionWithOpts(c.Instruction, 2048, 20),
		"scan_mode":       c.ScanMode,
		"max_budget_usd":  c.MaxBudgetUSD,
		"max_turns":       c.MaxTurns,
		"scope_mode":      c.ScopeMode,
		"diff_base":       diffBaseProj,
		"model":           TerminalProjectionWithOpts(model, 256, 20),
		"model_warning":   TerminalProjectionWithOpts(modelWarning, 512, 20),
		"caido_url":       TerminalProjectionWithOpts(caidoURL, 1024, 20),
		"messages":        messagesProj,
		"usage":           TerminalProjectionWithOpts(usage, 256, 20),
		"subscription":    subscription,
		"viewer_status":   c.ViewerStatus,
		"viewer_url":      viewerURL,
		"error":           errorProj,
	}
	return BoundedStateProjection(state)
}

func (c *TuiController) Collection(name string) ([]map[string]interface{}, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if name == "agents" {
		var agentsProj []map[string]interface{}
		for _, agent := range c.LiveView.BaseLiveView.GetAgents() {
			proj := make(map[string]interface{})
			keys := []string{"id", "name", "parent_id", "status", "error_message", "created_at", "updated_at"}
			for _, k := range keys {
				if val, ok := agent[k]; ok {
					proj[k] = TerminalProjectionWithOpts(val, 256, 5)
				}
			}
			agentsProj = append(agentsProj, proj)
		}
		return agentsProj, nil
	}

	if name == "events" {
		var eventsProj []map[string]interface{}
		for _, event := range c.LiveView.BaseLiveView.GetEvents() {
			eventsProj = append(eventsProj, CollectionItemProjection(event))
		}
		return eventsProj, nil
	}

	if name == "vulnerabilities" {
		var reports []map[string]interface{}
		if c.ReportState != nil && c.ReportState.VulnerabilityReports != nil {
			reports = c.ReportState.VulnerabilityReports
		}
		if len(reports) > MaxTerminalVulnerabilities {
			reports = reports[len(reports)-MaxTerminalVulnerabilities:]
		}
		var result []map[string]interface{}
		for i, report := range reports {
			proj := CollectionItemProjection(report)
			idVal, ok := proj["id"].(string)
			if !ok || idVal == "" {
				proj["id"] = fmt.Sprintf("vulnerability-%d", i)
			}
			result = append(result, proj)
		}
		return result, nil
	}

	return nil, fmt.Errorf("Unknown collection: %s", name)
}

func (c *TuiController) CollectionSnapshot(name string) (*int, []map[string]interface{}, error) {
	if name == "events" {
		c.mu.Lock()
		lv := c.LiveView
		c.mu.Unlock()
		limit := MaxTerminalEvents
		cursor, events := lv.EventSnapshot(&limit)
		var proj []map[string]interface{}
		for _, e := range events {
			proj = append(proj, CollectionItemProjection(e))
		}
		return &cursor, proj, nil
	}
	col, err := c.Collection(name)
	return nil, col, err
}

func (c *TuiController) CollectionChanges(name string, cursor int) (int, []map[string]interface{}, error) {
	if name != "events" {
		return 0, nil, fmt.Errorf("Collection %q does not expose incremental changes", name)
	}
	c.mu.Lock()
	lv := c.LiveView
	c.mu.Unlock()

	nextCursor, events, err := lv.EventChangesSince(cursor)
	if err != nil {
		return 0, nil, err
	}
	if len(events) > MaxTerminalEvents {
		events = events[len(events)-MaxTerminalEvents:]
	}
	var proj []map[string]interface{}
	for _, e := range events {
		proj = append(proj, CollectionItemProjection(e))
	}
	return nextCursor, proj, nil
}

func (c *TuiController) Handle(command string, payload map[string]interface{}) (map[string]interface{}, error) {
	var result map[string]interface{}
	var err error

	switch command {
	case "setup.add_target":
		result, err = c.addTarget(payload)
	case "setup.set_instruction":
		result, err = c.setInstruction(payload)
	case "setup.start":
		result, err = c.start(payload)
	case "setup.confirm_mount":
		result, err = c.confirmMount(payload)
	case "agent.send_message":
		result, err = c.sendMessage(payload)
	case "agent.stop":
		result, err = c.stopAgent(payload)
	case "viewer.open":
		result, err = c.openViewer(payload)
	case "app.quit":
		result, err = c.quit(payload)
	default:
		return nil, fmt.Errorf("Unknown command: %s", command)
	}

	if err == nil {
		c.NotifyChanged()
	}
	return result, err
}

func (c *TuiController) addTarget(payload map[string]interface{}) (map[string]interface{}, error) {
	if err := c.requireSetupMutable(); err != nil {
		return nil, err
	}
	target, err := c.requiredString(payload, "target")
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	found := false
	for _, t := range c.Targets {
		if t == target {
			found = true
			break
		}
	}
	if !found {
		c.Targets = append(c.Targets, target)
	}
	total := len(c.Targets)
	c.mu.Unlock()
	return map[string]interface{}{"target": target, "total": total}, nil
}

func (c *TuiController) setInstruction(payload map[string]interface{}) (map[string]interface{}, error) {
	if err := c.requireSetupMutable(); err != nil {
		return nil, err
	}
	instrVal, ok := payload["instruction"]
	if !ok {
		instrVal = ""
	}
	instruction, ok := instrVal.(string)
	if !ok {
		return nil, errors.New("instruction must be a string")
	}
	instruction = strings.TrimSpace(instruction)
	c.mu.Lock()
	c.Instruction = instruction
	c.mu.Unlock()
	return map[string]interface{}{"instruction": instruction}, nil
}

func (c *TuiController) start(payload map[string]interface{}) (map[string]interface{}, error) {
	c.mu.Lock()
	if c.ScanStarted || c.StartInProgress {
		c.mu.Unlock()
		return nil, errors.New("Scan is already starting or running")
	}
	c.mu.Unlock()

	verifyVal, ok := payload["verify"]
	if !ok {
		verifyVal = true
	}
	verify, ok := verifyVal.(bool)
	if !ok {
		return nil, errors.New("verify must be a boolean")
	}

	mountWorkingDirVal, ok := payload["mount_working_dir"]
	if !ok {
		mountWorkingDirVal = false
	}
	mountWorkingDir, ok := mountWorkingDirVal.(bool)
	if !ok {
		return nil, errors.New("mount_working_dir must be a boolean")
	}

	model := ""
	settings := loadSettings()
	if settings != nil {
		model = strings.TrimSpace(settings.Llm.Model)
	}
	if model == "" {
		return nil, errors.New("No model configured. Set APEX_LLM first.")
	}

	c.mu.Lock()
	if c.onStart == nil {
		c.mu.Unlock()
		return nil, errors.New("Scan start is unavailable")
	}
	targetsCount := len(c.Targets)
	c.mu.Unlock()

	if targetsCount == 0 {
		if !mountWorkingDir {
			return nil, errors.New("No target set. Add a target first.")
		}
		cwd, _ := os.Getwd()
		c.mu.Lock()
		c.PendingWorkspaceMount = &cwd
		c.PendingVerify = verify
		c.SetupMode = false
		c.ScanStarted = true
		c.ScanState = "preparing"
		c.mu.Unlock()
		return map[string]interface{}{"started": true}, nil
	}
	err := c.beginScan(verify)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"started": true}, nil
}

func (c *TuiController) beginScan(verify bool) error {
	c.mu.Lock()
	onStart := c.onStart
	if onStart == nil {
		c.mu.Unlock()
		return errors.New("Scan start is unavailable")
	}
	c.StartInProgress = true
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		c.StartInProgress = false
		c.mu.Unlock()
	}()

	if err := onStart(verify); err != nil {
		return err
	}

	c.mu.Lock()
	c.SetupMode = false
	c.ScanStarted = true
	c.ScanState = "running"
	c.mu.Unlock()
	return nil
}

func (c *TuiController) confirmMount(payload map[string]interface{}) (map[string]interface{}, error) {
	c.mu.Lock()
	mount := c.PendingWorkspaceMount
	c.mu.Unlock()

	if mount == nil {
		return nil, errors.New("No mount confirmation is pending")
	}

	approvedVal, ok := payload["approved"]
	if !ok {
		return nil, errors.New("approved must be a boolean")
	}
	approved, ok := approvedVal.(bool)
	if !ok {
		return nil, errors.New("approved must be a boolean")
	}

	c.mu.Lock()
	c.PendingWorkspaceMount = nil
	pendingVerify := c.PendingVerify
	c.mu.Unlock()

	if !approved {
		c.mu.Lock()
		c.WorkspaceMount = nil
		c.mu.Unlock()
		c.EnterSetup()
		return map[string]interface{}{"approved": false}, nil
	}

	c.mu.Lock()
	c.WorkspaceMount = mount
	c.mu.Unlock()

	err := c.beginScan(pendingVerify)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"approved": true}, nil
}

func (c *TuiController) sendMessage(payload map[string]interface{}) (map[string]interface{}, error) {
	agentID, err := c.requiredString(payload, "agent_id")
	if err != nil {
		return nil, err
	}
	message, err := c.requiredString(payload, "message")
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	coordinator := c.Coordinator
	liveView := c.LiveView
	scanCtx := c.ScanCtx
	c.mu.Unlock()

	if coordinator == nil {
		return nil, errors.New("Agent coordinator is unavailable")
	}
	if scanCtx == nil || scanCtx.Err() != nil {
		return nil, errors.New("Scan loop is not ready")
	}

	liveView.RecordUserMessage(agentID, message)

	delivered, err := coordinator.Send(agentID, map[string]interface{}{
		"from":    "user",
		"content": message,
		"type":    "instruction",
	})
	if err != nil {
		return nil, err
	}
	if !delivered {
		return nil, errors.New("Message could not be delivered")
	}
	return map[string]interface{}{"sent": true}, nil
}

func (c *TuiController) stopAgent(payload map[string]interface{}) (map[string]interface{}, error) {
	agentID, err := c.requiredString(payload, "agent_id")
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	liveView := c.LiveView
	coordinator := c.Coordinator
	scanCtx := c.ScanCtx
	c.mu.Unlock()

	agent, ok := liveView.BaseLiveView.GetAgents()[agentID]
	if !ok {
		return nil, fmt.Errorf("Unknown agent: %s", agentID)
	}

	status := ""
	if statusVal, exists := agent["status"]; exists {
		if s, ok := statusVal.(string); ok {
			status = s
		}
	}
	if !stoppableAgentStatuses[status] {
		if status == "" {
			status = "unknown"
		}
		return nil, fmt.Errorf("Agent '%s' cannot be stopped while %s", agentID, status)
	}

	if coordinator == nil || scanCtx == nil || scanCtx.Err() != nil {
		return nil, errors.New("Scan loop is not ready")
	}

	accepted, err := coordinator.CancelDescendantsGraceful(agentID)
	if err != nil {
		return nil, err
	}
	if !accepted {
		return nil, fmt.Errorf("Agent '%s' is no longer active", agentID)
	}
	return map[string]interface{}{"stopped": true}, nil
}

func (c *TuiController) openViewer(_ map[string]interface{}) (map[string]interface{}, error) {
	c.mu.Lock()
	viewerURL := c.ViewerURL
	reportState := c.ReportState
	c.mu.Unlock()

	if viewerURL != nil {
		// webbrowser.open(*viewerURL)
		return map[string]interface{}{"status": "running", "url": *viewerURL}, nil
	}
	if reportState == nil {
		c.mu.Lock()
		c.ViewerStatus = "failed"
		c.mu.Unlock()
		return map[string]interface{}{"status": "failed", "error": "Scan output is not ready"}, nil
	}

	// Start a local HTTP server serving the run directory
	tokenBytes := make([]byte, 16)
	rand.Read(tokenBytes)
	token := hex.EncodeToString(tokenBytes)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		c.mu.Lock()
		c.ViewerStatus = "failed"
		c.mu.Unlock()
		return map[string]interface{}{"status": "failed", "error": "Failed to start viewer server"}, nil
	}
	
	port := listener.Addr().(*net.TCPAddr).Port
	url := fmt.Sprintf("http://127.0.0.1:%d/?token=%s", port, token)
	runDir := reportState.GetRunDir()
	
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.Dir(runDir)))
	srv := &http.Server{Handler: mux}
	
	go func() {
		_ = srv.Serve(listener)
	}()

	c.mu.Lock()
	c.ViewerHTTPD = srv
	c.ViewerURL = &url
	c.ViewerStatus = "running"
	c.mu.Unlock()

	// Add PostHog telemetry
	viewerOpenedTelemetry("tui", true)

	return map[string]interface{}{"status": "running", "url": url}, nil
}

func (c *TuiController) CloseViewer() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ViewerHTTPD == nil {
		return
	}
	if srv, ok := c.ViewerHTTPD.(*http.Server); ok {
		go srv.Shutdown(context.Background())
	}
	c.ViewerHTTPD = nil
}

func (c *TuiController) quit(_ map[string]interface{}) (map[string]interface{}, error) {
	c.CloseViewer()
	c.mu.Lock()
	onQuit := c.onQuit
	c.mu.Unlock()

	if onQuit != nil {
		if err := onQuit(); err != nil {
			return nil, err
		}
	}
	c.mu.Lock()
	c.ScanState = "stopped"
	c.mu.Unlock()
	return map[string]interface{}{"quitting": true}, nil
}

func (c *TuiController) requiredString(payload map[string]interface{}, name string) (string, error) {
	val, ok := payload[name]
	if !ok {
		return "", fmt.Errorf("%s must be a non-empty string", name)
	}
	s, ok := val.(string)
	if !ok || strings.TrimSpace(s) == "" {
		return "", fmt.Errorf("%s must be a non-empty string", name)
	}
	return strings.TrimSpace(s), nil
}

func (c *TuiController) requireSetupMutable() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.SetupMode || c.ScanStarted || c.StartInProgress {
		return errors.New("Setup can no longer be changed after the scan starts")
	}
	return nil
}
