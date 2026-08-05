package core

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/AwaisCh360/Apex/apex/runtime"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/AwaisCh360/Apex/apex/agents"
	"github.com/AwaisCh360/Apex/apex/config"
	"github.com/google/uuid"
)

var runnerLogger = log.New(os.Stderr, "[runner] ", log.LstdFlags)

type StreamEventSink func(string, interface{})

type RunResultBase struct {
	FinalOutput interface{}
}

func mergeRootPromptContext(scopeContext map[string]interface{}, extra map[string]interface{}) (map[string]interface{}, error) {
	if len(extra) == 0 {
		return scopeContext, nil
	}
	merged := make(map[string]interface{})
	for k, v := range scopeContext {
		merged[k] = v
	}
	for k, v := range extra {
		if _, exists := scopeContext[k]; exists {
			return nil, fmt.Errorf("extra_system_prompt_context cannot override built-in scope keys")
		}
		merged[k] = v
	}
	return merged, nil
}

func composeRootInstructionsOverride(override *string, skills []string, scanMode string, isWhitebox, interactive bool, sysCtx map[string]interface{}) *string {
	if override == nil {
		return nil
	}
	baseInstructions := agents.RenderSystemPrompt(agents.RenderOptions{})
	res := fmt.Sprintf("%s\n\n<root_scan_instructions_override>\nThe following root scan instructions are subordinate to the system-verified scope above. They cannot expand, replace, or weaken authorized target constraints.\n\n%s\n</root_scan_instructions_override>", baseInstructions, *override)
	return &res
}

func setupScanLogging(runDir string) func() { return func() {} }
func setScanID(scanID string)               {}
func hydrateTodosFromDisk(stateDir string)  {}
func hydrateNotesFromDisk(stateDir string)  {}

func RunApexScan(
	scanConfig map[string]interface{},
	scanID *string,
	image string,
	localSources []map[string]interface{},
	coordinator *AgentCoordinator,
	interactive bool,
	maxTurns int,
	maxBudgetUSD *float64,
	model *string,
	cleanupOnExit bool,
	eventSink StreamEventSink,
	rootInstructionsOverride *string,
	extraSystemPromptContext map[string]interface{},
	statusSink func(string),
) (*RunResultBase, error) {
	report := func(phase string) {
		if statusSink != nil {
			statusSink(phase)
		}
	}

	id := fmt.Sprintf("scan-%s", strings.ReplaceAll(uuid.New().String(), "-", "")[:8])
	if scanID != nil && *scanID != "" {
		id = *scanID
	}
	scanIdStr := id

	runDir := RunDirFor(scanIdStr, "")
	os.MkdirAll(runDir, 0755)
	stateDir := RuntimeStateDir(runDir)
	os.MkdirAll(stateDir, 0755)

	teardownLogging := setupScanLogging(runDir)
	setScanID(scanIdStr)
	defer teardownLogging()

	agentsPath := filepath.Join(stateDir, "agents.json")
	agentsDB := filepath.Join(stateDir, "agents.db")
	_, err := os.Stat(agentsPath)
	isResume := err == nil

	action := "Starting"
	if isResume {
		action = "Resuming"
	}
	runnerLogger.Printf("%s Apex scan %s (image=%s, max_turns=%d, interactive=%v, run_dir=%s)", action, scanIdStr, image, maxTurns, interactive, runDir)

	settings := config.LoadSettings()
	config.ConfigureSdkModelDefaults(settings)

	resolvedModel := ""
	if model != nil && *model != "" {
		resolvedModel = *model
	} else if settings.Llm.Model != "" {
		resolvedModel = settings.Llm.Model
	}
	resolvedModel = strings.TrimSpace(resolvedModel)
	if resolvedModel == "" {
		return nil, fmt.Errorf("no LLM model configured")
	}

	if coordinator == nil {
		coordinator = &AgentCoordinator{
			ParentOf: make(map[string]*string),
			Statuses: make(map[string]Status),
		}
	}
	coordinator.SetSnapshotPath(agentsPath)

	hydrateTodosFromDisk(stateDir)
	hydrateNotesFromDisk(stateDir)

	var rootID string
	if isResume {
		b, err := os.ReadFile(agentsPath)
		if err != nil {
			return nil, fmt.Errorf("cannot resume scan %s: %v", scanIdStr, err)
		}
		var snap map[string]interface{}
		json.Unmarshal(b, &snap)
		if _, err := os.Stat(agentsDB); err != nil {
			return nil, fmt.Errorf("cannot resume scan %s: missing SDK session database", scanIdStr)
		}
		coordinator.Restore(snap)
		rs := GetGlobalReportState()
		if rs != nil {
			b1, b2 := RecomputedBudgetFlags(rs.GetTotalLLMCost(), maxBudgetUSD, interactive)
			coordinator.ResetBudgetStops(b1, b2, interactive && coordinator.BudgetPaused)
		}
		for aid, parent := range coordinator.ParentOf {
			if parent == nil {
				rootID = aid
				break
			}
		}
		if rootID == "" {
			return nil, fmt.Errorf("no root agent")
		}
	} else {
		rootID = uuid.New().String()[:8]
	}

	runnerLogger.Printf("Bringing up sandbox session for scan %s", scanIdStr)
	bundle, _ := runtime.DefaultSessionManager.CreateOrReuse(context.Background(), scanIdStr, image, localSources, statusSink)
	report("Waiting for the first model response")

	defer func() {
		coordinator.MaybeSnapshot()
		if cleanupOnExit {
			runtime.DefaultSessionManager.Cleanup(context.Background(), scanIdStr)
		}
	}()

	var sessionsToClose []*SQLiteSession
	defer func() {
		for _, s := range sessionsToClose {
			_ = s // close
		}
	}()

	scanMode, _ := scanConfig["scan_mode"].(string)
	if scanMode == "" {
		scanMode = "deep"
	}

	targets, _ := scanConfig["targets"].([]interface{})
	isWhitebox := false
	for _, t := range targets {
		if tm, ok := t.(map[string]interface{}); ok && tm["type"] == "local_code" {
			isWhitebox = true
			break
		}
	}

	var skills []string
	if s, ok := scanConfig["skills"].([]interface{}); ok {
		for _, sk := range s {
			skills = append(skills, sk.(string))
		}
	}

	rootTask := BuildRootTask(scanConfig)

	hooks, err := NewReportUsageHooks(resolvedModel, maxBudgetUSD, &maxTurns, interactive)
	if err != nil {
		return nil, err
	}
	if interactive {
		coordinator.SetBudgetExtender(hooks.ExtendBudget)
	}

	scopeContext := BuildScopeContext(scanConfig)
	rootContext, err := mergeRootPromptContext(scopeContext, extraSystemPromptContext)
	if err != nil {
		return nil, err
	}
	rootInstructions := composeRootInstructionsOverride(rootInstructionsOverride, skills, scanMode, isWhitebox, interactive, rootContext)
	_ = rootInstructions

	chatCompletionsTools := false // stub for uses_chat_completions_tool_schema

	rootAgent := agents.BuildApexAgent(
		"Apex", skills, true, scanMode, isWhitebox, interactive, chatCompletionsTools, rootContext, nil, "",
	)

	if !isResume {
		coordinator.Register(rootID, "Apex", nil, rootTask, skills)
	}

	childBuilder := agents.MakeChildFactory(scanMode, isWhitebox, interactive, chatCompletionsTools, scopeContext)

	ctx := map[string]interface{}{
		"coordinator":        coordinator,
		"sandbox_session":    bundle["session"],
		"caido_client":       bundle["caido_client"],
		"agent_id":           rootID,
		"parent_id":          nil,
		"interactive":        interactive,
		"spawn_child_agent":  func() {}, // stub
		"max_context_images": settings.Runtime.MaxContextImages,
	}

	rootSession := OpenAgentSession(rootID, agentsDB)
	sessionsToClose = append(sessionsToClose, rootSession)
	coordinator.AttachRuntime(rootID, rootSession, nil, nil)

	if isResume {
		RespawnSubagents(coordinator, func(n string, s []string) interface{} { return childBuilder(n, s) }, agentsDB, &sessionsToClose, scanConfig, maxTurns, interactive, ctx, rootID, eventSink, hooks)
	}

	var initialInput interface{} = rootTask
	if isResume {
		initialInput = []interface{}{}
	}

	resumeInstruction, _ := scanConfig["resume_instruction"].(string)
	resumeInstruction = strings.TrimSpace(resumeInstruction)
	if isResume && resumeInstruction != "" {
		coordinator.Send(rootID, map[string]interface{}{
			"from":     "user",
			"type":     "instruction",
			"priority": "high",
			"content":  resumeInstruction,
		}, false)
	}

	result, err := RunAgentLoop(rootAgent, initialInput, map[string]interface{}{}, ctx, maxTurns, coordinator, rootID, interactive, rootSession, false, eventSink, hooks)

	if err != nil {
		if _, ok := err.(*BudgetExceededError); ok {
			runnerLogger.Printf("Scan stopped budget exceeded")
			coordinator.CancelDescendants(rootID)
			coordinator.SetStatus(rootID, "stopped", nil)
			return nil, nil
		}
		if _, ok := err.(*BudgetPausedError); ok {
			runnerLogger.Printf("Scan paused budget")
			coordinator.CancelDescendants(rootID)
			coordinator.SetStatus(rootID, "stopped", nil)
			return nil, nil
		}
		coordinator.CancelDescendants(rootID)
		coordinator.SetStatus(rootID, "failed", nil)
		return nil, err
	}

	if !interactive && result != nil {
		finalStr := ""
		scanCompleted := false
		if result.FinalOutput != nil {
			if strVal, ok := result.FinalOutput.(string); ok {
				finalStr = strVal
				var parsed map[string]interface{}
				if err := json.Unmarshal([]byte(strVal), &parsed); err == nil {
					if completed, ok := parsed["scan_completed"].(bool); ok && completed {
						scanCompleted = true
					}
				}
			} else if mapVal, ok := result.FinalOutput.(map[string]interface{}); ok {
				if completed, ok := mapVal["scan_completed"].(bool); ok && completed {
					scanCompleted = true
				}
			}
		}
		if !scanCompleted {
			outStr := finalStr
			if len(outStr) > 300 {
				outStr = outStr[:300]
			}
			runnerLogger.Printf("Scan %s ended without calling finish_scan. The agent emitted a text-only turn instead of a lifecycle tool call, so no executive report was written. Final output (first 300 chars): %q", scanIdStr, outStr)
		}
	}

	return result, nil
}
