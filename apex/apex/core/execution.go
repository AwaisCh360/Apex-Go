package core


import (
	"errors"
	"fmt"
	"log"
	"strings"
	"time"
    "net"

	"github.com/google/uuid"
	"github.com/AwaisCh360/Apex/apex/llm"
)

func IsTransientModelError(err error) bool {
    if err == nil {
        return false
    }
    
    // Check if it's a content guardrail error
    if llm.IsContentGuardrailError(err) {
        return false
    }
    
    // Check provider errors
    var provErr *llm.ProviderError
    if errors.As(err, &provErr) {
        if provErr.StatusCode >= 500 && provErr.StatusCode < 600 {
            return true
        }
        if provErr.StatusCode == 429 || provErr.StatusCode == 408 {
            return true
        }
        return false // Other 4xx errors are not transient
    }
    
    // Check network errors
    errStr := strings.ToLower(err.Error())
    if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "connection reset") || strings.Contains(errStr, "no such host") || strings.Contains(errStr, "connection refused") || strings.Contains(errStr, "eof") {
        return true
    }
    
    var netErr net.Error
    if errors.As(err, &netErr) && netErr.Timeout() {
        return true
    }

    return false
}



var execLogger = log.New(log.Writer(), "[execution] ", log.LstdFlags)

type RunHooks interface {
	ExtendBudget()
}

type MaxTurnsExceeded struct{ Message string }

func (e *MaxTurnsExceeded) Error() string { return e.Message }

type ProviderRefusalError struct{ Message string }

func (e *ProviderRefusalError) Error() string { return e.Message }

func RunAgentLoop(
	agent interface{},
	initialInput interface{},
	runConfig interface{}, // agents.RunConfig
	ctx map[string]interface{},
	maxTurns int,
	coordinator *AgentCoordinator,
	agentID string,
	interactive bool,
	session *SQLiteSession,
	startParked bool,
	eventSink StreamEventSink,
	hooks RunHooks,
) (*RunResultBase, error) {
	err := coordinator.AttachRuntime(agentID, session, nil, &interactive)
	if err != nil {
		return nil, err
	}
	defer func() {
		coordinator.SetStatus(agentID, StatusStopped, nil)
	}()

	var result *RunResultBase

	// Seed first input
	firstCycleInput := initialInput
	if initialInput != nil && session != nil && !startParked {
		// _, err := seedInitialInput(session, initialInput)
		// if err == nil { firstCycleInput = []interface{}{} }
	}

	cLock := &coordinator.Lock
	cLock.Lock()
	budgetStopped := coordinator.BudgetStopped
	reserveStopped := coordinator.ReserveStopped
	cLock.Unlock()

	if budgetStopped {
		coordinator.SetStatus(agentID, StatusStopped, nil)
		return nil, &BudgetExceededError{"scan budget reached"}
	}

	parentID, hasParent := ctx["parent_id"]
	if reserveStopped && hasParent && parentID != nil {
		coordinator.SetStatus(agentID, StatusStopped, nil)
		return nil, &SubagentBudgetReservedError{"scan reached the sub-agent budget reserve"}
	}

	if reserveStopped && startParked && interactive && (!hasParent || parentID == nil) {
		coordinator.Send(agentID, map[string]interface{}{
			"from":    "system",
			"type":    "reserve_notice",
			"content": "[Budget] Sub-agent budget reserve reached...",
		}, true)
	}

	if !(startParked && interactive) {
		res, err := runUntilLifecycle(agent, coordinator, agentID, firstCycleInput, runConfig, ctx, maxTurns, session, interactive, eventSink, hooks)
		if err != nil {
			if _, ok := err.(*BudgetPausedError); !ok {
				return nil, err
			}
			errStr := err.Error()
			coordinator.SetStatus(agentID, StatusBudgetPaused, &errStr)
		} else {
			result = res
		}
	}

	if !interactive {
		return result, nil
	}

	for {
		timeout, err := plainWaitingTimeout(coordinator, agentID)
		if err != nil {
			return nil, err
		}

		woke, err := coordinator.WaitForMessage(agentID, timeout)
		if err != nil {
			return result, nil
		}

		cLock.Lock()
		bStop := coordinator.BudgetStopped
		rStop := coordinator.ReserveStopped
		cLock.Unlock()

		if bStop {
			coordinator.SetStatus(agentID, StatusStopped, nil)
			return nil, &BudgetExceededError{"scan budget reached"}
		}
		if rStop && hasParent && parentID != nil {
			coordinator.SetStatus(agentID, StatusStopped, nil)
			return nil, &SubagentBudgetReservedError{"scan reached reserve"}
		}

		if woke {
			coordinator.ResetRecovery(agentID)
			coordinator.ResetIdleResumes(agentID)
		} else {
			idleResumes, _ := coordinator.RecordIdleResume(agentID)
			if idleResumes >= 3 {
				execLogger.Printf("agent %s stalled after auto-resumes", agentID)
				coordinator.ParkWaiting(agentID, WaitKindStalled)
				continue
			}
			coordinator.Send(agentID, map[string]interface{}{
				"from": "system", "type": "auto_resume", "content": "Waiting timeout reached. Resuming.",
			}, false)
		}

		coordinator.ConsumePending(agentID, false)
		res, err := runUntilLifecycle(agent, coordinator, agentID, []interface{}{}, runConfig, ctx, maxTurns, session, true, eventSink, hooks)
		if err != nil {
			if _, ok := err.(*BudgetPausedError); !ok {
				return nil, err
			}
			errStr := err.Error()
			coordinator.SetStatus(agentID, StatusBudgetPaused, &errStr)
		} else {
			result = res
		}
	}
}

func plainWaitingTimeout(coordinator *AgentCoordinator, agentID string) (*time.Duration, error) {
	coordinator.Lock.Lock()
	defer coordinator.Lock.Unlock()

	status := coordinator.Statuses[agentID]
	_, hasError := coordinator.Errors[agentID]
	runtime := coordinator.Runtimes[agentID]
	gated := false
	if runtime != nil {
		gated = runtime.UserWakeRequired
	}
	waitKind := coordinator.WaitKinds[agentID]
	idleResumes := coordinator.IdleResumeCounts[agentID]

	if status != StatusWaiting || hasError || gated {
		return nil, nil
	}
	if waitKind != WaitKindAgents || idleResumes >= 3 {
		return nil, nil
	}
	d := 300 * time.Second
	return &d, nil
}

func runUntilLifecycle(
	agent interface{}, coordinator *AgentCoordinator, agentID string, initialInput interface{},
	runConfig interface{}, ctx map[string]interface{}, maxTurns int, session *SQLiteSession,
	interactive bool, eventSink StreamEventSink, hooks RunHooks,
) (*RunResultBase, error) {
	var result *RunResultBase
	inputData := initialInput
	recoveryLimit := 3
	if !interactive {
		recoveryLimit = maxTurns
		if recoveryLimit < 1 {
			recoveryLimit = 1
		}
	}

	for {
		cLock := &coordinator.Lock
		cLock.Lock()
		bStop := coordinator.BudgetStopped
		rStop := coordinator.ReserveStopped
		cLock.Unlock()

		if bStop {
			coordinator.SetStatus(agentID, StatusStopped, nil)
			return nil, &BudgetExceededError{"scan budget reached"}
		}
		parentID, hasParent := ctx["parent_id"]
		if rStop && hasParent && parentID != nil {
			coordinator.SetStatus(agentID, StatusStopped, nil)
			return nil, &SubagentBudgetReservedError{"scan reached reserve"}
		}

		res, err := runCycle(agent, coordinator, agentID, inputData, runConfig, ctx, maxTurns, session, interactive, eventSink, hooks)
		if err != nil {
			return nil, err
		}
		result = res

		cLock.Lock()
		status := coordinator.Statuses[agentID]
		cLock.Unlock()

		if status != StatusRunning {
			coordinator.ResetRecovery(agentID)
			return result, nil
		}

		recoveries, _ := coordinator.RecordRecovery(agentID)
		if recoveries >= recoveryLimit {
			return exhaustedRecovery(coordinator, agentID, result, interactive)
		}

		inputData = appendToolRequiredMessage(session, ctx, recoveries, recoveryLimit, interactive)
	}
}

func exhaustedRecovery(coordinator *AgentCoordinator, agentID string, result *RunResultBase, interactive bool) (*RunResultBase, error) {
	if !interactive {
		coordinator.SetStatus(agentID, StatusCrashed, nil)
		return nil, &MaxTurnsExceeded{"Agent exhausted recovery attempts without calling finish."}
	}
	coordinator.ParkWaiting(agentID, WaitKindStalled)
	return result, nil
}

func appendToolRequiredMessage(session *SQLiteSession, ctx map[string]interface{}, attempt, limit int, interactive bool) []interface{} {
	finishTool := "finish_scan"
	if ctx["parent_id"] != nil {
		finishTool = "agent_finish"
	}
	var message string
	if interactive {
		message = fmt.Sprintf("Your previous message ended a turn without a tool call. Plain text never ends execution and never hands control to the user: it is shown to the user, and the run continues. Continue immediately and call exactly one tool. If you have something to tell the user and nothing to do until they reply, call respond_to_user. If you are blocked waiting for another agent, call wait_for_agents. If the whole engagement is complete, call %s. Otherwise use the appropriate execution or planning tool. This is recovery attempt %d/%d.", finishTool, attempt, limit)
	} else {
		message = fmt.Sprintf("Your previous message ended a turn without a tool call. Plain text never ends execution. Continue immediately and call exactly one tool. If you are blocked waiting for another agent, call wait_for_agents. If the whole engagement is complete, call %s. Otherwise use the appropriate execution or planning tool. This is recovery attempt %d/%d.", finishTool, attempt, limit)
	}

	appended := []interface{}{
		map[string]interface{}{"role": "user", "content": message},
	}
	if session != nil {
		session.AddItems(appended)
	}
	return appended
}

var runCycle = func(
	agent interface{}, coordinator *AgentCoordinator, agentID string, inputData interface{},
	runConfig interface{}, ctx map[string]interface{}, maxTurns int, session *SQLiteSession,
	interactive bool, eventSink StreamEventSink, hooks RunHooks,
) (*RunResultBase, error) {
	coordinator.MarkRunning(agentID)
	// Mock streamed run loop
	return &RunResultBase{}, nil
}

func SpawnChildAgent(
	coordinator *AgentCoordinator,
	factory func(string, []string) interface{},
	agentsDBPath string,
	sessionsToClose *[]*SQLiteSession,
	runConfig interface{},
	maxTurns int,
	interactive bool,
	parentCtx map[string]interface{},
	name string,
	task string,
	skills []string,
	parentHistory []interface{},
	eventSink StreamEventSink,
	hooks RunHooks,
) (map[string]interface{}, error) {
	parentIDVal := parentCtx["agent_id"]
	if parentIDVal == nil {
		return nil, fmt.Errorf("Parent agent_id missing from context")
	}
	parentID := parentIDVal.(string)

	childID := uuid.New().String()[:8]
	childAgent := factory(name, skills)

	coordinator.Register(childID, name, &parentID, task, skills)

	initialInput := ChildInitialInput(name, childID, parentID, task, parentHistory)

	// Start child runner async
	go func() {
		// A budget stop is a clean scan-wide shutdown, not a child failure.
		// Swallow it here so the detached task does not surface a panic.
		// The root agent hits the same limit on its next call and tears the scan down.
		_, err := RunAgentLoop(
			childAgent,
			initialInput,
			runConfig,
			parentCtx, // Should we make a childCtx copy? Yes, in RunAgentLoop or here.
			maxTurns,
			coordinator,
			childID,
			interactive,
			nil, // session will be opened
			false, // startParked
			eventSink,
			hooks,
		)
		if err != nil {
			if _, ok := err.(*BudgetExceededError); ok {
				// logging child stopped after reaching scan budget limit
			}
		}
	}()


	return map[string]interface{}{
		"success":   true,
		"agent_id":  childID,
		"name":      name,
		"parent_id": parentID,
		"message":   fmt.Sprintf("Spawned '%s' (%s) running in parallel.", name, childID),
	}, nil
}

func RespawnSubagents(
	coordinator *AgentCoordinator,
	factory func(string, []string) interface{},
	agentsDBPath string,
	sessionsToClose *[]*SQLiteSession,
	runConfig interface{},
	maxTurns int,
	interactive bool,
	parentCtx map[string]interface{},
	rootID string,
	eventSink StreamEventSink,
	hooks RunHooks,
) error {
	coordinator.Lock.Lock()
	type cand struct {
		id       string
		name     string
		parentID *string
		md       map[string]interface{}
	}
	var candidates []cand
	for aid, status := range coordinator.Statuses {
		if !interactive && status != "running" && status != "waiting" {
			continue
		}
		if coordinator.ParentOf[aid] == nil || aid == rootID {
			continue
		}
		md := make(map[string]interface{})
		for k, v := range coordinator.Metadata[aid] {
			md[k] = v
		}
		md["_restored_status"] = string(status)
		candidates = append(candidates, cand{
			id:       aid,
			name:     coordinator.Names[aid],
			parentID: coordinator.ParentOf[aid],
			md:       md,
		})
	}
	coordinator.Lock.Unlock()

	for _, c := range candidates {
		restoredStatus := "running"
		if val, ok := c.md["_restored_status"].(string); ok && val != "" {
			restoredStatus = val
		}
		startParked := interactive && restoredStatus != "running"

		var childSkills []string
		if skillsRaw, ok := c.md["skills"].([]interface{}); ok {
			for _, s := range skillsRaw {
				if str, ok := s.(string); ok {
					childSkills = append(childSkills, str)
				}
			}
		}

		childAgent := factory(c.name, childSkills)
		task := ""
		if t, ok := c.md["task"].(string); ok {
			task = t
		}
		
		go func(c cand, childAgent interface{}, task string, startParked bool) {
			_, err := RunAgentLoop(
				childAgent,
				nil, // initialInput
				runConfig,
				parentCtx,
				maxTurns,
				coordinator,
				c.id,
				interactive,
				nil, // session
				startParked,
				eventSink,
				hooks,
			)
			if err != nil {
				if _, ok := err.(*BudgetExceededError); ok {
					// log budget exceeded
				}
			}
		}(c, childAgent, task, startParked)
	}

	return nil
}
