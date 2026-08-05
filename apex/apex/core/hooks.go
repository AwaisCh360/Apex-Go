package core

import (
	"fmt"
	"log"
	"math"
	"os"
)

var hooksLogger = log.New(os.Stderr, "[hooks] ", log.LstdFlags)

var (
	stageLabels             = []string{"NOTICE", "URGENT", "CRITICAL"}
	turnWarnBands           = []float64{0.70, 0.85, 0.95}
	rootBudgetWarnBands     = []float64{0.70, 0.85, 0.95}
	subagentBudgetWarnBands = []float64{0.75, 0.80, 0.85}
	subagentBudgetReserve   = 0.90
)

type BudgetExceededError struct {
	Message string
}

func (e *BudgetExceededError) Error() string { return e.Message }

type SubagentBudgetReservedError struct {
	Message string
}

func (e *SubagentBudgetReservedError) Error() string { return e.Message }

type BudgetPausedError struct {
	Message string
}

func (e *BudgetPausedError) Error() string { return e.Message }

func RecomputedBudgetFlags(cost float64, maxBudgetUSD *float64, interactive bool) (bool, bool) {
	if maxBudgetUSD == nil {
		return false, false
	}
	if interactive {
		return false, false
	}
	budgetStopped := cost >= *maxBudgetUSD
	reserveStopped := cost >= *maxBudgetUSD*subagentBudgetReserve
	return budgetStopped, reserveStopped
}

func crossedStage(fraction float64, bands []float64) *int {
	var crossed *int
	for i, band := range bands {
		if fraction >= band {
			idx := i
			crossed = &idx
		}
	}
	return crossed
}

var rootDirectives = []string{
	"As the root agent, begin planning your wind-down of the whole scan: avoid starting large new lines of investigation, and keep your required objectives on track so you can call finish_scan comfortably before the limit.",
	"As the root agent, prioritize wrapping up the whole scan now: stop opening new lines of investigation, close out only what is essential, and move toward calling finish_scan to compile and deliver the final report.",
	"As the root agent, STOP all other work on the whole scan and finish immediately: secure your findings and call finish_scan now — anything left unfinished when the limit is hit is discarded.",
}

var subagentDirectives = []string{
	"As a sub-agent, begin planning your wind-down: avoid starting large new subtasks, and if you are close to a confirmed, validated vulnerability, drive it to a result you can report.",
	"As a sub-agent, prioritize wrapping up your task now: report any confirmed, validated vulnerability, finish work that is nearly done rather than starting anything new, and prepare to call agent_finish.",
	"As a sub-agent, STOP all other work and finish immediately: report any confirmed vulnerability right now and call agent_finish to hand your results back to your parent before you are cut off.",
}

// Mocks for agents.lifecycle and apex.report.state
type RunContextWrapper struct {
	Context map[string]interface{}
	Usage   *Usage
}

type Usage struct {
	Requests int
}

type Agent struct {
	Name string
}

type ModelResponse struct {
	Usage interface{}
}

type GlobalReportState interface {
	GetTotalLLMCost() float64
	RecordSDKUsage(agentID, agentName, model string, usage interface{})
}

type defaultGlobalReportState struct{}

func (g *defaultGlobalReportState) GetTotalLLMCost() float64                                           { return 0.0 }
func (g *defaultGlobalReportState) RecordSDKUsage(agentID, agentName, model string, usage interface{}) {}

var GetGlobalReportState = func() GlobalReportState {
	// Stub
	return &defaultGlobalReportState{}
}

func wrapupDirective(context *RunContextWrapper, stage int) string {
	isRoot := context.Context["parent_id"] == nil
	if isRoot {
		return rootDirectives[stage]
	}
	return subagentDirectives[stage]
}

func urgency(stage int) string {
	return stageLabels[stage]
}

type ReportUsageHooks struct {
	model           string
	maxBudgetUSD    *float64
	budgetIncrement *float64
	maxTurns        *int
	interactive     bool
}

func NewReportUsageHooks(model string, maxBudgetUSD *float64, maxTurns *int, interactive bool) (*ReportUsageHooks, error) {
	if maxBudgetUSD != nil && (math.IsNaN(*maxBudgetUSD) || math.IsInf(*maxBudgetUSD, 0) || *maxBudgetUSD <= 0) {
		return nil, fmt.Errorf("max_budget_usd must be a finite number greater than 0")
	}
	if maxTurns != nil && *maxTurns <= 0 {
		return nil, fmt.Errorf("max_turns must be a positive integer")
	}
	return &ReportUsageHooks{
		model:           model,
		maxBudgetUSD:    maxBudgetUSD,
		budgetIncrement: maxBudgetUSD,
		maxTurns:        maxTurns,
		interactive:     interactive,
	}, nil
}

func (h *ReportUsageHooks) ExtendBudget() {
	if h.maxBudgetUSD == nil || h.budgetIncrement == nil {
		return
	}
	newBudget := *h.maxBudgetUSD + *h.budgetIncrement
	h.maxBudgetUSD = &newBudget
}

func (h *ReportUsageHooks) OnLLMStart(context *RunContextWrapper, agent *Agent, systemPrompt *string, inputItems *[]map[string]interface{}) {
	defer func() {
		if r := recover(); r != nil {
			hooksLogger.Printf("budget/turn warning injection failed: %v", r)
		}
	}()
	h.maybeWarnTurns(context, inputItems)
	h.maybeWarnBudget(context, inputItems)
}

func (h *ReportUsageHooks) maybeWarnTurns(context *RunContextWrapper, inputItems *[]map[string]interface{}) {
	if h.maxTurns == nil {
		return
	}
	if context.Usage == nil {
		return
	}
	turnsUsed := context.Usage.Requests + 1
	stage := crossedStage(float64(turnsUsed)/float64(*h.maxTurns), turnWarnBands)
	if stage == nil {
		return
	}
	remaining := *h.maxTurns - turnsUsed
	if remaining < 0 {
		remaining = 0
	}
	pct := math.Round(100 * float64(turnsUsed) / float64(*h.maxTurns))
	content := fmt.Sprintf("[%s] Turn budget: %d/%d used (%v%%). About %d turn(s) remain before this agent is force-stopped and any in-progress work is discarded. %s",
		urgency(*stage), turnsUsed, *h.maxTurns, pct, remaining, wrapupDirective(context, *stage))

	*inputItems = append(*inputItems, map[string]interface{}{
		"role":    "user",
		"content": content,
	})
}

func (h *ReportUsageHooks) maybeWarnBudget(context *RunContextWrapper, inputItems *[]map[string]interface{}) {
	if h.maxBudgetUSD == nil {
		return
	}
	reportState := GetGlobalReportState()
	if reportState == nil {
		return
	}
	cost := reportState.GetTotalLLMCost()
	isRoot := context.Context["parent_id"] == nil

	var bands []float64
	if h.interactive {
		bands = rootBudgetWarnBands
	} else {
		if isRoot {
			bands = rootBudgetWarnBands
		} else {
			bands = subagentBudgetWarnBands
		}
	}

	stage := crossedStage(cost / *h.maxBudgetUSD, bands)
	if stage == nil {
		return
	}
	pct := math.Round(100 * cost / *h.maxBudgetUSD)
	reservePct := math.Round(subagentBudgetReserve * 100)

	var content string
	if h.interactive {
		content = fmt.Sprintf("[%s] Scan cost budget: $%.2f/$%.2f spent (%v%%). This budget is shared across every agent in the scan; when it is reached all agents are paused until the user chooses to continue. %s",
			urgency(*stage), cost, *h.maxBudgetUSD, pct, wrapupDirective(context, *stage))
	} else if isRoot {
		content = fmt.Sprintf("[%s] Scan cost budget: $%.2f/$%.2f spent (%v%%). This budget is shared across every agent in the scan; when it is reached the whole scan is stopped immediately, and sub-agents are stopped at %v%% to reserve the remainder for your final report. %s",
			urgency(*stage), cost, *h.maxBudgetUSD, pct, reservePct, wrapupDirective(context, *stage))
	} else {
		content = fmt.Sprintf("[%s] Scan cost budget: $%.2f/$%.2f spent (%v%%). This budget is shared across every agent in the scan; sub-agents are stopped at %v%% to leave the remainder for the root agent's final report. %s",
			urgency(*stage), cost, *h.maxBudgetUSD, pct, reservePct, wrapupDirective(context, *stage))
	}

	*inputItems = append(*inputItems, map[string]interface{}{
		"role":    "user",
		"content": content,
	})
}

func (h *ReportUsageHooks) OnLLMEnd(context *RunContextWrapper, agent *Agent, response *ModelResponse) error {
	reportState := GetGlobalReportState()
	if reportState == nil {
		return nil
	}

	agentName := agent.Name
	var agentID string
	if val, ok := context.Context["agent_id"].(string); ok && val != "" {
		agentID = val
	} else if agentName != "" {
		agentID = agentName
	} else {
		agentID = "unknown"
	}

	defer func() {
		if r := recover(); r != nil {
			hooksLogger.Printf("failed to record SDK usage for agent %s: %v", agentID, r)
		}
	}()

	reportState.RecordSDKUsage(agentID, agentName, h.model, response.Usage)

	if h.maxBudgetUSD != nil {
		cost := reportState.GetTotalLLMCost()
		b1, b2 := RecomputedBudgetFlags(cost, h.maxBudgetUSD, h.interactive)
		if coord, ok := context.Context["coordinator"]; ok {
			if c, ok := coord.(*AgentCoordinator); ok {
				err := c.ResetBudgetStops(b1, b2, h.interactive && cost >= *h.maxBudgetUSD)
				if err != nil {
					hooksLogger.Printf("ResetBudgetStops error: %v", err)
				}
			} else {
				hooksLogger.Printf("Coordinator found but not *AgentCoordinator")
			}
		} else {
			hooksLogger.Printf("Coordinator not found in context")
		}

		if cost >= *h.maxBudgetUSD {
			if h.interactive {
				return &BudgetPausedError{fmt.Sprintf("Scan budget of $%.2f reached (spent $%.4f); pausing until the user continues", *h.maxBudgetUSD, cost)}
			}
			return &BudgetExceededError{fmt.Sprintf("Token budget of $%.2f exceeded (spent $%.4f)", *h.maxBudgetUSD, cost)}
		}

		isRoot := context.Context["parent_id"] == nil
		if !h.interactive && !isRoot {
			reserveLimit := *h.maxBudgetUSD * subagentBudgetReserve
			if cost >= reserveLimit {
				return &SubagentBudgetReservedError{fmt.Sprintf("Sub-agent budget reserve reached: spent $%.4f of $%.2f (>= %v%% reserve); stopping this sub-agent so the root agent can finish the scan.", cost, *h.maxBudgetUSD, math.Round(subagentBudgetReserve*100))}
			}
		}
	}
	return nil
}
