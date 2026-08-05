// Package thinking provides a tool to record a private chain-of-thought note with no side effects.
package thinking

import (
	"encoding/json"
	"strings"
)

// FunctionTool is a local stub for the Python @function_tool decorator.
// It simulates the configuration of function tools.
func FunctionTool(timeout int) func(any) any {
	return func(fn any) any {
		return fn
	}
}

// Think records a private chain-of-thought note. No side effects, no new info.
//
// Use Think when you need a dedicated space to reason before acting —
// not as an output channel. It's particularly valuable for:
//
// - **Tool output analysis** — carefully processing the output of a
//   previous tool call before deciding the next step.
// - **Policy-heavy environments** — when you need to follow detailed
//   guidelines (engagement scope, auth boundaries) and verify compliance
//   before each action.
// - **Sequential decision making** — when each action builds on previous
//   ones and mistakes are costly (e.g., destructive operations,
//   irreversible auth changes).
// - **Multi-step exploit planning** — breaking down a complex chain into
//   manageable steps and tracking what's been confirmed vs. assumed.
//
// Structure your thought to be useful: current state, what you've
// confirmed, your next planned actions, risk assessment. Don't use
// Think to chat — use it to plan.
//
// Args:
//     thought: The reasoning to record. Must be non-empty.
func Think(thought string) string {
	if thought == "" || strings.TrimSpace(thought) == "" {
		out, _ := json.Marshal(map[string]any{
			"success": false,
			"error":   "Thought cannot be empty",
		})
		return string(out)
	}

	out, _ := json.Marshal(map[string]any{
		"success": true,
		"message": "Thought recorded",
	})
	return string(out)
}
