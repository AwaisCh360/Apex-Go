package respond


import (
	"bytes"
	"encoding/json"
	"sync"
)

var coordinatorMutex sync.Mutex

func toJSONString(v interface{}) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		// Return JSON error if encoding fails
		return `{"success":false,"error":"Failed to encode JSON response"}`
	}
	// json.Encoder adds a newline, strip it if we want exactly like Marshal but unescaped
	s := buf.String()
	if len(s) > 0 && s[len(s)-1] == '\n' {
		s = s[:len(s)-1]
	}
	return s
}

// RunContextWrapper represents the context passed to the tool.
type RunContextWrapper struct {
	Context map[string]interface{}
}

func _ctx(ctx *RunContextWrapper) map[string]interface{} {
	if ctx != nil && ctx.Context != nil {
		return ctx.Context
	}
	return make(map[string]interface{})
}

type Coordinator interface {
	GetStatus(agentID string) string
	ConsumePending(agentID string, blocking bool) (int, []string, error)
	MarkRunning(agentID string) error
	ParkWaiting(agentID string, target string) error
}

func coordinatorFromContext(ctx map[string]interface{}) Coordinator {
	if coord, ok := ctx["coordinator"].(Coordinator); ok {
		return coord
	}
	return nil
}

// RespondToUser answers the user and hands control back to them.
//
// This is the ONLY way to yield to the user. Delivering the message and
// yielding are the same call on purpose: there is no way to answer and
// then forget to stop, and no way to stop without having answered.
//
// Call it when you have something for the user and nothing to do until
// they reply — you answered their question, you need a decision or a
// credential only they can give, or you finished a chunk of work and
// want direction. You resume exactly where you left off when they
// reply, with everything you have done so far intact.
//
// Do NOT call it to narrate progress or to think out loud. Plain text
// is still shown to the user as you work, so say whatever you like
// mid-task without stopping; RespondToUser is specifically the
// act of *waiting* for them. Every call costs the user their attention.
//
// Not for these:
//
// - **Waiting on another agent** (a child's report, a peer's reply) —
//   use wait_for_agents.
// - **Ending the engagement** — use finish_scan (root) or
//   agent_finish (subagent). Those are terminal; this is a pause.
func RespondToUser(ctx *RunContextWrapper, message string) (string, error) {
	inner := _ctx(ctx)
	coordinator := coordinatorFromContext(inner)

	me, meOk := inner["agent_id"].(string)

	interactive := false
	if val, ok := inner["interactive"].(bool); ok {
		interactive = val
	}

	if coordinator == nil || !meOk || me == "" {
		res := map[string]interface{}{
			"success": false,
			"error":   "Agent coordinator or agent_id missing in context",
		}
		return toJSONString(res), nil
	}

	if !interactive {
		res := map[string]interface{}{
			"success": false,
			"error":   "No user is attached to an autonomous run. Keep working, and call finish_scan (root) or agent_finish (subagent) when the task is done.",
		}
		return toJSONString(res), nil
	}

	coordinatorMutex.Lock()
	status := coordinator.GetStatus(me)
	coordinatorMutex.Unlock()

	if status == "stopped" {
		res := map[string]interface{}{
			"success":      true,
			"wait_outcome": "stopped",
			"message":      message,
		}
		return toJSONString(res), nil
	}

	pending, _, err := coordinator.ConsumePending(me, false)
	if err != nil {
		return "", err
	}

	if pending > 0 {
		err = coordinator.MarkRunning(me)
		if err != nil {
			return "", err
		}
		res := map[string]interface{}{
			"success":          true,
			"wait_outcome":     "message_arrived",
			"pending_messages": pending,
			"message":          message,
			"note":             "Your reply was delivered; the user had already sent a new message.",
		}
		return toJSONString(res), nil
	}

	coordinatorMutex.Lock()
	err = coordinator.ParkWaiting(me, "user")
	coordinatorMutex.Unlock()
	if err != nil {
		return "", err
	}

	res := map[string]interface{}{
		"success":      true,
		"wait_outcome": "waiting",
		"message":      message,
		"note":         "Reply delivered; parked until the user responds.",
	}
	return toJSONString(res), nil
}
