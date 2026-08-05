package core

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

)

var agentsLogger = log.New(os.Stderr, "[agents] ", log.LstdFlags)

type Status string

const (
	StatusRunning      Status = "running"
	StatusWaiting      Status = "waiting"
	StatusCompleted    Status = "completed"
	StatusStopped      Status = "stopped"
	StatusCrashed      Status = "crashed"
	StatusFailed       Status = "failed"
	StatusBudgetPaused Status = "budget_paused"
)

type WaitKind string

const (
	WaitKindUser    WaitKind = "user"
	WaitKindAgents  WaitKind = "agents"
	WaitKindStalled WaitKind = "stalled"
)

type AgentRuntime struct {
	Session            *SQLiteSession
	Task               context.CancelFunc // Stub for asyncio.Task
	Stream             interface{}
	InterruptOnMessage bool
	Wake               chan struct{}
	Mailbox            []map[string]interface{}
	UserWakeRequired   bool
}

func NewAgentRuntime() *AgentRuntime {
	return &AgentRuntime{
		Wake:    make(chan struct{}, 1),
		Mailbox: make([]map[string]interface{}, 0),
	}
}

type AgentCoordinator struct {
	Statuses         map[string]Status
	ParentOf         map[string]*string
	Names            map[string]string
	Metadata         map[string]map[string]interface{}
	PendingCounts    map[string]int
	Errors           map[string]string
	RecoveryCounts   map[string]int
	IdleResumeCounts map[string]int
	WaitKinds        map[string]WaitKind
	Runtimes         map[string]*AgentRuntime
	ParentNotified   map[string]bool
	Lock             sync.Mutex
	SnapshotPath     *string
	IsShuttingDown   bool
	BudgetStopped    bool
	ReserveStopped   bool
	BudgetPaused     bool
	ExtendBudget     func()
}

func NewAgentCoordinator() *AgentCoordinator {
	return &AgentCoordinator{
		Statuses:         make(map[string]Status),
		ParentOf:         make(map[string]*string),
		Names:            make(map[string]string),
		Metadata:         make(map[string]map[string]interface{}),
		PendingCounts:    make(map[string]int),
		Errors:           make(map[string]string),
		RecoveryCounts:   make(map[string]int),
		IdleResumeCounts: make(map[string]int),
		WaitKinds:        make(map[string]WaitKind),
		Runtimes:         make(map[string]*AgentRuntime),
		ParentNotified:   make(map[string]bool),
	}
}

func (c *AgentCoordinator) SetSnapshotPath(path string) {
	c.SnapshotPath = &path
}

func (c *AgentCoordinator) MarkShuttingDown() {
	c.IsShuttingDown = true
}

func (c *AgentCoordinator) TriggerBudgetStop() error {
	c.Lock.Lock()
	defer c.Lock.Unlock()
	c.BudgetStopped = true
	for _, runtime := range c.Runtimes {
		select {
		case runtime.Wake <- struct{}{}:
		default:
		}
	}
	return nil
}

func (c *AgentCoordinator) SetBudgetExtender(extend func()) {
	c.ExtendBudget = extend
}

func (c *AgentCoordinator) PauseForBudget(agentID string) error {
	c.Lock.Lock()
	c.BudgetPaused = true
	c.Lock.Unlock()
	return c.SetStatus(agentID, StatusBudgetPaused, nil)
}

func (c *AgentCoordinator) ResumeFromBudgetPause(exclude *string) error {
	c.Lock.Lock()
	if !c.BudgetPaused {
		c.Lock.Unlock()
		return nil
	}
	c.BudgetPaused = false
	var paused []string
	for aid, status := range c.Statuses {
		if status == StatusBudgetPaused {
			paused = append(paused, aid)
		}
	}
	c.Lock.Unlock()

	if c.ExtendBudget != nil {
		c.ExtendBudget()
	}

	for _, aid := range paused {
		c.SetStatus(aid, StatusRunning, nil)
		if exclude == nil || aid != *exclude {
			c.Send(aid, map[string]interface{}{
				"from":    "system",
				"type":    "budget_extended",
				"content": "[Budget] The user extended the scan budget — continue your current task.",
			}, true)
		}
	}
	return nil
}

func (c *AgentCoordinator) ResetBudgetStops(budgetStopped bool, reserveStopped bool, budgetPaused bool) error {
	c.Lock.Lock()
	c.BudgetStopped = budgetStopped
	c.ReserveStopped = reserveStopped
	c.BudgetPaused = budgetPaused
	if !budgetPaused {
		c.BudgetPaused = false
		for aid, status := range c.Statuses {
			if status == StatusBudgetPaused {
				c.Statuses[aid] = StatusWaiting
			}
		}
	}
	if budgetStopped || reserveStopped || !budgetPaused {
		fmt.Printf("ResetBudgetStops waking up %d runtimes\n", len(c.Runtimes))
		for id, runtime := range c.Runtimes {
			select {
			case runtime.Wake <- struct{}{}:
				fmt.Printf("Woke up %s\n", id)
			default:
				fmt.Printf("Failed to wake up %s\n", id)
			}
		}
	}
	c.Lock.Unlock()
	return c.MaybeSnapshot()
}

func (c *AgentCoordinator) ClaimReserveNotification() (*string, error) {
	c.Lock.Lock()
	defer c.Lock.Unlock()
	if c.ReserveStopped {
		return nil, nil
	}
	c.ReserveStopped = true
	for _, runtime := range c.Runtimes {
		select {
		case runtime.Wake <- struct{}{}:
		default:
		}
	}
	for aid, parent := range c.ParentOf {
		if parent == nil {
			return &aid, nil
		}
	}
	return nil, nil
}

func (c *AgentCoordinator) Register(agentID string, name string, parentID *string, task string, skills []string) error {
	c.Lock.Lock()
	c.Statuses[agentID] = StatusRunning
	c.ParentOf[agentID] = parentID
	c.Names[agentID] = name
	c.PendingCounts[agentID] = 0

	if skills == nil {
		skills = []string{}
	}
	c.Metadata[agentID] = map[string]interface{}{
		"task":   task,
		"skills": skills,
	}
	if _, ok := c.Runtimes[agentID]; !ok {
		c.Runtimes[agentID] = NewAgentRuntime()
	}
	c.Lock.Unlock()

	parentStr := "-"
	if parentID != nil {
		parentStr = *parentID
	}
	agentsLogger.Printf("agent.register %s (%s) parent=%s", agentID, name, parentStr)
	return c.MaybeSnapshot()
}

func (c *AgentCoordinator) AttachRuntime(agentID string, session *SQLiteSession, task context.CancelFunc, interruptOnMessage *bool) error {
	c.Lock.Lock()
	defer c.Lock.Unlock()
	runtime, ok := c.Runtimes[agentID]
	if !ok {
		runtime = NewAgentRuntime()
		c.Runtimes[agentID] = runtime
	}
	if session != nil {
		runtime.Session = session
	}
	if task != nil {
		runtime.Task = task
	}
	if interruptOnMessage != nil {
		runtime.InterruptOnMessage = *interruptOnMessage
	}
	return nil
}

func (c *AgentCoordinator) MarkRunning(agentID string) error {
	c.Lock.Lock()
	if _, ok := c.Statuses[agentID]; ok {
		c.Statuses[agentID] = StatusRunning
		delete(c.Errors, agentID)
		delete(c.WaitKinds, agentID)
		if rt, exists := c.Runtimes[agentID]; exists {
			rt.UserWakeRequired = false
		} else {
			rt = NewAgentRuntime()
			rt.UserWakeRequired = false
			c.Runtimes[agentID] = rt
		}
		delete(c.ParentNotified, agentID)
	}
	c.Lock.Unlock()
	return c.MaybeSnapshot()
}

func (c *AgentCoordinator) ParkWaiting(agentID string, waitKind WaitKind) error {
	c.Lock.Lock()
	if _, ok := c.Statuses[agentID]; ok {
		c.WaitKinds[agentID] = waitKind
	}
	c.Lock.Unlock()
	return c.SetStatus(agentID, StatusWaiting, nil)
}

func (c *AgentCoordinator) WaitKindOf(agentID string) (*WaitKind, error) {
	c.Lock.Lock()
	defer c.Lock.Unlock()
	if wk, ok := c.WaitKinds[agentID]; ok {
		return &wk, nil
	}
	return nil, nil
}

func (c *AgentCoordinator) RecordRecovery(agentID string) (int, error) {
	c.Lock.Lock()
	count := c.RecoveryCounts[agentID] + 1
	c.RecoveryCounts[agentID] = count
	c.Lock.Unlock()
	c.MaybeSnapshot()
	return count, nil
}

func (c *AgentCoordinator) ResetRecovery(agentID string) error {
	c.Lock.Lock()
	_, ok := c.RecoveryCounts[agentID]
	if ok {
		delete(c.RecoveryCounts, agentID)
	}
	c.Lock.Unlock()
	if ok {
		return c.MaybeSnapshot()
	}
	return nil
}

func (c *AgentCoordinator) RecordIdleResume(agentID string) (int, error) {
	c.Lock.Lock()
	count := c.IdleResumeCounts[agentID] + 1
	c.IdleResumeCounts[agentID] = count
	c.Lock.Unlock()
	c.MaybeSnapshot()
	return count, nil
}

func (c *AgentCoordinator) ResetIdleResumes(agentID string) error {
	c.Lock.Lock()
	_, ok := c.IdleResumeCounts[agentID]
	if ok {
		delete(c.IdleResumeCounts, agentID)
	}
	c.Lock.Unlock()
	if ok {
		return c.MaybeSnapshot()
	}
	return nil
}

func (c *AgentCoordinator) SetStatus(agentID string, status Status, errorStr *string) error {
	c.Lock.Lock()
	if _, ok := c.Statuses[agentID]; !ok {
		c.Lock.Unlock()
		return nil
	}
	c.Statuses[agentID] = status
	if errorStr != nil {
		c.Errors[agentID] = *errorStr
	} else if status == StatusRunning {
		delete(c.Errors, agentID)
	}
	if status == StatusRunning {
		delete(c.ParentNotified, agentID)
	}
	runtime, ok := c.Runtimes[agentID]
	if !ok {
		runtime = NewAgentRuntime()
		c.Runtimes[agentID] = runtime
	}
	runtime.UserWakeRequired = (status == StatusFailed || status == StatusCrashed)
	select {
	case runtime.Wake <- struct{}{}:
	default:
	}
	c.Lock.Unlock()
	agentsLogger.Printf("agent.status %s=%s", agentID, status)
	return c.MaybeSnapshot()
}

func (c *AgentCoordinator) ClaimParentNotice(agentID string) (bool, error) {
	c.Lock.Lock()
	defer c.Lock.Unlock()
	if c.ParentNotified[agentID] {
		return false, nil
	}
	c.ParentNotified[agentID] = true
	return true, nil
}

func (c *AgentCoordinator) Send(targetAgentID string, message map[string]interface{}, interrupt bool) (bool, error) {
	fromUser := false
	if from, ok := message["from"].(string); ok && from == "user" {
		fromUser = true
	}
	if fromUser && c.BudgetPaused {
		c.ResumeFromBudgetPause(&targetAgentID)
	}
	c.Lock.Lock()
	if _, ok := c.Statuses[targetAgentID]; !ok {
		c.Lock.Unlock()
		agentsLogger.Printf("agent.send dropped unknown target=%s", targetAgentID)
		return false, nil
	}
	runtime, ok := c.Runtimes[targetAgentID]
	if !ok {
		runtime = NewAgentRuntime()
		c.Runtimes[targetAgentID] = runtime
	}

	msgCopy := make(map[string]interface{})
	for k, v := range message {
		msgCopy[k] = v
	}
	runtime.Mailbox = append(runtime.Mailbox, msgCopy)
	c.PendingCounts[targetAgentID]++
	if fromUser {
		runtime.UserWakeRequired = false
	}
	select {
	case runtime.Wake <- struct{}{}:
	default:
	}
	// stream := runtime.Stream
	// interruptOnMessage := runtime.InterruptOnMessage
	c.Lock.Unlock()

	// if stream != nil && interrupt && interruptOnMessage {
	// 	// Cancel stream (stubbed out here as stream object is dynamic)
	// }

	c.MaybeSnapshot()
	return true, nil
}

func (c *AgentCoordinator) WaitForMessage(agentID string, timeout *time.Duration) (bool, error) {
	for {
		c.Lock.Lock()
		runtime, ok := c.Runtimes[agentID]
		if !ok {
			runtime = NewAgentRuntime()
			c.Runtimes[agentID] = runtime
		}
		parent, hasParent := c.ParentOf[agentID]
		reserveExit := c.ReserveStopped && hasParent && parent != nil
		pendingReady := c.PendingCounts[agentID] > 0 && !runtime.UserWakeRequired

		if c.BudgetStopped || reserveExit || pendingReady {
			c.Lock.Unlock()
			return true, nil
		}

		// Clear wake channel
		select {
		case <-runtime.Wake:
		default:
		}
		wake := runtime.Wake
		c.Lock.Unlock()

		if timeout == nil {
			<-wake
		} else {
			select {
			case <-wake:
			case <-time.After(*timeout):
				return false, nil
			}
		}
	}
}

func (c *AgentCoordinator) ConsumePending(agentID string, includeItems bool) (int, []interface{}, error) {
	c.Lock.Lock()
	runtime, ok := c.Runtimes[agentID]
	if !ok {
		runtime = NewAgentRuntime()
		c.Runtimes[agentID] = runtime
	}
	queued := make([]map[string]interface{}, len(runtime.Mailbox))
	copy(queued, runtime.Mailbox)
	runtime.Mailbox = make([]map[string]interface{}, 0)

	count := c.PendingCounts[agentID]
	if len(queued) > count {
		count = len(queued)
	}
	c.PendingCounts[agentID] = 0
	session := runtime.Session
	c.Lock.Unlock()

	if count <= 0 {
		return 0, nil, nil
	}

	var items []interface{}
	for _, m := range queued {
		items = append(items, c.messageToSessionItem(m))
	}

	if len(items) > 0 {
		if session == nil {
			agentsLogger.Printf("agent %s has no SDK session attached; %d queued messages were not persisted", agentID, len(items))
		} else {
			// Write to session
			// ... (stub for sessionWriteLock and AddItems)
		}
	}

	c.MaybeSnapshot()
	if !includeItems {
		return count, nil, nil
	}
	return count, items, nil
}

func (c *AgentCoordinator) RequestStop(agentID string) error {
	c.Lock.Lock()
	if _, ok := c.Statuses[agentID]; !ok {
		c.Lock.Unlock()
		return nil
	}
	c.Statuses[agentID] = StatusStopped
	runtime, ok := c.Runtimes[agentID]
	if !ok {
		runtime = NewAgentRuntime()
		c.Runtimes[agentID] = runtime
	}
	select {
	case runtime.Wake <- struct{}{}:
	default:
	}
	// stream := runtime.Stream
	c.Lock.Unlock()
	// if stream != nil { stream.cancel() }
	return c.MaybeSnapshot()
}

func (c *AgentCoordinator) CancelDescendants(agentID string) error {
	c.Lock.Lock()
	order := c.subtreeOrderLocked(agentID)
	var funcs []context.CancelFunc
	for i := len(order) - 1; i >= 0; i-- {
		aid := order[i]
		if rt, ok := c.Runtimes[aid]; ok && rt.Task != nil {
			funcs = append(funcs, rt.Task)
		}
	}
	c.Lock.Unlock()
	for _, f := range funcs {
		f()
	}
	return nil
}

func (c *AgentCoordinator) AttachStream(agentID string, stream interface{}) error {
	c.Lock.Lock()
	defer c.Lock.Unlock()
	if rt, ok := c.Runtimes[agentID]; ok {
		rt.Stream = stream
	} else {
		rt = NewAgentRuntime()
		rt.Stream = stream
		c.Runtimes[agentID] = rt
	}
	return nil
}

func (c *AgentCoordinator) DetachStream(agentID string, stream interface{}) error {
	c.Lock.Lock()
	defer c.Lock.Unlock()
	if rt, ok := c.Runtimes[agentID]; ok && rt.Stream == stream {
		rt.Stream = nil
	}
	return nil
}

func (c *AgentCoordinator) Snapshot() (map[string]interface{}, error) {
	c.Lock.Lock()
	defer c.Lock.Unlock()

	statuses := make(map[string]interface{})
	for k, v := range c.Statuses {
		statuses[k] = string(v)
	}

	parentOf := make(map[string]interface{})
	for k, v := range c.ParentOf {
		if v != nil {
			parentOf[k] = *v
		} else {
			parentOf[k] = nil
		}
	}

	names := make(map[string]interface{})
	for k, v := range c.Names {
		names[k] = v
	}

	metadata := make(map[string]interface{})
	for k, v := range c.Metadata {
		m := make(map[string]interface{})
		for mk, mv := range v {
			m[mk] = mv
		}
		metadata[k] = m
	}

	pendingCounts := make(map[string]interface{})
	for k, v := range c.PendingCounts {
		pendingCounts[k] = v
	}

	recoveryCounts := make(map[string]interface{})
	for k, v := range c.RecoveryCounts {
		recoveryCounts[k] = v
	}

	idleResumeCounts := make(map[string]interface{})
	for k, v := range c.IdleResumeCounts {
		idleResumeCounts[k] = v
	}

	waitKinds := make(map[string]interface{})
	for k, v := range c.WaitKinds {
		waitKinds[k] = string(v)
	}

	mailboxes := make(map[string]interface{})
	for aid, rt := range c.Runtimes {
		if len(rt.Mailbox) > 0 {
			var mbs []interface{}
			for _, mb := range rt.Mailbox {
				m := make(map[string]interface{})
				for k, v := range mb {
					m[k] = v
				}
				mbs = append(mbs, m)
			}
			mailboxes[aid] = mbs
		}
	}

	errors := make(map[string]interface{})
	for k, v := range c.Errors {
		errors[k] = v
	}

	return map[string]interface{}{
		"statuses":           statuses,
		"parent_of":          parentOf,
		"names":              names,
		"metadata":           metadata,
		"pending_counts":     pendingCounts,
		"recovery_counts":    recoveryCounts,
		"idle_resume_counts": idleResumeCounts,
		"wait_kinds":         waitKinds,
		"mailboxes":          mailboxes,
		"errors":             errors,
		"budget_stopped":     c.BudgetStopped,
		"reserve_stopped":    c.ReserveStopped,
		"budget_paused":      c.BudgetPaused,
	}, nil
}

func (c *AgentCoordinator) Restore(snap map[string]interface{}) error {
	c.Lock.Lock()
	defer c.Lock.Unlock()

	if statuses, ok := snap["statuses"].(map[string]interface{}); ok {
		for k, v := range statuses {
			c.Statuses[k] = Status(v.(string))
		}
	}
	if parentOf, ok := snap["parent_of"].(map[string]interface{}); ok {
		for k, v := range parentOf {
			if v != nil {
				s := v.(string)
				c.ParentOf[k] = &s
			} else {
				c.ParentOf[k] = nil
			}
		}
	}
	if names, ok := snap["names"].(map[string]interface{}); ok {
		for k, v := range names {
			c.Names[k] = v.(string)
		}
	}
	if metadata, ok := snap["metadata"].(map[string]interface{}); ok {
		for k, v := range metadata {
			m := v.(map[string]interface{})
			newM := make(map[string]interface{})
			for mk, mv := range m {
				newM[mk] = mv
			}
			c.Metadata[k] = newM
		}
	}
	if pendingCounts, ok := snap["pending_counts"].(map[string]interface{}); ok {
		for k, v := range pendingCounts {
			switch val := v.(type) {
			case float64:
				c.PendingCounts[k] = int(val)
			case int:
				c.PendingCounts[k] = val
			}
		}
	}
	if errors, ok := snap["errors"].(map[string]interface{}); ok {
		for k, v := range errors {
			c.Errors[k] = v.(string)
		}
	}
	if recoveryCounts, ok := snap["recovery_counts"].(map[string]interface{}); ok {
		for k, v := range recoveryCounts {
			switch val := v.(type) {
			case float64:
				c.RecoveryCounts[k] = int(val)
			case int:
				c.RecoveryCounts[k] = val
			}
		}
	}
	if idleResumeCounts, ok := snap["idle_resume_counts"].(map[string]interface{}); ok {
		for k, v := range idleResumeCounts {
			switch val := v.(type) {
			case float64:
				c.IdleResumeCounts[k] = int(val)
			case int:
				c.IdleResumeCounts[k] = val
			}
		}
	}
	if waitKinds, ok := snap["wait_kinds"].(map[string]interface{}); ok {
		for k, v := range waitKinds {
			c.WaitKinds[k] = WaitKind(v.(string))
		}
	}
	if mailboxes, ok := snap["mailboxes"].(map[string]interface{}); ok {
		for aid, msgs := range mailboxes {
			if msgsList, ok := msgs.([]interface{}); ok {
				rt, exists := c.Runtimes[aid]
				if !exists {
					rt = NewAgentRuntime()
					c.Runtimes[aid] = rt
				}
				for _, mb := range msgsList {
					if m, ok := mb.(map[string]interface{}); ok {
						newM := make(map[string]interface{})
						for k, v := range m {
							newM[k] = v
						}
						rt.Mailbox = append(rt.Mailbox, newM)
					}
				}
			}
		}
	}

	if val, ok := snap["budget_stopped"].(bool); ok {
		c.BudgetStopped = val
	}
	if val, ok := snap["reserve_stopped"].(bool); ok {
		c.ReserveStopped = val
	}
	if val, ok := snap["budget_paused"].(bool); ok {
		c.BudgetPaused = val
	}

	for aid := range c.Statuses {
		if _, exists := c.Runtimes[aid]; !exists {
			c.Runtimes[aid] = NewAgentRuntime()
		}
	}
	return nil
}

func (c *AgentCoordinator) MaybeSnapshot() error {
	if c.SnapshotPath == nil {
		return nil
	}
	data, err := c.Snapshot()
	if err != nil {
		return err
	}

	b, err := json.Marshal(data)
	if err != nil {
		return err
	}

	path := *c.SnapshotPath
	dir := filepath.Dir(path)
	os.MkdirAll(dir, 0755)

	tmpFile, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(b); err != nil {
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}

	return os.Rename(tmpFile.Name(), path)
}

func (c *AgentCoordinator) messageToSessionItem(message map[string]interface{}) map[string]interface{} {
	sender := "unknown"
	if s, ok := message["from"].(string); ok {
		sender = s
	}
	content := ""
	if s, ok := message["content"].(string); ok {
		content = s
	}

	if sender == "user" {
		return map[string]interface{}{"role": "user", "content": content}
	}

	senderName := sender
	if name, ok := c.Names[sender]; ok {
		senderName = name
	}
	msgType := "information"
	if t, ok := message["type"].(string); ok {
		msgType = t
	}
	priority := "normal"
	if p, ok := message["priority"].(string); ok {
		priority = p
	}

	return map[string]interface{}{
		"role":    "user",
		"content": fmt.Sprintf("[Message from %s (%s) | type=%s | priority=%s]\n%s", senderName, sender, msgType, priority, content),
	}
}

func (c *AgentCoordinator) subtreeOrderLocked(agentID string) []string {
	queue := []string{agentID}
	var order []string

	for len(queue) > 0 {
		aid := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		order = append(order, aid)

		for child, parent := range c.ParentOf {
			if parent != nil && *parent == aid {
				queue = append(queue, child)
			}
		}
	}
	return order
}
