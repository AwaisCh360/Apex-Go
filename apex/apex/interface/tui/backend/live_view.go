package backend

import (
	"fmt"
	"sort"
)

const maxLiveEvents = 10000

type BaseLiveView interface {
	UpsertAgent(agentID string, name string, parentID string, status string, errorMessage string) bool
	IngestSDKEvent(agentID string, event any)
	SetUserInstruction(text *string, timestamp *string)
	FlushUserInstruction() bool
	HydrateFromRunDir(runDir string)
	RecordAgentError(agentID string, errorMsg string)
	RecordUserMessage(agentID string, content string)
	GetAgents() map[string]map[string]any
	GetEvents() []map[string]any
	SetEvents(events []map[string]any)
	CleanupEventReferences(eventID string)
}

// TuiLiveView adds protocol cursors and bounds on top of the shared projection state.
type TuiLiveView struct {
	BaseLiveView
	eventCursor       int
	eventChangeCursor map[string]int
	eventVersions     map[string]int
	eventsByID        map[string]map[string]any
}

func NewTuiLiveView(base BaseLiveView) *TuiLiveView {
	return &TuiLiveView{
		BaseLiveView:      base,
		eventCursor:       0,
		eventChangeCursor: make(map[string]int),
		eventVersions:     make(map[string]int),
		eventsByID:        make(map[string]map[string]any),
	}
}

// sync processes the underlying TuiLiveView Events to update the cursors and changes.
func (v *TuiLiveView) sync() {
	events := v.BaseLiveView.GetEvents()
	for len(events) > maxLiveEvents {
		removed := events[0]
		events = events[1:]
		if id, ok := removed["id"].(string); ok {
			delete(v.eventsByID, id)
			delete(v.eventChangeCursor, id)
			delete(v.eventVersions, id)
			v.BaseLiveView.CleanupEventReferences(id)
		}
	}

	v.BaseLiveView.SetEvents(events)

	for _, ev := range events {
		id, ok := ev["id"].(string)
		if !ok || id == "" {
			continue
		}

		currentVersion, _ := ev["version"].(int)
		lastVersion, exists := v.eventVersions[id]

		if !exists || currentVersion != lastVersion {
			v.eventsByID[id] = ev
			v.eventVersions[id] = currentVersion
			v.markEventChanged(ev)
		}
	}
}

func (v *TuiLiveView) markEventChanged(event map[string]any) {
	id, ok := event["id"].(string)
	if !ok || id == "" {
		return
	}
	v.eventCursor++
	v.eventChangeCursor[id] = v.eventCursor
}

func (v *TuiLiveView) EventSnapshot(limit *int) (int, []map[string]any) {
	events := v.BaseLiveView.GetEvents()
	if limit != nil && *limit > 0 && len(events) > *limit {
		events = events[len(events)-*limit:]
	}
	result := make([]map[string]any, len(events))
	copy(result, events)
	return v.eventCursor, result
}

type changeEntry struct {
	cursor int
	id     string
}

func (v *TuiLiveView) EventChangesSince(cursor int) (int, []map[string]any, error) {
	if cursor < 0 || cursor > v.eventCursor {
		return 0, nil, fmt.Errorf("event cursor is outside the available history")
	}

	var changedIDs []changeEntry
	for eventID, changeCursor := range v.eventChangeCursor {
		if changeCursor > cursor {
			changedIDs = append(changedIDs, changeEntry{cursor: changeCursor, id: eventID})
		}
	}

	sort.Slice(changedIDs, func(i, j int) bool {
		return changedIDs[i].cursor < changedIDs[j].cursor
	})

	var changed []map[string]any
	for _, entry := range changedIDs {
		if ev, ok := v.eventsByID[entry.id]; ok {
			changed = append(changed, ev)
		}
	}

	return v.eventCursor, changed, nil
}

// UpsertAgent overrides the base method to ensure it's exposed in the backend model.
func (v *TuiLiveView) UpsertAgent(agentID string, name string, parentID string, status string, errorMessage string) bool {
	return v.BaseLiveView.UpsertAgent(agentID, name, parentID, status, errorMessage)
}

// IngestSDKEvent parses SDK stream items and syncs changes into the event cursor.
func (v *TuiLiveView) IngestSDKEvent(agentID string, event any) {
	v.BaseLiveView.IngestSDKEvent(agentID, event)
	v.sync()
}

func (v *TuiLiveView) SetUserInstruction(text *string, timestamp *string) {
	v.BaseLiveView.SetUserInstruction(text, timestamp)
	v.sync()
}

func (v *TuiLiveView) FlushUserInstruction() bool {
	res := v.BaseLiveView.FlushUserInstruction()
	if res {
		v.sync()
	}
	return res
}

func (v *TuiLiveView) HydrateFromRunDir(runDir string) {
	v.BaseLiveView.HydrateFromRunDir(runDir)
	v.sync()
}

func (v *TuiLiveView) RecordAgentError(agentID string, errorMsg string) {
	v.BaseLiveView.RecordAgentError(agentID, errorMsg)
	v.sync()
}

func (v *TuiLiveView) RecordUserMessage(agentID string, content string) {
	v.BaseLiveView.RecordUserMessage(agentID, content)
	v.sync()
}
