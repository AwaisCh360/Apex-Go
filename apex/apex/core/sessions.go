package core

import (
	"log"
	"os"
	"path/filepath"
	"sync"
)

var sessionsLogger = log.New(os.Stderr, "[sessions] ", log.LstdFlags)

// Mocks for internal agents SDK (agents.memory, agents.items)
type Session interface {
	GetItems() ([]interface{}, error)
	AddItems([]interface{}) error
	ClearSession() error
}

type SQLiteSession struct {
	SessionID string
	DBPath    string
	Mu        sync.Mutex
}

func (s *SQLiteSession) Lock()   { s.Mu.Lock() }
func (s *SQLiteSession) Unlock() { s.Mu.Unlock() }

func (s *SQLiteSession) GetItems() ([]interface{}, error) { return nil, nil }
func (s *SQLiteSession) AddItems([]interface{}) error     { return nil }
func (s *SQLiteSession) ClearSession() error              { return nil }

type ItemHelpers struct{}

func (h *ItemHelpers) InputToNewInputList(initialInput interface{}) []interface{} {
	// Stub
	return nil
}

func OpenAgentSession(agentID string, path string) *SQLiteSession {
	os.MkdirAll(filepath.Dir(path), 0755)
	return &SQLiteSession{
		SessionID: agentID,
		DBPath:    path,
	}
}

func sessionWriteLock(session Session) func() {
	if locker, ok := session.(interface {
		Lock()
		Unlock()
	}); ok {
		locker.Lock()
		return locker.Unlock
	}
	// Fallback for mock/stub Sessions that do not implement Lock()/Unlock()
	// This prevents crashing, though in practice all real sessions will be SQLiteSession.
	mu := &sync.Mutex{}
	mu.Lock()
	return mu.Unlock
}

func SeedInitialInput(session Session, initialInput interface{}) bool {
	h := &ItemHelpers{}
	items := h.InputToNewInputList(initialInput)
	if len(items) == 0 {
		return false
	}
	unlock := sessionWriteLock(session)
	defer unlock()

	existing, _ := session.GetItems()
	if len(existing) > 0 {
		return false
	}
	session.AddItems(items)
	return true
}

const (
	ImageRejectedText  = "[image rejected by the model]"
	ImageElidedText    = "[older screenshot elided to bound context memory]"
	InheritedImageText = "[screenshot omitted from inherited context]"
)

func outputHasImage(itemDict map[string]interface{}) bool {
	if itemDict["type"] != "function_call_output" {
		return false
	}
	output, ok := itemDict["output"].([]interface{})
	if !ok {
		return false
	}
	for _, b := range output {
		if block, isDict := b.(map[string]interface{}); isDict && block["type"] == "input_image" {
			return true
		}
	}
	return false
}

func elidedOutput(itemDict map[string]interface{}, text string) map[string]interface{} {
	output, _ := itemDict["output"].([]interface{})
	var newOutput []interface{}
	for _, b := range output {
		if block, isDict := b.(map[string]interface{}); isDict && block["type"] == "input_image" {
			newOutput = append(newOutput, map[string]interface{}{
				"type": "input_text",
				"text": text,
			})
		} else {
			newOutput = append(newOutput, b)
		}
	}
	return map[string]interface{}{
		"type":    "function_call_output",
		"call_id": itemDict["call_id"],
		"output":  newOutput,
	}
}

func rewriteSession(session Session, transform func([]interface{}) ([]interface{}, bool)) (bool, error) {
	unlock := sessionWriteLock(session)
	defer unlock()

	items, _ := session.GetItems()
	if len(items) == 0 {
		return false, nil
	}
	rebuilt, changed := transform(items)
	if !changed {
		return false, nil
	}
	session.ClearSession()
	err := session.AddItems(rebuilt)
	if err != nil {
		sessionsLogger.Printf("session rewrite failed; restoring original items: %v", err)
		session.ClearSession()
		session.AddItems(items)
		return false, err
	}
	return true, nil
}

func ReplaceSessionItems(session Session, newItems []interface{}, expectedLen *int) (bool, error) {
	unlock := sessionWriteLock(session)
	defer unlock()

	original, _ := session.GetItems()
	if expectedLen != nil && len(original) != *expectedLen {
		sessionsLogger.Printf("skipping session rewrite: expected %d items, found %d", *expectedLen, len(original))
		return false, nil
	}
	session.ClearSession()
	err := session.AddItems(newItems)
	if err != nil {
		sessionsLogger.Printf("session rewrite failed; restoring original items: %v", err)
		session.ClearSession()
		session.AddItems(original)
		return false, err
	}
	return true, nil
}

func StripAllImagesFromSession(session Session) (bool, error) {
	return rewriteSession(session, func(items []interface{}) ([]interface{}, bool) {
		var rebuilt []interface{}
		changed := false
		for _, item := range items {
			if itemDict, isDict := item.(map[string]interface{}); isDict && outputHasImage(itemDict) {
				rebuilt = append(rebuilt, elidedOutput(itemDict, ImageRejectedText))
				changed = true
			} else {
				rebuilt = append(rebuilt, item)
			}
		}
		return rebuilt, changed
	})
}

func EnforceImageBudget(session Session, maxImages int) (bool, error) {
	if maxImages < 0 {
		return false, nil
	}
	return rewriteSession(session, func(items []interface{}) ([]interface{}, bool) {
		var imageIndices []int
		for i, item := range items {
			if itemDict, isDict := item.(map[string]interface{}); isDict && outputHasImage(itemDict) {
				imageIndices = append(imageIndices, i)
			}
		}
		if len(imageIndices) <= maxImages {
			return items, false
		}
		toElide := make(map[int]bool)
		for i := 0; i < len(imageIndices)-maxImages; i++ {
			toElide[imageIndices[i]] = true
		}
		var rebuilt []interface{}
		for i, item := range items {
			if toElide[i] {
				rebuilt = append(rebuilt, elidedOutput(item.(map[string]interface{}), ImageElidedText))
			} else {
				rebuilt = append(rebuilt, item)
			}
		}
		return rebuilt, true
	})
}

func ScrubImagesFromItems(items []interface{}) []interface{} {
	var scrub func(interface{}) interface{}
	scrub = func(obj interface{}) interface{} {
		if dict, isDict := obj.(map[string]interface{}); isDict {
			if dict["type"] == "input_image" {
				return map[string]interface{}{"type": "input_text", "text": InheritedImageText}
			}
			newDict := make(map[string]interface{})
			for k, v := range dict {
				newDict[k] = scrub(v)
			}
			return newDict
		}
		if list, isList := obj.([]interface{}); isList {
			var newList []interface{}
			for _, v := range list {
				newList = append(newList, scrub(v))
			}
			return newList
		}
		return obj
	}

	var res []interface{}
	for _, item := range items {
		res = append(res, scrub(item))
	}
	return res
}
