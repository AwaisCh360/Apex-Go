package notes

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// RunContextWrapper is a stub for the agent context wrapper.
type RunContextWrapper struct {
	Context map[string]any
}

var (
	notesStorage               = make(map[string]map[string]any)
	validNoteCategories        = []string{"general", "findings", "methodology", "questions", "plan", "wiki"}
	notesLock                  sync.RWMutex
	defaultContentPreviewChars = 280
	noteIDGenerationAttempts   = 1024
	notesPath                  *string
)

func callerIdentity(ctx RunContextWrapper) (agentID *string, agentName *string) {
	inner := ctx.Context
	if inner == nil {
		return nil, nil
	}

	rawAgentID, ok := inner["agent_id"]
	if ok {
		if idStr, ok := rawAgentID.(string); ok {
			agentID = &idStr
		}
	}

	coordinator, ok := inner["coordinator"]
	if agentID != nil && ok && coordinator != nil {
		if coordMap, ok := coordinator.(map[string]any); ok {
			if namesMap, ok := coordMap["names"].(map[string]any); ok {
				if name, ok := namesMap[*agentID].(string); ok {
					agentName = &name
				}
			}
		} else if coord, ok := coordinator.(interface{ Names() map[string]string }); ok {
			names := coord.Names()
			if name, exists := names[*agentID]; exists {
				agentName = &name
			}
		}
	}

	return agentID, agentName
}

func generateNoteID() *string {
	for i := 0; i < noteIDGenerationAttempts; i++ {
		bytes := make([]byte, 3) // 6 hex chars
		_, _ = rand.Read(bytes)
		id := hex.EncodeToString(bytes)
		if _, exists := notesStorage[id]; !exists {
			return &id
		}
	}
	return nil
}

// HydrateNotesFromDisk loads notes from the state directory.
func HydrateNotesFromDisk(stateDir string) {
	path := filepath.Join(stateDir, "notes.json")

	notesLock.Lock()
	defer notesLock.Unlock()

	notesPath = &path
	notesStorage = make(map[string]map[string]any)

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return
	}

	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("notes.json at %s is unreadable; starting with empty notes: %v\n", path, err)
		return
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		log.Printf("notes.json at %s is unreadable; starting with empty notes: %v\n", path, err)
		return
	}

	for nid, noteAny := range parsed {
		if note, ok := noteAny.(map[string]any); ok {
			notesStorage[nid] = note
		}
	}
	log.Printf("notes hydrated from %s (%d note(s))\n", path, len(notesStorage))
}

func persistLocked() {
	if notesPath == nil {
		return
	}
	path := *notesPath

	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(notesStorage); err != nil {
		log.Printf("notes persist to %s failed: %v", path, err)
		return
	}
	data := []byte(buf.String())

	dir := filepath.Dir(path)
	_ = os.MkdirAll(dir, 0755)

	tmpFile, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		log.Printf("notes persist to %s failed: %v", path, err)
		return
	}
	tmpName := tmpFile.Name()

	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		log.Printf("notes persist to %s failed: %v", path, err)
		return
	}
	tmpFile.Close()

	if err := os.Rename(tmpName, path); err != nil {
		log.Printf("notes persist to %s failed: %v", path, err)
	}
}

func filterNotes(category *string, tags []string, searchQuery *string) []map[string]any {
	filtered := []map[string]any{}
	for noteID, note := range notesStorage {
		if category != nil {
			if noteCat, ok := note["category"].(string); !ok || noteCat != *category {
				continue
			}
		}
		if len(tags) > 0 {
			hasTag := false
			if noteTagsAny, ok := note["tags"].([]any); ok {
				for _, ntAny := range noteTagsAny {
					if nt, ok := ntAny.(string); ok {
						for _, t := range tags {
							if nt == t {
								hasTag = true
								break
							}
						}
					}
					if hasTag {
						break
					}
				}
			} else if noteTagsStr, ok := note["tags"].([]string); ok {
				for _, nt := range noteTagsStr {
					for _, t := range tags {
						if nt == t {
							hasTag = true
							break
						}
					}
					if hasTag {
						break
					}
				}
			}
			if !hasTag {
				continue
			}
		}
		if searchQuery != nil && *searchQuery != "" {
			searchLower := strings.ToLower(*searchQuery)
			titleMatch := false
			if title, ok := note["title"].(string); ok {
				titleMatch = strings.Contains(strings.ToLower(title), searchLower)
			}
			contentMatch := false
			if content, ok := note["content"].(string); ok {
				contentMatch = strings.Contains(strings.ToLower(content), searchLower)
			}
			if !titleMatch && !contentMatch {
				continue
			}
		}

		entry := make(map[string]any)
		for k, v := range note {
			entry[k] = v
		}
		entry["note_id"] = noteID
		filtered = append(filtered, entry)
	}

	sort.Slice(filtered, func(i, j int) bool {
		sI, _ := filtered[i]["created_at"].(string)
		sJ, _ := filtered[j]["created_at"].(string)
		return sI > sJ
	})

	return filtered
}

func markAuthorship(entry map[string]any, note map[string]any, callerAgentID *string) map[string]any {
	if agentName, ok := note["agent_name"].(string); ok && agentName != "" {
		entry["agent_name"] = agentName
	}
	if agentID, ok := note["agent_id"].(string); ok && agentID != "" {
		entry["agent_id"] = agentID
		if callerAgentID != nil && agentID == *callerAgentID {
			entry["by_you"] = true
		}
	}
	return entry
}

func toNoteListingEntry(note map[string]any, includeContent bool, callerAgentID *string) map[string]any {
	entry := map[string]any{
		"note_id":    note["note_id"],
		"title":      "",
		"category":   "general",
		"tags":       []string{},
		"created_at": "",
		"updated_at": "",
	}
	if t, ok := note["title"].(string); ok {
		entry["title"] = t
	}
	if c, ok := note["category"].(string); ok {
		entry["category"] = c
	}
	if tsAny, ok := note["tags"].([]any); ok {
		ts := make([]string, 0, len(tsAny))
		for _, t := range tsAny {
			if s, ok := t.(string); ok {
				ts = append(ts, s)
			}
		}
		entry["tags"] = ts
	} else if ts, ok := note["tags"].([]string); ok {
		entry["tags"] = ts
	}
	if ca, ok := note["created_at"].(string); ok {
		entry["created_at"] = ca
	}
	if ua, ok := note["updated_at"].(string); ok {
		entry["updated_at"] = ua
	}

	content := ""
	if c, ok := note["content"].(string); ok {
		content = c
	}

	if includeContent {
		entry["content"] = content
	} else if content != "" {
		if len(content) > defaultContentPreviewChars {
			entry["content_preview"] = strings.TrimRight(content[:defaultContentPreviewChars], " \t\n\r") + "..."
		} else {
			entry["content_preview"] = content
		}
	}

	return markAuthorship(entry, note, callerAgentID)
}

func isValidCategory(c string) bool {
	for _, v := range validNoteCategories {
		if v == c {
			return true
		}
	}
	return false
}

func toJSONStr(v any) (string, error) {
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return strings.TrimSpace(buf.String()), nil
}

// CreateNote documents an observation, finding, methodology step, or research note.
func CreateNote(ctx RunContextWrapper, title string, content string, category string, tags []string) (string, error) {
	if category == "" {
		category = "general"
	}
	agentID, agentName := callerIdentity(ctx)

	notesLock.Lock()
	defer notesLock.Unlock()

	var result map[string]any
	title = strings.TrimSpace(title)
	content = strings.TrimSpace(content)

	if title == "" {
		result = map[string]any{"success": false, "error": "Title cannot be empty", "note_id": nil}
		return toJSONStr(result)
	}
	if content == "" {
		result = map[string]any{"success": false, "error": "Content cannot be empty", "note_id": nil}
		return toJSONStr(result)
	}
	if !isValidCategory(category) {
		result = map[string]any{
			"success": false,
			"error":   fmt.Sprintf("Invalid category. Must be one of: %s", strings.Join(validNoteCategories, ", ")),
			"note_id": nil,
		}
		return toJSONStr(result)
	}

	noteID := generateNoteID()
	if noteID == nil {
		result = map[string]any{"success": false, "error": "Failed to generate a unique note ID", "note_id": nil}
		return toJSONStr(result)
	}

	timestamp := time.Now().UTC().Format("2006-01-02T15:04:05.000000+00:00")

	note := map[string]any{
		"title":      title,
		"content":    content,
		"category":   category,
		"tags":       tags,
		"created_at": timestamp,
		"updated_at": timestamp,
	}
	if tags == nil {
		note["tags"] = []string{}
	}
	if agentID != nil {
		note["agent_id"] = *agentID
	}
	if agentName != nil {
		note["agent_name"] = *agentName
	}

	notesStorage[*noteID] = note
	persistLocked()

	result = map[string]any{
		"success":     true,
		"note_id":     *noteID,
		"message":     fmt.Sprintf("Note '%s' created successfully", title),
		"total_count": len(notesStorage),
	}
	return toJSONStr(result)
}

// ListNotes lists existing notes — metadata-first by default.
func ListNotes(ctx RunContextWrapper, category *string, tags []string, search *string, includeContent bool) (string, error) {
	callerAgentID, _ := callerIdentity(ctx)

	notesLock.RLock()
	defer notesLock.RUnlock()

	filtered := filterNotes(category, tags, search)
	notes := make([]map[string]any, 0, len(filtered))
	for _, n := range filtered {
		notes = append(notes, toNoteListingEntry(n, includeContent, callerAgentID))
	}

	result := map[string]any{
		"success":        true,
		"notes":          notes,
		"filtered_count": len(notes),
		"total_count":    len(notesStorage),
	}
	return toJSONStr(result)
}

// GetNote fetches one note by its 6-char ID. Returns the full content.
func GetNote(ctx RunContextWrapper, noteID string) (string, error) {
	callerAgentID, _ := callerIdentity(ctx)

	notesLock.RLock()
	defer notesLock.RUnlock()

	noteID = strings.TrimSpace(noteID)
	if noteID == "" {
		result := map[string]any{"success": false, "error": "Note ID cannot be empty", "note": nil}
		return toJSONStr(result)
	}

	note, exists := notesStorage[noteID]
	if !exists {
		result := map[string]any{"success": false, "error": fmt.Sprintf("Note with ID '%s' not found", noteID), "note": nil}
		return toJSONStr(result)
	}

	noteWithID := make(map[string]any)
	for k, v := range note {
		noteWithID[k] = v
	}
	noteWithID["note_id"] = noteID
	markAuthorship(noteWithID, note, callerAgentID)

	result := map[string]any{"success": true, "note": noteWithID}
	return toJSONStr(result)
}

// UpdateNote updates a note's title, content, or tags.
// A nil pointer for title, content, or tags means it is left unchanged.
func UpdateNote(ctx RunContextWrapper, noteID string, title *string, content *string, tags []string) (string, error) {
	notesLock.Lock()
	defer notesLock.Unlock()

	note, exists := notesStorage[noteID]
	if !exists {
		result := map[string]any{"success": false, "error": fmt.Sprintf("Note with ID '%s' not found", noteID)}
		return toJSONStr(result)
	}

	if title != nil {
		t := strings.TrimSpace(*title)
		if t == "" {
			result := map[string]any{"success": false, "error": "Title cannot be empty"}
			return toJSONStr(result)
		}
		note["title"] = t
	}
	if content != nil {
		c := strings.TrimSpace(*content)
		if c == "" {
			result := map[string]any{"success": false, "error": "Content cannot be empty"}
			return toJSONStr(result)
		}
		note["content"] = c
	}
	if tags != nil {
		note["tags"] = tags
	}
	note["updated_at"] = time.Now().UTC().Format("2006-01-02T15:04:05.000000+00:00")

	persistLocked()

	noteTitle, _ := note["title"].(string)
	result := map[string]any{
		"success":     true,
		"note_id":     noteID,
		"message":     fmt.Sprintf("Note '%s' updated successfully", noteTitle),
		"total_count": len(notesStorage),
	}
	return toJSONStr(result)
}

// DeleteNote deletes a note.
func DeleteNote(ctx RunContextWrapper, noteID string) (string, error) {
	notesLock.Lock()
	defer notesLock.Unlock()

	note, exists := notesStorage[noteID]
	if !exists {
		result := map[string]any{"success": false, "error": fmt.Sprintf("Note with ID '%s' not found", noteID)}
		return toJSONStr(result)
	}

	noteTitle, _ := note["title"].(string)
	delete(notesStorage, noteID)

	persistLocked()

	result := map[string]any{
		"success":     true,
		"note_id":     noteID,
		"message":     fmt.Sprintf("Note '%s' deleted successfully", noteTitle),
		"total_count": len(notesStorage),
	}
	return toJSONStr(result)
}
