package todo


import (
	"bytes"

	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// RunContextWrapper is a stub for the missing dependency
type RunContextWrapper struct {
	Context map[string]interface{}
	Usage   interface{}
}

var (
	validPriorities = map[string]bool{"low": true, "normal": true, "high": true, "critical": true}
	validStatuses   = map[string]bool{"pending": true, "in_progress": true, "done": true}

	priorityRank = map[string]int{"critical": 0, "high": 1, "normal": 2, "low": 3}
	statusRank   = map[string]int{"done": 0, "in_progress": 1, "pending": 2}

	todosStorage = make(map[string]map[string]map[string]interface{})
	todosPath    string
	todosIOLock  sync.Mutex
)

// HydrateTodosFromDisk reads todos from disk.
func HydrateTodosFromDisk(stateDir string) {
	todosIOLock.Lock()
	defer todosIOLock.Unlock()

	todosPath = filepath.Join(stateDir, "todos.json")
	todosStorage = make(map[string]map[string]map[string]interface{})

	data, err := os.ReadFile(todosPath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("todos.json at %s is unreadable; starting with empty todos: %v", todosPath, err)
		}
		return
	}

	var parsed map[string]map[string]map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		log.Printf("todos.json at %s is unreadable; starting with empty todos: %v", todosPath, err)
		return
	}

	loaded := 0
	for aid, byID := range parsed {
		cleaned := make(map[string]map[string]interface{})
		for tid, t := range byID {
			cleaned[tid] = t
		}
		if len(cleaned) > 0 {
			todosStorage[aid] = cleaned
			loaded += len(cleaned)
		}
	}
	log.Printf("todos hydrated from %s (%d agent(s), %d todo(s))", todosPath, len(todosStorage), loaded)
}

// persistLocked assumes todosIOLock is held.
func persistLocked() {
	if todosPath == "" {
		return
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	err := enc.Encode(todosStorage)
	payload := buf.Bytes()
	if err != nil {
		log.Printf("todos persist to %s failed: %v", todosPath, err)
		return
	}

	dir := filepath.Dir(todosPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Printf("todos persist to %s failed: %v", todosPath, err)
		return
	}

	tmpFile, err := os.CreateTemp(dir, fmt.Sprintf(".%s.*.tmp", filepath.Base(todosPath)))
	if err != nil {
		log.Printf("todos persist to %s failed: %v", todosPath, err)
		return
	}
	tmpName := tmpFile.Name()

	if _, err := tmpFile.Write(payload); err != nil {
		tmpFile.Close()
		os.Remove(tmpName)
		log.Printf("todos persist to %s failed: %v", todosPath, err)
		return
	}
	tmpFile.Close()

	if err := os.Rename(tmpName, todosPath); err != nil {
		os.Remove(tmpName)
		log.Printf("todos persist to %s failed: %v", todosPath, err)
	}
}

func agentIDFrom(ctx *RunContextWrapper) string {
	if ctx == nil || ctx.Context == nil {
		return "default"
	}
	if aid, ok := ctx.Context["agent_id"].(string); ok && aid != "" {
		return aid
	}
	return "default"
}

func getAgentTodos(agentID string) map[string]map[string]interface{} {
	if _, ok := todosStorage[agentID]; !ok {
		todosStorage[agentID] = make(map[string]map[string]interface{})
	}
	return todosStorage[agentID]
}

func normalizePriority(priority interface{}, def string) (string, error) {
	cand := def
	if pStr, ok := priority.(string); ok && pStr != "" {
		cand = strings.ToLower(pStr)
	}
	if !validPriorities[cand] {
		return "", fmt.Errorf("Invalid priority. Must be one of: low, normal, high, critical")
	}
	return cand, nil
}

func todoSortKey(t1, t2 map[string]interface{}) bool {
	s1 := 99
	if s, ok := t1["status"].(string); ok {
		if v, exists := statusRank[s]; exists {
			s1 = v
		}
	}
	s2 := 99
	if s, ok := t2["status"].(string); ok {
		if v, exists := statusRank[s]; exists {
			s2 = v
		}
	}
	if s1 != s2 {
		return s1 < s2
	}

	p1 := 99
	if p, ok := t1["priority"].(string); ok {
		if v, exists := priorityRank[p]; exists {
			p1 = v
		}
	}
	p2 := 99
	if p, ok := t2["priority"].(string); ok {
		if v, exists := priorityRank[p]; exists {
			p2 = v
		}
	}
	if p1 != p2 {
		return p1 < p2
	}

	c1 := ""
	if c, ok := t1["created_at"].(string); ok {
		c1 = c
	}
	c2 := ""
	if c, ok := t2["created_at"].(string); ok {
		c2 = c
	}
	return c1 < c2
}

func sortedTodos(agentID string) []map[string]interface{} {
	todos := getAgentTodos(agentID)
	var list []map[string]interface{}
	for tid, t := range todos {
		cp := make(map[string]interface{})
		for k, v := range t {
			cp[k] = v
		}
		cp["todo_id"] = tid
		list = append(list, cp)
	}

	sort.Slice(list, func(i, j int) bool {
		return todoSortKey(list[i], list[j])
	})
	if list == nil {
		list = []map[string]interface{}{}
	}
	return list
}

func normalizeTodoIDs(rawIDs string) ([]string, error) {
	str := strings.TrimSpace(rawIDs)
	if str == "" {
		return []string{}, nil
	}

	var data interface{}
	if err := json.Unmarshal([]byte(str), &data); err != nil {
		if strings.Contains(str, ",") {
			parts := strings.Split(str, ",")
			var res []string
			for _, p := range parts {
				if tp := strings.TrimSpace(p); tp != "" {
					res = append(res, tp)
				}
			}
			return res, nil
		}
		return []string{str}, nil
	}

	switch v := data.(type) {
	case []interface{}:
		var res []string
		for _, item := range v {
			if s := strings.TrimSpace(fmt.Sprintf("%v", item)); s != "" {
				res = append(res, s)
			}
		}
		return res, nil
	default:
		s := strings.TrimSpace(fmt.Sprintf("%v", data))
		if s == "" {
			return []string{}, nil
		}
		return []string{s}, nil
	}
}

func normalizeBulkUpdates(rawUpdates string) ([]map[string]interface{}, error) {
	str := strings.TrimSpace(rawUpdates)
	if str == "" {
		return []map[string]interface{}{}, nil
	}

	var data interface{}
	if err := json.Unmarshal([]byte(str), &data); err != nil {
		return nil, fmt.Errorf("Updates must be valid JSON")
	}

	var list []interface{}
	if v, ok := data.([]interface{}); ok {
		list = v
	} else if v, ok := data.(map[string]interface{}); ok {
		list = []interface{}{v}
	} else {
		return nil, fmt.Errorf("Updates must be a list of update objects")
	}

	var res []map[string]interface{}
	for _, item := range list {
		obj, ok := item.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("Each update must be an object with todo_id")
		}
		var todoID string
		if tid, ok := obj["todo_id"]; ok {
			todoID = strings.TrimSpace(fmt.Sprintf("%v", tid))
		} else if tid, ok := obj["id"]; ok {
			todoID = strings.TrimSpace(fmt.Sprintf("%v", tid))
		}
		if todoID == "" {
			return nil, fmt.Errorf("Each update must include 'todo_id'")
		}
		
		upd := map[string]interface{}{
			"todo_id": todoID,
		}
		if t, ok := obj["title"]; ok { upd["title"] = t }
		if d, ok := obj["description"]; ok { upd["description"] = d }
		if p, ok := obj["priority"]; ok { upd["priority"] = p }
		if s, ok := obj["status"]; ok { upd["status"] = s }
		res = append(res, upd)
	}
	return res, nil
}

func normalizeBulkTodos(rawTodos string) ([]map[string]interface{}, error) {
	str := strings.TrimSpace(rawTodos)
	if str == "" {
		return []map[string]interface{}{}, nil
	}

	var data interface{}
	if err := json.Unmarshal([]byte(str), &data); err != nil {
		lines := strings.Split(str, "\n")
		var res []map[string]interface{}
		for _, line := range lines {
			l := strings.Trim(line, " -*\t")
			if l != "" {
				res = append(res, map[string]interface{}{"title": l})
			}
		}
		return res, nil
	}

	var list []interface{}
	if v, ok := data.([]interface{}); ok {
		list = v
	} else if v, ok := data.(map[string]interface{}); ok {
		list = []interface{}{v}
	} else {
		return nil, fmt.Errorf("Todos must be provided as a list, dict, or JSON string")
	}

	var res []map[string]interface{}
	for _, item := range list {
		if s, ok := item.(string); ok {
			s = strings.TrimSpace(s)
			if s != "" {
				res = append(res, map[string]interface{}{"title": s})
			}
			continue
		}
		obj, ok := item.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("Each todo entry must be a string or object with a title")
		}
		title, _ := obj["title"].(string)
		title = strings.TrimSpace(title)
		if title == "" {
			return nil, fmt.Errorf("Each todo entry must include a non-empty 'title'")
		}
		
		t := map[string]interface{}{
			"title": title,
		}
		if d, ok := obj["description"].(string); ok {
			d = strings.TrimSpace(d)
			if d != "" {
				t["description"] = d
			} else {
				t["description"] = nil
			}
		} else {
			t["description"] = nil
		}
		if p, ok := obj["priority"]; ok {
			t["priority"] = p
		}
		res = append(res, t)
	}
	return res, nil
}

func applySingleUpdate(agentTodos map[string]map[string]interface{}, todoID string, upd map[string]interface{}) map[string]interface{} {
	if _, exists := agentTodos[todoID]; !exists {
		return map[string]interface{}{"todo_id": todoID, "error": fmt.Sprintf("Todo with ID '%s' not found", todoID)}
	}
	todo := agentTodos[todoID]
	
	if t, ok := upd["title"]; ok && t != nil {
		title := strings.TrimSpace(fmt.Sprintf("%v", t))
		if title == "" {
			return map[string]interface{}{"todo_id": todoID, "error": "Title cannot be empty"}
		}
		todo["title"] = title
	}
	
	if d, ok := upd["description"]; ok {
		if d == nil {
			todo["description"] = nil
		} else {
			desc := strings.TrimSpace(fmt.Sprintf("%v", d))
			if desc == "" {
				todo["description"] = nil
			} else {
				todo["description"] = desc
			}
		}
	}
	
	if p, ok := upd["priority"]; ok && p != nil {
		def := "normal"
		if cur, ok := todo["priority"].(string); ok {
			def = cur
		}
		normP, err := normalizePriority(p, def)
		if err != nil {
			return map[string]interface{}{"todo_id": todoID, "error": err.Error()}
		}
		todo["priority"] = normP
	}
	
	if s, ok := upd["status"]; ok && s != nil {
		status := strings.ToLower(fmt.Sprintf("%v", s))
		if !validStatuses[status] {
			return map[string]interface{}{"todo_id": todoID, "error": "Invalid status. Must be one of: pending, in_progress, done"}
		}
		todo["status"] = status
		if status == "done" {
			todo["completed_at"] = time.Now().UTC().Format("2006-01-02T15:04:05.000000+00:00")
		} else {
			todo["completed_at"] = nil
		}
	}
	
	todo["updated_at"] = time.Now().UTC().Format("2006-01-02T15:04:05.000000+00:00")
	return nil
}

func CreateTodo(ctx *RunContextWrapper, todos string) string {
	agentID := agentIDFrom(ctx)
	
	tasks, err := normalizeBulkTodos(todos)
	if err != nil {
		return toJSONString(map[string]interface{}{"success": false, "error": fmt.Sprintf("Failed to create todo: %v", err)})
	}
	if len(tasks) == 0 {
		return toJSONString(map[string]interface{}{"success": false, "error": "Provide a non-empty 'todos' list to create"})
	}

	todosIOLock.Lock()
	defer todosIOLock.Unlock()

	agentTodos := getAgentTodos(agentID)
	
	var created []map[string]interface{}
	for _, task := range tasks {
		priority, _ := normalizePriority(task["priority"], "normal")
		id := strings.ReplaceAll(uuid.New().String(), "-", "")[:6]
		timestamp := time.Now().UTC().Format("2006-01-02T15:04:05.000000+00:00")
		
		agentTodos[id] = map[string]interface{}{
			"title":        task["title"],
			"description":  task["description"],
			"priority":     priority,
			"status":       "pending",
			"created_at":   timestamp,
			"updated_at":   timestamp,
			"completed_at": nil,
		}
		created = append(created, map[string]interface{}{"todo_id": id, "title": task["title"], "priority": priority})
	}
	persistLocked()

	sorted := sortedTodos(agentID)
	totalCount := len(agentTodos)
	
	return toJSONString(map[string]interface{}{
		"success":       true,
		"created":       created,
		"created_count": len(created),
		"todos":         sorted,
		"total_count":   totalCount,
	})
}

func ListTodos(ctx *RunContextWrapper, status *string, priority *string) string {
	agentID := agentIDFrom(ctx)
	todosIOLock.Lock()
	defer todosIOLock.Unlock()
	
	agentTodos := getAgentTodos(agentID)
	
	statusFilter := ""
	if status != nil {
		statusFilter = strings.ToLower(*status)
	}
	priorityFilter := ""
	if priority != nil {
		priorityFilter = strings.ToLower(*priority)
	}

	var todosList []map[string]interface{}
	summary := map[string]int{"pending": 0, "in_progress": 0, "done": 0}

	for tid, todo := range agentTodos {
		s, _ := todo["status"].(string)
		p, _ := todo["priority"].(string)
		
		if statusFilter != "" && s != statusFilter {
			continue
		}
		if priorityFilter != "" && p != priorityFilter {
			continue
		}
		
		cp := make(map[string]interface{})
		for k, v := range todo {
			cp[k] = v
		}
		cp["todo_id"] = tid
		todosList = append(todosList, cp)
	}

	sort.Slice(todosList, func(i, j int) bool {
		return todoSortKey(todosList[i], todosList[j])
	})
	if todosList == nil {
		todosList = []map[string]interface{}{}
	}

	for _, todo := range todosList {
		sv := "pending"
		if s, ok := todo["status"].(string); ok && s != "" {
			sv = s
		}
		summary[sv]++
	}

	totalCount := len(agentTodos)

	return toJSONString(map[string]interface{}{
		"success":        true,
		"todos":          todosList,
		"filtered_count": len(todosList),
		"summary":        summary,
		"total_count":    totalCount,
	})
}

func UpdateTodo(ctx *RunContextWrapper, updates string) string {
	agentID := agentIDFrom(ctx)
	
	updatesToApply, err := normalizeBulkUpdates(updates)
	if err != nil {
		return toJSONString(map[string]interface{}{"success": false, "error": err.Error()})
	}
	if len(updatesToApply) == 0 {
		return toJSONString(map[string]interface{}{"success": false, "error": "Provide a non-empty 'updates' list"})
	}

	todosIOLock.Lock()
	defer todosIOLock.Unlock()

	agentTodos := getAgentTodos(agentID)
	
	var updated []string
	var errors []map[string]interface{}
	
	for _, upd := range updatesToApply {
		tid := upd["todo_id"].(string)
		errObj := applySingleUpdate(agentTodos, tid, upd)
		if errObj != nil {
			errors = append(errors, errObj)
		} else {
			updated = append(updated, tid)
		}
	}
	
	if len(updated) > 0 {
		persistLocked()
	}
	
	sorted := sortedTodos(agentID)
	totalCount := len(agentTodos)
	
	if updated == nil {
		updated = []string{}
	}
	resp := map[string]interface{}{
		"success":       len(errors) == 0,
		"updated":       updated,
		"updated_count": len(updated),
		"todos":         sorted,
		"total_count":   totalCount,
	}
	if len(errors) > 0 {
		resp["errors"] = errors
	}
	return toJSONString(resp)
}

func mark(agentID string, todoIDs string, newStatus string) string {
	ids, err := normalizeTodoIDs(todoIDs)
	if err != nil {
		return toJSONString(map[string]interface{}{"success": false, "error": err.Error()})
	}
	if len(ids) == 0 {
		return toJSONString(map[string]interface{}{"success": false, "error": fmt.Sprintf("Provide a non-empty 'todo_ids' list to mark as %s", newStatus)})
	}

	todosIOLock.Lock()
	defer todosIOLock.Unlock()

	agentTodos := getAgentTodos(agentID)
	
	var marked []string
	var errors []map[string]interface{}
	timestamp := time.Now().UTC().Format("2006-01-02T15:04:05.000000+00:00")
	
	for _, tid := range ids {
		todo, exists := agentTodos[tid]
		if !exists {
			errors = append(errors, map[string]interface{}{"todo_id": tid, "error": fmt.Sprintf("Todo with ID '%s' not found", tid)})
			continue
		}
		todo["status"] = newStatus
		if newStatus == "done" {
			todo["completed_at"] = timestamp
		} else {
			todo["completed_at"] = nil
		}
		todo["updated_at"] = timestamp
		marked = append(marked, tid)
	}
	
	if len(marked) > 0 {
		persistLocked()
	}
	
	sorted := sortedTodos(agentID)
	totalCount := len(agentTodos)
	
	if marked == nil {
		marked = []string{}
	}
	resp := map[string]interface{}{
		"success":       len(errors) == 0,
		"marked":        marked,
		"marked_count":  len(marked),
		"new_status":    newStatus,
		"todos":         sorted,
		"total_count":   totalCount,
	}
	if len(errors) > 0 {
		resp["errors"] = errors
	}
	return toJSONString(resp)
}

func MarkTodoDone(ctx *RunContextWrapper, todoIDs string) string {
	return mark(agentIDFrom(ctx), todoIDs, "done")
}

func MarkTodoPending(ctx *RunContextWrapper, todoIDs string) string {
	return mark(agentIDFrom(ctx), todoIDs, "pending")
}

func DeleteTodo(ctx *RunContextWrapper, todoIDs string) string {
	agentID := agentIDFrom(ctx)
	ids, err := normalizeTodoIDs(todoIDs)
	if err != nil {
		return toJSONString(map[string]interface{}{"success": false, "error": err.Error()})
	}
	if len(ids) == 0 {
		return toJSONString(map[string]interface{}{"success": false, "error": "Provide a non-empty 'todo_ids' list to delete"})
	}

	todosIOLock.Lock()
	defer todosIOLock.Unlock()

	agentTodos := getAgentTodos(agentID)
	
	var deleted []string
	var errors []map[string]interface{}
	
	for _, tid := range ids {
		if _, exists := agentTodos[tid]; !exists {
			errors = append(errors, map[string]interface{}{"todo_id": tid, "error": fmt.Sprintf("Todo with ID '%s' not found", tid)})
			continue
		}
		delete(agentTodos, tid)
		deleted = append(deleted, tid)
	}
	
	if len(deleted) > 0 {
		persistLocked()
	}
	
	sorted := sortedTodos(agentID)
	totalCount := len(agentTodos)
	
	if deleted == nil {
		deleted = []string{}
	}
	resp := map[string]interface{}{
		"success":       len(errors) == 0,
		"deleted":       deleted,
		"deleted_count": len(deleted),
		"todos":         sorted,
		"total_count":   totalCount,
	}
	if len(errors) > 0 {
		resp["errors"] = errors
	}
	return toJSONString(resp)
}


func toJSONString(v interface{}) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return `{"success":false,"error":"Failed to encode JSON response"}`
	}
	s := buf.String()
	if len(s) > 0 && s[len(s)-1] == '\n' {
		s = s[:len(s)-1]
	}
	return s
}
