package tui

import (
	"database/sql"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type HistoryItem struct {
	AgentID   string
	Data      map[string]any
	CreatedAt string
}

func runtimeStateDir(runDir string) string {
	return filepath.Join(runDir, ".state")
}

func sqliteTimestampToISO(value string) string {
	if strings.TrimSpace(value) == "" {
		return time.Now().UTC().Format(time.RFC3339)
	}
	text := strings.TrimSpace(value)

	formats := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05.999999999",
		"2006-01-02T15:04:05",
	}

	for _, f := range formats {
		if parsed, err := time.Parse(f, text); err == nil {
			return parsed.UTC().Format(time.RFC3339)
		}
	}

	return text
}

func LoadSessionHistory(runDir string, agentIDs []any) []HistoryItem {
	agentsDB := filepath.Join(runtimeStateDir(runDir), "agents.db")

	var sessionIDs []string
	for _, aid := range agentIDs {
		if s, ok := aid.(string); ok {
			sessionIDs = append(sessionIDs, s)
		}
	}

	if len(sessionIDs) == 0 {
		return []HistoryItem{}
	}

	if _, err := os.Stat(agentsDB); os.IsNotExist(err) {
		return []HistoryItem{}
	}

	sessionIDSet := make(map[string]struct{})
	for _, sid := range sessionIDs {
		sessionIDSet[sid] = struct{}{}
	}

	db, err := sql.Open("sqlite3", "file:"+agentsDB+"?mode=ro")
	if err != nil {
		log.Printf("Failed to hydrate TUI history from %s", agentsDB)
		return []HistoryItem{}
	}
	defer db.Close()

	rows, err := db.Query("select id, session_id, message_data, created_at from agent_messages order by id")
	if err != nil {
		log.Printf("Failed to hydrate TUI history from %s", agentsDB)
		return []HistoryItem{}
	}
	defer rows.Close()

	items := []HistoryItem{}
	for rows.Next() {
		var id string
		var agentID string
		var messageData string
		var createdAt sql.NullString

		err := rows.Scan(&id, &agentID, &messageData, &createdAt)
		if err != nil {
			continue
		}

		if _, ok := sessionIDSet[agentID]; !ok {
			continue
		}

		var item map[string]any
		if err := json.Unmarshal([]byte(messageData), &item); err != nil {
			log.Printf("Skipping unreadable SDK session item %s for %s", id, agentID)
			continue
		}

		items = append(items, HistoryItem{
			AgentID:   agentID,
			Data:      item,
			CreatedAt: sqliteTimestampToISO(createdAt.String),
		})
	}

	return items
}
