package backend

import (
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strings"
)

var (
	ScanModes  = []string{"quick", "standard", "deep"}
	ScopeModes = []string{"auto", "diff", "full"}
)

const (
	MaxProjectionString        = 64 * 1024
	MaxImageDataURIBytes       = 2 * 1024 * 1024
	MaxCollectionItemBytes     = 512 * 1024
	MaxTerminalEvents          = 5000
	MaxTerminalVulnerabilities = 1000
	StateTargetBytes           = 48 * 1024
)

var TerminalEscapeRe = regexp.MustCompile(`\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-_][0-?]*[ -/]*[@-~]`)

func SanitizeTerminalText(value string) string {
	withoutEscapes := TerminalEscapeRe.ReplaceAllString(value, "")
	var builder strings.Builder
	for _, char := range withoutEscapes {
		if char == '\n' || char == '\t' || (char >= 32 && !(char >= 127 && char <= 159)) {
			builder.WriteRune(char)
		}
	}
	return builder.String()
}

func TerminalProjection(value any) any {
	return terminalProjectionInternal(value, MaxProjectionString, 200, 0)
}

func TerminalProjectionWithOpts(value any, maxString int, maxItems int) any {
	return terminalProjectionInternal(value, maxString, maxItems, 0)
}

func terminalProjectionInternal(value any, maxString int, maxItems int, depth int) any {
	switch v := value.(type) {
	case string:
		if strings.HasPrefix(v, "data:image/") {
			if len(v) <= MaxImageDataURIBytes {
				return v
			}
			return "[image omitted from terminal projection]"
		}
		clean := SanitizeTerminalText(v)
		if len(clean) <= maxString {
			return clean
		}
		omitted := len(clean) - maxString
		return fmt.Sprintf("%s\n...[%d characters omitted from terminal projection]", clean[:maxString], omitted)
	case nil, bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		return v
	default:
		if depth >= 8 {
			return "[nested value omitted from terminal projection]"
		}

		if m, ok := v.(map[string]any); ok {
			projected := make(map[string]any)
			count := 0
			for key, item := range m {
				if count >= maxItems {
					break
				}
				projected[SanitizeTerminalText(key)] = terminalProjectionInternal(item, maxString, maxItems, depth+1)
				count++
			}
			if len(m) > maxItems {
				projected["_projection_notice"] = fmt.Sprintf("%d fields omitted from terminal projection", len(m)-maxItems)
			}
			return projected
		}

		val := reflect.ValueOf(v)
		if val.Kind() == reflect.Slice || val.Kind() == reflect.Array {
			var projectedItems []any
			for i := 0; i < val.Len(); i++ {
				if i >= maxItems {
					break
				}
				projectedItems = append(projectedItems, terminalProjectionInternal(val.Index(i).Interface(), maxString, maxItems, depth+1))
			}
			if val.Len() > maxItems {
				projectedItems = append(projectedItems, fmt.Sprintf("[%d items omitted from terminal projection]", val.Len()-maxItems))
			}
			return projectedItems
		}

		return terminalProjectionInternal(fmt.Sprintf("%v", v), maxString, maxItems, depth)
	}
}

func CollectionItemProjection(item map[string]any) map[string]any {
	itemBudget := MaxCollectionItemBytes + MaxImageDataURIBytes
	projectedRaw := TerminalProjection(item)
	projected, ok := projectedRaw.(map[string]any)
	if !ok {
		panic("projected value is not a map")
	}

	bytes1, err := json.Marshal(projected)
	if err == nil && len(bytes1) <= itemBudget {
		return projected
	}

	projectedRaw2 := TerminalProjectionWithOpts(item, 8*1024, 40)
	projected2, ok := projectedRaw2.(map[string]any)
	if !ok {
		panic("projected value is not a map")
	}
	projected2["projection_truncated"] = true

	bytes2, err2 := json.Marshal(projected2)
	if err2 == nil && len(bytes2) <= itemBudget {
		return projected2
	}

	compact := make(map[string]any)
	keys := []string{"id", "version", "type", "agent_id", "timestamp", "title", "severity", "description"}
	for _, key := range keys {
		if val, ok := item[key]; ok {
			compact[key] = TerminalProjectionWithOpts(val, 8*1024, 10)
		}
	}
	compact["projection_truncated"] = true
	return compact
}

func BoundedStateProjection(state map[string]any) map[string]any {
	encodedSize := func(value map[string]any) int {
		b, err := json.Marshal(value)
		if err != nil {
			return MaxCollectionFrameBytes + 1
		}
		return len(b)
	}

	if encodedSize(state) <= StateTargetBytes {
		return state
	}

	state["projection_truncated"] = true

	if targetsRaw, ok := state["targets"]; ok {
		val := reflect.ValueOf(targetsRaw)
		if val.Kind() == reflect.Slice || val.Kind() == reflect.Array {
			var newTargets []any
			for i := 0; i < val.Len(); i++ {
				if i >= 8 {
					break
				}
				newTargets = append(newTargets, TerminalProjectionWithOpts(val.Index(i).Interface(), 64, 200))
			}
			state["targets"] = newTargets
		} else {
			state["targets"] = TerminalProjectionWithOpts(targetsRaw, 64, 200)
		}
	}

	if instr, ok := state["instruction"]; ok {
		state["instruction"] = TerminalProjectionWithOpts(instr, 512, 200)
	}

	if msgsRaw, ok := state["messages"]; ok {
		val := reflect.ValueOf(msgsRaw)
		if val.Kind() == reflect.Slice || val.Kind() == reflect.Array {
			var newMsgs []any
			startIdx := val.Len() - 5
			if startIdx < 0 {
				startIdx = 0
			}
			for i := startIdx; i < val.Len(); i++ {
				msgVal := val.Index(i).Interface()
				msgObj, ok := msgVal.(map[string]any)
				if !ok {
					newMsgs = append(newMsgs, msgVal)
					continue
				}
				newMsg := make(map[string]any)
				for k, v := range msgObj {
					newMsg[k] = v
				}
				text := ""
				if textRaw, hasText := msgObj["text"]; hasText {
					if s, ok := textRaw.(string); ok {
						text = s
					}
				}
				newMsg["text"] = TerminalProjectionWithOpts(text, 128, 200)
				newMsgs = append(newMsgs, newMsg)
			}
			state["messages"] = newMsgs
		}
	}

	state["usage"] = make(map[string]any)

	if errVal, ok := state["error"]; ok {
		state["error"] = TerminalProjectionWithOpts(errVal, 512, 200)
	}
	if val, ok := state["model_warning"]; ok {
		state["model_warning"] = TerminalProjectionWithOpts(val, 256, 200)
	}
	if val, ok := state["caido_url"]; ok {
		state["caido_url"] = TerminalProjectionWithOpts(val, 256, 200)
	}
	if val, ok := state["viewer_url"]; ok {
		state["viewer_url"] = TerminalProjectionWithOpts(val, 256, 200)
	}

	if encodedSize(state) <= StateTargetBytes {
		return state
	}

	defensive := map[string]any{
		"setup_mode":           state["setup_mode"],
		"scan_started":         state["scan_started"],
		"scan_state":           state["scan_state"],
		"target_count":         state["target_count"],
		"scan_mode":            state["scan_mode"],
		"max_budget_usd":       state["max_budget_usd"],
		"max_turns":            state["max_turns"],
		"scope_mode":           state["scope_mode"],
		"diff_base":            state["diff_base"],
		"provider":             state["provider"],
		"model":                state["model"],
		"model_warning":        "",
		"caido_url":            nil,
		"messages":             []any{},
		"usage":                map[string]any{},
		"subscription":         state["subscription"],
		"viewer_status":        state["viewer_status"],
		"viewer_url":           nil,
		"projection_truncated": true,
	}

	if targetsRaw, ok := state["targets"]; ok {
		val := reflect.ValueOf(targetsRaw)
		if val.Kind() == reflect.Slice || val.Kind() == reflect.Array {
			var newTargets []any
			for i := 0; i < val.Len(); i++ {
				if i >= 4 {
					break
				}
				newTargets = append(newTargets, TerminalProjectionWithOpts(val.Index(i).Interface(), 64, 200))
			}
			defensive["targets"] = newTargets
		} else {
			defensive["targets"] = TerminalProjectionWithOpts(targetsRaw, 64, 200)
		}
	} else {
		defensive["targets"] = nil
	}

	if instr, ok := state["instruction"]; ok {
		defensive["instruction"] = TerminalProjectionWithOpts(instr, 128, 200)
	} else {
		defensive["instruction"] = nil
	}

	if errVal, ok := state["error"]; ok {
		defensive["error"] = TerminalProjectionWithOpts(errVal, 256, 200)
	} else {
		defensive["error"] = nil
	}

	return defensive
}
