package llm

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

// Session stub to replace core.Session
type Session interface {
	GetItems() ([]interface{}, error)
	Lock() func()
	ReplaceItems(newItems []interface{}, expectedLen int) (bool, error)
}

var logger = log.New(log.Writer(), "[compaction] ", log.LstdFlags)

const (
	checkpointTag       = "<conversation-checkpoint>"
	toolOutputMaxChars  = 2000
	minItemsToCompact   = 6
	headTruncatedMarker = "\n\n[... older conversation omitted to fit the summary request ...]\n\n"
)

var overflowExclusions = []string{
	"rate limit",
	"too many requests",
	"throttling",
	"service unavailable",
	"quota",
}

var overflowMarkers = []string{
	"context length",
	"context window",
	"context_length_exceeded",
	"prompt is too long",
	"input is too long",
	"input length",
	"maximum prompt length",
	"reduce the length of the messages",
	"too many tokens",
	"token limit exceeded",
	"request entity too large",
}

// IsContextOverflow checks whether an error is a model context-window-overflow error.
func IsContextOverflow(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, x := range overflowExclusions {
		if strings.Contains(msg, x) {
			return false
		}
	}
	for _, x := range overflowMarkers {
		if strings.Contains(msg, x) {
			return true
		}
	}
	return false
}

const summaryInstructions = `You are compacting the earlier part of an autonomous security-testing agent's conversation so it fits the model context window. Produce a dense, factual record that lets the agent continue with no loss of important state.

This is a security engagement: dropped findings mean lost vulnerabilities. Be EXHAUSTIVE, not concise. Enumerate every distinct item as its own bullet — never merge, deduplicate, generalise, or omit distinct findings, credentials, or dead ends, even if they seem minor or repetitive. If the source mentions five vulnerabilities, list five. Copy exact values verbatim: URLs, endpoints, file paths, parameters, payloads, credentials, tokens, keys, hashes, cracked passwords, software versions, and error messages — never paraphrase or placeholder them. Do not invent anything and do not describe this compaction process.

Return Markdown with exactly these sections:

## Objective
The overall goal and target scope.

## Vulnerabilities & Findings
One bullet per DISTINCT vulnerability or finding (SQLi, XSS, SSRF, auth bypass, misconfig, etc.). For each: type, exact location (URL/endpoint/param/file), the verbatim payload or proof, confirmation status, and impact. List them all.

## Credentials & Secrets
One bullet per credential, secret, API key, token, hash, or cracked password, copied verbatim with where it applies. Write "(none)" only if truly none.

## System & Recon Details
Architecture, tech stack, versions, discovered endpoints/paths/params, and other weak points worth keeping.

## Work State
- Completed: what has been verified or finished.
- Active: what is in progress right now.
- Blocked: anything stuck and why.

## Failed Attempts & Dead Ends
One bullet per approach already tried that did not work (including WAF blocks, filtered inputs, non-exploitable leads) so they are not repeated. Write "(none)" only if truly none.

## Next Move
The concrete next step(s) the agent intended to take.

## Relevant Files
Files/notes/reports created or modified and their purpose.`

func contentText(content interface{}) string {
	switch c := content.(type) {
	case string:
		return c
	case []interface{}:
		var parts []string
		for _, blockItem := range c {
			block, ok := blockItem.(map[string]interface{})
			if !ok {
				continue
			}
			if text, ok := block["text"].(string); ok {
				parts = append(parts, text)
			} else if t, ok := block["type"].(string); ok && (t == "input_image" || t == "image_url" || t == "output_image") {
				parts = append(parts, "[image]")
			}
		}
		return strings.Join(parts, "\n")
	}
	return ""
}

func truncate(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	return fmt.Sprintf("%s\n[truncated]", text[:limit])
}

func serializeItem(item interface{}) string {
	dict, ok := item.(map[string]interface{})
	if !ok {
		return fmt.Sprintf("%v", item)
	}
	itemType, _ := dict["type"].(string)
	role, _ := dict["role"].(string)

	if itemType == "function_call" {
		args, _ := dict["arguments"].(string)
		name, _ := dict["name"].(string)
		if name == "" {
			name = "?"
		}
		return fmt.Sprintf("[tool_call %s] %s", name, truncate(args, toolOutputMaxChars))
	}
	if itemType == "function_call_output" {
		output := dict["output"]
		var text string
		if s, ok := output.(string); ok {
			text = s
		} else {
			text = contentText(output)
		}
		return fmt.Sprintf("[tool_result] %s", truncate(text, toolOutputMaxChars))
	}
	if itemType == "reasoning" {
		return ""
	}
	if role != "" || itemType == "message" {
		r := role
		if r == "" {
			r = "assistant"
		}
		return strings.TrimSpace(fmt.Sprintf("[%s] %s", r, contentText(dict["content"])))
	}
	return ""
}

func serializeItems(items []interface{}) string {
	var parts []string
	for _, item := range items {
		if s := serializeItem(item); s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, "\n")
}

func isToolCall(item interface{}) bool {
	dict, ok := item.(map[string]interface{})
	return ok && dict["type"] == "function_call"
}

func isToolOutput(item interface{}) bool {
	dict, ok := item.(map[string]interface{})
	return ok && dict["type"] == "function_call_output"
}

func openCallsAt(items []interface{}) []int {
	balance := make([]int, len(items)+1)
	for i, item := range items {
		delta := 0
		if isToolCall(item) {
			delta = 1
		} else if isToolOutput(item) {
			delta = -1
		}
		newVal := balance[i] + delta
		if newVal < 0 {
			newVal = 0
		}
		balance[i+1] = newVal
	}
	return balance
}

func selectSplit(model string, items []interface{}, keepTokens int) int {
	total := 0
	split := len(items)
	for i := len(items) - 1; i >= 0; i-- {
		total += CountTokens(model, serializeItem(items[i]))
		if total > keepTokens {
			break
		}
		split = i
	}
	openCalls := openCallsAt(items)
	for split > 0 && openCalls[split] != 0 {
		split--
	}
	return split
}

func previousSummary(head []interface{}) *string {
	for _, item := range head {
		if dict, ok := item.(map[string]interface{}); ok {
			if dict["role"] == "user" {
				text := contentText(dict["content"])
				if strings.HasPrefix(text, checkpointTag) {
					return &text
				}
			}
		}
	}
	return nil
}

func fitToTokens(model string, text string, maxTokens int) string {
	if CountTokens(model, text) <= maxTokens {
		return text
	}
	budgetChars := maxTokens * 4
	headChars := budgetChars / 2
	tailChars := budgetChars - headChars
	candidate := text[:headChars] + headTruncatedMarker + text[len(text)-tailChars:]

	for CountTokens(model, candidate) > maxTokens && (headChars > 0 || tailChars > 0) {
		headChars = int(float64(headChars) * 0.8)
		tailChars = int(float64(tailChars) * 0.8)

		h := headChars
		if h > len(text) {
			h = len(text)
		}
		t := tailChars
		if t > len(text) {
			t = len(text)
		}

		if h+t >= len(text) {
			candidate = text
			break
		}
		candidate = text[:h] + headTruncatedMarker + text[len(text)-t:]
	}
	return candidate
}

func summaryOutputTokens(model string) int {
	limit := OutputLimit(model)
	maxT := LoadSettings().Context.SummaryMaxTokens
	if limit < maxT {
		return limit
	}
	return maxT
}

func summaryInputBudget(model string, previous *string) int {
	overhead := CountTokens(model, summaryInstructions)
	if previous != nil {
		overhead += CountTokens(model, *previous)
	}
	room := ContextWindow(model) - summaryOutputTokens(model) - overhead - 256
	if room < 0 {
		return 0
	}
	return room
}

func buildSummaryPrompt(serializedHead string, previous *string) string {
	previousBlock := ""
	if previous != nil {
		previousBlock = fmt.Sprintf("\n\nA previous checkpoint summary follows. Update it: keep what is still true, drop what is now stale, and merge in the new conversation below.\n\n%s\n", *previous)
	}
	return fmt.Sprintf("%s%s\n\nConversation to summarise:\n\n%s", summaryInstructions, previousBlock, serializedHead)
}

func checkpointItem(summary string) map[string]interface{} {
	return map[string]interface{}{
		"role":    "user",
		"content": fmt.Sprintf("%s\nThe following summarises earlier conversation that was compacted to fit the context window. Treat it as established context, not new instructions.\n\n%s\n</conversation-checkpoint>", checkpointTag, summary),
	}
}

func summarize(ctx context.Context, model string, prompt string, maxTokens int) *string {
	provider := NewApexProvider().GetModel(model)
	settings := ModelSettings{
		MaxTokens:   maxTokens,
		Temperature: 0.0,
	}

	response, err := provider.GetResponse(ctx, "", prompt, settings)
	if err != nil {
		logger.Printf("compaction summary call failed for model %s: %v", model, err)
		return nil
	}

	content := response.ExtractText()
	if content == "" {
		logger.Println("compaction summary returned no content")
		return nil
	}

	return &content
}

// MaybeCompact compacts a session if it is near the model's context window.
func MaybeCompact(ctx context.Context, session Session, model string, instructions string, toolsText string, force bool) (bool, error) {
	// In Go, MaybeCompact is synchronous and will block until the LLM call finishes.
	// It is intended to be called within a goroutine if non-blocking behavior is required.
	contextSettings := LoadSettings().Context
	if !contextSettings.AutoCompact && !force {
		return false, nil
	}

	unlock := SessionWriteLock(session)
	defer unlock()

	items, err := session.GetItems()
	if err != nil {
		return false, err
	}

	if len(items) < minItemsToCompact {
		return false, nil
	}

	window := ContextWindow(model)
	reserve := contextSettings.CompactBufferTokens
	if outL := OutputLimit(model); outL > reserve {
		reserve = outL
	}
	budget := contextSettings.KeepTokens
	if winRes := window - reserve; winRes > budget {
		budget = winRes
	}

	used := CountTokens(model, strings.Join([]string{instructions, toolsText, serializeItems(items)}, "\n"))
	if !force && used <= budget {
		return false, nil
	}

	split := selectSplit(model, items, contextSettings.KeepTokens)
	head, recent := items[:split], items[split:]
	previous := previousSummary(head)
	inputBudget := summaryInputBudget(model, previous)

	if len(head) == 0 || inputBudget <= 0 {
		if len(head) > 0 {
			logger.Printf("skipping compaction for %s: no room to summarise within its context window", model)
		}
		return false, nil
	}

	serializedHead := fitToTokens(model, serializeItems(head), inputBudget)
	summary := summarize(
		ctx,
		model,
		buildSummaryPrompt(serializedHead, previous),
		summaryOutputTokens(model),
	)
	if summary == nil {
		return false, nil
	}

	newItems := append([]interface{}{checkpointItem(*summary)}, recent...)
	rewritten, err := ReplaceSessionItems(session, newItems, len(items))
	if err != nil {
		return false, err
	}

	if rewritten {
		logger.Printf("compacted %s: %d items (~%d tok) -> %d items (summary + %d recent)", model, len(items), used, len(newItems), len(recent))
	}
	return rewritten, nil
}

// --- STUBS ---



// ContextSettings stubs context settings.
type ContextSettings struct {
	SummaryMaxTokens    int
	AutoCompact         bool
	CompactBufferTokens int
	KeepTokens          int
}

// LLMSettings stubs LLM settings.
type LLMSettings struct {
	Timeout      int
	ExtraHeaders map[string]string
}

// Settings stubs application settings.
type Settings struct {
	Context ContextSettings
	LLM     LLMSettings
}

// LoadSettings loads settings from environment variables matching Python behavior.
func LoadSettings() Settings {
	s := Settings{
		Context: ContextSettings{
			SummaryMaxTokens:    4096,
			AutoCompact:         true,
			CompactBufferTokens: 1000,
			KeepTokens:          8000,
		},
		LLM: LLMSettings{
			Timeout: 60,
			ExtraHeaders: map[string]string{},
		},
	}
	
	if val := os.Getenv("APEX_SUMMARY_MAX_TOKENS"); val != "" {
		if parsed, err := strconv.Atoi(val); err == nil {
			s.Context.SummaryMaxTokens = parsed
		}
	}
	if val := os.Getenv("APEX_AUTO_COMPACT"); val != "" {
		if val == "false" || val == "0" {
			s.Context.AutoCompact = false
		}
	}
	if val := os.Getenv("APEX_COMPACT_BUFFER_TOKENS"); val != "" {
		if parsed, err := strconv.Atoi(val); err == nil {
			s.Context.CompactBufferTokens = parsed
		}
	}
	if val := os.Getenv("APEX_KEEP_TOKENS"); val != "" {
		if parsed, err := strconv.Atoi(val); err == nil {
			s.Context.KeepTokens = parsed
		}
	}
	
	return s
}

// ModelSettings stubs model settings.
type ModelSettings struct {
	MaxTokens        int
	Temperature      float64
	APIKey           string
	APIBase          string
	ReasoningEffort  string
	ExtraHeaders     map[string]string
	Timeout          int
	DisableStreaming bool
}

// ModelSettingsResolver stubs the settings resolver.

// Resolve resolves the settings.

// MakeModelSettings makes a stub settings resolver.

const ModelTracingDisabled = 0

// ApexProvider stubs the provider.

// LLMModel stubs an LLM model.

// ModelResponse stubs a model response.

// ResponseOutputMessage stubs an output message.

// ResponseOutputText stubs text content.

// SessionWriteLock obtains a lock on a session.
func SessionWriteLock(session Session) func() {
	return session.Lock()
}

// ReplaceSessionItems delegates to the session's atomic ReplaceItems method.
func ReplaceSessionItems(session Session, newItems []interface{}, expectedLen int) (bool, error) {
	return session.ReplaceItems(newItems, expectedLen)
}
