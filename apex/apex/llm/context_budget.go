package llm

import (
	"errors"
	"log/slog"
	"strings"
	"sync"
	"os"
	"strconv"

	"github.com/pkoukk/tiktoken-go"
)

var _STRIPPABLE_PREFIXES = []string{
	"openai/",
	"chatgpt/",
	"litellm/",
	"any-llm/",
	"ollama/",
	"ollama_chat/",
}

const _DEFAULT_OUTPUT_TOKENS = 8192

// Local stubs for missing LiteLLM dependencies
var litellmGetModelInfo = func(model string) (map[string]any, error) {
	// A static map for common models since LiteLLM is not available in Go.
	// We use max_input_tokens and max_output_tokens.
	modelInfo := map[string]map[string]any{
		// OpenAI
		"gpt-4":                      {"max_input_tokens": 8192, "max_output_tokens": 8192},
		"gpt-4-turbo":                {"max_input_tokens": 128000, "max_output_tokens": 4096},
		"gpt-4o":                     {"max_input_tokens": 128000, "max_output_tokens": 16384},
		"gpt-4o-mini":                {"max_input_tokens": 128000, "max_output_tokens": 16384},
		"gpt-3.5-turbo":              {"max_input_tokens": 16385, "max_output_tokens": 4096},
		// Anthropic
		"claude-3-opus-20240229":     {"max_input_tokens": 200000, "max_output_tokens": 4096},
		"claude-3-sonnet-20240229":   {"max_input_tokens": 200000, "max_output_tokens": 4096},
		"claude-3-haiku-20240307":    {"max_input_tokens": 200000, "max_output_tokens": 4096},
		"claude-3-5-sonnet-20240620": {"max_input_tokens": 200000, "max_output_tokens": 8192},
		"claude-3-5-sonnet-20241022": {"max_input_tokens": 200000, "max_output_tokens": 8192},
		"claude-3-5-haiku-20241022":  {"max_input_tokens": 200000, "max_output_tokens": 8192},
		// Google Gemini
		"gemini-1.5-pro":             {"max_input_tokens": 2097152, "max_output_tokens": 8192},
		"gemini-1.5-flash":           {"max_input_tokens": 1048576, "max_output_tokens": 8192},
		"gemini-1.0-pro":             {"max_input_tokens": 30720, "max_output_tokens": 2048},
		// Meta Llama
		"llama-3.1-405b":             {"max_input_tokens": 128000, "max_output_tokens": 4096},
		"llama-3.1-70b":              {"max_input_tokens": 128000, "max_output_tokens": 4096},
		"llama-3.1-8b":               {"max_input_tokens": 128000, "max_output_tokens": 4096},
		// Mistral
		"mistral-large-2407":         {"max_input_tokens": 128000, "max_output_tokens": 4096},
		"mistral-nemo":               {"max_input_tokens": 128000, "max_output_tokens": 4096},
	}
	
	// Normalize model name (remove provider prefixes if present and look it up)
	modelBase := model
	if strings.Contains(model, "/") {
		parts := strings.SplitN(model, "/", 2)
		modelBase = parts[1]
	}

	if info, ok := modelInfo[modelBase]; ok {
		return info, nil
	}
	if info, ok := modelInfo[model]; ok {
		return info, nil
	}
	
	return nil, errors.New("unmapped model")
}

var litellmTokenCounter = func(model string, text string) (int, error) {
	tkm, err := tiktoken.EncodingForModel(model)
	if err != nil {
		// fallback to cl100k_base if model not found
		tkm, err = tiktoken.GetEncoding("cl100k_base")
		if err != nil {
			return 0, err
		}
	}
	tokens := tkm.Encode(text, nil, nil)
	return len(tokens), nil
}

func _lookupKey(model string) string {
	for _, prefix := range _STRIPPABLE_PREFIXES {
		if strings.HasPrefix(model, prefix) {
			return model[len(prefix):]
		}
	}
	return model
}

func _safeGetModelInfo(model string) map[string]any {
	info, err := litellmGetModelInfo(model)
	if err != nil || info == nil {
		return nil
	}
	return info
}

var (
	_modelInfoCache     = make(map[string]map[string]int)
	_modelInfoCacheLock sync.RWMutex
)

func _modelInfo(model string) map[string]int {
	_modelInfoCacheLock.RLock()
	if info, ok := _modelInfoCache[model]; ok {
		_modelInfoCacheLock.RUnlock()
		return info
	}
	_modelInfoCacheLock.RUnlock()

	lookupKey := _lookupKey(model)

	var candidates []string
	if strings.HasPrefix(model, "chatgpt/") {
		candidates = []string{lookupKey}
	} else {
		candidates = []string{model, lookupKey}
	}

	var result map[string]int
	found := false

	for _, candidate := range candidates {
		info := _safeGetModelInfo(candidate)
		if info != nil {
			getInt := func(key string) int {
				if val, ok := info[key]; ok {
					switch v := val.(type) {
					case int:
						return v
					case float64:
						return int(v)
					case float32:
						return int(v)
					case int64:
						return int(v)
					}
				}
				return 0
			}

			maxInputTokens := getInt("max_input_tokens")
			if maxInputTokens == 0 {
				maxInputTokens = getInt("max_tokens")
			}
			maxOutputTokens := getInt("max_output_tokens")

			result = map[string]int{
				"max_input_tokens":  maxInputTokens,
				"max_output_tokens": maxOutputTokens,
			}
			found = true
			break
		}
	}

	if !found {
		slog.Debug("No LiteLLM model info for model; using configured fallbacks", "model", model)
		result = map[string]int{"max_input_tokens": 0, "max_output_tokens": 0}
	}

	_modelInfoCacheLock.Lock()
	_modelInfoCache[model] = result
	_modelInfoCacheLock.Unlock()

	return result
}

// ContextWindow returns the input token capacity for model (configured fallback when unmapped).
func ContextWindow(model string) int {
	resolved := _modelInfo(model)["max_input_tokens"]
	if resolved != 0 {
		return resolved
	}
	fallback := 128000
	if val := os.Getenv("APEX_FALLBACK_CONTEXT_TOKENS"); val != "" {
		if parsed, err := strconv.Atoi(val); err == nil {
			fallback = parsed
		}
	}
	return fallback
}

// OutputLimit returns the max output tokens for model (a conservative default when unmapped).
func OutputLimit(model string) int {
	resolved := _modelInfo(model)["max_output_tokens"]
	if resolved != 0 {
		return resolved
	}
	return _DEFAULT_OUTPUT_TOKENS
}

// CountTokens returns the token count for text under model.
// Falls back to UTF-8 byte length (a guaranteed upper bound) when LiteLLM
// can't count, so budget checks stay conservative.
func CountTokens(model string, text string) int {
	if text == "" {
		return 0
	}
	count, err := litellmTokenCounter(_lookupKey(model), text)
	if err != nil {
		return len(text)
	}
	return count
}
