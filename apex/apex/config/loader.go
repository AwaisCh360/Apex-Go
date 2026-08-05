package config

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/AwaisCh360/Apex/apex/utils"
)

var logger = log.New(log.Writer(), "[config] ", log.LstdFlags)

var (
	defaultPath string
	override    string
	cached      *Settings
	mu          sync.Mutex
)

func init() {
	home, _ := os.UserHomeDir()
	defaultPath = filepath.Join(home, ".apex", "cli-config.json")
}

func getEnvValue(aliases []string, jsonEnv map[string]string) (string, bool) {
	for _, alias := range aliases {
		if val, exists := os.LookupEnv(alias); exists {
			return val, true
		}
	}
	for _, alias := range aliases {
		if val, exists := jsonEnv[alias]; exists {
			return val, true
		}
	}
	return "", false
}

func getBool(aliases []string, jsonEnv map[string]string, defaultVal bool) bool {
	valStr, exists := getEnvValue(aliases, jsonEnv)
	if !exists {
		return defaultVal
	}
	val, err := strconv.ParseBool(strings.ToLower(valStr))
	if err != nil {
		return defaultVal
	}
	return val
}

func getInt(aliases []string, jsonEnv map[string]string, defaultVal int) int {
	valStr, exists := getEnvValue(aliases, jsonEnv)
	if !exists {
		return defaultVal
	}
	val, err := strconv.Atoi(valStr)
	if err != nil {
		return defaultVal
	}
	return val
}

func getString(aliases []string, jsonEnv map[string]string, defaultVal string) string {
	valStr, exists := getEnvValue(aliases, jsonEnv)
	if !exists {
		return defaultVal
	}
	return valStr
}

func getMap(aliases []string, jsonEnv map[string]string) map[string]string {
	valStr, exists := getEnvValue(aliases, jsonEnv)
	if !exists {
		return nil
	}
	var res map[string]string
	if err := json.Unmarshal([]byte(valStr), &res); err != nil {
		return nil
	}
	return res
}

func readJsonOverrides(path string) map[string]string {
	res := make(map[string]string)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return res
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return res
	}
	var data map[string]interface{}
	if err := json.Unmarshal(b, &data); err != nil {
		return res
	}
	if envBlock, ok := data["env"].(map[string]interface{}); ok {
		for k, v := range envBlock {
			if strVal, isStr := v.(string); isStr {
				res[strings.ToUpper(k)] = strVal
			}
		}
	}
	return res
}

func LoadSettings() *Settings {
	mu.Lock()
	defer mu.Unlock()

	if cached != nil {
		return cached
	}

	sourcePath := defaultPath
	if override != "" {
		sourcePath = override
	}

	jsonEnv := readJsonOverrides(sourcePath)

	s := &Settings{
		Llm: LlmSettings{
			Model:                   getString([]string{"APEX_LLM"}, jsonEnv, ""),
			APIKey:                  getString([]string{"LLM_API_KEY", "OPENAI_API_KEY"}, jsonEnv, ""),
			APIBase:                 getString([]string{"LLM_API_BASE", "OPENAI_API_BASE", "OPENAI_BASE_URL", "LITELLM_BASE_URL", "OLLAMA_API_BASE"}, jsonEnv, ""),
			ExtraHeaders:            getMap([]string{"LLM_EXTRA_HEADERS"}, jsonEnv),
			ReasoningEffort:         getString([]string{"APEX_REASONING_EFFORT"}, jsonEnv, "high"),
			ForceRequiredToolChoice: getBool([]string{"APEX_FORCE_REQUIRED_TOOL_CHOICE"}, jsonEnv, false),
			PromptCache:             getBool([]string{"APEX_PROMPT_CACHE"}, jsonEnv, true),
			DisableStreaming:        getBool([]string{"LLM_DISABLE_STREAMING"}, jsonEnv, false),
			Timeout:                 getInt([]string{"LLM_TIMEOUT"}, jsonEnv, 300),
		},
		Dedupe: DedupeSettings{
			Model:           getString([]string{"APEX_DEDUPE_MODEL"}, jsonEnv, ""),
			ReasoningEffort: getString([]string{"APEX_DEDUPE_REASONING_EFFORT"}, jsonEnv, ""),
			APIKey:          getString([]string{"DEDUPE_LLM_API_KEY"}, jsonEnv, ""),
			APIBase:         getString([]string{"DEDUPE_LLM_API_BASE"}, jsonEnv, ""),
			ExtraHeaders:    getMap([]string{"DEDUPE_LLM_EXTRA_HEADERS"}, jsonEnv),
		},
		Runtime: RuntimeSettings{
			Image:            getString([]string{"APEX_IMAGE"}, jsonEnv, "ghcr.io/useapex/apex-sandbox:1.2.0"),
			Backend:          getString([]string{"APEX_RUNTIME_BACKEND"}, jsonEnv, "docker"),
			MaxContextImages: getInt([]string{"APEX_MAX_CONTEXT_IMAGES"}, jsonEnv, 3),
		},
		Context: ContextSettings{
			AutoCompact:           getBool([]string{"APEX_CONTEXT_AUTO_COMPACT"}, jsonEnv, true),
			CompactBufferTokens:   getInt([]string{"APEX_CONTEXT_BUFFER_TOKENS"}, jsonEnv, 20000),
			KeepTokens:            getInt([]string{"APEX_CONTEXT_KEEP_TOKENS"}, jsonEnv, 8000),
			FallbackContextTokens: getInt([]string{"APEX_CONTEXT_FALLBACK_TOKENS"}, jsonEnv, 200000),
			SummaryMaxTokens:      getInt([]string{"APEX_CONTEXT_SUMMARY_TOKENS"}, jsonEnv, 4096),
			ToolOutputMaxTokens:   getInt([]string{"APEX_TOOL_OUTPUT_MAX_TOKENS"}, jsonEnv, 8000),
			ToolOutputMaxLines:    getInt([]string{"APEX_TOOL_OUTPUT_MAX_LINES"}, jsonEnv, 2000),
			ToolOutputMaxBytes:    getInt([]string{"APEX_TOOL_OUTPUT_MAX_BYTES"}, jsonEnv, 50*1024),
		},
		Telemetry: TelemetrySettings{
			Enabled: getBool([]string{"APEX_TELEMETRY"}, jsonEnv, true),
		},
		Integrations: IntegrationSettings{
			PerplexityAPIKey: getString([]string{"PERPLEXITY_API_KEY"}, jsonEnv, ""),
			PostmanAPIKey:    getString([]string{"POSTMAN_API_KEY"}, jsonEnv, ""),
		},
		Viewer: ViewerSettings{
			AppURL: getString([]string{"APEX_APP_URL"}, jsonEnv, "https://app.apex.ai"),
		},
	}

	cached = s
	_, err := os.Stat(sourcePath)
	fileUsed := err == nil
	logger.Printf("load_settings: resolved (override=%v, file_used=%v, json_keys=%d, path=%s)", override != "", fileUsed, len(jsonEnv), sourcePath)
	return s
}

func ApplyConfigOverride(path string) {
	mu.Lock()
	defer mu.Unlock()
	override = path
	cached = nil
	logger.Printf("config override applied: %s", path)
}

// PersistCurrent writes currently-set env vars to the active config file.
func PersistCurrent() error {
	mu.Lock()
	defer mu.Unlock()

	target := defaultPath
	if override != "" {
		target = override
	}

	envBlock := make(map[string]string)

	allAliases := [][]string{
		{"APEX_LLM"},
		{"LLM_API_KEY", "OPENAI_API_KEY"},
		{"LLM_API_BASE", "OPENAI_API_BASE", "OPENAI_BASE_URL", "LITELLM_BASE_URL", "OLLAMA_API_BASE"},
		{"LLM_EXTRA_HEADERS"},
		{"APEX_REASONING_EFFORT"},
		{"APEX_FORCE_REQUIRED_TOOL_CHOICE"},
		{"APEX_PROMPT_CACHE"},
		{"LLM_DISABLE_STREAMING"},
		{"LLM_TIMEOUT"},
		{"APEX_DEDUPE_MODEL"},
		{"APEX_DEDUPE_REASONING_EFFORT"},
		{"DEDUPE_LLM_API_KEY"},
		{"DEDUPE_LLM_API_BASE"},
		{"DEDUPE_LLM_EXTRA_HEADERS"},
		{"APEX_IMAGE"},
		{"APEX_RUNTIME_BACKEND"},
		{"APEX_MAX_CONTEXT_IMAGES"},
		{"APEX_CONTEXT_AUTO_COMPACT"},
		{"APEX_CONTEXT_BUFFER_TOKENS"},
		{"APEX_CONTEXT_KEEP_TOKENS"},
		{"APEX_CONTEXT_FALLBACK_TOKENS"},
		{"APEX_CONTEXT_SUMMARY_TOKENS"},
		{"APEX_TOOL_OUTPUT_MAX_TOKENS"},
		{"APEX_TOOL_OUTPUT_MAX_LINES"},
		{"APEX_TOOL_OUTPUT_MAX_BYTES"},
		{"APEX_TELEMETRY"},
		{"PERPLEXITY_API_KEY"},
		{"POSTMAN_API_KEY"},
		{"APEX_APP_URL"},
	}

	for _, aliases := range allAliases {
		for _, alias := range aliases {
			if val, exists := os.LookupEnv(alias); exists {
				envBlock[alias] = val
				break
			}
		}
	}

	data, err := json.MarshalIndent(map[string]interface{}{"env": envBlock}, "", "  ")
	if err != nil {
		return err
	}

	return utils.WriteSecretText(target, string(data))
}
