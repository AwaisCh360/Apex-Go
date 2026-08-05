package config

import (
	"os"
	"strings"
)

// NewApexProvider creates a new instance of the Apex provider.
// This is a placeholder that should be implemented when the provider stack is ported to Go.
func NewApexProvider() any {
	return nil
}

var RecommendedModelNames = []string{
	"openai/gpt-5.6-sol",
	"openai/gpt-5.6-terra",
	"openai/gpt-5.6-luna",
	"openai/gpt-5.6",
	"openai/gpt-5.5-pro",
	"openai/gpt-5.5",
	"openai/gpt-5.4",
	"openai/gpt-5.3-codex",
	"anthropic/claude-fable-5",
	"anthropic/claude-opus-5",
	"anthropic/claude-opus-4-8",
	"anthropic/claude-sonnet-5",
	"anthropic/claude-sonnet-4-6",
	"vertex_ai/gemini-3.1-pro-preview",
	"gemini/gemini-3.1-pro-preview",
	"gemini/gemini-3.6-flash",
	"deepseek/deepseek-v4-pro",
	"deepseek/deepseek-v4-flash",
	"dashscope/qwen3.8-max",
	"dashscope/qwen3.7-max-2026-06-08",
	"moonshot/kimi-k3",
	"moonshot/kimi-k2.7-code",
}

var recommendedModelNameSet = make(map[string]bool)

func init() {
	for _, name := range RecommendedModelNames {
		recommendedModelNameSet[strings.ToLower(name)] = true
	}
}

var FrontierModelFamilies = []struct {
	Providers []string
	Prefixes  []string
}{
	{
		Providers: []string{"azure", "azure_ai", "bedrock_mantle", "chatgpt", "openai"},
		Prefixes:  []string{"gpt-5"},
	},
	{
		Providers: []string{"anthropic", "azure_ai", "bedrock", "claude", "databricks", "snowflake", "vertex_ai"},
		Prefixes:  []string{"claude-fable-5", "claude-opus-5", "claude-opus-4", "claude-sonnet-5", "claude-sonnet-4"},
	},
	{
		Providers: []string{"google", "gemini", "vertex_ai"},
		Prefixes:  []string{"gemini-3"},
	},
	{
		Providers: []string{"deepseek"},
		Prefixes:  []string{"deepseek-v4", "deepseek-r1", "deepseek-reasoner"},
	},
	{
		Providers: []string{"alibaba", "dashscope", "qwen"},
		Prefixes:  []string{"qwen3.8", "qwen3.7", "qwen3-max"},
	},
	{
		Providers: []string{"moonshot", "moonshotai", "kimi"},
		Prefixes:  []string{"kimi-k3", "kimi-k2.7", "kimi-k2.6"},
	},
}

// Mocks for internal agents SDK and LiteLLM that don't exist natively in Go yet.
// These stubs ensure the architectural footprint and function signatures exactly match
// the Python implementation, so behavior is preserved when these SDKs are wired up.

func setTracingDisabled(disabled bool) {
	// Stub for agents.set_tracing_disabled
}

func setDefaultOpenAIKey(key string, useForTracing bool) {
	// Stub for agents.set_default_openai_key
}

func setDefaultOpenAIAPI(api string) {
	// Stub for agents.set_default_openai_api
}

func registerOpenAIClientWithHeaders(llm LlmSettings, headers map[string]string) {
	// Stub for agents.set_default_openai_client
	// The Python version instantiates AsyncOpenAI with the headers and sets it.
}

func configureLiteLLMCompatibility() {
	// Applies LiteLLM compatibility, privacy, and callback settings.
	// litellm.drop_params = True
	// litellm.modify_params = True
	// litellm.turn_off_message_logging = True
	// litellm.disable_streaming_logging = False
	// litellm.suppress_debug_info = True

	registerLiteLLMCostCallback()
	installOpenRouterStreamCostCapture()
}

func installOpenRouterStreamCostCapture() {
	// Preserves OpenRouter's per-stream cost which LiteLLM normally drops when streaming.
	// In Python this subclasses OpenRouterChatCompletionStreamingHandler.
}

var openRouterAttributionHeaders = map[string]string{
	"HTTP-Referer":            "https://apex.ai",
	"X-Title":                 "Apex",
	"X-OpenRouter-Categories": "cli-agent",
}

func configureOpenRouterAttribution(modelName string) {
	if modelName == "" || !strings.Contains(strings.ToLower(strings.TrimSpace(modelName)), "openrouter/") {
		// Remove headers if present
		return
	}
	// litellm.headers = {**existing, **openRouterAttributionHeaders}
}

func configureExtraHeaders(llm LlmSettings) {
	if len(llm.ExtraHeaders) == 0 {
		return
	}
	mergeLiteLLMHeaders(llm.ExtraHeaders)
	registerOpenAIClientWithHeaders(llm, llm.ExtraHeaders)
}

func mergeLiteLLMHeaders(headers map[string]string) {
	// litellm.headers = {**existing, **headers}
}

func registerLiteLLMCostCallback() {
	// Registers litellm_cost_callback to success_callback and _async_success_callback
}

func configureLiteLLMDefault(name, value string) {
	// setattr(litellm, name, value)
}

func mirrorAPIKeyToProviderEnv(modelName, apiKey string) {
	if modelName == "" {
		return
	}
	// In Python this calls litellm.validate_environment and sets missing *_API_KEY
}

func ConfigureSdkModelDefaults(settings *Settings) {
	llm := settings.Llm
	setTracingDisabled(true)

	if SubscriptionModel(llm.Model) != "" {
		return
	}

	configureLiteLLMCompatibility()
	configureOpenRouterAttribution(llm.Model)

	if llm.APIKey != "" {
		setDefaultOpenAIKey(llm.APIKey, false)
		configureLiteLLMDefault("api_key", llm.APIKey)
		mirrorAPIKeyToProviderEnv(llm.Model, llm.APIKey)
	}

	if llm.APIBase != "" {
		os.Setenv("OPENAI_BASE_URL", llm.APIBase)
		configureLiteLLMDefault("api_base", llm.APIBase)
		setDefaultOpenAIAPI("chat_completions")
	} else {
		setDefaultOpenAIAPI("responses")
	}

	configureExtraHeaders(llm)
}

func normalizedModelName(modelName string) string {
	name := strings.ToLower(strings.TrimSpace(modelName))
	for _, prefix := range []string{"litellm/", "any-llm/"} {
		if strings.HasPrefix(name, prefix) {
			name = name[len(prefix):]
			break
		}
	}
	return name
}

func splitModelProvider(modelName string) (string, string) {
	idx := strings.LastIndex(modelName, "/")
	if idx == -1 {
		return "", modelName
	}
	return modelName[:idx], modelName[idx+1:]
}

func modelNameCandidates(modelName string) []string {
	if !strings.Contains(modelName, ".") {
		return []string{modelName}
	}
	parts := strings.Split(modelName, ".")
	candidates := []string{modelName}
	for i := 1; i < len(parts); i++ {
		candidates = append(candidates, strings.Join(parts[i:], "."))
	}
	return candidates
}

func matchesModelPrefix(modelName string, prefixes []string) bool {
	for _, candidate := range modelNameCandidates(modelName) {
		for _, prefix := range prefixes {
			if strings.HasPrefix(candidate, prefix) {
				return true
			}
		}
	}
	return false
}

func containsProviderMarker(value string, markers []string, splitCompound bool) bool {
	partsMap := make(map[string]bool)
	valNorm := strings.ReplaceAll(value, ".", "/")
	for _, p := range strings.Split(valNorm, "/") {
		partsMap[p] = true
	}
	if splitCompound {
		var toAdd []string
		for p := range partsMap {
			for _, sep := range []string{"_", "-"} {
				toAdd = append(toAdd, strings.Split(p, sep)...)
			}
		}
		for _, p := range toAdd {
			partsMap[p] = true
		}
	}
	for _, marker := range markers {
		if partsMap[marker] {
			return true
		}
	}
	return false
}

func matchesFrontierFamily(providerName, modelName string, markers, prefixes []string) bool {
	if !matchesModelPrefix(modelName, prefixes) {
		return false
	}
	if providerName == "" {
		return true
	}
	return containsProviderMarker(providerName, markers, true) || containsProviderMarker(modelName, markers, false)
}

func IsRecommendedOrFrontierModel(modelName string) bool {
	name := normalizedModelName(modelName)
	if name == "" {
		return false
	}
	if recommendedModelNameSet[name] {
		return true
	}
	providerName, bareModelName := splitModelProvider(name)
	for _, family := range FrontierModelFamilies {
		if matchesFrontierFamily(providerName, bareModelName, family.Providers, family.Prefixes) {
			return true
		}
	}
	return false
}

func IsClaudeModel(modelName string) bool {
	return strings.Contains(strings.ToLower(strings.TrimSpace(modelName)), "claude")
}

func IsBedrockRoute(modelName string) bool {
	name := strings.ToLower(strings.TrimSpace(modelName))
	return strings.HasPrefix(name, "bedrock/") || strings.Contains(name, "anthropic.")
}

var DefaultModelRetry = 5 // mock default

func RequestTimeoutExtraArgs(timeout *float64) map[string]interface{} {
	if timeout == nil || *timeout <= 0 {
		return nil
	}
	return map[string]interface{}{"timeout": *timeout}
}

func ModelSupportsReasoning(modelName string) bool {
	// Stub to match litellm's capability check
	return strings.Contains(strings.ToLower(modelName), "reasoning") || strings.Contains(strings.ToLower(modelName), "o1") || strings.Contains(strings.ToLower(modelName), "o3")
}

func IsKnownOpenAIBareModel(modelName string) bool {
	name := strings.ToLower(strings.TrimSpace(modelName))
	if name == "" || strings.Contains(name, "/") {
		return false
	}
	// Stub
	return strings.HasPrefix(name, "gpt-") || strings.HasPrefix(name, "o1-") || strings.HasPrefix(name, "o3-")
}

func BedrockRouteSupportsPromptCaching(modelName string) bool {
	// Stub
	return false
}
