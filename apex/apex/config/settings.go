package config

type LlmSettings struct {
	Model                   string
	APIKey                  string
	APIBase                 string
	ExtraHeaders            map[string]string
	ReasoningEffort         string
	ForceRequiredToolChoice bool
	PromptCache             bool
	DisableStreaming        bool
	Timeout                 int
}

type DedupeSettings struct {
	Model           string
	ReasoningEffort string
	APIKey          string
	APIBase         string
	ExtraHeaders    map[string]string
}

type ContextSettings struct {
	AutoCompact           bool
	CompactBufferTokens   int
	KeepTokens            int
	FallbackContextTokens int
	SummaryMaxTokens      int
	ToolOutputMaxTokens   int
	ToolOutputMaxLines    int
	ToolOutputMaxBytes    int
}

type RuntimeSettings struct {
	Image            string
	Backend          string
	MaxContextImages int
}

type TelemetrySettings struct {
	Enabled bool
}

type IntegrationSettings struct {
	PerplexityAPIKey string
	PostmanAPIKey    string
}

type ViewerSettings struct {
	AppURL string
}

type Settings struct {
	Llm          LlmSettings
	Dedupe       DedupeSettings
	Runtime      RuntimeSettings
	Context      ContextSettings
	Telemetry    TelemetrySettings
	Integrations IntegrationSettings
	Viewer       ViewerSettings
}
