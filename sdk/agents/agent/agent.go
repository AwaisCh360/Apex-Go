package agent

type FunctionToolResult struct {
	Tool struct {
		Name string
	}
	Output interface{}
}

type ToolsToFinalOutputResult struct {
	IsFinalOutput bool
	FinalOutput   interface{}
}

type RunContextWrapper struct {
	Context interface{}
}

type ModelSettings struct {
	ModelName      string
	RequestTimeout interface{}
	PromptCache    bool
	ExtraHeaders   interface{}
}

var ModelTracingDisabled = interface{}(nil)
