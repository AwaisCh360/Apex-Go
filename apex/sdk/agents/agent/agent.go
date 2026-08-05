package agent

import "github.com/AwaisCh360/Apex/sdk/agents/tool"

type FunctionToolResult struct {
	Tool   *tool.FunctionTool
	Output interface{}
}

type ToolsToFinalOutputResult struct {
	IsFinalOutput bool
	FinalOutput   interface{}
}

type RunContextWrapper struct {
	Context interface{}
}
