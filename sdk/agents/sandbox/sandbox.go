package sandbox

import "github.com/AwaisCh360/Apex/sdk/agents/sandbox/capabilities"
import "github.com/AwaisCh360/Apex/sdk/agents/agent"
import "github.com/AwaisCh360/Apex/sdk/agents/tool"

type SandboxAgent struct {
	Name            string
	Instructions    string
	Tools           []tool.Tool
	ToolUseBehavior func(ctx agent.RunContextWrapper, toolResults []agent.FunctionToolResult) agent.ToolsToFinalOutputResult
	Model           interface{}
	Capabilities    []capabilities.Capability
}
