package agents

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/AwaisCh360/Apex/apex/config"
	"github.com/AwaisCh360/Apex/apex/tools/output_store"

	sdk_agent "github.com/AwaisCh360/Apex/sdk/agents/agent"
	sdk_sandbox "github.com/AwaisCh360/Apex/sdk/agents/sandbox"
	sdk_capabilities "github.com/AwaisCh360/Apex/sdk/agents/sandbox/capabilities"
	sdk_errors "github.com/AwaisCh360/Apex/sdk/agents/sandbox/errors"
	sdk_tool "github.com/AwaisCh360/Apex/sdk/agents/tool"
)

var logger = log.New(log.Writer(), "[factory] ", log.LstdFlags)

var customToolInputFieldByName = map[string]string{
	"apply_patch": "patch",
}

const defaultCustomToolInputField = "input"

func customToolInputField(tool *sdk_tool.CustomTool) string {
	if val, ok := customToolInputFieldByName[tool.Name]; ok {
		return val
	}
	return defaultCustomToolInputField
}

func rawInputSchema(tool *sdk_tool.CustomTool) map[string]interface{} {
	inputField := customToolInputField(tool)
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			inputField: map[string]interface{}{
				"type":        "string",
				"description": fmt.Sprintf("Complete `%s` payload. Follow the tool description exactly.", tool.Name),
			},
		},
		"required":             []string{inputField},
		"additionalProperties": false,
	}
}

func extractCustomInput(tool *sdk_tool.CustomTool, rawInput interface{}) string {
	var parsed map[string]interface{}
	switch v := rawInput.(type) {
	case string:
		if err := json.Unmarshal([]byte(v), &parsed); err != nil {
			return ""
		}
	case map[string]interface{}:
		parsed = v
	default:
		return ""
	}

	val, ok := parsed[customToolInputField(tool)].(string)
	if !ok {
		return ""
	}
	return val
}

func toolOutputLimits() (int, int) {
	ctx := config.LoadSettings().Context
	return ctx.ToolOutputMaxLines, ctx.ToolOutputMaxBytes
}

func boundResult(result interface{}) interface{} {
	strResult, ok := result.(string)
	if !ok {
		return result
	}
	maxLines, maxBytes := toolOutputLimits()
	return output_store.BoundText(strResult, maxLines, maxBytes)
}

func formatToolError(err error) string {
	msg := err.Error()
	if msg == "" {
		msg = fmt.Sprintf("%T", err)
	}
	maxLines, maxBytes := toolOutputLimits()
	return output_store.BoundText(msg, maxLines, maxBytes)
}

func withBoundedResult(tool *sdk_tool.FunctionTool) *sdk_tool.FunctionTool {
	if tool.ApexBounded {
		return tool
	}
	origInvoke := tool.OnInvokeTool
	tool.OnInvokeTool = func(ctx context.Context, rawInput string) (interface{}, error) {
		res, err := origInvoke(ctx, rawInput)
		if err != nil {
			return nil, err
		}
		return boundResult(res), nil
	}
	tool.ApexBounded = true
	return tool
}

func schemaTypes(spec map[string]interface{}) map[string]bool {
	types := make(map[string]bool)
	if raw, ok := spec["type"].(string); ok {
		types[raw] = true
	} else if rawList, ok := spec["type"].([]interface{}); ok {
		for _, t := range rawList {
			if str, isStr := t.(string); isStr {
				types[str] = true
			}
		}
	}
	if anyOf, ok := spec["anyOf"].([]interface{}); ok {
		for _, variant := range anyOf {
			if vMap, isMap := variant.(map[string]interface{}); isMap {
				for t := range schemaTypes(vMap) {
					types[t] = true
				}
			}
		}
	}
	delete(types, "null")
	return types
}

func decodeStructured(value string, types map[string]bool) interface{} {
	stripped := strings.TrimSpace(value)
	if stripped == "" {
		return value
	}
	var decoded interface{}
	if err := json.Unmarshal([]byte(stripped), &decoded); err != nil {
		return value
	}
	if types["array"] {
		if _, ok := decoded.([]interface{}); ok {
			return decoded
		}
	} else {
		if _, ok := decoded.(map[string]interface{}); ok {
			return decoded
		}
	}
	return value
}

func coerceArgument(value interface{}, spec map[string]interface{}) interface{} {
	types := schemaTypes(spec)
	if len(types) == 0 || value == nil {
		return value
	}
	isListOrDict := false
	switch value.(type) {
	case []interface{}, map[string]interface{}:
		isListOrDict = true
	}

	if isListOrDict && types["string"] && !types["array"] && !types["object"] {
		b, _ := json.Marshal(value)
		return string(b)
	}
	if strVal, ok := value.(string); ok && (types["array"] || types["object"]) && !types["string"] {
		return decodeStructured(strVal, types)
	}
	return value
}

func coerceArguments(rawInput string, schema map[string]interface{}) string {
	props, ok := schema["properties"].(map[string]interface{})
	if !ok || len(props) == 0 {
		return rawInput
	}
	var payload map[string]interface{}
	if rawInput != "" {
		if err := json.Unmarshal([]byte(rawInput), &payload); err != nil {
			return rawInput
		}
	}
	if payload == nil {
		return rawInput
	}

	changed := false
	for key, value := range payload {
		spec, isMap := props[key].(map[string]interface{})
		if !isMap {
			continue
		}
		coerced := coerceArgument(value, spec)
		// Check pointer/value equality roughly via formatting
		if fmt.Sprintf("%v", coerced) != fmt.Sprintf("%v", value) {
			payload[key] = coerced
			changed = true
		}
	}

	if !changed {
		return rawInput
	}
	b, _ := json.Marshal(payload)
	return string(b)
}

func withCoercedArguments(tool *sdk_tool.FunctionTool) *sdk_tool.FunctionTool {
	if tool.ApexCoerced {
		return tool
	}
	origInvoke := tool.OnInvokeTool
	schema := tool.ParamsJSONSchema

	tool.OnInvokeTool = func(ctx context.Context, rawInput string) (interface{}, error) {
		return origInvoke(ctx, coerceArguments(rawInput, schema))
	}
	tool.ApexCoerced = true
	return tool
}

func functionToolWithErrorResult(tool *sdk_tool.FunctionTool) *sdk_tool.FunctionTool {
	origInvoke := tool.OnInvokeTool
	tool.OnInvokeTool = func(ctx context.Context, rawInput string) (interface{}, error) {
		res, err := origInvoke(ctx, rawInput)
		if err != nil {
			logger.Printf("Tool %s failed; returning error as result: %v", tool.Name, err)
			return formatToolError(err), nil
		}
		return boundResult(res), nil
	}
	return tool
}

func customToolAsFunctionTool(tool *sdk_tool.CustomTool) *sdk_tool.FunctionTool {
	invoke := func(ctx context.Context, rawInput string) (interface{}, error) {
		customInput := extractCustomInput(tool, rawInput)
		if customInput == "" {
			return fmt.Sprintf("`%s` must be a non-empty string.", customToolInputField(tool)), nil
		}
		res, err := tool.OnInvokeTool(ctx, customInput)
		if err != nil {
			logger.Printf("Tool %s failed; returning error as result: %v", tool.Name, err)
			return formatToolError(err), nil
		}
		return boundResult(res), nil
	}

	needsApproval := tool.NeedsApproval
	return &sdk_tool.FunctionTool{
		Name: tool.Name,
		Description: fmt.Sprintf("%s\n\nPass the complete `%s` payload in `%s`.",
			tool.Description, tool.Name, customToolInputField(tool)),
		ParamsJSONSchema: rawInputSchema(tool),
		OnInvokeTool:     invoke,
		StrictJSONSchema: false,
		NeedsApproval:    needsApproval,
	}
}

func boundCustomTool(tool *sdk_tool.CustomTool) *sdk_tool.CustomTool {
	origInvoke := tool.OnInvokeTool
	tool.OnInvokeTool = func(ctx context.Context, rawInput string) (interface{}, error) {
		res, err := origInvoke(ctx, rawInput)
		if err != nil {
			return nil, err
		}
		return boundResult(res), nil
	}
	return tool
}

func configureFilesystemTools(toolset *sdk_capabilities.FilesystemToolset, chatCompletions bool) {
	for name, tool := range toolset.Tools {
		if chatCompletions {
			if ct, ok := tool.(*sdk_tool.CustomTool); ok {
				toolset.Tools[name] = customToolAsFunctionTool(ct)
			} else if ft, ok := tool.(*sdk_tool.FunctionTool); ok {
				toolset.Tools[name] = functionToolWithErrorResult(withCoercedArguments(ft))
			}
		} else {
			if ct, ok := tool.(*sdk_tool.CustomTool); ok {
				toolset.Tools[name] = boundCustomTool(ct)
			} else if ft, ok := tool.(*sdk_tool.FunctionTool); ok {
				toolset.Tools[name] = withBoundedResult(withCoercedArguments(ft))
			}
		}
	}
}

func makeFilesystemConfigurator(chatCompletions bool) func(*sdk_capabilities.FilesystemToolset) {
	return func(toolset *sdk_capabilities.FilesystemToolset) {
		configureFilesystemTools(toolset, chatCompletions)
	}
}

var charsEscapeRe = regexp.MustCompile(`\\(?:u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|[0abtnvfr\\])`)
var charsEscapeMap = map[string]string{
	`\\`: `\`,
	`\n`: "\n",
	`\t`: "\t",
	`\r`: "\r",
	`\0`: "\x00",
	`\a`: "\x07",
	`\b`: "\x08",
	`\v`: "\x0b",
	`\f`: "\x0c",
}

func decodeCharsEscape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	return charsEscapeRe.ReplaceAllStringFunc(s, func(token string) string {
		if val, ok := charsEscapeMap[token]; ok {
			return val
		}
		if strings.HasPrefix(token, `\u`) || strings.HasPrefix(token, `\x`) {
			val, err := strconv.ParseInt(token[2:], 16, 32)
			if err == nil {
				return string(rune(val))
			}
		}
		return token
	})
}

func formatValidationError(toolName string, err error) string {
	return fmt.Sprintf("%s: invalid arguments — %v", toolName, err)
}

func applyShellOutputCap(parsed map[string]interface{}) {
	ceiling := config.LoadSettings().Context.ToolOutputMaxTokens
	reqObj := parsed["max_output_tokens"]
	var req int
	switch v := reqObj.(type) {
	case float64:
		req = int(v)
	case int:
		req = v
	default:
		parsed["max_output_tokens"] = ceiling
		return
	}
	if req > ceiling {
		parsed["max_output_tokens"] = ceiling
	} else {
		parsed["max_output_tokens"] = req
	}
}

func wrapExecCommand(tool *sdk_tool.FunctionTool) *sdk_tool.FunctionTool {
	origInvoke := tool.OnInvokeTool
	tool.OnInvokeTool = func(ctx context.Context, rawInput string) (interface{}, error) {
		var parsed map[string]interface{}
		if err := json.Unmarshal([]byte(rawInput), &parsed); err == nil && parsed != nil {
			if _, ok := parsed["shell"]; !ok {
				parsed["shell"] = "bash"
			}
			applyShellOutputCap(parsed)
			b, _ := json.Marshal(parsed)
			rawInput = string(b)
		}
		res, err := origInvoke(ctx, rawInput)
		if err != nil {
			if invalidPath, ok := err.(*sdk_errors.InvalidManifestPathError); ok {
				return fmt.Sprintf("exec_command: workdir must be a path inside /workspace (or omitted to use the turn's cwd). Got: %v.", invalidPath.Context["rel"]), nil
			}
			return formatValidationError(tool.Name, err), nil
		}
		return res, nil
	}
	return tool
}

func wrapWriteStdin(tool *sdk_tool.FunctionTool) *sdk_tool.FunctionTool {
	origInvoke := tool.OnInvokeTool
	tool.OnInvokeTool = func(ctx context.Context, rawInput string) (interface{}, error) {
		var parsed map[string]interface{}
		if err := json.Unmarshal([]byte(rawInput), &parsed); err == nil && parsed != nil {
			if chars, ok := parsed["chars"].(string); ok {
				parsed["chars"] = decodeCharsEscape(chars)
			}
			applyShellOutputCap(parsed)
			b, _ := json.Marshal(parsed)
			rawInput = string(b)
		}
		res, err := origInvoke(ctx, rawInput)
		if err != nil {
			return formatValidationError(tool.Name, err), nil
		}
		return res, nil
	}
	return tool
}

func configureShellTools(toolset *sdk_capabilities.ShellToolset, chatCompletions bool) {
	for name, t := range toolset.Tools {
		tool, ok := t.(*sdk_tool.FunctionTool)
		if !ok {
			continue
		}
		wrapped := withCoercedArguments(tool)
		if tool.Name == "exec_command" {
			wrapped = wrapExecCommand(wrapped)
		} else if tool.Name == "write_stdin" {
			wrapped = wrapWriteStdin(wrapped)
		}
		if chatCompletions {
			wrapped = functionToolWithErrorResult(wrapped)
		}
		toolset.Tools[name] = wrapped
	}
}

func makeShellConfigurator(chatCompletions bool) func(*sdk_capabilities.ShellToolset) {
	return func(toolset *sdk_capabilities.ShellToolset) {
		configureShellTools(toolset, chatCompletions)
	}
}

var parkingTools = map[string]bool{
	"respond_to_user": true,
	"wait_for_agents": true,
}

func lifecycleToolCompleted(toolName string, output interface{}) bool {
	completionKey := ""
	if toolName == "agent_finish" {
		completionKey = "agent_completed"
	} else if toolName == "finish_scan" {
		completionKey = "scan_completed"
	} else {
		return false
	}

	strOutput, ok := output.(string)
	if !ok {
		return false
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(strOutput), &parsed); err != nil {
		return false
	}
	success, _ := parsed["success"].(bool)
	comp, _ := parsed[completionKey].(bool)
	return success && comp
}

func waitToolParked(toolName string, output interface{}) bool {
	if !parkingTools[toolName] {
		return false
	}
	strOutput, ok := output.(string)
	if !ok {
		return false
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(strOutput), &parsed); err != nil {
		return false
	}
	success, _ := parsed["success"].(bool)
	waitOutcome, _ := parsed["wait_outcome"].(string)
	return success && waitOutcome == "waiting"
}

func finishToolUseBehavior(ctx sdk_agent.RunContextWrapper, toolResults []sdk_agent.FunctionToolResult) sdk_agent.ToolsToFinalOutputResult {
	interactive := false
	if ctxMap, ok := ctx.Context.(map[string]interface{}); ok {
		if val, exists := ctxMap["interactive"].(bool); exists {
			interactive = val
		}
	}
	for _, tr := range toolResults {
		if lifecycleToolCompleted(tr.Tool.Name, tr.Output) {
			return sdk_agent.ToolsToFinalOutputResult{
				IsFinalOutput: true,
				FinalOutput:   tr.Output,
			}
		}
		if interactive && waitToolParked(tr.Tool.Name, tr.Output) {
			return sdk_agent.ToolsToFinalOutputResult{
				IsFinalOutput: true,
				FinalOutput:   tr.Output,
			}
		}
	}
	return sdk_agent.ToolsToFinalOutputResult{
		IsFinalOutput: false,
		FinalOutput:   nil,
	}
}

var baseTools = []sdk_tool.Tool{}

var extraToolsMu sync.RWMutex
var extraTools []sdk_tool.Tool

func ensureUniqueToolNames(tools []sdk_tool.Tool) {
	seen := make(map[string]bool)
	var duplicates []string
	for _, tool := range tools {
		name := tool.GetName()
		if seen[name] {
			duplicates = append(duplicates, name)
		}
		seen[name] = true
	}
	if len(duplicates) > 0 {
		panic(fmt.Sprintf("Agent tools must have unique names: %v", duplicates))
	}
}

func RegisterAgentTools(tools ...sdk_tool.Tool) {
	extraToolsMu.Lock()
	defer extraToolsMu.Unlock()

	var newTools []sdk_tool.Tool
	for _, t := range tools {
		exists := false
		for _, e := range extraTools {
			if e == t {
				exists = true
				break
			}
		}
		for _, n := range newTools {
			if n == t {
				exists = true
				break
			}
		}
		if !exists {
			newTools = append(newTools, t)
		}
	}

	all := append([]sdk_tool.Tool{}, baseTools...)
	all = append(all, extraTools...)
	all = append(all, newTools...)
	var finishScanTool = &sdk_tool.FunctionTool{Name: "finish_scan"}
	var agentFinishTool = &sdk_tool.FunctionTool{Name: "agent_finish"}
	all = append(all, finishScanTool, agentFinishTool)
	ensureUniqueToolNames(all)

	for _, t := range newTools {
		extraTools = append(extraTools, t)
		logger.Printf("Registered extra agent tool: %s", t.GetName())
	}
}

func RegisteredAgentTools() []sdk_tool.Tool {
	extraToolsMu.RLock()
	defer extraToolsMu.RUnlock()
	res := make([]sdk_tool.Tool, len(extraTools))
	copy(res, extraTools)
	return res
}

func BuildApexAgent(
	name string,
	skills []string,
	isRoot bool,
	scanMode string,
	isWhitebox bool,
	interactive bool,
	chatCompletionsTools bool,
	systemPromptContext map[string]interface{},
	xtraTools []sdk_tool.Tool,
	instructionsOverride string,
) *sdk_sandbox.SandboxAgent {
	if name == "" {
		name = "apex"
	}
	if scanMode == "" {
		scanMode = "deep"
	}

	var instructions string
	if instructionsOverride != "" {
		instructions = instructionsOverride
	} else {
		opts := RenderOptions{
			Skills:              skills,
			ScanMode:            scanMode,
			IsWhitebox:          isWhitebox,
			IsRoot:              isRoot,
			Interactive:         interactive,
			SystemPromptContext: systemPromptContext,
		}
		instructions = RenderSystemPrompt(opts)
	}

	agentTools := append([]sdk_tool.Tool{}, RegisteredAgentTools()...)
	agentTools = append(agentTools, xtraTools...)

	var interactiveTools []sdk_tool.Tool
	var waitForAgentsTool = &sdk_tool.FunctionTool{Name: "wait_for_agents"}
	interactiveTools = append(interactiveTools, waitForAgentsTool)
	if interactive {
		var respondToUserTool = &sdk_tool.FunctionTool{Name: "respond_to_user"}
		interactiveTools = append(interactiveTools, respondToUserTool)
	}

	var tools []sdk_tool.Tool
	var finishScanTool = &sdk_tool.FunctionTool{Name: "finish_scan"}
	if isRoot {
		tools = append(append(append(baseTools, interactiveTools...), agentTools...), finishScanTool)
	} else {
		var agentFinishTool = &sdk_tool.FunctionTool{Name: "agent_finish"}
		tools = append(append(append(baseTools, interactiveTools...), agentTools...), agentFinishTool)
	}
	ensureUniqueToolNames(tools)

	processedTools := make([]sdk_tool.Tool, 0, len(tools))
	for _, t := range tools {
		if ft, ok := t.(*sdk_tool.FunctionTool); ok {
			processedTools = append(processedTools, withBoundedResult(withCoercedArguments(ft)))
		} else {
			processedTools = append(processedTools, t)
		}
	}

	logger.Printf("Built %s agent '%s' (skills=%d, tools=%d, scan_mode=%s, whitebox=%v)",
		map[bool]string{true: "root", false: "child"}[isRoot],
		name,
		len(skills),
		len(processedTools),
		scanMode,
		isWhitebox,
	)

	return &sdk_sandbox.SandboxAgent{
		Name:            name,
		Instructions:    instructions,
		Tools:           processedTools,
		ToolUseBehavior: finishToolUseBehavior,
		Model:           nil,
		Capabilities: []sdk_capabilities.Capability{
			&sdk_capabilities.Filesystem{
				ConfigureTools: makeFilesystemConfigurator(chatCompletionsTools),
			},
			&sdk_capabilities.Shell{
				ConfigureTools: makeShellConfigurator(chatCompletionsTools),
			},
		},
	}
}

type ChildFactory func(name string, skills []string) *sdk_sandbox.SandboxAgent

func MakeChildFactory(
	scanMode string,
	isWhitebox bool,
	interactive bool,
	chatCompletionsTools bool,
	systemPromptContext map[string]interface{},
) ChildFactory {
	if scanMode == "" {
		scanMode = "deep"
	}
	return func(name string, skills []string) *sdk_sandbox.SandboxAgent {
		return BuildApexAgent(
			name,
			skills,
			false, // isRoot
			scanMode,
			isWhitebox,
			interactive,
			chatCompletionsTools,
			systemPromptContext,
			nil,
			"",
		)
	}
}
