package core

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/AwaisCh360/Apex/apex/config"
)

func acceptsRequiredToolChoice(modelName *string) bool {
	name := ""
	if modelName != nil {
		name = strings.ToLower(strings.TrimSpace(*modelName))
	}
	for _, prefix := range []string{"litellm/", "any-llm/"} {
		if strings.HasPrefix(name, prefix) {
			name = name[len(prefix):]
			break
		}
	}
	return strings.HasPrefix(name, "openai/") || config.IsKnownOpenAIBareModel(name)
}

func renderDiffScope(diffScope map[string]interface{}) []string {
	if active, _ := diffScope["active"].(bool); !active {
		return nil
	}
	parts := []string{
		"\n\nScope Constraints:",
		"- Pull request diff-scope mode is active. Prioritize changed files and use other files only for context.",
	}
	repos, _ := diffScope["repos"].([]interface{})
	for _, r := range repos {
		repoScope, _ := r.(map[string]interface{})
		label := "repository"
		if val, ok := repoScope["workspace_subdir"].(string); ok && val != "" {
			label = val
		} else if val, ok := repoScope["source_path"].(string); ok && val != "" {
			label = val
		}

		var changed int
		if val, ok := repoScope["analyzable_files_count"].(float64); ok {
			changed = int(val)
		}
		var deleted int
		if val, ok := repoScope["deleted_files_count"].(float64); ok {
			deleted = int(val)
		}
		parts = append(parts, fmt.Sprintf("- %s: %d changed file(s) in primary scope", label, changed))
		if deleted > 0 {
			parts = append(parts, fmt.Sprintf("- %s: %d deleted file(s) are context-only", label, deleted))
		}
	}
	return parts
}

func renderAPISpec(details map[string]interface{}) []string {
	title := "API"
	if val, ok := details["spec_title"].(string); ok && val != "" {
		title = val
	} else if val, ok := details["target_spec"].(string); ok && val != "" {
		title = val
	}

	format := "api"
	if val, ok := details["spec_format"].(string); ok && val != "" {
		format = val
	}

	workspacePath, _ := details["workspace_path"].(string)

	line := fmt.Sprintf("- %s (%s specification", title, format)
	if workspacePath != "" {
		line += fmt.Sprintf(", available at: %s", workspacePath)
	}
	line += ")"

	lines := []string{line}
	if baseUrls, ok := details["base_urls"].([]interface{}); ok && len(baseUrls) > 0 {
		var urlsStr []string
		for _, u := range baseUrls {
			if s, isStr := u.(string); isStr {
				urlsStr = append(urlsStr, s)
			}
		}
		if len(urlsStr) > 0 {
			lines = append(lines, "  - Base URL(s): "+strings.Join(urlsStr, ", "))
		}
	}
	lines = append(lines, "  - Read the specification and test every operation it declares, using its declared parameters, request bodies, and auth. Endpoints in the specification are in scope even when nothing links to them. Load the `api_spec_testing` skill for the methodology, or spawn a specialist with it.")
	return lines
}

func BuildRootTask(scanConfig map[string]interface{}) string {
	targets, _ := scanConfig["targets"].([]interface{})
	diffScope, _ := scanConfig["diff_scope"].(map[string]interface{})
	userInstructions, _ := scanConfig["user_instructions"].(string)

	sections := map[string][]string{
		"Repositories":       {},
		"Local Codebases":    {},
		"URLs":               {},
		"IP Addresses":       {},
		"API Specifications": {},
	}

	for _, t := range targets {
		target, _ := t.(map[string]interface{})
		ttype, _ := target["type"].(string)
		details, _ := target["details"].(map[string]interface{})
		if details == nil {
			details = make(map[string]interface{})
		}

		workspaceSubdir, _ := details["workspace_subdir"].(string)
		workspacePath := "/workspace"
		if workspaceSubdir != "" {
			workspacePath = "/workspace/" + workspaceSubdir
		}

		switch ttype {
		case "repository":
			url, _ := details["target_repo"].(string)
			if _, cloned := details["cloned_repo_path"]; cloned {
				sections["Repositories"] = append(sections["Repositories"], fmt.Sprintf("- %s (available at: %s)", url, workspacePath))
			} else {
				sections["Repositories"] = append(sections["Repositories"], fmt.Sprintf("- %s", url))
			}
		case "local_code":
			path := "unknown"
			if val, ok := details["target_path"].(string); ok {
				path = val
			}
			sections["Local Codebases"] = append(sections["Local Codebases"], fmt.Sprintf("- %s (available at: %s; this is the user's real directory, mounted live and writable — .git/.agents/.codex are read-only)", path, workspacePath))
		case "web_application":
			url, _ := details["target_url"].(string)
			sections["URLs"] = append(sections["URLs"], fmt.Sprintf("- %s", url))
		case "ip_address":
			ip, _ := details["target_ip"].(string)
			sections["IP Addresses"] = append(sections["IP Addresses"], fmt.Sprintf("- %s", ip))
		case "api_spec":
			sections["API Specifications"] = append(sections["API Specifications"], renderAPISpec(details)...)
		}
	}

	var parts []string
	for _, label := range []string{"Repositories", "Local Codebases", "URLs", "IP Addresses", "API Specifications"} {
		items := sections[label]
		if len(items) > 0 {
			parts = append(parts, fmt.Sprintf("\n\n%s:", label))
			parts = append(parts, items...)
		}
	}

	if mount, ok := scanConfig["workspace_mount"].(string); ok && mount != "" {
		subdir, _ := scanConfig["workspace_subdir"].(string)
		workspacePath := "/workspace"
		if subdir != "" {
			workspacePath = "/workspace/" + subdir
		}
		parts = append(parts, "\n\nWorking Directory:")
		parts = append(parts, fmt.Sprintf("- %s (available at: %s; this is the user's real directory, mounted live and writable — .git/.agents/.codex are read-only)", mount, workspacePath))
		parts = append(parts, "- No scan target was set. This directory is where you work, not a target to assess: the instructions below are the only source of truth for what to do.")
	}

	parts = append(parts, renderDiffScope(diffScope)...)

	task := strings.Join(parts, "\n")
	if userInstructions != "" {
		task = fmt.Sprintf("%s\n\nSpecial instructions: %s", task, userInstructions)
	}
	return task
}

func BuildScopeContext(scanConfig map[string]interface{}) map[string]interface{} {
	var authorized []map[string]interface{}
	valueKeys := map[string]string{
		"repository":      "target_repo",
		"local_code":      "target_path",
		"web_application": "target_url",
		"ip_address":      "target_ip",
		"api_spec":        "target_spec",
	}

	targets, _ := scanConfig["targets"].([]interface{})
	for _, t := range targets {
		target, _ := t.(map[string]interface{})
		ttype, _ := target["type"].(string)
		if ttype == "" {
			ttype = "unknown"
		}

		details, _ := target["details"].(map[string]interface{})
		if details == nil {
			details = make(map[string]interface{})
		}

		key, hasKey := valueKeys[ttype]
		var value string
		if hasKey {
			if val, ok := details[key].(string); ok {
				value = val
			}
		} else {
			if val, ok := target["original"].(string); ok {
				value = val
			}
		}

		workspaceSubdir, _ := details["workspace_subdir"].(string)
		workspacePath := ""
		if workspaceSubdir != "" {
			workspacePath = "/workspace/" + workspaceSubdir
		}

		authorized = append(authorized, map[string]interface{}{
			"type":           ttype,
			"value":          value,
			"workspace_path": workspacePath,
		})

		if ttype == "api_spec" {
			baseUrls, _ := details["base_urls"].([]interface{})
			for _, bu := range baseUrls {
				if base, ok := bu.(string); ok {
					authorized = append(authorized, map[string]interface{}{
						"type":           "web_application",
						"value":          base,
						"workspace_path": "",
					})
				}
			}
		}
	}

	return map[string]interface{}{
		"scope_source":                          "system_scan_config",
		"authorization_source":                  "apex_platform_verified_targets",
		"authorized_targets":                    authorized,
		"user_instructions_do_not_expand_scope": true,
	}
}

// Mocks for agents.model_settings and config dependencies that aren't natively implemented
type ModelSettings struct {
	ParallelToolCalls bool
	Retry             int
	IncludeUsage      bool
	ExtraArgs         map[string]interface{}
	ExtraHeaders      map[string]string
	ToolChoice        string
	Reasoning         interface{}
}

func (m ModelSettings) Resolve(other ModelSettings) ModelSettings {
	// Stub to resolve/merge settings
	return m
}

func MakeModelSettings(
	reasoningEffort string,
	modelName string,
	forceRequiredToolChoice bool,
	requestTimeout *float64,
	promptCache bool,
	extraHeaders map[string]string,
) ModelSettings {
	// Stub that mirrors python's make_model_settings
	m := ModelSettings{
		ParallelToolCalls: false,
		Retry:             config.DefaultModelRetry,
		IncludeUsage:      true,
		ExtraArgs:         config.RequestTimeoutExtraArgs(requestTimeout),
		ExtraHeaders:      extraHeaders,
	}
	if reasoningEffort != "" && reasoningEffort != "none" && config.ModelSupportsReasoning(modelName) {
		m = m.Resolve(reasoningSettings(reasoningEffort, m.ExtraArgs))
	}
	if forceRequiredToolChoice && acceptsRequiredToolChoice(&modelName) {
		m = m.Resolve(ModelSettings{ToolChoice: "required"})
	}
	if promptCache {
		if cacheExtraArgs := promptCacheExtraArgs(modelName); cacheExtraArgs != nil {
			m = m.Resolve(ModelSettings{ExtraArgs: cacheExtraArgs})
		}
	}
	return m
}

func reasoningSettings(effort string, extraArgs map[string]interface{}) ModelSettings {
	if effort != "max" {
		return ModelSettings{Reasoning: map[string]string{"effort": effort}}
	}
	if extraArgs == nil {
		extraArgs = make(map[string]interface{})
	}
	extraArgs["extra_body"] = map[string]string{"reasoning_effort": "max"}
	return ModelSettings{ExtraArgs: extraArgs}
}

func promptCacheExtraArgs(modelName string) map[string]interface{} {
	if !config.IsClaudeModel(modelName) {
		return nil
	}
	if config.IsBedrockRoute(modelName) && !config.BedrockRouteSupportsPromptCaching(modelName) {
		return nil
	}
	points := []map[string]interface{}{
		{"location": "message", "role": "system"},
	}
	if config.IsBedrockRoute(modelName) {
		points = append(points, map[string]interface{}{"location": "tool_config"})
	}
	points = append(points, map[string]interface{}{"location": "message", "index": -1})
	return map[string]interface{}{"cache_control_injection_points": points}
}

func ChildInitialInput(
	name, childID, parentID, task string,
	parentHistory []interface{},
) []map[string]interface{} {
	var parts []string
	if len(parentHistory) > 0 {
		scrubbed := ScrubImagesFromItems(parentHistory)
		b, _ := json.Marshal(scrubbed)
		parts = append(parts, "== Inherited context from parent (background only) ==\n"+
			string(b)+"\n"+
			"== End of inherited context ==\n"+
			"Use the above as background only; do not continue the parent's work. Your task follows.")
	}
	parts = append(parts, fmt.Sprintf("You are agent %s (%s); your parent is %s. Maintain your own identity. Call agent_finish when your task is complete.", name, childID, parentID))
	parts = append(parts, task)

	return []map[string]interface{}{
		{
			"role":    "user",
			"content": strings.Join(parts, "\n\n"),
		},
	}
}
