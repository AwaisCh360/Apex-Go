// Package load_skill provides a tool to fetch skill reference material into the conversation.
package load_skill

import (
	"fmt"
	"strings"

	"github.com/AwaisCh360/Apex/apex/skills"
)

// RunContextWrapper is a local stub for the Python RunContextWrapper.
type RunContextWrapper any

// FunctionTool is a local stub for the Python @function_tool decorator.
// It simulates the configuration of function tools.
func FunctionTool(timeout int) func(any) any {
	return func(fn any) any {
		return fn
	}
}

// LoadSkill returns the markdown body of one or more skills as reference material.
//
// Use this when you need exact syntax / workflow / payload guidance
// right before acting on a technology that wasn't preloaded for your
// agent. The skill content lands inline as a tool result — no
// permanent prompt change, just in-conversation reference.
//
// For permanent skill assignment, pass `skills=[…]` to
// `create_agent` when spawning a specialist child instead.
//
// Args:
//
//	skills: List of skill names (e.g. `["xss", "sql_injection"]`).
//	    Max 5. Names match the bare files under
//	    `apex/skills/<category>/<name>.md`.
func LoadSkill(ctx RunContextWrapper, requestedSkills []string) string {
	var requested []string
	if requestedSkills != nil {
		requested = append(requested, requestedSkills...)
	}

	err := skills.ValidateRequestedSkills(requested, 5)
	if err != "" {
		return "load_skill: " + err
	}

	contents := skills.LoadSkills(requested)
	if len(contents) == 0 {
		return "load_skill: no content loaded for requested skills."
	}

	var sections []string
	for _, name := range requested {
		if body, ok := contents[name]; ok {
			sections = append(sections, fmt.Sprintf("## Skill: %s\n\n%s", name, body))
		}
	}

	return strings.Join(sections, "\n\n---\n\n")
}
