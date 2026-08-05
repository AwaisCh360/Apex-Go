package agents

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/flosch/pongo2/v6"

	"github.com/AwaisCh360/Apex/apex/skills"
	"github.com/AwaisCh360/Apex/apex/utils"
)

const promptDirName = "prompts"

func init() {
	pongo2.RegisterFilter("dictsort", func(in *pongo2.Value, param *pongo2.Value) (*pongo2.Value, *pongo2.Error) {
		// Dummy implementation to allow parsing
		return in, nil
	})
}

func init() {
	pongo2.RegisterFilter("dictsort", func(in *pongo2.Value, param *pongo2.Value) (*pongo2.Value, *pongo2.Error) {
		return in, nil
	})
}

func resolveSkills(requested []string, scanMode string, isWhitebox, isRoot bool) []string {
	var ordered []string
	if requested != nil {
		ordered = append(ordered, requested...)
	}

	if scanMode == "" {
		scanMode = "deep"
	}

	ordered = append(ordered, fmt.Sprintf("scan_modes/%s", scanMode))
	ordered = append(ordered, "tooling/agent_browser", "tooling/python")

	if isRoot {
		ordered = append(ordered, "coordination/root_agent")
	}
	if isWhitebox {
		ordered = append(ordered, "coordination/source_aware_whitebox", "custom/source_aware_sast")
	}

	var deduped []string
	seen := make(map[string]bool)
	for _, skill := range ordered {
		if skill != "" && !seen[skill] {
			deduped = append(deduped, skill)
			seen[skill] = true
		}
	}
	return deduped
}

type RenderOptions struct {
	Skills              []string
	ScanMode            string
	IsWhitebox          bool
	IsRoot              bool
	Interactive         bool
	SystemPromptContext map[string]interface{}
}

// RenderSystemPrompt renders the system prompt. Returns empty string on template failure.
func RenderSystemPrompt(opts RenderOptions) string {
	scanMode := opts.ScanMode
	if scanMode == "" {
		scanMode = "deep"
	}
	sysCtx := opts.SystemPromptContext
	if sysCtx == nil {
		sysCtx = make(map[string]interface{})
	}

	promptDir := utils.GetApexResourcePath("agents", promptDirName)

	// Create a template set with a loader that searches all required directories
	loaderDirs := append([]string{promptDir}, skills.SkillSearchDirs()...)

	// We use the first found template by iterating over the loaderDirs.
	// Since Pongo2's default loader takes one base dir, we can find the file manually.
	var tpl *pongo2.Template
	var err error
	var errs []error
	for _, dir := range loaderDirs {
		tplPath := filepath.Join(dir, "system_prompt.jinja")
		b, readErr := os.ReadFile(tplPath)
		if readErr != nil {
			errs = append(errs, readErr)
			continue
		}

		s := string(b)
		s = strings.ReplaceAll(s, " | dictsort", "")
		s = strings.ReplaceAll(s, "names | join(', ')", "names|join:\", \"")

		tpl, err = pongo2.FromString(s)
		if err == nil {
			break
		}
		errs = append(errs, err)
	}

	if tpl == nil {
		log.Printf("render_system_prompt failed: %v; returning empty prompt", errs)
		return ""
	}

	skillsToLoad := resolveSkills(opts.Skills, scanMode, opts.IsWhitebox, opts.IsRoot)
	skillContent := skills.LoadSkills(skillsToLoad)

	loadedSkillNames := make([]string, 0, len(skillContent))
	for name := range skillContent {
		loadedSkillNames = append(loadedSkillNames, name)
	}

	// Prepare Pongo2 context
	ctx := pongo2.Context{
		"loaded_skill_names":    loadedSkillNames,
		"available_skills":      skills.GetAvailableSkills(),
		"interactive":           opts.Interactive,
		"is_root":               opts.IsRoot,
		"system_prompt_context": sysCtx,
		"get_skill": func(name string) string {
			if content, ok := skillContent[name]; ok {
				return content
			}
			return ""
		},
	}

	// Inject skill content variables directly into the context as Python kwargs equivalent
	for k, v := range skillContent {
		ctx[k] = v
	}

	rendered, err := tpl.Execute(ctx)
	if err != nil {
		log.Printf("render_system_prompt failed (execution error %v); returning empty prompt", err)
		return ""
	}

	log.Printf("render_system_prompt: scan_mode=%s root=%v whitebox=%v skills=%d prompt_len=%d",
		scanMode, opts.IsRoot, opts.IsWhitebox, len(skillContent), len(rendered))

	return rendered
}
