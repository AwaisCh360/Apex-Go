package skills

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/AwaisCh360/Apex/apex/utils"
)

var logger = log.New(os.Stderr, "[skills] ", log.LstdFlags)

var frontmatterPattern = regexp.MustCompile(`(?s)^---\s*\n.*?\n---\s*\n`)

var internalSkillCategories = map[string]bool{
	"scan_modes":   true,
	"coordination": true,
}

const rootSkillCategory = "root"

var (
	extraSkillDirs []string
	skillDirsMu    sync.RWMutex
)

func RegisterSkillDir(path string) {
	skillDirsMu.Lock()
	defer skillDirsMu.Unlock()

	absPath, err := filepath.Abs(path)
	if err != nil {
		absPath = path
	}

	for _, dir := range extraSkillDirs {
		if dir == absPath {
			return
		}
	}
	extraSkillDirs = append(extraSkillDirs, absPath)
	logger.Printf("Registered extra skill dir: %s", absPath)
}

func RegisteredSkillDirs() []string {
	skillDirsMu.RLock()
	defer skillDirsMu.RUnlock()

	res := make([]string, len(extraSkillDirs))
	for i, dir := range extraSkillDirs {
		res[len(extraSkillDirs)-1-i] = dir // Reversed
	}
	return res
}

func SkillSearchDirs() []string {
	var roots []string
	for _, dir := range RegisteredSkillDirs() {
		if stat, err := os.Stat(dir); err == nil && stat.IsDir() {
			roots = append(roots, dir)
		}
	}
	builtin := utils.GetApexResourcePath("skills")
	if stat, err := os.Stat(builtin); err == nil && stat.IsDir() {
		roots = append(roots, builtin)
	}
	return roots
}

type skillKey struct {
	Category string
	Name     string
}

func iterUserSkillFiles() []skillKey {
	seen := make(map[skillKey]bool)
	var result []skillKey

	for _, skillsDir := range SkillSearchDirs() {
		// Root .md files
		files, _ := os.ReadDir(skillsDir)
		for _, file := range files {
			if !file.IsDir() && strings.HasSuffix(file.Name(), ".md") {
				if strings.HasPrefix(file.Name(), "__") || file.Name() == "README.md" {
					continue
				}
				name := strings.TrimSuffix(file.Name(), ".md")
				key := skillKey{Category: rootSkillCategory, Name: name}
				if !seen[key] {
					seen[key] = true
					result = append(result, key)
				}
			}
		}

		// Category directories
		for _, catDir := range files {
			if !catDir.IsDir() || strings.HasPrefix(catDir.Name(), "__") {
				continue
			}
			if internalSkillCategories[catDir.Name()] {
				continue
			}

			catPath := filepath.Join(skillsDir, catDir.Name())
			subFiles, _ := os.ReadDir(catPath)
			for _, subFile := range subFiles {
				if !subFile.IsDir() && strings.HasSuffix(subFile.Name(), ".md") {
					name := strings.TrimSuffix(subFile.Name(), ".md")
					key := skillKey{Category: catDir.Name(), Name: name}
					if !seen[key] {
						seen[key] = true
						result = append(result, key)
					}
				}
			}
		}
	}
	return result
}

func isSelectableRootSkillFile(fileName string) bool {
	return strings.HasSuffix(fileName, ".md") && !strings.HasPrefix(filepath.Base(fileName), "__") && filepath.Base(fileName) != "README.md"
}

func qualifiedSkillFile(skillsDir, category, name string) string {
	if category == rootSkillCategory {
		candidate := filepath.Join(skillsDir, name+".md")
		if stat, err := os.Stat(candidate); err == nil && !stat.IsDir() && isSelectableRootSkillFile(candidate) {
			return candidate
		}
		return ""
	}
	candidate := filepath.Join(skillsDir, category, name+".md")
	if stat, err := os.Stat(candidate); err == nil && !stat.IsDir() {
		return candidate
	}
	return ""
}

func GetAllSkillNames() map[string]bool {
	names := make(map[string]bool)
	for _, k := range iterUserSkillFiles() {
		names[k.Name] = true
	}
	return names
}

func getAllSkillKeys() map[string]bool {
	keys := make(map[string]bool)
	for _, k := range iterUserSkillFiles() {
		keys[k.Category+"/"+k.Name] = true
	}
	return keys
}

func getAmbiguousSkillNames() map[string]bool {
	counts := make(map[string]int)
	for _, k := range iterUserSkillFiles() {
		counts[k.Name]++
	}
	ambiguous := make(map[string]bool)
	for name, count := range counts {
		if count > 1 {
			ambiguous[name] = true
		}
	}
	return ambiguous
}

func qualifiedSkillFiles(skillName string) []string {
	parts := strings.SplitN(skillName, "/", 2)
	if len(parts) != 2 {
		return nil
	}
	category, name := parts[0], parts[1]
	for _, skillsDir := range SkillSearchDirs() {
		if candidate := qualifiedSkillFile(skillsDir, category, name); candidate != "" {
			return []string{candidate}
		}
	}
	return nil
}

func bareSkillFiles(skillName string) []string {
	seen := make(map[skillKey]bool)
	var candidates []string

	for _, skillsDir := range SkillSearchDirs() {
		files, _ := os.ReadDir(skillsDir)
		for _, catDir := range files {
			if !catDir.IsDir() || strings.HasPrefix(catDir.Name(), "__") || internalSkillCategories[catDir.Name()] {
				continue
			}
			key := skillKey{Category: catDir.Name(), Name: skillName}
			if seen[key] {
				continue
			}
			candidate := filepath.Join(skillsDir, catDir.Name(), skillName+".md")
			if stat, err := os.Stat(candidate); err == nil && !stat.IsDir() {
				seen[key] = true
				candidates = append(candidates, candidate)
			}
		}

		key := skillKey{Category: rootSkillCategory, Name: skillName}
		if !seen[key] {
			rootCandidate := qualifiedSkillFile(skillsDir, rootSkillCategory, skillName)
			if rootCandidate != "" {
				seen[key] = true
				candidates = append(candidates, rootCandidate)
			}
		}
	}
	return candidates
}

func GetAvailableSkills() map[string][]string {
	grouped := make(map[string][]string)
	for _, k := range iterUserSkillFiles() {
		grouped[k.Category] = append(grouped[k.Category], k.Name)
	}
	return grouped
}

func ValidateRequestedSkills(skillList []string, maxSkills int) string {
	if maxSkills <= 0 {
		maxSkills = 5
	}
	if len(skillList) > maxSkills {
		return fmt.Sprintf("Cannot specify more than %d skills per agent; got %d. Aim for 1-3 related skills per specialist.", maxSkills, len(skillList))
	}
	if len(skillList) == 0 {
		return ""
	}

	available := GetAllSkillNames()
	availableKeys := getAllSkillKeys()

	var invalid []string
	for _, s := range skillList {
		if !available[s] && !availableKeys[s] {
			invalid = append(invalid, s)
		}
	}
	if len(invalid) > 0 {
		sort.Strings(invalid)
		var availList []string
		for k := range available {
			availList = append(availList, k)
		}
		sort.Strings(availList)
		return fmt.Sprintf("Invalid skill name(s): %v. Available skills: %v", invalid, availList)
	}

	ambiguousSet := getAmbiguousSkillNames()
	var ambiguous []string
	for _, s := range skillList {
		if !strings.Contains(s, "/") && ambiguousSet[s] {
			ambiguous = append(ambiguous, s)
		}
	}
	if len(ambiguous) > 0 {
		sort.Strings(ambiguous)
		var availKeysList []string
		for k := range availableKeys {
			availKeysList = append(availKeysList, k)
		}
		sort.Strings(availKeysList)
		return fmt.Sprintf("Ambiguous skill name(s): %v. Use category-qualified names from: %v", ambiguous, availKeysList)
	}
	return ""
}

func trackSkillLoaded(skillName, filePath string) {
	builtin := utils.GetApexResourcePath("skills")
	isBuiltin := false
	if rel, err := filepath.Rel(builtin, filePath); err == nil && !strings.HasPrefix(rel, "..") && rel != ".." {
		isBuiltin = true
	}
	if !isBuiltin {
		skillName = "custom"
	}

	go func() {
		// Mock implementations for Posthog and Scarf telemetry tracking
		// posthog.SkillLoaded(skillName)
		// scarf.SkillLoaded(skillName)
	}()
}

func candidateSkillFiles(skillName string) []string {
	if strings.Contains(skillName, "/") {
		return qualifiedSkillFiles(skillName)
	}
	return bareSkillFiles(skillName)
}

func debugLog(format string, v ...interface{}) {
	if os.Getenv("APEX_DEBUG") != "" {
		logger.Printf(format, v...)
	}
}

func LoadSkills(skillNames []string) map[string]string {
	searchDirs := SkillSearchDirs()
	if len(searchDirs) == 0 {
		return make(map[string]string)
	}

	skillContent := make(map[string]string)
	for _, skillName := range skillNames {
		candidates := candidateSkillFiles(skillName)
		if len(candidates) == 0 {
			logger.Printf("Skill not found: %s", skillName)
			continue
		}
		if len(candidates) > 1 {
			logger.Printf("Ambiguous skill name %s; use a category-qualified name", skillName)
			continue
		}

		filePath := candidates[0]
		b, err := os.ReadFile(filePath)
		if err != nil {
			logger.Printf("Failed to load skill %s: %v", skillName, err)
			continue
		}

		content := string(b)
		parts := strings.Split(skillName, "/")
		varName := parts[len(parts)-1]

		stripped := frontmatterPattern.ReplaceAllString(content, "")
		skillContent[varName] = strings.TrimLeft(stripped, " \t\r\n")

		debugLog("Loaded skill: %s -> %s", skillName, varName)
		trackSkillLoaded(varName, filePath)
	}

	debugLog("load_skills: %d skill(s) resolved", len(skillContent))
	return skillContent
}
