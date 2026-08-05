package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type DiffScopeResult struct {
	Active           bool
	Mode             string
	InstructionBlock string
	Metadata         map[string]interface{}
}

func ReadTargetListFile(path string) ([]string, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("--target-list path must not be empty.")
	}
	expanded := os.ExpandEnv(path)
	if strings.HasPrefix(expanded, "~/") {
		dirname, _ := os.UserHomeDir()
		expanded = filepath.Join(dirname, expanded[2:])
	}

	content, err := os.ReadFile(expanded)
	if err != nil {
		return nil, fmt.Errorf("Failed to read target list file '%s': %v", path, err)
	}

	if !utf8.Valid(content) {
		return nil, fmt.Errorf("Target list file '%s' must be valid UTF-8 text.", path)
	}

	var targets []string
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			targets = append(targets, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("Failed to read target list file '%s': %v", path, err)
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("Target list file '%s' is empty.", path)
	}
	return targets, nil
}

func isHttpGitRepo(targetUrl string) bool {
	u := strings.TrimRight(targetUrl, "/") + "/info/refs?service=git-upload-pack"
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "git/apex")
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return resp.StatusCode == 401
	}
	return strings.Contains(resp.Header.Get("Content-Type"), "x-git-upload-pack-advertisement")
}

func DetectSpecFormat(path string) string {
	lowerPath := strings.ToLower(path)
	if strings.HasSuffix(lowerPath, ".json") || strings.HasSuffix(lowerPath, ".yaml") || strings.HasSuffix(lowerPath, ".yml") {
        content, err := os.ReadFile(path)
        if err == nil && (strings.Contains(string(content), "openapi") || strings.Contains(string(content), "swagger") || strings.Contains(string(content), "info")) {
		    return "openapi"
        }
	}
	return ""
}

func checkMountableDir(path string) error {
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("not an existing directory")
	}

	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		resolved = path
	}
	resolved = strings.ToLower(filepath.Clean(resolved))

	forbiddenRoots := []string{
		"/", "/private", "/var", "/opt", "/home", "/root", "/srv", "/users", "/volumes",
	}
	for _, root := range forbiddenRoots {
		if resolved == root {
			return fmt.Errorf("Refusing to mount '%s' into the sandbox: it is a system or home directory", path)
		}
	}

	forbiddenTrees := []string{
		"/bin", "/sbin", "/usr", "/etc", "/private/etc", "/lib", "/lib64", "/nix/store", "/run/current-system/sw",
		"/applications", "/library", "/system", "/dev", "/boot", "/proc", "/sys",
	}
	for _, tree := range forbiddenTrees {
		if strings.HasPrefix(resolved, tree+"/") || resolved == tree {
			return fmt.Errorf("Refusing to mount '%s' into the sandbox: it is a system or home directory", path)
		}
	}

	forbiddenDirs := map[string]bool{
		".ssh": true, ".tsh": true, ".brev": true, ".gnupg": true, ".aws": true,
		".azure": true, ".kube": true, ".docker": true, ".config": true,
		".npm": true, ".pki": true, ".terraform.d": true,
	}
	parts := strings.Split(resolved, string(os.PathSeparator))
	for _, part := range parts {
		if forbiddenDirs[strings.ToLower(part)] {
			return fmt.Errorf("Refusing to mount '%s' into the sandbox: '%s' holds credentials", path, part)
		}
	}
	return nil
}

func InferTargetType(target string) (string, map[string]interface{}, error) {
	if target == "" {
		return "", nil, errors.New("Target must be a non-empty string")
	}
	target = strings.TrimSpace(target)

	if strings.HasPrefix(target, "git@") || strings.HasPrefix(target, "git://") {
		return "repository", map[string]interface{}{"target_repo": target}, nil
	}

	parsed, err := url.Parse(target)
	if err == nil && parsed.Scheme != "" {
		if parsed.Scheme == "postman" {
			collectionUid := strings.Trim(parsed.Host+parsed.Path, "/")
			if collectionUid == "" {
				return "", nil, fmt.Errorf("Missing Postman collection id in '%s'", target)
			}
			details := map[string]interface{}{
				"target_spec":    target,
				"spec_format":    "postman",
				"source":         "postman_api",
				"collection_uid": collectionUid,
			}
			query := parsed.Query()
			if envs, ok := query["env"]; ok && len(envs) > 0 {
				details["environment_uid"] = strings.TrimSpace(envs[0])
			} else if envs, ok := query["environment"]; ok && len(envs) > 0 {
				details["environment_uid"] = strings.TrimSpace(envs[0])
			}
			return "api_spec", details, nil
		}

		if parsed.Scheme == "http" || parsed.Scheme == "https" {
			if parsed.User != nil {
				return "repository", map[string]interface{}{"target_repo": target}, nil
			}
			if strings.HasSuffix(strings.TrimRight(parsed.Path, "/"), ".git") {
				return "repository", map[string]interface{}{"target_repo": target}, nil
			}
			if parsed.RawQuery != "" || parsed.Fragment != "" {
				return "web_application", map[string]interface{}{"target_url": target}, nil
			}
			pathSegments := strings.Split(parsed.Path, "/")
			var nonEmpty []string
			for _, s := range pathSegments {
				if s != "" {
					nonEmpty = append(nonEmpty, s)
				}
			}
			if len(nonEmpty) >= 2 && isHttpGitRepo(target) {
				return "repository", map[string]interface{}{"target_repo": target}, nil
			}
			return "web_application", map[string]interface{}{"target_url": target}, nil
		}
	}

	if ip := net.ParseIP(target); ip != nil {
		return "ip_address", map[string]interface{}{"target_ip": ip.String()}, nil
	}

	expanded := os.ExpandEnv(target)
	if strings.HasPrefix(expanded, "~/") {
		dirname, _ := os.UserHomeDir()
		expanded = filepath.Join(dirname, expanded[2:])
	}
	path, err := filepath.Abs(expanded)
	if err == nil {
		info, err := os.Stat(path)
		if err == nil {
			if info.IsDir() {
				if err := checkMountableDir(path); err != nil {
					return "", nil, err
				}
				return "local_code", map[string]interface{}{"target_path": path}, nil
			}
			specFmt := DetectSpecFormat(path)
			if specFmt != "" {
				return "api_spec", map[string]interface{}{"target_spec": path, "spec_format": specFmt}, nil
			}
			return "", nil, fmt.Errorf("Path exists but is not a directory: %s", target)
		}
	}

	if strings.HasSuffix(target, ".git") {
		return "repository", map[string]interface{}{"target_repo": target}, nil
	}

	if strings.Contains(target, "/") {
		parts := strings.SplitN(target, "/", 2)
		hostPart := parts[0]
		pathPart := parts[1]
		if strings.Contains(hostPart, ".") && !strings.HasPrefix(hostPart, ".") && pathPart != "" {
			fullUrl := "https://" + target
			if isHttpGitRepo(fullUrl) {
				return "repository", map[string]interface{}{"target_repo": fullUrl}, nil
			}
			return "web_application", map[string]interface{}{"target_url": fullUrl}, nil
		}
	}

	if strings.Contains(target, ".") && !strings.Contains(target, "/") && !strings.HasPrefix(target, ".") {
		parts := strings.Split(target, ".")
		valid := true
		for _, p := range parts {
			if strings.TrimSpace(p) == "" {
				valid = false
				break
			}
		}
		if valid && len(parts) >= 2 {
			return "web_application", map[string]interface{}{"target_url": "https://" + target}, nil
		}
	}

	return "", nil, fmt.Errorf("Invalid target: %s\nTarget must be one of:\n- A valid URL (http:// or https://)\n- A Git repository URL\n- A local directory path\n- An API spec file\n- A Postman collection\n- A domain name\n- An IP address", target)
}

func DedupeLocalTargets(targets []map[string]interface{}) []map[string]interface{} {
	var result []map[string]interface{}
	seenPaths := make(map[string]bool)
	for _, target := range targets {
		details, ok := target["details"].(map[string]interface{})
		if !ok {
			result = append(result, target)
			continue
		}
		path, hasPath := details["target_path"].(string)
		if target["type"] != "local_code" || !hasPath {
			result = append(result, target)
			continue
		}
		if !seenPaths[path] {
			seenPaths[path] = true
			result = append(result, target)
		}
	}
	return result
}

func sanitizeName(name string) string {
	re := regexp.MustCompile(`[^A-Za-z0-9._-]+`)
	sanitized := re.ReplaceAllString(strings.TrimSpace(name), "-")
	if sanitized == "" {
		return "target"
	}
	return sanitized
}

func DeriveRepoBaseName(repoUrl string) string {
	repoUrl = strings.TrimRight(repoUrl, "/")
	pathPart := repoUrl
	if strings.Contains(repoUrl, ":") && strings.HasPrefix(repoUrl, "git@") {
		parts := strings.SplitN(repoUrl, ":", 2)
		pathPart = parts[1]
	} else {
		parsed, err := url.Parse(repoUrl)
		if err == nil && parsed.Path != "" {
			pathPart = parsed.Path
		}
	}
	parts := strings.Split(pathPart, "/")
	candidate := parts[len(parts)-1]
	if strings.HasSuffix(candidate, ".git") {
		candidate = candidate[:len(candidate)-4]
	}
	if candidate == "" {
		candidate = "repository"
	}
	return sanitizeName(candidate)
}

func DeriveLocalBaseName(pathStr string) string {
	base := filepath.Base(pathStr)
	if base == "" {
		base = "workspace"
	}
	return sanitizeName(base)
}

func AssignWorkspaceSubdirs(targets []map[string]interface{}) {
	nameCounts := make(map[string]int)
	for _, target := range targets {
		targetType, _ := target["type"].(string)
		details, ok := target["details"].(map[string]interface{})
		if !ok {
			continue
		}

		var baseName string
		if targetType == "repository" {
			baseName = DeriveRepoBaseName(details["target_repo"].(string))
		} else if targetType == "local_code" {
			targetPath, ok := details["target_path"].(string)
			if !ok {
				targetPath = "local"
			}
			baseName = DeriveLocalBaseName(targetPath)
		}

		if baseName == "" {
			continue
		}

		nameCounts[baseName]++
		count := nameCounts[baseName]

		workspaceSubdir := baseName
		if count > 1 {
			workspaceSubdir = fmt.Sprintf("%s-%d", baseName, count)
		}
		details["workspace_subdir"] = workspaceSubdir
	}
}

func isLocalhostHost(host string) bool {
	hostLower := strings.ToLower(strings.Trim(host, "[]"))
	if hostLower == "localhost" || hostLower == "0.0.0.0" || hostLower == "::1" {
		return true
	}
	ip := net.ParseIP(hostLower)
	if ip != nil {
		if ip.IsLoopback() {
			return true
		}
	}
	return false
}

func RewriteLocalhostTargets(targets []map[string]interface{}, gateway string) {
	for _, target := range targets {
		targetType, _ := target["type"].(string)
		details, ok := target["details"].(map[string]interface{})
		if !ok {
			continue
		}

		if targetType == "web_application" {
			targetUrl, _ := details["target_url"].(string)
			parsed, err := url.Parse(targetUrl)
			if err == nil {
				host := parsed.Hostname()
				if host != "" && isLocalhostHost(host) {
					port := parsed.Port()
					newHost := gateway
					if port != "" {
						newHost = newHost + ":" + port
					}
					parsed.Host = newHost
					details["target_url"] = parsed.String()
				}
			}
		} else if targetType == "ip_address" {
			targetIp, _ := details["target_ip"].(string)
			if targetIp != "" && isLocalhostHost(targetIp) {
				details["target_ip"] = gateway
			}
		}
	}
}

func slugifyForRunName(text string, maxLength int) string {
	text = strings.ToLower(strings.TrimSpace(text))
	re := regexp.MustCompile(`[^a-z0-9]+`)
	text = re.ReplaceAllString(text, "-")
	text = strings.Trim(text, "-")
	if len(text) > maxLength {
		text = strings.TrimRight(text[:maxLength], "-")
	}
	if text == "" {
		return "pentest"
	}
	return text
}

func deriveTargetLabelForRunName(targetsInfo []map[string]interface{}) string {
	if len(targetsInfo) == 0 {
		return "pentest"
	}
	first := targetsInfo[0]
	targetType, _ := first["type"].(string)
	details, _ := first["details"].(map[string]interface{})
	if details == nil {
		details = make(map[string]interface{})
	}
	original, _ := first["original"].(string)

	if targetType == "web_application" {
		urlStr, _ := details["target_url"].(string)
		if urlStr == "" {
			urlStr = original
		}
		parsed, err := url.Parse(urlStr)
		if err == nil {
			if parsed.Host != "" {
				return parsed.Host
			}
			if parsed.Path != "" {
				return parsed.Path
			}
		}
		return urlStr
	}

	if targetType == "repository" {
		repo, _ := details["target_repo"].(string)
		if repo == "" {
			repo = original
		}
		parsed, err := url.Parse(repo)
		path := repo
		if err == nil && parsed.Path != "" {
			path = parsed.Path
		}
		parts := strings.Split(strings.TrimRight(path, "/"), "/")
		name := parts[len(parts)-1]
		if name == "" {
			name = path
		}
		if strings.HasSuffix(name, ".git") {
			name = name[:len(name)-4]
		}
		return name
	}

	if targetType == "local_code" {
		pathStr, _ := details["target_path"].(string)
		if pathStr == "" {
			pathStr = original
		}
		name := filepath.Base(pathStr)
		if name != "" {
			return name
		}
		return pathStr
	}

	if targetType == "ip_address" {
		ip, _ := details["target_ip"].(string)
		if ip != "" {
			return ip
		}
		return original
	}

	if targetType == "api_spec" {
		source, _ := details["source"].(string)
		if source == "postman_api" {
			return "postman-collection"
		}
		specPath, _ := details["target_spec"].(string)
		if specPath == "" {
			specPath = original
		}
		name := strings.TrimSuffix(filepath.Base(specPath), filepath.Ext(specPath))
		if name != "" {
			return name
		}
		return specPath
	}

	if original != "" {
		return original
	}
	return "pentest"
}

func GenerateRunName(targets []map[string]interface{}) string {
	baseLabel := deriveTargetLabelForRunName(targets)
	slug := slugifyForRunName(baseLabel, 32)
	bytes := make([]byte, 2)
	rand.Read(bytes)
	randomSuffix := hex.EncodeToString(bytes)
	return fmt.Sprintf("%s_%s", slug, randomSuffix)
}

func CloneRepository(repoUrl, runName, destName string) (string, error) {
	gitExecutable, err := exec.LookPath("git")
	if err != nil {
		return "", fmt.Errorf("Git executable not found in PATH")
	}

	tempDir := filepath.Join(os.TempDir(), "apex_repos", runName)
	os.MkdirAll(tempDir, 0755)

	repoName := destName
	if repoName == "" {
		base := filepath.Base(repoUrl)
		if strings.HasSuffix(base, ".git") {
			repoName = base[:len(base)-4]
		} else {
			repoName = base
		}
	}

	clonePath := filepath.Join(tempDir, repoName)
	if _, err := os.Stat(clonePath); err == nil {
		os.RemoveAll(clonePath)
	}

	cmd := exec.Command(gitExecutable, "clone", repoUrl, clonePath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("Could not clone repository %s: %s", repoUrl, string(output))
	}

	absPath, _ := filepath.Abs(clonePath)
	return absPath, nil
}

func CollectLocalSources(targets []map[string]interface{}) []map[string]interface{} {
	var localSources []map[string]interface{}
	for _, target := range targets {
		details, ok := target["details"].(map[string]interface{})
		if !ok {
			continue
		}
		workspaceSubdir, _ := details["workspace_subdir"].(string)
		targetType, _ := target["type"].(string)

		if targetType == "local_code" {
			targetPath, ok := details["target_path"].(string)
			if ok {
				localSources = append(localSources, map[string]interface{}{
					"source_path":      targetPath,
					"workspace_subdir": workspaceSubdir,
					"protect_metadata": true,
				})
			}
		} else if targetType == "repository" {
			clonedPath, ok := details["cloned_repo_path"].(string)
			if ok {
				localSources = append(localSources, map[string]interface{}{
					"source_path":      clonedPath,
					"workspace_subdir": workspaceSubdir,
					"protect_metadata": false,
				})
			}
		}
	}
	return localSources
}

func WriteFetchedCollection(collection map[string]interface{}, collectionUID string) string {
	staging := filepath.Join(os.TempDir(), "apex_api_specs", "fetched")
	os.MkdirAll(staging, 0755)

	sanitized := sanitizeName(collectionUID)
	path := filepath.Join(staging, fmt.Sprintf("%s.postman_collection.json", sanitized))

	data, err := json.MarshalIndent(collection, "", "  ")
	if err == nil {
		os.WriteFile(path, data, 0644)
	}

	return path
}

func StageApiSpecs(targets []map[string]interface{}, runName string) []map[string]interface{} {
	var specs []map[string]interface{}
	for _, target := range targets {
		if targetType, _ := target["type"].(string); targetType == "api_spec" {
			specs = append(specs, target)
		}
	}
	if len(specs) == 0 {
		return nil
	}

	staging := filepath.Join(os.TempDir(), "apex_api_specs", runName)
	os.MkdirAll(staging, 0755)

	used := make(map[string]bool)
	for _, target := range specs {
		details, _ := target["details"].(map[string]interface{})
		targetSpec, _ := details["target_spec"].(string)
		source := targetSpec
		name := filepath.Base(source)
		stem := strings.TrimSuffix(name, filepath.Ext(name))
		suffix := filepath.Ext(name)
		count := 1
		for used[name] {
			count++
			name = fmt.Sprintf("%s-%d%s", stem, count, suffix)
		}
		used[name] = true

		srcFile, _ := os.Open(source)
		dstFile, _ := os.Create(filepath.Join(staging, name))
		io.Copy(dstFile, srcFile)
		srcFile.Close()
		dstFile.Close()

		details["workspace_path"] = fmt.Sprintf("/workspace/api-specs/%s", name)
	}

	return []map[string]interface{}{
		{
			"source_path":      staging,
			"workspace_subdir": "api-specs",
			"protect_metadata": false,
		},
	}
}

var supportedScopeModes = map[string]bool{"auto": true, "diff": true, "full": true}

const maxFilesPerSection = 120

type DiffEntry struct {
	Status     string
	Path       string
	OldPath    *string
	Similarity *int
}

type RepoDiffScope struct {
	SourcePath        string
	WorkspaceSubdir   *string
	BaseRef           string
	MergeBase         string
	AddedFiles        []string
	ModifiedFiles     []string
	RenamedFiles      []map[string]interface{}
	DeletedFiles      []string
	AnalyzableFiles   []string
	TruncatedSections map[string]bool
}

func (r *RepoDiffScope) ToMetadata() map[string]interface{} {
	return map[string]interface{}{
		"source_path":            r.SourcePath,
		"workspace_subdir":       r.WorkspaceSubdir,
		"base_ref":               r.BaseRef,
		"merge_base":             r.MergeBase,
		"added_files":            r.AddedFiles,
		"modified_files":         r.ModifiedFiles,
		"renamed_files":          r.RenamedFiles,
		"deleted_files":          r.DeletedFiles,
		"analyzable_files":       r.AnalyzableFiles,
		"added_files_count":      len(r.AddedFiles),
		"modified_files_count":   len(r.ModifiedFiles),
		"renamed_files_count":    len(r.RenamedFiles),
		"deleted_files_count":    len(r.DeletedFiles),
		"analyzable_files_count": len(r.AnalyzableFiles),
		"truncated_sections":     r.TruncatedSections,
	}
}

func runGitCommand(repoPath string, args []string, check bool) (string, string, error) {
	cmdArgs := append([]string{"-C", repoPath}, args...)
	cmd := exec.Command("git", cmdArgs...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if check && err != nil {
		return stdout.String(), stderr.String(), err
	}
	return stdout.String(), stderr.String(), err
}

func runGitCommandRaw(repoPath string, args []string, check bool) ([]byte, []byte, error) {
	cmdArgs := append([]string{"-C", repoPath}, args...)
	cmd := exec.Command("git", cmdArgs...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if check && err != nil {
		return stdout.Bytes(), stderr.Bytes(), err
	}
	return stdout.Bytes(), stderr.Bytes(), err
}

func isCiEnvironment(env map[string]string) bool {
	keys := []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL", "BUILDKITE", "CIRCLECI"}
	for _, key := range keys {
		if val, ok := env[key]; ok && val != "" {
			return true
		}
	}
	return false
}

func isPrEnvironment(env map[string]string) bool {
	keys := []string{
		"GITHUB_BASE_REF",
		"GITHUB_HEAD_REF",
		"CI_MERGE_REQUEST_TARGET_BRANCH_NAME",
		"GITLAB_MERGE_REQUEST_TARGET_BRANCH_NAME",
		"SYSTEM_PULLREQUEST_TARGETBRANCH",
	}
	for _, key := range keys {
		if val, ok := env[key]; ok && val != "" {
			return true
		}
	}
	return false
}

func isGitRepo(repoPath string) bool {
	stdout, _, err := runGitCommand(repoPath, []string{"rev-parse", "--is-inside-work-tree"}, false)
	return err == nil && strings.ToLower(strings.TrimSpace(stdout)) == "true"
}

func isRepoShallow(repoPath string) bool {
	stdout, _, err := runGitCommand(repoPath, []string{"rev-parse", "--is-shallow-repository"}, false)
	if err == nil {
		val := strings.ToLower(strings.TrimSpace(stdout))
		if val == "true" || val == "false" {
			return val == "true"
		}
	}

	gitMeta := filepath.Join(repoPath, ".git")
	if info, err := os.Stat(gitMeta); err == nil {
		if info.IsDir() {
			_, err := os.Stat(filepath.Join(gitMeta, "shallow"))
			return err == nil
		}
		if !info.IsDir() {
			content, err := os.ReadFile(gitMeta)
			if err == nil {
				strContent := strings.TrimSpace(string(content))
				if strings.HasPrefix(strContent, "gitdir:") {
					gitDir := strings.TrimSpace(strings.SplitN(strContent, ":", 2)[1])
					resolved := filepath.Join(repoPath, gitDir)
					_, err := os.Stat(filepath.Join(resolved, "shallow"))
					return err == nil
				}
			}
		}
	}
	return false
}

func gitRefExists(repoPath, ref string) bool {
	_, _, err := runGitCommand(repoPath, []string{"rev-parse", "--verify", "--quiet", ref}, false)
	return err == nil
}

func resolveOriginHeadRef(repoPath string) *string {
	stdout, _, err := runGitCommand(repoPath, []string{"symbolic-ref", "--quiet", "refs/remotes/origin/HEAD"}, false)
	if err != nil {
		return nil
	}
	ref := strings.TrimSpace(stdout)
	if ref == "" {
		return nil
	}
	return &ref
}

func extractBranchName(ref *string) *string {
	if ref == nil {
		return nil
	}
	val := strings.TrimSpace(*ref)
	if val == "" {
		return nil
	}
	parts := strings.Split(val, "/")
	res := parts[len(parts)-1]
	return &res
}

func extractGithubBaseSha(env map[string]string) *string {
	eventPath, ok := env["GITHUB_EVENT_PATH"]
	if !ok {
		return nil
	}
	eventPath = strings.TrimSpace(eventPath)
	if eventPath == "" {
		return nil
	}
	content, err := os.ReadFile(eventPath)
	if err != nil {
		return nil
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(content, &payload); err != nil {
		return nil
	}
	pr, ok := payload["pull_request"].(map[string]interface{})
	if !ok {
		return nil
	}
	base, ok := pr["base"].(map[string]interface{})
	if !ok {
		return nil
	}
	sha, ok := base["sha"].(string)
	if ok && strings.TrimSpace(sha) != "" {
		res := strings.TrimSpace(sha)
		return &res
	}
	return nil
}

func resolveDefaultBranchName(repoPath string, env map[string]string) *string {
	if githubBaseRef, ok := env["GITHUB_BASE_REF"]; ok {
		githubBaseRef = strings.TrimSpace(githubBaseRef)
		if githubBaseRef != "" {
			return &githubBaseRef
		}
	}

	originHead := resolveOriginHeadRef(repoPath)
	if originHead != nil {
		branch := extractBranchName(originHead)
		if branch != nil {
			return branch
		}
	}

	if gitRefExists(repoPath, "refs/remotes/origin/main") {
		main := "main"
		return &main
	}
	if gitRefExists(repoPath, "refs/remotes/origin/master") {
		master := "master"
		return &master
	}

	return nil
}

func resolveBaseRef(repoPath string, diffBase *string, env map[string]string) (string, error) {
	if diffBase != nil && strings.TrimSpace(*diffBase) != "" {
		return strings.TrimSpace(*diffBase), nil
	}

	if githubBaseRef, ok := env["GITHUB_BASE_REF"]; ok {
		githubBaseRef = strings.TrimSpace(githubBaseRef)
		if githubBaseRef != "" {
			candidate := fmt.Sprintf("refs/remotes/origin/%s", githubBaseRef)
			if gitRefExists(repoPath, candidate) {
				return candidate, nil
			}
		}
	}

	githubBaseSha := extractGithubBaseSha(env)
	if githubBaseSha != nil && gitRefExists(repoPath, *githubBaseSha) {
		return *githubBaseSha, nil
	}

	originHead := resolveOriginHeadRef(repoPath)
	if originHead != nil && gitRefExists(repoPath, *originHead) {
		return *originHead, nil
	}

	if gitRefExists(repoPath, "refs/remotes/origin/main") {
		return "refs/remotes/origin/main", nil
	}
	if gitRefExists(repoPath, "refs/remotes/origin/master") {
		return "refs/remotes/origin/master", nil
	}

	return "", fmt.Errorf("Unable to resolve a base ref for diff-scope. Pass --diff-base explicitly (for example: --diff-base origin/main).")
}

func getCurrentBranchName(repoPath string) *string {
	stdout, _, err := runGitCommand(repoPath, []string{"rev-parse", "--abbrev-ref", "HEAD"}, false)
	if err != nil {
		return nil
	}
	branchName := strings.TrimSpace(stdout)
	if branchName == "" || branchName == "HEAD" {
		return nil
	}
	return &branchName
}

func parseNameStatusZ(rawOutput []byte) []DiffEntry {
	if len(rawOutput) == 0 {
		return []DiffEntry{}
	}

	parts := bytes.Split(rawOutput, []byte{0})
	var tokens []string
	for _, part := range parts {
		if len(part) > 0 {
			tokens = append(tokens, string(part))
		}
	}

	var entries []DiffEntry
	index := 0
	for index < len(tokens) {
		token := tokens[index]
		statusRaw := token
		statusCode := statusRaw[:1]
		var similarity *int
		if len(statusRaw) > 1 {
			simStr := statusRaw[1:]
			if val, err := strconv.Atoi(simStr); err == nil {
				similarity = &val
			}
		}

		if (statusCode == "R" || statusCode == "C") && index+2 < len(tokens) {
			oldPath := tokens[index+1]
			newPath := tokens[index+2]
			entries = append(entries, DiffEntry{
				Status:     statusCode,
				Path:       newPath,
				OldPath:    &oldPath,
				Similarity: similarity,
			})
			index += 3
			continue
		}

		if index+1 < len(tokens) {
			path := tokens[index+1]
			entries = append(entries, DiffEntry{
				Status:     statusCode,
				Path:       path,
				Similarity: similarity,
			})
			index += 2
			continue
		}
		break
	}
	return entries
}

func appendUnique(container *[]string, seen map[string]bool, path string) {
	if path != "" && !seen[path] {
		seen[path] = true
		*container = append(*container, path)
	}
}

func classifyDiffEntries(entries []DiffEntry) map[string]interface{} {
	var addedFiles []string
	var modifiedFiles []string
	var deletedFiles []string
	var renamedFiles []map[string]interface{}
	var analyzableFiles []string

	analyzableSeen := make(map[string]bool)
	modifiedSeen := make(map[string]bool)

	for _, entry := range entries {
		path := entry.Path
		if path == "" {
			continue
		}

		if entry.Status == "D" {
			deletedFiles = append(deletedFiles, path)
			continue
		}

		if entry.Status == "A" {
			addedFiles = append(addedFiles, path)
			appendUnique(&analyzableFiles, analyzableSeen, path)
			continue
		}

		if entry.Status == "M" {
			appendUnique(&modifiedFiles, modifiedSeen, path)
			appendUnique(&analyzableFiles, analyzableSeen, path)
			continue
		}

		if entry.Status == "R" {
			renameMap := map[string]interface{}{
				"new_path": path,
			}
			if entry.OldPath != nil {
				renameMap["old_path"] = *entry.OldPath
			} else {
				renameMap["old_path"] = nil
			}
			if entry.Similarity != nil {
				renameMap["similarity"] = *entry.Similarity
			} else {
				renameMap["similarity"] = nil
			}
			renamedFiles = append(renamedFiles, renameMap)

			appendUnique(&analyzableFiles, analyzableSeen, path)
			if entry.Similarity == nil || *entry.Similarity < 100 {
				appendUnique(&modifiedFiles, modifiedSeen, path)
			}
			continue
		}

		if entry.Status == "C" {
			appendUnique(&modifiedFiles, modifiedSeen, path)
			appendUnique(&analyzableFiles, analyzableSeen, path)
			continue
		}

		appendUnique(&modifiedFiles, modifiedSeen, path)
		appendUnique(&analyzableFiles, analyzableSeen, path)
	}

	if addedFiles == nil {
		addedFiles = []string{}
	}
	if modifiedFiles == nil {
		modifiedFiles = []string{}
	}
	if deletedFiles == nil {
		deletedFiles = []string{}
	}
	if renamedFiles == nil {
		renamedFiles = []map[string]interface{}{}
	}
	if analyzableFiles == nil {
		analyzableFiles = []string{}
	}

	return map[string]interface{}{
		"added_files":      addedFiles,
		"modified_files":   modifiedFiles,
		"deleted_files":    deletedFiles,
		"renamed_files":    renamedFiles,
		"analyzable_files": analyzableFiles,
	}
}

func truncateFileList(files []string, maxFiles int) ([]string, bool) {
	if len(files) <= maxFiles {
		return files, false
	}
	return files[:maxFiles], true
}

func buildDiffScopeInstruction(scopes []RepoDiffScope) string {
	var lines []string
	lines = append(lines,
		"The user is requesting a review of a Pull Request.",
		"Instruction: Direct your analysis primarily at the changes in the listed files. "+
			"You may reference other files in the repository for context (imports, definitions, "+
			"usage), but report findings only if they relate to the listed changes.",
		"For Added files, review the entire file content.",
		"For Modified files, focus primarily on the changed areas.",
	)

	for _, scope := range scopes {
		repoName := "repository"
		if scope.WorkspaceSubdir != nil && *scope.WorkspaceSubdir != "" {
			repoName = *scope.WorkspaceSubdir
		} else if scope.SourcePath != "" {
			repoName = filepath.Base(scope.SourcePath)
		}

		lines = append(lines, "")
		lines = append(lines, fmt.Sprintf("Repository Scope: %s", repoName))
		lines = append(lines, fmt.Sprintf("Base reference: %s", scope.BaseRef))
		lines = append(lines, fmt.Sprintf("Merge base: %s", scope.MergeBase))

		focusFiles, focusTruncated := truncateFileList(scope.AnalyzableFiles, maxFilesPerSection)
		if scope.TruncatedSections == nil {
			scope.TruncatedSections = make(map[string]bool)
		}
		scope.TruncatedSections["analyzable_files"] = focusTruncated

		if len(focusFiles) > 0 {
			lines = append(lines, "Primary Focus (changed files to analyze):")
			for _, path := range focusFiles {
				lines = append(lines, fmt.Sprintf("- %s", path))
			}
			if focusTruncated {
				lines = append(lines, fmt.Sprintf("- ... (%d more files)", len(scope.AnalyzableFiles)-len(focusFiles)))
			}
		} else {
			lines = append(lines, "Primary Focus: No analyzable changed files detected.")
		}

		addedFiles, addedTruncated := truncateFileList(scope.AddedFiles, maxFilesPerSection)
		scope.TruncatedSections["added_files"] = addedTruncated
		if len(addedFiles) > 0 {
			lines = append(lines, "Added files (review entire file):")
			for _, path := range addedFiles {
				lines = append(lines, fmt.Sprintf("- %s", path))
			}
			if addedTruncated {
				lines = append(lines, fmt.Sprintf("- ... (%d more files)", len(scope.AddedFiles)-len(addedFiles)))
			}
		}

		modifiedFiles, modifiedTruncated := truncateFileList(scope.ModifiedFiles, maxFilesPerSection)
		scope.TruncatedSections["modified_files"] = modifiedTruncated
		if len(modifiedFiles) > 0 {
			lines = append(lines, "Modified files (focus on changes):")
			for _, path := range modifiedFiles {
				lines = append(lines, fmt.Sprintf("- %s", path))
			}
			if modifiedTruncated {
				lines = append(lines, fmt.Sprintf("- ... (%d more files)", len(scope.ModifiedFiles)-len(modifiedFiles)))
			}
		}

		if len(scope.RenamedFiles) > 0 {
			var renameLines []string
			for _, rename := range scope.RenamedFiles {
				oldPath := "unknown"
				if op, ok := rename["old_path"].(string); ok {
					oldPath = op
				} else if rename["old_path"] == nil {
					// fine, already unknown
				}
				newPath := "unknown"
				if np, ok := rename["new_path"].(string); ok {
					newPath = np
				}
				similarity := rename["similarity"]
				if simInt, ok := similarity.(int); ok {
					renameLines = append(renameLines, fmt.Sprintf("- %s -> %s (similarity %d%%)", oldPath, newPath, simInt))
				} else {
					renameLines = append(renameLines, fmt.Sprintf("- %s -> %s", oldPath, newPath))
				}
			}
			lines = append(lines, "Renamed files:")
			lines = append(lines, renameLines...)
		}

		deletedFiles, deletedTruncated := truncateFileList(scope.DeletedFiles, maxFilesPerSection)
		scope.TruncatedSections["deleted_files"] = deletedTruncated
		if len(deletedFiles) > 0 {
			lines = append(lines, "Note: These files were deleted (context only, not analyzable):")
			for _, path := range deletedFiles {
				lines = append(lines, fmt.Sprintf("- %s", path))
			}
			if deletedTruncated {
				lines = append(lines, fmt.Sprintf("- ... (%d more files)", len(scope.DeletedFiles)-len(deletedFiles)))
			}
		}
	}
	return strings.Join(lines, "\n")
}

func shouldActivateAutoScope(localSources []map[string]interface{}, nonInteractive bool, env map[string]string) bool {
	if len(localSources) == 0 {
		return false
	}
	if !nonInteractive {
		return false
	}
	if !isCiEnvironment(env) {
		return false
	}
	if isPrEnvironment(env) {
		return true
	}

	for _, source := range localSources {
		sourcePath, ok := source["source_path"].(string)
		if !ok || sourcePath == "" {
			continue
		}
		if !isGitRepo(sourcePath) {
			continue
		}
		currentBranch := getCurrentBranchName(sourcePath)
		defaultBranch := resolveDefaultBranchName(sourcePath, env)
		if currentBranch != nil && defaultBranch != nil && *currentBranch != *defaultBranch {
			return true
		}
	}
	return false
}

func resolveRepoDiffScope(source map[string]interface{}, diffBase *string, env map[string]string) (RepoDiffScope, error) {
	sourcePath, _ := source["source_path"].(string)
	var workspaceSubdir *string
	if ws, ok := source["workspace_subdir"].(string); ok {
		workspaceSubdir = &ws
	}

	if !isGitRepo(sourcePath) {
		return RepoDiffScope{}, fmt.Errorf("Source is not a git repository: %s", sourcePath)
	}

	if isRepoShallow(sourcePath) {
		return RepoDiffScope{}, fmt.Errorf("Apex requires full git history for diff-scope. Please set fetch-depth: 0 in your CI config.")
	}

	baseRef, err := resolveBaseRef(sourcePath, diffBase, env)
	if err != nil {
		return RepoDiffScope{}, err
	}

	stdout, stderr, err := runGitCommand(sourcePath, []string{"merge-base", baseRef, "HEAD"}, false)
	if err != nil {
		errMsg := strings.TrimSpace(stderr)
		if errMsg == "" {
			errMsg = "Ensure the base branch history is fetched and reachable."
		}
		return RepoDiffScope{}, fmt.Errorf("Unable to compute merge-base against '%s' for '%s'. %s", baseRef, sourcePath, errMsg)
	}

	mergeBase := strings.TrimSpace(stdout)
	if mergeBase == "" {
		return RepoDiffScope{}, fmt.Errorf("Unable to compute merge-base against '%s' for '%s'. Ensure the base branch history is fetched and reachable.", baseRef, sourcePath)
	}

	rawOut, rawErr, err := runGitCommandRaw(sourcePath, []string{"diff", "--name-status", "-z", "--find-renames", "--find-copies", fmt.Sprintf("%s...HEAD", mergeBase)}, false)
	if err != nil {
		errMsg := strings.TrimSpace(string(rawErr))
		if errMsg == "" {
			errMsg = "Ensure the repository has enough history for diff-scope."
		}
		return RepoDiffScope{}, fmt.Errorf("Unable to resolve changed files for '%s'. %s", sourcePath, errMsg)
	}

	entries := parseNameStatusZ(rawOut)
	classified := classifyDiffEntries(entries)

	addedFiles, _ := classified["added_files"].([]string)
	modifiedFiles, _ := classified["modified_files"].([]string)
	renamedFiles, _ := classified["renamed_files"].([]map[string]interface{})
	deletedFiles, _ := classified["deleted_files"].([]string)
	analyzableFiles, _ := classified["analyzable_files"].([]string)

	return RepoDiffScope{
		SourcePath:        sourcePath,
		WorkspaceSubdir:   workspaceSubdir,
		BaseRef:           baseRef,
		MergeBase:         mergeBase,
		AddedFiles:        addedFiles,
		ModifiedFiles:     modifiedFiles,
		RenamedFiles:      renamedFiles,
		DeletedFiles:      deletedFiles,
		AnalyzableFiles:   analyzableFiles,
		TruncatedSections: make(map[string]bool),
	}, nil
}

func getOsEnvironMap() map[string]string {
	res := make(map[string]string)
	for _, e := range os.Environ() {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			res[parts[0]] = parts[1]
		}
	}
	return res
}

func ResolveDiffScopeContext(localSources []map[string]interface{}, scopeMode string, diffBase *string, nonInteractive bool) (DiffScopeResult, error) {
	if !supportedScopeModes[scopeMode] {
		return DiffScopeResult{}, fmt.Errorf("Unsupported scope mode: %s", scopeMode)
	}

	envMap := getOsEnvironMap()

	if scopeMode == "full" {
		return DiffScopeResult{
			Active:   false,
			Mode:     scopeMode,
			Metadata: map[string]interface{}{"active": false, "mode": scopeMode},
		}, nil
	}

	if scopeMode == "auto" {
		shouldActivate := shouldActivateAutoScope(localSources, nonInteractive, envMap)
		if !shouldActivate {
			return DiffScopeResult{
				Active:   false,
				Mode:     scopeMode,
				Metadata: map[string]interface{}{"active": false, "mode": scopeMode},
			}, nil
		}
	}

	if len(localSources) == 0 {
		return DiffScopeResult{}, fmt.Errorf("Diff-scope is active, but no local repository targets were provided.")
	}

	var repoScopes []RepoDiffScope
	var skippedNonGit []string
	var skippedDiffScope []string

	for _, source := range localSources {
		sourcePath, _ := source["source_path"].(string)
		if sourcePath == "" {
			continue
		}
		if !isGitRepo(sourcePath) {
			skippedNonGit = append(skippedNonGit, sourcePath)
			continue
		}

		scope, err := resolveRepoDiffScope(source, diffBase, envMap)
		if err != nil {
			if scopeMode == "auto" {
				skippedDiffScope = append(skippedDiffScope, fmt.Sprintf("%s (diff-scope skipped: %v)", sourcePath, err))
				continue
			}
			return DiffScopeResult{}, err
		}
		repoScopes = append(repoScopes, scope)
	}

	if len(repoScopes) == 0 {
		if scopeMode == "auto" {
			metadata := map[string]interface{}{"active": false, "mode": scopeMode}
			if len(skippedNonGit) > 0 {
				metadata["skipped_non_git_sources"] = skippedNonGit
			}
			if len(skippedDiffScope) > 0 {
				metadata["skipped_diff_scope_sources"] = skippedDiffScope
			}
			return DiffScopeResult{Active: false, Mode: scopeMode, Metadata: metadata}, nil
		}
		return DiffScopeResult{}, fmt.Errorf("Diff-scope is active, but no Git repositories were found. Use --scope-mode full to disable diff-scope for this run.")
	}

	instructionBlock := buildDiffScopeInstruction(repoScopes)

	var reposMetadata []map[string]interface{}
	totalAnalyzable := 0
	totalDeleted := 0
	for _, scope := range repoScopes {
		reposMetadata = append(reposMetadata, scope.ToMetadata())
		totalAnalyzable += len(scope.AnalyzableFiles)
		totalDeleted += len(scope.DeletedFiles)
	}

	metadata := map[string]interface{}{
		"active":                 true,
		"mode":                   scopeMode,
		"repos":                  reposMetadata,
		"total_repositories":     len(repoScopes),
		"total_analyzable_files": totalAnalyzable,
		"total_deleted_files":    totalDeleted,
	}
	if len(skippedNonGit) > 0 {
		metadata["skipped_non_git_sources"] = skippedNonGit
	}
	if len(skippedDiffScope) > 0 {
		metadata["skipped_diff_scope_sources"] = skippedDiffScope
	}

	return DiffScopeResult{
		Active:           true,
		Mode:             scopeMode,
		InstructionBlock: instructionBlock,
		Metadata:         metadata,
	}, nil
}

func WriteRunRecord(runDir string, runRecord map[string]interface{}) {
	path := filepath.Join(runDir, "run_record.json")
	data, err := json.MarshalIndent(runRecord, "", "  ")
	if err == nil {
		os.WriteFile(path, data, 0644)
	}
}
