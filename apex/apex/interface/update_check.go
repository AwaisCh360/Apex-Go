package main

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	githubRepo            = "useapex/apex"
	pypiPackage           = "apex-agent"
	checkIntervalSeconds  = 24 * 60 * 60
	requestTimeoutSeconds = 5
)

var backgroundCheckDone = make(chan struct{})
var backgroundCheckStarted = false

func cachePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".apex/update-check.json"
	}
	return filepath.Join(home, ".apex", "update-check.json")
}

func isDisabled() bool {
	if os.Getenv("APEX_NO_UPDATE_CHECK") != "" {
		return true
	}
	keys := []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL", "BUILDKITE", "CIRCLECI"}
	for _, k := range keys {
		if os.Getenv(k) != "" {
			return true
		}
	}
	return false
}

func IsBinaryInstall() bool {
	exe, err := os.Executable()
	if err != nil {
		return true
	}
	exe = filepath.ToSlash(exe)
	if strings.Contains(exe, "/pipx/") || strings.HasSuffix(exe, "/pipx") || strings.Contains(exe, "/uv/tools/") || strings.Contains(exe, "/site-packages/") || strings.Contains(exe, "/.local/bin/") || strings.Contains(exe, "/bin/python") {
		return false
	}
	if strings.Contains(exe, "go-build") || strings.Contains(exe, "/tmp/go-build") {
		return false
	}
	return true
}

func GetInstallMethod() string {
	if IsBinaryInstall() {
		return "binary"
	}
	exe, err := os.Executable()
	if err == nil {
		exe = filepath.ToSlash(exe)
		if strings.Contains(exe, "/pipx/") || strings.HasSuffix(exe, "/pipx") {
			return "pipx"
		}
		if strings.Contains(exe, "/uv/tools/") {
			return "uv"
		}
	}
	return "pip"
}

func GetUpgradeCommand(method string) string {
	if method == "" {
		method = GetInstallMethod()
	}
	commands := map[string]string{
		"binary": "apex --update",
		"pipx":   "pipx upgrade apex-agent",
		"uv":     "uv tool upgrade apex-agent",
		"pip":    "pip install --upgrade apex-agent",
	}
	if cmd, ok := commands[method]; ok {
		return cmd
	}
	return commands["binary"]
}

func parseVersion(value string) []int {
	value = strings.TrimSpace(strings.TrimPrefix(value, "v"))
	parts := strings.Split(value, ".")
	var parsed []int
	for _, part := range parts {
		if val, err := strconv.Atoi(part); err == nil {
			parsed = append(parsed, val)
		} else {
			return nil
		}
	}
	return parsed
}

func isNewer(latest, current string) bool {
	latestParts := parseVersion(latest)
	currentParts := parseVersion(current)
	if latestParts == nil || currentParts == nil {
		return false
	}
	for i := 0; i < len(latestParts) && i < len(currentParts); i++ {
		if latestParts[i] > currentParts[i] {
			return true
		} else if latestParts[i] < currentParts[i] {
			return false
		}
	}
	return len(latestParts) > len(currentParts)
}

func fetchLatestVersion() string {
	client := &http.Client{Timeout: requestTimeoutSeconds * time.Second}
	if IsBinaryInstall() {
		resp, err := client.Get(fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", githubRepo))
		if err != nil {
			return ""
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return ""
		}
		var result struct {
			TagName string `json:"tag_name"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return ""
		}
		return strings.TrimPrefix(result.TagName, "v")
	}

	resp, err := client.Get(fmt.Sprintf("https://pypi.org/pypi/%s/json", pypiPackage))
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var result struct {
		Info struct {
			Version string `json:"version"`
		} `json:"info"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return ""
	}
	return result.Info.Version
}

func fetchAssetDigest(version, filename string) string {
	client := &http.Client{Timeout: requestTimeoutSeconds * time.Second}
	resp, err := client.Get(fmt.Sprintf("https://api.github.com/repos/%s/releases/tags/v%s", githubRepo, version))
	if err != nil || resp.StatusCode != http.StatusOK {
		return ""
	}
	defer resp.Body.Close()
	var result struct {
		Assets []struct {
			Name   string `json:"name"`
			Digest string `json:"digest,omitempty"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
		for _, asset := range result.Assets {
			if asset.Name == filename {
				if strings.HasPrefix(asset.Digest, "sha256:") {
					return strings.TrimPrefix(asset.Digest, "sha256:")
				}
			}
		}
	}
	return ""
}

func sha256File(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func readCache() map[string]interface{} {
	cache := make(map[string]interface{})
	b, err := os.ReadFile(cachePath())
	if err == nil {
		json.Unmarshal(b, &cache)
	}
	return cache
}

func writeCache(fields map[string]interface{}) {
	cache := readCache()
	for k, v := range fields {
		cache[k] = v
	}
	b, err := json.Marshal(cache)
	if err == nil {
		p := cachePath()
		os.MkdirAll(filepath.Dir(p), 0755)
		os.WriteFile(p, b, 0644)
	}
}

func SkipVersion(version string) {
	writeCache(map[string]interface{}{"skipped_version": version})
}

func refreshCache() {
	latest := fetchLatestVersion()
	if latest != "" {
		writeCache(map[string]interface{}{
			"latest_version": latest,
			"checked_at":     time.Now().Unix(),
		})
	}
	close(backgroundCheckDone)
}

func StartBackgroundCheck() {
	if isDisabled() {
		close(backgroundCheckDone)
		return
	}
	cache := readCache()
	if checkedAtFloat, ok := cache["checked_at"].(float64); ok {
		if time.Now().Unix()-int64(checkedAtFloat) < checkIntervalSeconds {
			close(backgroundCheckDone)
			return
		}
	}
	backgroundCheckStarted = true
	go refreshCache()
}

func GetAvailableUpdate(respectSkip bool) string {
	if isDisabled() {
		return ""
	}
	if backgroundCheckStarted {
		select {
		case <-backgroundCheckDone:
		case <-time.After(200 * time.Millisecond):
		}
	}
	cache := readCache()
	latest, ok := cache["latest_version"].(string)
	if !ok {
		return ""
	}
	current := GetVersion()
	if current == "unknown" || !isNewer(latest, current) {
		return ""
	}
	if respectSkip {
		if skipped, ok := cache["skipped_version"].(string); ok && skipped == latest {
			return ""
		}
	}
	return latest
}

func NotifyUpdate() {
	latest := GetAvailableUpdate(true)
	if latest == "" {
		return
	}
	fmt.Printf("\033[33mA new version of apex is available:\033[0m \033[2m%s\033[0m \033[2m→\033[0m \033[1;32m%s\033[0m  \033[2m·\033[0m  \033[34m%s\033[0m\n\n", GetVersion(), latest, GetUpgradeCommand(""))
}

func RunPackageUpgrade(method string) bool {
	command := GetUpgradeCommand(method)
	fmt.Printf("\033[2mRunning\033[0m \033[34m%s\033[0m\n", command)
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return false
	}
	cmd := exec.Command(parts[0], parts[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		fmt.Printf("\033[1;31mUpdate failed:\033[0m %v\n", err)
		return false
	}
	fmt.Printf("\033[32m✓ apex updated — restart the scan to use the new version\033[0m\n")
	return true
}

func isTerminal() bool {
	fileInfo, _ := os.Stdout.Stat()
	return (fileInfo.Mode() & os.ModeCharDevice) != 0
}

func PromptUpdateIfAvailable() bool {
	latest := GetAvailableUpdate(true)
	if latest == "" || !isTerminal() {
		return false
	}
	fmt.Println()
	fmt.Printf("\033[33mA new version of apex is available:\033[0m \033[2m%s\033[0m \033[2m→\033[0m \033[1;32m%s\033[0m\n", GetVersion(), latest)
	fmt.Printf("\033[2m  y — update now    n — not now (ask again next run)    s — skip this version\033[0m\n")
	fmt.Print("Update apex? [y/n/s] (n): ")

	reader := bufio.NewReader(os.Stdin)
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(strings.ToLower(choice))
	if choice == "" {
		choice = "n"
	}
	fmt.Println()
	if choice == "s" {
		SkipVersion(latest)
		return false
	}
	if choice != "y" {
		return false
	}
	method := GetInstallMethod()
	if method == "binary" {
		return SelfUpdate(latest)
	}
	return RunPackageUpgrade(method)
}

func releaseTarget() string {
	osName := runtime.GOOS
	if osName == "darwin" {
		osName = "macos"
	}
	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "x86_64"
	}
	target := fmt.Sprintf("%s-%s", osName, arch)
	supported := map[string]bool{
		"linux-x86_64":   true,
		"linux-arm64":    true,
		"macos-x86_64":   true,
		"macos-arm64":    true,
		"windows-x86_64": true,
	}
	if supported[target] {
		return target
	}
	return ""
}

func downloadAndReplace(version, target string) error {
	isWindows := strings.HasPrefix(target, "windows")
	archiveExt := ".tar.gz"
	if isWindows {
		archiveExt = ".zip"
	}
	filename := fmt.Sprintf("apex-%s-%s%s", version, target, archiveExt)
	url := fmt.Sprintf("https://github.com/%s/releases/download/v%s/%s", githubRepo, version, filename)
	binaryName := fmt.Sprintf("apex-%s-%s", version, target)
	if isWindows {
		binaryName += ".exe"
	}

	currentExe, err := os.Executable()
	if err != nil {
		return err
	}
	currentExe, err = filepath.EvalSymlinks(currentExe)
	if err != nil {
		return err
	}

	tmpDir, err := os.MkdirTemp("", "apex-update-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	archivePath := filepath.Join(tmpDir, filename)
	fmt.Printf("\033[2mDownloading\033[0m %s\n", url)

	client := &http.Client{Timeout: requestTimeoutSeconds * 12 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed with status: %s", resp.Status)
	}

	outFile, err := os.Create(archivePath)
	if err != nil {
		return err
	}
	_, err = io.Copy(outFile, resp.Body)
	outFile.Close()
	if err != nil {
		return err
	}

	expectedDigest := fetchAssetDigest(version, filename)
	if expectedDigest != "" {
		actualDigest := sha256File(archivePath)
		if actualDigest != expectedDigest {
			return fmt.Errorf("checksum mismatch for %s: expected sha256 %s, got %s", filename, expectedDigest, actualDigest)
		}
	} else {
		fmt.Printf("\033[2;33mNo published checksum available; skipping verification\033[0m\n")
	}

	newBinaryPath := filepath.Join(tmpDir, binaryName)
	if isWindows {
		r, err := zip.OpenReader(archivePath)
		if err != nil {
			return err
		}
		defer r.Close()
		for _, f := range r.File {
			if f.Name == binaryName {
				rc, err := f.Open()
				if err != nil {
					return err
				}
				dest, err := os.Create(newBinaryPath)
				if err != nil {
					rc.Close()
					return err
				}
				io.Copy(dest, rc)
				dest.Close()
				rc.Close()
				break
			}
		}
	} else {
		f, err := os.Open(archivePath)
		if err != nil {
			return err
		}
		defer f.Close()
		gzr, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer gzr.Close()
		tr := tar.NewReader(gzr)
		for {
			header, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
			if header.Name == binaryName {
				dest, err := os.Create(newBinaryPath)
				if err != nil {
					return err
				}
				io.Copy(dest, tr)
				dest.Close()
				break
			}
		}
	}

	err = os.Chmod(newBinaryPath, 0755)
	if err != nil {
		return err
	}

	staged := currentExe + ".new"
	err = copyFile(newBinaryPath, staged)
	if err != nil {
		return err
	}
	defer os.Remove(staged)

	if isWindows {
		old := currentExe + ".old"
		os.Remove(old)
		err = os.Rename(currentExe, old)
		if err != nil {
			return err
		}
		err = os.Rename(staged, currentExe)
		if err != nil {
			os.Rename(old, currentExe)
			return err
		}
	} else {
		err = os.Rename(staged, currentExe)
		if err != nil {
			return err
		}
	}
	return nil
}

func copyFile(src, dst string) error {
	s, err := os.Open(src)
	if err != nil {
		return err
	}
	defer s.Close()
	d, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer d.Close()
	_, err = io.Copy(d, s)
	return err
}

func SelfUpdate(version string) bool {
	if !IsBinaryInstall() {
		method := GetInstallMethod()
		fmt.Printf("\033[33mThis apex was installed via %s;\033[0m upgrade it with: \033[34m%s\033[0m\n", method, GetUpgradeCommand(method))
		return false
	}
	latest := version
	if latest == "" {
		latest = fetchLatestVersion()
	}
	if latest == "" {
		fmt.Printf("\033[1;31mCould not determine the latest apex version.\033[0m\n")
		return false
	}
	current := GetVersion()
	if current != "unknown" && !isNewer(latest, current) {
		fmt.Printf("\033[32mapex %s is already the latest version.\033[0m\n", current)
		return true
	}
	target := releaseTarget()
	if target == "" {
		fmt.Printf("\033[1;31mNo prebuilt binary for this platform (%s/%s).\033[0m\n", runtime.GOOS, runtime.GOARCH)
		return false
	}
	err := downloadAndReplace(latest, target)
	if err != nil {
		log.Printf("self-update failed: %v", err)
		fmt.Printf("\033[1;31mUpdate failed:\033[0m %v\n", err)
		fmt.Printf("\033[2mYou can reinstall manually with:\033[0m \033[34mcurl -sSL https://apex.ai/install | bash\033[0m\n")
		return false
	}
	writeCache(map[string]interface{}{
		"latest_version": latest,
		"checked_at":     time.Now().Unix(),
	})
	fmt.Printf("\033[32m✓ Updated apex to %s\033[0m\n", latest)
	return true
}

func CheckForUpdates() {
	StartBackgroundCheck()
	PromptUpdateIfAvailable()
}
