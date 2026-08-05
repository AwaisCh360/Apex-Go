package runtime

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

const (
	ContainerCaidoPort = 48080
	WorkspaceRoot      = "/workspace"
)

var ProtectedMetadataNames = []string{".git", ".agents", ".codex"}

// Local structures for missing dependencies
type BaseEntry interface{}

type LocalDir struct {
	Src string `json:"src"`
}

type Environment struct {
	Value map[string]string `json:"value"`
}

func (e *Environment) Resolve() (map[string]string, error) {
	if e == nil || e.Value == nil {
		return make(map[string]string), nil
	}
	return e.Value, nil
}

type Manifest struct {
	Entries     map[string]BaseEntry `json:"entries"`
	Environment *Environment         `json:"environment"`
}

type SessionWithExposedPort interface {
	BackendSession
}

type DockerClient interface {
	Close() error
}

type ClientWithDelete interface {
	BackendClient
	Delete(session BackendSession) error
}

type ClientWithDockerClient interface {
	BackendClient
	DockerClient() DockerClient
}

// Mock functions for external dependencies
func loadSettingsBackend() string {
	return "docker"
}

// Removed stub bootstrapCaido

// SessionManager struct encapsulates the session cache state
type SessionManager struct {
	mu    sync.Mutex
	cache map[string]map[string]interface{}
}

// DefaultSessionManager is the package-level instance equivalent to the global in Python
var DefaultSessionManager = &SessionManager{
	cache: make(map[string]map[string]interface{}),
}

func HostIdentityEnv() map[string]string {
	if runtime.GOOS != "linux" {
		return map[string]string{}
	}
	return map[string]string{
		"APEX_HOST_UID": fmt.Sprintf("%d", os.Getuid()),
		"APEX_HOST_GID": fmt.Sprintf("%d", os.Getgid()),
	}
}

func BuildBindMounts(localSources []map[string]interface{}) []map[string]interface{} {
	var bindMounts []map[string]interface{}
	for _, src := range localSources {
		wsSubdir, _ := src["workspace_subdir"].(string)
		hostPath, _ := src["source_path"].(string)
		if wsSubdir == "" || hostPath == "" {
			continue
		}
		
		resolved := expandAndResolve(hostPath)
		target := fmt.Sprintf("%s/%s", WorkspaceRoot, wsSubdir)
		bindMounts = append(bindMounts, map[string]interface{}{
			"source":    resolved,
			"target":    target,
			"read_only": false,
		})
		
		if protect, ok := src["protect_metadata"].(bool); ok && protect {
			bindMounts = append(bindMounts, MetadataMounts(resolved, target)...)
		}
	}
	return bindMounts
}

func BuildManifestEntries(localSources []map[string]interface{}) map[string]BaseEntry {
	entries := make(map[string]BaseEntry)
	for _, src := range localSources {
		wsSubdir, _ := src["workspace_subdir"].(string)
		hostPath, _ := src["source_path"].(string)
		if wsSubdir == "" || hostPath == "" {
			continue
		}
		entries[wsSubdir] = &LocalDir{Src: expandAndResolve(hostPath)}
	}
	return entries
}

func MetadataMounts(tree string, target string) []map[string]interface{} {
	var mounts []map[string]interface{}
	for _, name := range ProtectedMetadataNames {
		metadata := filepath.Join(tree, name)
		info, err := os.Stat(metadata)
		if err != nil {
			continue
		}
		
		if !info.IsDir() && !info.Mode().IsRegular() {
			continue
		}
		
		resolvedMetadata := expandAndResolve(metadata)
		resolvedTree := expandAndResolve(tree)
		if !strings.HasPrefix(resolvedMetadata, resolvedTree) {
			continue
		}
		
		mounts = append(mounts, map[string]interface{}{
			"source":    resolvedMetadata,
			"target":    fmt.Sprintf("%s/%s", target, name),
			"read_only": true,
		})
		
		if info.Mode().IsRegular() {
			gitdir := GitdirFromPointer(resolvedMetadata)
			if gitdir != "" {
				if _, err := os.Stat(gitdir); err == nil {
					resolvedGitdir := expandAndResolve(gitdir)
					if strings.HasPrefix(resolvedGitdir, resolvedTree) {
						rel, err := filepath.Rel(resolvedTree, resolvedGitdir)
						if err == nil {
							rel = strings.ReplaceAll(rel, "\\", "/")
							mounts = append(mounts, map[string]interface{}{
								"source":    resolvedGitdir,
								"target":    fmt.Sprintf("%s/%s", target, rel),
								"read_only": true,
							})
						}
					}
				}
			}
		}
	}
	return mounts
}

func GitdirFromPointer(gitFile string) string {
	contentBytes, err := os.ReadFile(gitFile)
	if err != nil {
		return ""
	}
	content := string(contentBytes)
	for _, line := range strings.Split(content, "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			prefix := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			if prefix == "gitdir" && value != "" {
				candidate := expandUser(value)
				if !filepath.IsAbs(candidate) {
					candidate = filepath.Join(filepath.Dir(gitFile), candidate)
				}
				return expandAndResolve(candidate)
			}
		}
	}
	return ""
}

func expandUser(path string) string {
	if strings.HasPrefix(path, "~") {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, path[1:])
		}
	}
	return path
}

func expandAndResolve(path string) string {
	expanded := expandUser(path)
	abs, err := filepath.Abs(expanded)
	if err != nil {
		return expanded
	}
	if eval, err := filepath.EvalSymlinks(abs); err == nil {
		return eval
	}
	return abs
}

// CreateOrReuse returns the existing session bundle for scanID or creates a new one.
func (sm *SessionManager) CreateOrReuse(ctx context.Context, scanID string, image string, localSources []map[string]interface{}, statusSink StatusSink) (map[string]interface{}, error) {
	report := func(phase string) {
		if statusSink != nil {
			statusSink(phase)
		}
	}

	sm.mu.Lock()
	if cached, ok := sm.cache[scanID]; ok {
		sm.mu.Unlock()
		log.Printf("Reusing existing sandbox session for scan %s", scanID)
		return cached, nil
	}
	sm.mu.Unlock()

	backendName := loadSettingsBackend()
	backend, err := GetBackend(backendName)
	if err != nil {
		return nil, err
	}

	var bindMounts []map[string]interface{}
	var entries map[string]BaseEntry

	if BackendSupportsBindMounts(backendName) {
		bindMounts = BuildBindMounts(localSources)
		entries = make(map[string]BaseEntry)
	} else {
		bindMounts = []map[string]interface{}{}
		entries = BuildManifestEntries(localSources)
	}

	containerCaidoURL := fmt.Sprintf("http://127.0.0.1:%d", ContainerCaidoPort)
	envMap := map[string]string{
		"PYTHONUNBUFFERED": "1",
		"HOST_GATEWAY":     "host.docker.internal",
		"http_proxy":       containerCaidoURL,
		"https_proxy":      containerCaidoURL,
		"ALL_PROXY":        containerCaidoURL,
		"NO_PROXY":         "localhost,127.0.0.1",
	}
	for k, v := range HostIdentityEnv() {
		envMap[k] = v
	}

	manifest := &Manifest{
		Entries: entries,
		Environment: &Environment{
			Value: envMap,
		},
	}

	log.Printf("Creating sandbox session for scan %s (backend=%s, image=%s)", scanID, backendName, image)
	report("Starting sandbox container")
	
	client, session, err := backend.Create(ctx, image, manifest, []int{ContainerCaidoPort}, bindMounts)
	if err != nil {
		return nil, err
	}

	report("Setting up the proxy")
	
	caidoEndpoint, err := session.ResolveExposedPort(ctx, ContainerCaidoPort)
	if err != nil {
		return nil, err
	}

	scheme := "http"
	if caidoEndpoint.TLS {
		scheme = "https"
	}
	hostCaidoURL := fmt.Sprintf("%s://%s:%d", scheme, caidoEndpoint.Host, caidoEndpoint.Port)
	log.Printf("Caido host endpoint resolved: %s", hostCaidoURL)

	caidoClient, err := BootstrapCaido(ctx, session, hostCaidoURL, containerCaidoURL)
	if err != nil {
		return nil, err
	}

	bundle := map[string]interface{}{
		"client":       client,
		"session":      session,
		"caido_client": caidoClient,
	}

	sm.mu.Lock()
	sm.cache[scanID] = bundle
	sm.mu.Unlock()

	log.Printf("Sandbox session for scan %s ready and cached", scanID)
	return bundle, nil
}

// Cleanup tears down scanID's container and drops its cache entry.
func (sm *SessionManager) Cleanup(ctx context.Context, scanID string) {
	sm.mu.Lock()
	bundle, ok := sm.cache[scanID]
	if ok {
		delete(sm.cache, scanID)
	}
	sm.mu.Unlock()

	if !ok {
		log.Printf("cleanup(%s): no cached session", scanID)
		return
	}

	if caidoClient, ok := bundle["caido_client"].(*CaidoClient); ok && caidoClient != nil {
		if err := caidoClient.Close(); err != nil {
			log.Printf("cleanup(%s): caido_client.aclose() raised: %v", scanID, err)
		}
	}

	if client, ok := bundle["client"]; ok && client != nil {
		session := bundle["session"].(BackendSession)
		
		if clientWithDelete, ok := client.(ClientWithDelete); ok {
			if err := clientWithDelete.Delete(session); err != nil {
				log.Printf("cleanup(%s): client.delete raised; container may need manual reaping: %v", scanID, err)
			} else {
				log.Printf("Cleaned up sandbox session for scan %s", scanID)
			}
		}

		if clientWithDockerClient, ok := client.(ClientWithDockerClient); ok {
			if dockerClient := clientWithDockerClient.DockerClient(); dockerClient != nil {
				if err := dockerClient.Close(); err != nil {
					log.Printf("cleanup(%s): docker_client.close() raised: %v", scanID, err)
				}
			}
		}
	}
}

// CreateOrReuse is a module-level convenience function
func CreateOrReuse(ctx context.Context, scanID string, image string, localSources []map[string]interface{}, statusSink StatusSink) (map[string]interface{}, error) {
	return DefaultSessionManager.CreateOrReuse(ctx, scanID, image, localSources, statusSink)
}

// Cleanup is a module-level convenience function
func Cleanup(ctx context.Context, scanID string) {
	DefaultSessionManager.Cleanup(ctx, scanID)
}
