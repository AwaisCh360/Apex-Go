package runtime

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"

	"github.com/docker/docker/client"
)

// BackendManifest represents the Sandbox manifest.
type BackendManifest interface{}

// BackendClient represents a Sandbox client.
type BackendClient interface{}

// BackendSession represents a Sandbox session.
type BackendSession interface {
	Start(ctx context.Context) error
	Exec(ctx context.Context, cmd ...string) (ExecResult, error)
	ResolveExposedPort(ctx context.Context, port int) (*ExposedPortEndpoint, error)
}

// SandboxBackend is the interface for a runtime backend.
type SandboxBackend interface {
	Create(ctx context.Context, image string, manifest BackendManifest, exposedPorts []int, bindMounts []map[string]interface{}) (BackendClient, BackendSession, error)
}

// DockerBackend implements SandboxBackend for the local Docker daemon.
type DockerBackend struct{}

// Create brings up a session backed by the local Docker daemon.
//
// Uses ApexDockerSandboxClient to inject NET_ADMIN / NET_RAW caps + host.docker.internal host-gateway.
func (b *DockerBackend) Create(ctx context.Context, image string, manifest BackendManifest, exposedPorts []int, bindMounts []map[string]interface{}) (BackendClient, BackendSession, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create docker client: %w", err)
	}

	apexClient := &ApexDockerSandboxClient{
		DockerSandboxClient: DockerSandboxClient{
			Client: cli,
		},
		ApexBindMounts: bindMounts,
	}

	// Cast BackendManifest to concrete Manifest
	var concreteManifest *Manifest
	if manifest != nil {
		if cm, ok := manifest.(*Manifest); ok {
			concreteManifest = cm
		}
	}

	session, err := apexClient.Create(ctx, image, concreteManifest, exposedPorts)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create session: %w", err)
	}

	if err := session.Start(ctx); err != nil {
		return nil, nil, fmt.Errorf("failed to start session: %w", err)
	}

	return apexClient, session, nil
}

var (
	backendsMu sync.RWMutex

	backends = map[string]SandboxBackend{
		"docker": &DockerBackend{},
	}

	bindMountBackends = map[string]bool{
		"docker": true,
	}
)

// GetBackend returns the backend factory for name or returns an error.
func GetBackend(name string) (SandboxBackend, error) {
	backendsMu.RLock()
	backend, ok := backends[name]
	backendsMu.RUnlock()

	if !ok {
		supported := strings.Join(SupportedBackends(), ", ")
		return nil, fmt.Errorf("Unknown APEX_RUNTIME_BACKEND: %q (supported: %s)", name, supported)
	}
	log.Printf("Selected sandbox backend: %s", name)
	return backend, nil
}

// RegisterBackend registers a custom backend under name.
func RegisterBackend(name string, backend SandboxBackend, supportsBindMounts bool) {
	backendsMu.Lock()
	backends[name] = backend
	if supportsBindMounts {
		bindMountBackends[name] = true
	} else {
		delete(bindMountBackends, name)
	}
	backendsMu.Unlock()
	log.Printf("Registered sandbox backend: %s (bind mounts: %t)", name, supportsBindMounts)
}

// BackendSupportsBindMounts returns true if the backend supports bind mounts.
func BackendSupportsBindMounts(name string) bool {
	backendsMu.RLock()
	defer backendsMu.RUnlock()
	return bindMountBackends[name]
}

// SupportedBackends returns a sorted list of registered backend names.
func SupportedBackends() []string {
	backendsMu.RLock()
	defer backendsMu.RUnlock()

	names := make([]string, 0, len(backends))
	for name := range backends {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
