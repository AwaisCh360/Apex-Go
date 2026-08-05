package runtime

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/docker/errdefs"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/docker/go-connections/nat"
	"github.com/docker/go-units"
)

const sandboxNetworkEnv = "APEX_DOCKER_SANDBOX_NETWORK"

func sandboxNetwork() string {
	return strings.TrimSpace(os.Getenv(sandboxNetworkEnv))
}

func applySandboxNetwork(hostConfig *container.HostConfig, networkingConfig *network.NetworkingConfig) {
	networkName := sandboxNetwork()
	if networkName != "" {
		hostConfig.NetworkMode = container.NetworkMode(networkName)
		if networkingConfig.EndpointsConfig == nil {
			networkingConfig.EndpointsConfig = make(map[string]*network.EndpointSettings)
		}
		networkingConfig.EndpointsConfig[networkName] = &network.EndpointSettings{}
		hostConfig.PortBindings = nil
	}
}

func applyResourceLimits(hostConfig *container.HostConfig) {
	memLimit := strings.TrimSpace(os.Getenv("APEX_SANDBOX_MEM_LIMIT"))
	if memLimit != "" {
		if bytes, err := units.RAMInBytes(memLimit); err == nil {
			hostConfig.Resources.Memory = bytes
		}
	}

	shmSize := strings.TrimSpace(os.Getenv("APEX_SANDBOX_SHM_SIZE"))
	if shmSize != "" {
		if bytes, err := units.RAMInBytes(shmSize); err == nil {
			hostConfig.ShmSize = bytes
		}
	}

	cpus := strings.TrimSpace(os.Getenv("APEX_SANDBOX_CPUS"))
	if cpus != "" {
		if floatCpus, err := strconv.ParseFloat(cpus, 64); err == nil {
			nanoCpus := int64(floatCpus * 1000000000)
			if nanoCpus > 0 {
				hostConfig.Resources.NanoCPUs = nanoCpus
			}
		}
	}

	pidsLimit := strings.TrimSpace(os.Getenv("APEX_SANDBOX_PIDS_LIMIT"))
	if pidsLimit != "" {
		if pids, err := strconv.ParseInt(pidsLimit, 10, 64); err == nil {
			hostConfig.Resources.PidsLimit = &pids
		}
	}
}

func applyLogLimits(hostConfig *container.HostConfig) {
	maxSize := strings.TrimSpace(os.Getenv("APEX_SANDBOX_LOG_MAX_SIZE"))
	if maxSize == "" {
		maxSize = "50m"
	}
	lowerSize := strings.ToLower(maxSize)
	if lowerSize == "0" || lowerSize == "off" || lowerSize == "none" || lowerSize == "unlimited" {
		return
	}

	maxFile := strings.TrimSpace(os.Getenv("APEX_SANDBOX_LOG_MAX_FILE"))
	if maxFile == "" {
		maxFile = "3"
	}

	hostConfig.LogConfig = container.LogConfig{
		Type: "json-file",
		Config: map[string]string{
			"max-size": maxSize,
			"max-file": maxFile,
		},
	}
}

func applyRunLabels(config *container.Config) {
	runID := os.Getenv("APEX_RUN_ID")
	if runID == "" {
		return
	}
	if config.Labels == nil {
		config.Labels = make(map[string]string)
	}
	config.Labels["apex-run-id"] = runID

	runType := os.Getenv("APEX_RUN_TYPE")
	if runType != "" {
		config.Labels["apex-run-type"] = runType
	}
}

// Fallback interfaces / types for OpenAI Agents SDK

type ExposedPortEndpoint struct {
	Host string
	Port int
	TLS  bool
}

type SandboxState struct {
	ContainerID  string
	ExposedPorts []int
}

type SandboxSession interface {
	Inner() interface{}
	State() SandboxState
	Start(ctx context.Context) error
	Exec(ctx context.Context, cmd ...string) (ExecResult, error)
	ResolveExposedPort(ctx context.Context, port int) (*ExposedPortEndpoint, error)
}

type DockerSandboxSession struct {
	Container *client.Client
	state     SandboxState
}

func (s *DockerSandboxSession) Inner() interface{} { return s }
func (s *DockerSandboxSession) State() SandboxState { return s.state }

func (s *DockerSandboxSession) Start(ctx context.Context) error {
	if s.state.ContainerID == "" {
		return fmt.Errorf("no container to start")
	}
	return s.Container.ContainerStart(ctx, s.state.ContainerID, types.ContainerStartOptions{})
}

func (s *DockerSandboxSession) ResolveExposedPort(ctx context.Context, port int) (*ExposedPortEndpoint, error) {
	return nil, fmt.Errorf("network resolution not available on base docker session")
}

type DockerExecResult struct {
	exitCode int
	stdout   string
	stderr   []byte
}

func (r *DockerExecResult) Ok() bool       { return r.exitCode == 0 }
func (r *DockerExecResult) Stdout() string { return r.stdout }
func (r *DockerExecResult) Stderr() []byte { return r.stderr }
func (r *DockerExecResult) ExitCode() int  { return r.exitCode }

func (s *DockerSandboxSession) Exec(ctx context.Context, cmd ...string) (ExecResult, error) {
	if s.state.ContainerID == "" {
		return nil, fmt.Errorf("no container to exec in")
	}
	execConfig := types.ExecConfig{
		Cmd:          cmd,
		AttachStdout: true,
		AttachStderr: true,
	}
	resp, err := s.Container.ContainerExecCreate(ctx, s.state.ContainerID, execConfig)
	if err != nil {
		return nil, err
	}
	
	attachResp, err := s.Container.ContainerExecAttach(ctx, resp.ID, types.ExecStartCheck{})
	if err != nil {
		return nil, err
	}
	defer attachResp.Close()
	
	var stdout, stderr bytes.Buffer
	_, err = stdcopy.StdCopy(&stdout, &stderr, attachResp.Reader)
	if err != nil {
		return nil, err
	}

	inspect, err := s.Container.ContainerExecInspect(ctx, resp.ID)
	if err != nil {
		return nil, err
	}
	
	return &DockerExecResult{
		exitCode: inspect.ExitCode,
		stdout:   stdout.String(),
		stderr:   stderr.Bytes(),
	}, nil
}

type ApexDockerSandboxSession struct {
	DockerSandboxSession
	SandboxNetwork string
	ContainerInfo  *types.ContainerJSON
}

type ExposedPortUnavailableError struct {
	Port         int
	ExposedPorts []int
	Reason       string
	Context      map[string]interface{}
	Cause        error
}

func (e *ExposedPortUnavailableError) Error() string {
	return fmt.Sprintf("exposed port unavailable: %d", e.Port)
}

func (s *ApexDockerSandboxSession) ResolveExposedPort(ctx context.Context, port int) (*ExposedPortEndpoint, error) {
	inspect, err := s.Container.ContainerInspect(ctx, s.state.ContainerID)
	if err != nil {
		return nil, &ExposedPortUnavailableError{
			Port:         port,
			ExposedPorts: s.state.ExposedPorts,
			Reason:       "backend_unavailable",
			Context: map[string]interface{}{
				"backend": "docker",
				"detail":  "container_reload_failed",
				"network": s.SandboxNetwork,
			},
			Cause: err,
		}
	}

	s.ContainerInfo = &inspect

	networks := inspect.NetworkSettings.Networks
	var ip string
	if endpoint, ok := networks[s.SandboxNetwork]; ok && endpoint != nil {
		if endpoint.IPAddress != "" {
			ip = endpoint.IPAddress
		} else if endpoint.GlobalIPv6Address != "" {
			ip = endpoint.GlobalIPv6Address
		}
	}

	if ip == "" {
		return nil, &ExposedPortUnavailableError{
			Port:         port,
			ExposedPorts: s.state.ExposedPorts,
			Reason:       "backend_unavailable",
			Context: map[string]interface{}{
				"backend": "docker",
				"detail":  "container_not_on_network",
				"network": s.SandboxNetwork,
			},
		}
	}

	host := ip
	if strings.Contains(ip, ":") {
		host = fmt.Sprintf("[%s]", ip)
	}

	return &ExposedPortEndpoint{
		Host: host,
		Port: port,
		TLS:  false,
	}, nil
}



type DockerSandboxClient struct {
	Client *client.Client
}

func (c *DockerSandboxClient) DockerClient() DockerClient {
	return c.Client
}

func (c *DockerSandboxClient) ImageExists(ctx context.Context, imageName string) bool {
	_, _, err := c.Client.ImageInspectWithRaw(ctx, imageName)
	return err == nil
}

type ApexDockerSandboxClient struct {
	DockerSandboxClient
	ApexBindMounts []map[string]interface{}
}

func buildDockerVolumeMounts(manifest *Manifest, sessionID string) []mount.Mount {
	if manifest == nil || manifest.Entries == nil {
		return nil
	}
	var mounts []mount.Mount
	for target, entry := range manifest.Entries {
		if localDir, ok := entry.(*LocalDir); ok {
			mounts = append(mounts, mount.Mount{
				Type:   mount.TypeBind,
				Source: localDir.Src,
				Target: target,
			})
		}
	}
	return mounts
}

func manifestRequiresFuse(manifest *Manifest) bool {
	return false
}

func manifestRequiresSysAdmin(manifest *Manifest) bool {
	return false
}

func dockerPortKey(port int) nat.Port {
	return nat.Port(fmt.Sprintf("%d/tcp", port))
}

func (c *ApexDockerSandboxClient) CreateContainer(
	ctx context.Context,
	imageName string,
	manifest *Manifest,
	exposedPorts []int,
	sessionID string,
) (container.CreateResponse, error) {
	if !c.ImageExists(ctx, imageName) {
		reader, err := c.Client.ImagePull(ctx, imageName, types.ImagePullOptions{})
		if err != nil {
			return container.CreateResponse{}, fmt.Errorf("failed to pull image: %w", err)
		}
		defer reader.Close()
		_, _ = io.Copy(io.Discard, reader)
	}

	var env []string
	if manifest != nil && manifest.Environment != nil {
		resolvedEnv, _ := manifest.Environment.Resolve()
		for k, v := range resolvedEnv {
			env = append(env, fmt.Sprintf("%s=%s", k, v))
		}
	}

	config := &container.Config{
		Image: imageName,
		Cmd:   []string{"tail", "-f", "/dev/null"},
		Env:   env,
	}

	hostConfig := &container.HostConfig{}

	if manifest != nil {
		dockerMounts := buildDockerVolumeMounts(manifest, sessionID)
		if len(dockerMounts) > 0 {
			hostConfig.Mounts = dockerMounts
		}

		if manifestRequiresFuse(manifest) {
			hostConfig.Resources.Devices = append(hostConfig.Resources.Devices, container.DeviceMapping{
				PathOnHost:        "/dev/fuse",
				PathInContainer:   "/dev/fuse",
				CgroupPermissions: "rwm",
			})
			hostConfig.CapAdd = append(hostConfig.CapAdd, "SYS_ADMIN")
			hostConfig.SecurityOpt = append(hostConfig.SecurityOpt, "apparmor:unconfined")
		} else if manifestRequiresSysAdmin(manifest) {
			hostConfig.CapAdd = append(hostConfig.CapAdd, "SYS_ADMIN")
			hostConfig.SecurityOpt = append(hostConfig.SecurityOpt, "apparmor:unconfined")
		}
	}

	if len(exposedPorts) > 0 {
		hostConfig.PortBindings = make(nat.PortMap)
		config.ExposedPorts = make(nat.PortSet)
		for _, port := range exposedPorts {
			portKey := dockerPortKey(port)
			hostConfig.PortBindings[portKey] = []nat.PortBinding{
				{HostIP: "127.0.0.1", HostPort: ""},
			}
			config.ExposedPorts[portKey] = struct{}{}
		}
	}

	capAddMap := make(map[string]bool)
	for _, cap := range hostConfig.CapAdd {
		capAddMap[cap] = true
	}
	for _, cap := range []string{"NET_ADMIN", "NET_RAW"} {
		if !capAddMap[cap] {
			hostConfig.CapAdd = append(hostConfig.CapAdd, cap)
			capAddMap[cap] = true
		}
	}

	if hostConfig.ExtraHosts == nil {
		hostConfig.ExtraHosts = []string{}
	}
	hostConfig.ExtraHosts = append(hostConfig.ExtraHosts, "host.docker.internal:host-gateway")

	networkingConfig := &network.NetworkingConfig{}

	applySandboxNetwork(hostConfig, networkingConfig)
	applyResourceLimits(hostConfig)
	applyLogLimits(hostConfig)
	applyRunLabels(config)

	if len(c.ApexBindMounts) > 0 {
		bindMounts := make([]map[string]interface{}, len(c.ApexBindMounts))
		copy(bindMounts, c.ApexBindMounts)
		sort.SliceStable(bindMounts, func(i, j int) bool {
			targetI, _ := bindMounts[i]["target"].(string)
			targetJ, _ := bindMounts[j]["target"].(string)
			return strings.Count(targetI, "/") < strings.Count(targetJ, "/")
		})

		for _, m := range bindMounts {
			target, _ := m["target"].(string)
			source, _ := m["source"].(string)
			readOnly, _ := m["read_only"].(bool)

			hostConfig.Mounts = append(hostConfig.Mounts, mount.Mount{
				Type:     mount.TypeBind,
				Source:   source,
				Target:   target,
				ReadOnly: readOnly,
			})
		}
	}

	return c.Client.ContainerCreate(ctx, config, hostConfig, networkingConfig, nil, "")
}

func (c *ApexDockerSandboxClient) Create(ctx context.Context, image string, manifest *Manifest, exposedPorts []int) (SandboxSession, error) {
	// Generate a fake session ID or use UUID. We'll use a simple string for now.
	sessionID := "apex-session-1234"

	resp, err := c.CreateContainer(ctx, image, manifest, exposedPorts, sessionID)
	if err != nil {
		return nil, err
	}

	session := &DockerSandboxSession{
		Container: c.Client,
		state: SandboxState{
			ContainerID:  resp.ID,
			ExposedPorts: exposedPorts,
		},
	}

	networkName := sandboxNetwork()
	if networkName != "" {
		apexSession := &ApexDockerSandboxSession{
			DockerSandboxSession: *session,
			SandboxNetwork:       networkName,
		}
		return apexSession, nil
	}

	return session, nil
}

func isBestEffortKillError(err error) bool {
	if err == nil {
		return true
	}
	if client.IsErrConnectionFailed(err) {
		return true
	}
	if strings.Contains(err.Error(), "connection reset by peer") || strings.Contains(err.Error(), "connection refused") {
		return true
	}
	if errdefs.IsNotFound(err) {
		return true
	}
	if errdefs.IsSystem(err) {
		return true
	}
	return false
}

func (c *ApexDockerSandboxClient) Delete(ctx context.Context, session SandboxSession) (SandboxSession, error) {
	containerID := session.State().ContainerID
	if containerID != "" {
		err := c.Client.ContainerKill(ctx, containerID, "KILL")
		if err != nil && !isBestEffortKillError(err) {
			return nil, err
		}
		_ = c.Client.ContainerRemove(ctx, containerID, types.ContainerRemoveOptions{Force: true})
	}
	return session, nil
}
