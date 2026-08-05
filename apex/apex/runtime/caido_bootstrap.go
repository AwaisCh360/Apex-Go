package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

var logger = log.New(os.Stderr, "[caido_bootstrap] ", log.LstdFlags)

const loginAsGuestBody = `{"query":"mutation LoginAsGuest { loginAsGuest { token { accessToken } } }"}`

type ExecResult interface {
	Ok() bool
	Stdout() string
	Stderr() []byte
	ExitCode() int
}

type CaidoSandboxSession interface {
	Exec(ctx context.Context, cmd ...string) (ExecResult, error)
}

type CaidoClient struct {
	HostURL     string
	AccessToken string
	httpClient  *http.Client
}

func (c *CaidoClient) Close() error {
	return nil
}

func (c *CaidoClient) Connect(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/graphql", c.HostURL), nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to Caido host: %w", err)
	}
	defer resp.Body.Close()
	return nil
}

type GraphQLReq struct {
	Query     string                 `json:"query"`
	Variables map[string]interface{} `json:"variables,omitempty"`
}

type GraphQLRes struct {
	Data   map[string]interface{} `json:"data"`
	Errors []interface{}          `json:"errors,omitempty"`
}

func (c *CaidoClient) executeGraphQL(ctx context.Context, query string, variables map[string]interface{}) (map[string]interface{}, error) {
	reqBody := GraphQLReq{
		Query:     query,
		Variables: variables,
	}
	b, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.HostURL+"/graphql", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	if c.AccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.AccessToken)
	}

	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("graphql request failed with status %d", res.StatusCode)
	}

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var gqlRes GraphQLRes
	if err := json.Unmarshal(resBytes, &gqlRes); err != nil {
		return nil, err
	}

	if len(gqlRes.Errors) > 0 {
		return nil, fmt.Errorf("graphql errors: %v", gqlRes.Errors)
	}

	return gqlRes.Data, nil
}

func loginAsGuest(ctx context.Context, session CaidoSandboxSession, containerURL string, attempts int) (string, error) {
	var lastErr string
	for i := 1; i <= attempts; i++ {
		execCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		result, err := session.Exec(
			execCtx,
			"curl",
			"-fsS",
			"-X", "POST",
			"-H", "Content-Type: application/json",
			"-d", loginAsGuestBody,
			fmt.Sprintf("%s/graphql", containerURL),
		)
		cancel()

		if err == nil {
			if result.Ok() {
				var payload struct {
					Data struct {
						LoginAsGuest struct {
							Token struct {
								AccessToken string `json:"accessToken"`
							} `json:"token"`
						} `json:"loginAsGuest"`
					} `json:"data"`
				}
				if err := json.Unmarshal([]byte(result.Stdout()), &payload); err == nil {
					token := payload.Data.LoginAsGuest.Token.AccessToken
					if token != "" {
						return token, nil
					}
					lastErr = fmt.Sprintf("loginAsGuest returned no token: %s", result.Stdout())
				} else {
					lastErr = fmt.Sprintf("unparseable response: %v: %q", err, result.Stdout())
				}
			} else {
				stderr := result.Stderr()
				if len(stderr) > 200 {
					stderr = stderr[:200]
				}
				lastErr = fmt.Sprintf("curl exit %d: %s", result.ExitCode(), string(stderr))
			}
		} else {
			lastErr = fmt.Sprintf("session.Exec failed: %v", err)
		}

		logger.Printf("loginAsGuest attempt %d/%d failed: %s", i, attempts, lastErr)

		sleepTime := time.Duration(2*i) * time.Second
		if sleepTime > 8*time.Second {
			sleepTime = 8 * time.Second
		}

		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(sleepTime):
		}
	}

	return "", fmt.Errorf("loginAsGuest failed after %d attempts: %s", attempts, lastErr)
}

func BootstrapCaido(ctx context.Context, session CaidoSandboxSession, hostURL, containerURL string) (*CaidoClient, error) {
	logger.Printf("Bootstrapping Caido client (host=%s, container=%s)", hostURL, containerURL)

	accessToken, err := loginAsGuest(ctx, session, containerURL, 10)
	if err != nil {
		return nil, err
	}

	client := &CaidoClient{
		HostURL:     hostURL,
		AccessToken: accessToken,
		httpClient:  &http.Client{},
	}

	if err := client.Connect(ctx); err != nil {
		return nil, err
	}

	createProjectQuery := `mutation CreateProject($input: CreateProjectInput!) { createProject(input: $input) { project { id } } }`
	createVars := map[string]interface{}{
		"input": map[string]interface{}{
			"name":      "sandbox",
			"temporary": true,
		},
	}

	data, err := client.executeGraphQL(ctx, createProjectQuery, createVars)
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to create project: %w", err)
	}

	createProjectData, ok := data["createProject"].(map[string]interface{})
	if !ok {
		client.Close()
		return nil, fmt.Errorf("invalid createProject response")
	}

	project, ok := createProjectData["project"].(map[string]interface{})
	if !ok {
		client.Close()
		return nil, fmt.Errorf("invalid project response")
	}

	projectID, ok := project["id"].(string)
	if !ok {
		client.Close()
		return nil, fmt.Errorf("invalid project id")
	}

	selectProjectQuery := `mutation SelectProject($id: ID!) { selectProject(id: $id) { project { id } } }`
	selectVars := map[string]interface{}{
		"id": projectID,
	}

	_, err = client.executeGraphQL(ctx, selectProjectQuery, selectVars)
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to select project: %w", err)
	}

	logger.Printf("Caido project selected: %s", projectID)
	return client, nil
}
