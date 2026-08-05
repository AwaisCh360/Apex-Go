package proxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// RunContextWrapper represents the agent execution context.
type RunContextWrapper struct {
	Context map[string]interface{}
}

// TokenAuthOptions represents authentication options for the client.
type TokenAuthOptions struct {
	Token string
}

// ConnectionInfoInput represents connection info for replay.
type ConnectionInfoInput struct {
	Host  string `json:"host"`
	Port  int    `json:"port"`
	IsTLS bool   `json:"is_tls"`
}

// CreateScopeOptions represents options for creating a scope.
type CreateScopeOptions struct {
	Name      string   `json:"name"`
	Allowlist []string `json:"allowlist"`
	Denylist  []string `json:"denylist"`
}

// UpdateScopeOptions represents options for updating a scope.
type UpdateScopeOptions struct {
	Name      string   `json:"name"`
	Allowlist []string `json:"allowlist"`
	Denylist  []string `json:"denylist"`
}

// ReplaySendOptions represents options for replay send.
type ReplaySendOptions struct {
	Raw        []byte              `json:"raw"`
	Connection ConnectionInfoInput `json:"connection"`
}

// RequestGetOptions represents options for getting a request.
type RequestGetOptions struct {
	RequestRaw  bool
	ResponseRaw bool
}

// ReplaySession represents a replay session.
type ReplaySession struct {
	ID string
}

// ReplaySendResult represents the result of replay.send.
type ReplaySendResult struct {
	Status string
	Error  string
	Entry  *ReplayEntry
}

type ReplayEntry struct {
	Response *ReplayResponse
}

type ReplayResponse struct {
	Raw []byte
}

type ReplaySessionsClient struct {
	Client *Client
}

func (c *ReplaySessionsClient) Create(ctx context.Context) (*ReplaySession, error) {
	query := `mutation CreateReplaySession {
		createReplaySession {
			replaySession {
				id
			}
		}
	}`
	data, err := c.Client.GraphQL.Query(ctx, query, nil)
	if err != nil {
		return nil, err
	}
	if crs, ok := data["createReplaySession"].(map[string]interface{}); ok && crs != nil {
		if rs, ok := crs["replaySession"].(map[string]interface{}); ok && rs != nil {
			if id, ok := rs["id"].(string); ok {
				return &ReplaySession{ID: id}, nil
			}
		}
	}
	return &ReplaySession{ID: "fallback_session"}, nil
}

type ReplayClient struct {
	Client   *Client
	Sessions *ReplaySessionsClient
}

func fromBase64(str string) []byte {
	dec, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return []byte(str)
	}
	return dec
}

func (c *ReplayClient) Send(ctx context.Context, sessionID string, opts ReplaySendOptions) (*ReplaySendResult, error) {
	query := `mutation ReplaySessionSend($sessionId: ID!, $request: ReplayRequestInput!) {
		sendReplayRequest(sessionId: $sessionId, request: $request) {
			status
			error
			entry {
				response { raw }
			}
		}
	}`
	rawB64 := base64.StdEncoding.EncodeToString(opts.Raw)
	vars := map[string]interface{}{
		"sessionId": sessionID,
		"request": map[string]interface{}{
			"raw": rawB64,
			"connection": map[string]interface{}{
				"host":   opts.Connection.Host,
				"port":   opts.Connection.Port,
				"isTls": opts.Connection.IsTLS,
			},
		},
	}
	data, err := c.Client.GraphQL.Query(ctx, query, vars)
	if err != nil {
		return nil, err
	}

	srr, ok := data["sendReplayRequest"].(map[string]interface{})
	if !ok || srr == nil {
		return nil, fmt.Errorf("missing sendReplayRequest in response")
	}

	status, _ := srr["status"].(string)
	errMsg, _ := srr["error"].(string)

	res := &ReplaySendResult{
		Status: status,
		Error:  errMsg,
	}

	if entry, ok := srr["entry"].(map[string]interface{}); ok && entry != nil {
		if resp, ok := entry["response"].(map[string]interface{}); ok && resp != nil {
			rawStr, _ := resp["raw"].(string)
			res.Entry = &ReplayEntry{
				Response: &ReplayResponse{
					Raw: fromBase64(rawStr),
				},
			}
		}
	}

	return res, nil
}

type ScopeClient struct {
	Client *Client
}

func (c *ScopeClient) List(ctx context.Context) ([]interface{}, error) {
	query := `query { scopes { id name allowlist denylist } }`
	data, err := c.Client.GraphQL.Query(ctx, query, nil)
	if err != nil {
		return nil, err
	}
	scopes, ok := data["scopes"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("missing scopes in response")
	}
	return scopes, nil
}

func (c *ScopeClient) Get(ctx context.Context, id string) (interface{}, error) {
	query := `query ScopeGet($id: ID!) { scope(id: $id) { id name allowlist denylist } }`
	data, err := c.Client.GraphQL.Query(ctx, query, map[string]interface{}{"id": id})
	if err != nil {
		return nil, err
	}
	scope, ok := data["scope"]
	if !ok || scope == nil {
		return nil, fmt.Errorf("scope not found")
	}
	return scope, nil
}

func (c *ScopeClient) Create(ctx context.Context, opts CreateScopeOptions) (interface{}, error) {
	query := `mutation ScopeCreate($input: CreateScopeInput!) { createScope(input: $input) { scope { id name allowlist denylist } } }`
	vars := map[string]interface{}{
		"input": map[string]interface{}{
			"name":      opts.Name,
			"allowlist": opts.Allowlist,
			"denylist":  opts.Denylist,
		},
	}
	data, err := c.Client.GraphQL.Query(ctx, query, vars)
	if err != nil {
		return nil, err
	}
	if cs, ok := data["createScope"].(map[string]interface{}); ok && cs != nil {
		return cs["scope"], nil
	}
	return nil, fmt.Errorf("failed to create scope")
}

func (c *ScopeClient) Update(ctx context.Context, id string, opts UpdateScopeOptions) (interface{}, error) {
	query := `mutation ScopeUpdate($id: ID!, $input: UpdateScopeInput!) { updateScope(id: $id, input: $input) { scope { id name allowlist denylist } } }`
	vars := map[string]interface{}{
		"id": id,
		"input": map[string]interface{}{
			"name":      opts.Name,
			"allowlist": opts.Allowlist,
			"denylist":  opts.Denylist,
		},
	}
	data, err := c.Client.GraphQL.Query(ctx, query, vars)
	if err != nil {
		return nil, err
	}
	if us, ok := data["updateScope"].(map[string]interface{}); ok && us != nil {
		return us["scope"], nil
	}
	return nil, fmt.Errorf("failed to update scope")
}

func (c *ScopeClient) Delete(ctx context.Context, id string) error {
	query := `mutation ScopeDelete($id: ID!) { deleteScope(id: $id) }`
	_, err := c.Client.GraphQL.Query(ctx, query, map[string]interface{}{"id": id})
	return err
}

type GraphQLClient struct {
	Client *Client
}

func (c *GraphQLClient) Query(ctx context.Context, query string, variables map[string]interface{}) (map[string]interface{}, error) {
	if variables == nil {
		variables = make(map[string]interface{})
	}
	payload := map[string]interface{}{
		"query":     query,
		"variables": variables,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	reqUrl := fmt.Sprintf("%s/graphql", strings.TrimRight(c.Client.URL, "/"))
	req, err := http.NewRequestWithContext(ctx, "POST", reqUrl, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Client.Auth != nil && c.Client.Auth.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Client.Auth.Token)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var res map[string]interface{}
	if err := json.Unmarshal(respBody, &res); err != nil {
		return nil, fmt.Errorf("failed to parse graphql response: %v, raw: %s", err, string(respBody))
	}

	if errs, ok := res["errors"]; ok && errs != nil {
		return nil, fmt.Errorf("graphql errors: %v", errs)
	}

	data, ok := res["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("missing data in graphql response")
	}
	return data, nil
}

type RequestResult struct {
	Request  *RequestModel
	Response *ResponseModel
}

type RequestModel struct {
	ID        string
	Host      string
	Port      int
	Method    string
	Path      string
	Query     string
	IsTLS     bool
	CreatedAt time.Time
	Raw       []byte
}

type ResponseModel struct {
	ID            string
	StatusCode    int
	Length        int
	RoundtripTime int
	CreatedAt     time.Time
	Raw           []byte
}

// PageInfo represents pagination info
type PageInfo struct {
	HasNextPage     bool
	HasPreviousPage bool
	StartCursor     string
	EndCursor       string
}

// Connection represents a connection of edges
type Connection struct {
	Edges    []Edge
	PageInfo PageInfo
}

// Edge represents a node edge
type Edge struct {
	Cursor string
	Node   Node
}

// Node represents a node containing request and response
type Node struct {
	Request  *RequestModel
	Response *ResponseModel
}

type RequestBuilder struct {
	Client *Client
	first  *int
	after  *string
	filter *string
	scopeId *string
}

func (b *RequestBuilder) First(n int) *RequestBuilder                     { b.first = &n; return b }
func (b *RequestBuilder) Filter(f string) *RequestBuilder                 { b.filter = &f; return b }
func (b *RequestBuilder) After(a string) *RequestBuilder                  { b.after = &a; return b }
func (b *RequestBuilder) Scope(s string) *RequestBuilder                  { b.scopeId = &s; return b }
func (b *RequestBuilder) Ascending(target, field string) *RequestBuilder  { return b }
func (b *RequestBuilder) Descending(target, field string) *RequestBuilder { return b }

func parseTime(t interface{}) time.Time {
	if str, ok := t.(string); ok {
		if parsed, err := time.Parse(time.RFC3339, str); err == nil {
			return parsed
		}
	}
	return time.Time{}
}

func (b *RequestBuilder) Execute(ctx context.Context) (*Connection, error) {
	query := `query RequestList($first: Int, $after: String, $filters: HttpqlFilter, $scopeId: ID) {
		requests(first: $first, after: $after, filters: $filters, scopeId: $scopeId) {
			edges {
				cursor
				node {
					id host port method path query isTls createdAt raw
					response { id statusCode length roundtripTime createdAt raw }
				}
			}
			pageInfo { hasNextPage hasPreviousPage startCursor endCursor }
		}
	}`
	vars := map[string]interface{}{}
	if b.first != nil {
		vars["first"] = *b.first
	}
	if b.after != nil {
		vars["after"] = *b.after
	}
	if b.filter != nil {
		vars["filters"] = map[string]interface{}{"httpql": *b.filter}
	}
	if b.scopeId != nil {
		vars["scopeId"] = *b.scopeId
	}

	data, err := b.Client.GraphQL.Query(ctx, query, vars)
	if err != nil {
		return nil, err
	}

	requestsData, ok := data["requests"].(map[string]interface{})
	if !ok || requestsData == nil {
		return nil, fmt.Errorf("missing requests in response")
	}

	conn := &Connection{}

	if pageInfo, ok := requestsData["pageInfo"].(map[string]interface{}); ok && pageInfo != nil {
		if hnp, ok := pageInfo["hasNextPage"].(bool); ok {
			conn.PageInfo.HasNextPage = hnp
		}
		if hpp, ok := pageInfo["hasPreviousPage"].(bool); ok {
			conn.PageInfo.HasPreviousPage = hpp
		}
		if sc, ok := pageInfo["startCursor"].(string); ok {
			conn.PageInfo.StartCursor = sc
		}
		if ec, ok := pageInfo["endCursor"].(string); ok {
			conn.PageInfo.EndCursor = ec
		}
	}

	if edges, ok := requestsData["edges"].([]interface{}); ok {
		for _, eInterface := range edges {
			edgeData, ok := eInterface.(map[string]interface{})
			if !ok {
				continue
			}

			cursor, _ := edgeData["cursor"].(string)
			nodeData, _ := edgeData["node"].(map[string]interface{})
			if nodeData == nil {
				continue
			}

			reqID, _ := nodeData["id"].(string)
			host, _ := nodeData["host"].(string)
			portF, _ := nodeData["port"].(float64)
			method, _ := nodeData["method"].(string)
			path, _ := nodeData["path"].(string)
			queryStr, _ := nodeData["query"].(string)
			isTls, _ := nodeData["isTls"].(bool)
			createdAt := parseTime(nodeData["createdAt"])
			rawStr, _ := nodeData["raw"].(string)

			reqModel := &RequestModel{
				ID:        reqID,
				Host:      host,
				Port:      int(portF),
				Method:    method,
				Path:      path,
				Query:     queryStr,
				IsTLS:     isTls,
				CreatedAt: createdAt,
				Raw:       fromBase64(rawStr),
			}

			var respModel *ResponseModel
			if respData, ok := nodeData["response"].(map[string]interface{}); ok && respData != nil {
				respID, _ := respData["id"].(string)
				statusCodeF, _ := respData["statusCode"].(float64)
				lengthF, _ := respData["length"].(float64)
				roundtripTimeF, _ := respData["roundtripTime"].(float64)
				respCreatedAt := parseTime(respData["createdAt"])
				respRawStr, _ := respData["raw"].(string)

				respModel = &ResponseModel{
					ID:            respID,
					StatusCode:    int(statusCodeF),
					Length:        int(lengthF),
					RoundtripTime: int(roundtripTimeF),
					CreatedAt:     respCreatedAt,
					Raw:           fromBase64(respRawStr),
				}
			}

			conn.Edges = append(conn.Edges, Edge{
				Cursor: cursor,
				Node: Node{
					Request:  reqModel,
					Response: respModel,
				},
			})
		}
	}

	return conn, nil
}

type RequestClient struct {
	Client *Client
}

func (c *RequestClient) List() *RequestBuilder {
	return &RequestBuilder{Client: c.Client}
}

func (c *RequestClient) Get(ctx context.Context, id string, opts RequestGetOptions) (*RequestResult, error) {
	query := `query RequestGet($id: ID!, $includeRequestRaw: Boolean!, $includeResponseRaw: Boolean!) {
		request(id: $id) {
			id host port method path query isTls createdAt
			raw @include(if: $includeRequestRaw)
			response {
				id statusCode length roundtripTime createdAt
				raw @include(if: $includeResponseRaw)
			}
		}
	}`
	vars := map[string]interface{}{
		"id":                 id,
		"includeRequestRaw":  opts.RequestRaw,
		"includeResponseRaw": opts.ResponseRaw,
	}
	data, err := c.Client.GraphQL.Query(ctx, query, vars)
	if err != nil {
		return nil, err
	}

	nodeData, ok := data["request"].(map[string]interface{})
	if !ok || nodeData == nil {
		return nil, fmt.Errorf("request not found")
	}

	reqID, _ := nodeData["id"].(string)
	host, _ := nodeData["host"].(string)
	portF, _ := nodeData["port"].(float64)
	method, _ := nodeData["method"].(string)
	path, _ := nodeData["path"].(string)
	queryStr, _ := nodeData["query"].(string)
	isTls, _ := nodeData["isTls"].(bool)
	createdAt := parseTime(nodeData["createdAt"])
	rawStr, _ := nodeData["raw"].(string)

	reqModel := &RequestModel{
		ID:        reqID,
		Host:      host,
		Port:      int(portF),
		Method:    method,
		Path:      path,
		Query:     queryStr,
		IsTLS:     isTls,
		CreatedAt: createdAt,
		Raw:       fromBase64(rawStr),
	}

	var respModel *ResponseModel
	if respData, ok := nodeData["response"].(map[string]interface{}); ok && respData != nil {
		respID, _ := respData["id"].(string)
		statusCodeF, _ := respData["statusCode"].(float64)
		lengthF, _ := respData["length"].(float64)
		roundtripTimeF, _ := respData["roundtripTime"].(float64)
		respCreatedAt := parseTime(respData["createdAt"])
		respRawStr, _ := respData["raw"].(string)

		respModel = &ResponseModel{
			ID:            respID,
			StatusCode:    int(statusCodeF),
			Length:        int(lengthF),
			RoundtripTime: int(roundtripTimeF),
			CreatedAt:     respCreatedAt,
			Raw:           fromBase64(respRawStr),
		}
	}

	return &RequestResult{
		Request:  reqModel,
		Response: respModel,
	}, nil
}

// Client is a stub for the caido SDK client
type Client struct {
	URL     string
	Auth    *TokenAuthOptions
	Replay  *ReplayClient
	Scope   *ScopeClient
	GraphQL *GraphQLClient
	Request *RequestClient
}

func NewClient(url string, auth *TokenAuthOptions) *Client {
	c := &Client{
		URL:  url,
		Auth: auth,
	}
	c.GraphQL = &GraphQLClient{Client: c}
	c.Replay = &ReplayClient{Client: c, Sessions: &ReplaySessionsClient{Client: c}}
	c.Scope = &ScopeClient{Client: c}
	c.Request = &RequestClient{Client: c}
	return c
}

func (c *Client) Connect(ctx context.Context) error {
	return nil
}

func (c *Client) Close(ctx context.Context) error {
	return nil
}
