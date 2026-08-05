package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type RequestPart string
const (
	RequestPartRequest  RequestPart = "request"
	RequestPartResponse RequestPart = "response"
)

type SortBy string
type SortOrder string
type ScopeAction string
type SitemapDepth string

const (
	SortByTimestamp    SortBy = "timestamp"
	SortByHost         SortBy = "host"
	SortByMethod       SortBy = "method"
	SortByPath         SortBy = "path"
	SortByStatusCode   SortBy = "status_code"
	SortByResponseTime SortBy = "response_time"
	SortByResponseSize SortBy = "response_size"
	SortBySource       SortBy = "source"
)

const (
	SitemapDepthDirect SitemapDepth = "DIRECT"
	SitemapDepthAll    SitemapDepth = "ALL"
)

const (
	SitemapPageSize = 30
	DefaultCaidoUrl = "http://127.0.0.1:48080"
)

var (
	clientCache map[string]*Client = make(map[string]*Client)
	clientLock  sync.Mutex
	reqFieldMap = map[SortBy][2]string{
		SortByTimestamp:    {"req", "created_at"},
		SortByHost:         {"req", "host"},
		SortByMethod:       {"req", "method"},
		SortByPath:         {"req", "path"},
		SortBySource:       {"req", "source"},
		SortByStatusCode:   {"resp", "code"},
		SortByResponseTime: {"resp", "roundtrip"},
		SortByResponseSize: {"resp", "length"},
	}
)

func CaidoUrl() string {
	u := os.Getenv("APEX_CAIDO_URL")
	if u == "" {
		u = DefaultCaidoUrl
	}
	return strings.TrimRight(u, "/")
}

func graphqlUrl() (string, error) {
	baseUrl := CaidoUrl()
	parsed, err := url.Parse(baseUrl)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return "", fmt.Errorf("Invalid Caido URL: %s", baseUrl)
	}
	return fmt.Sprintf("%s/graphql", baseUrl), nil
}

func loginAsGuest(ctx context.Context) (string, error) {
	gUrl, err := graphqlUrl()
	if err != nil {
		return "", err
	}
	body := []byte(`{"query": "mutation { loginAsGuest { token { accessToken } } }"}`)
	req, err := http.NewRequestWithContext(ctx, "POST", gUrl, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	
	var payload map[string]interface{}
	if err := json.Unmarshal(respBody, &payload); err != nil {
		return "", err
	}
	
	data, ok := payload["data"].(map[string]interface{})
	if !ok {
		return "", errors.New("missing data in response")
	}
	login, ok := data["loginAsGuest"].(map[string]interface{})
	if !ok {
		return "", errors.New("missing loginAsGuest")
	}
	tokenData, ok := login["token"].(map[string]interface{})
	if !ok {
		return "", errors.New("missing token")
	}
	accessToken, ok := tokenData["accessToken"].(string)
	if !ok {
		return "", errors.New("missing accessToken")
	}
	return accessToken, nil
}

func newClient(ctx context.Context) (*Client, error) {
	token, err := loginAsGuest(ctx)
	if err != nil {
		return nil, err
	}
	client := NewClient(CaidoUrl(), &TokenAuthOptions{Token: token})
	if err := client.Connect(ctx); err != nil {
		return nil, err
	}
	return client, nil
}

var newClientFunc = newClient

func GetClient(ctx context.Context) (*Client, error) {
	clientLock.Lock()
	defer clientLock.Unlock()
	
	if client, ok := clientCache["default"]; ok {
		return client, nil
	}
	
	client, err := newClientFunc(ctx)
	if err != nil {
		return nil, err
	}
	clientCache["default"] = client
	return client, nil
}

func CallWithClient[T any](ctx context.Context, fn func(context.Context, *Client) (T, error)) (T, error) {
	clientLock.Lock()
	defer clientLock.Unlock()
	
	client, ok := clientCache["default"]
	if !ok {
		var err error
		client, err = newClientFunc(ctx)
		if err != nil {
			var zero T
			return zero, err
		}
		clientCache["default"] = client
	}
	return fn(ctx, client)
}

func CloseClient(ctx context.Context) error {
	clientLock.Lock()
	defer clientLock.Unlock()
	
	client, ok := clientCache["default"]
	if !ok {
		return nil
	}
	delete(clientCache, "default")
	return client.Close(ctx)
}

func ListRequestsWithClient(ctx context.Context, client *Client, httpqlFilter *string, first int, after *string, sortBy SortBy, sortOrder SortOrder, scopeId *string) (*Connection, error) {
	builder := client.Request.List().First(first)
	if httpqlFilter != nil && *httpqlFilter != "" {
		builder = builder.Filter(*httpqlFilter)
	}
	if after != nil && *after != "" {
		builder = builder.After(*after)
	}
	if scopeId != nil && *scopeId != "" {
		builder = builder.Scope(*scopeId)
	}
	
	mapping, ok := reqFieldMap[sortBy]
	if !ok {
		mapping = reqFieldMap[SortByTimestamp]
	}
	
	if sortOrder == "desc" {
		builder = builder.Descending(mapping[0], mapping[1])
	} else {
		builder = builder.Ascending(mapping[0], mapping[1])
	}
	return builder.Execute(ctx)
}

func GetRequestWithClient(ctx context.Context, client *Client, requestId string, part RequestPart) (*RequestResult, error) {
	opts := RequestGetOptions{RequestRaw: true, ResponseRaw: true}
	return client.Request.Get(ctx, requestId, opts)
}

var framingHeaders = map[string]bool{
	"content-length":    true,
	"transfer-encoding": true,
}

func BuildRawRequest(method, urlStr string, headers map[string]string, body string) (ConnectionInfoInput, []byte, error) {
	parsed, err := url.Parse(urlStr)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ConnectionInfoInput{}, nil, fmt.Errorf("Invalid URL: %s", urlStr)
	}
	
	isTls := strings.ToLower(parsed.Scheme) == "https"
	host := parsed.Hostname()
	
	port := 80
	if isTls {
		port = 443
	}
	if parsed.Port() != "" {
		if p, err := strconv.Atoi(parsed.Port()); err == nil {
			port = p
		}
	}
	
	path := parsed.Path
	if path == "" {
		path = "/"
	}
	if parsed.RawQuery != "" {
		path = fmt.Sprintf("%s?%s", path, parsed.RawQuery)
	}
	
	finalHeaders := make(map[string]string)
	for k, v := range headers {
		finalHeaders[k] = v
	}
	if _, ok := finalHeaders["Host"]; !ok {
		finalHeaders["Host"] = parsed.Host
	}
	if _, ok := finalHeaders["User-Agent"]; !ok {
		finalHeaders["User-Agent"] = "apex"
	}
	
	for k := range finalHeaders {
		if framingHeaders[strings.ToLower(k)] {
			delete(finalHeaders, k)
		}
	}
	
	if body != "" {
		finalHeaders["Content-Length"] = strconv.Itoa(len(body))
	}
	
	lines := []string{fmt.Sprintf("%s %s HTTP/1.1", strings.ToUpper(method), path)}
	for k, v := range finalHeaders {
		lines = append(lines, fmt.Sprintf("%s: %s", k, v))
	}
	
	rawStr := strings.Join(lines, "\r\n") + "\r\n\r\n" + body
	
	return ConnectionInfoInput{
		Host:  host,
		Port:  port,
		IsTLS: isTls,
	}, []byte(rawStr), nil
}

const responseBodyMaxChars = 8192

func ParseRawResponse(rawBytes []byte) map[string]interface{} {
	if len(rawBytes) == 0 {
		return nil
	}
	
	parts := bytes.SplitN(rawBytes, []byte("\r\n\r\n"), 2)
	if len(parts) < 2 {
		return nil
	}
	
	head := string(parts[0])
	bodyBytes := parts[1]
	
	lines := strings.Split(head, "\r\n")
	if len(lines) == 0 {
		return nil
	}
	
	statusParts := strings.SplitN(lines[0], " ", 3)
	if len(statusParts) < 2 {
		return nil
	}
	
	statusCode, err := strconv.Atoi(statusParts[1])
	if err != nil {
		return nil
	}
	
	headers := make(map[string]string)
	for _, line := range lines[1:] {
		if idx := strings.Index(line, ":"); idx != -1 {
			k := strings.TrimSpace(line[:idx])
			v := strings.TrimSpace(line[idx+1:])
			headers[k] = v
		}
	}
	
	bodyText := string(bodyBytes)
	bodyTruncated := len(bodyText) > responseBodyMaxChars
	if bodyTruncated {
		bodyText = bodyText[:responseBodyMaxChars]
	}
	
	return map[string]interface{}{
		"status_code":    statusCode,
		"length":         len(bodyBytes),
		"headers":        headers,
		"body":           bodyText,
		"body_truncated": bodyTruncated,
	}
}

func ParseRawRequest(rawContent string) (map[string]interface{}, error) {
	lines := strings.Split(rawContent, "\n")
	if len(lines) == 0 {
		return nil, errors.New("Invalid request line format")
	}
	requestLine := strings.SplitN(strings.TrimSpace(lines[0]), " ", 3)
	if len(requestLine) < 2 {
		return nil, errors.New("Invalid request line format")
	}
	method := requestLine[0]
	urlPath := requestLine[1]
	
	parsedHeaders := make(map[string]string)
	bodyStart := 0
	for i := 1; i < len(lines); i++ {
		line := lines[i]
		if strings.TrimSpace(line) == "" || strings.TrimSpace(line) == "\r" {
			bodyStart = i + 1
			break
		}
		if idx := strings.Index(line, ":"); idx != -1 {
			k := strings.TrimSpace(line[:idx])
			v := strings.TrimSpace(line[idx+1:])
			parsedHeaders[k] = v
		}
	}
	
	body := ""
	if bodyStart > 0 && bodyStart < len(lines) {
		body = strings.TrimSpace(strings.Join(lines[bodyStart:], "\n"))
	}
	
	return map[string]interface{}{
		"method":   method,
		"url_path": urlPath,
		"headers":  parsedHeaders,
		"body":     body,
	}, nil
}

func FullUrlFromComponents(original *RequestModel, components map[string]interface{}, modifications map[string]interface{}) string {
	if urlMod, ok := modifications["url"]; ok {
		return fmt.Sprintf("%v", urlMod)
	}
	
	headers, _ := components["headers"].(map[string]string)
	hostHeader := headers["Host"]
	if hostHeader == "" {
		hostHeader = original.Host
	}
	
	scheme := "http"
	if original.IsTLS {
		scheme = "https"
	}
	
	urlPath, _ := components["url_path"].(string)
	return fmt.Sprintf("%s://%s%s", scheme, hostHeader, urlPath)
}

func ApplyModifications(components map[string]interface{}, modifications map[string]interface{}, fullUrl string) map[string]interface{} {
	headers := make(map[string]string)
	if origHeaders, ok := components["headers"].(map[string]string); ok {
		for k, v := range origHeaders {
			headers[k] = v
		}
	}
	
	body, _ := components["body"].(string)
	finalUrl := fullUrl
	
	if paramsMod, ok := modifications["params"].(map[string]interface{}); ok {
		parsed, err := url.Parse(finalUrl)
		if err == nil {
			existing := parsed.Query()
			for k, v := range paramsMod {
				existing.Set(k, fmt.Sprintf("%v", v))
			}
			parsed.RawQuery = existing.Encode()
			finalUrl = parsed.String()
		}
	}
	
	if headersMod, ok := modifications["headers"].(map[string]interface{}); ok {
		for k, v := range headersMod {
			headers[k] = fmt.Sprintf("%v", v)
		}
	}
	
	if bodyMod, ok := modifications["body"].(string); ok {
		body = bodyMod
	}
	
	if cookiesMod, ok := modifications["cookies"].(map[string]interface{}); ok {
		cookies := make(map[string]string)
		if cookieStr, ok := headers["Cookie"]; ok && cookieStr != "" {
			parts := strings.Split(cookieStr, ";")
			for _, p := range parts {
				idx := strings.Index(p, "=")
				if idx != -1 {
					cookies[strings.TrimSpace(p[:idx])] = strings.TrimSpace(p[idx+1:])
				}
			}
		}
		for k, v := range cookiesMod {
			cookies[k] = fmt.Sprintf("%v", v)
		}
		cookieParts := []string{}
		for k, v := range cookies {
			cookieParts = append(cookieParts, fmt.Sprintf("%s=%s", k, v))
		}
		headers["Cookie"] = strings.Join(cookieParts, "; ")
	}
	
	method, _ := components["method"].(string)
	
	return map[string]interface{}{
		"method":  method,
		"url":     finalUrl,
		"headers": headers,
		"body":    body,
	}
}

func ReplaySendRaw(ctx context.Context, client *Client, raw []byte, connection ConnectionInfoInput) (map[string]interface{}, error) {
	started := time.Now()
	
	session, err := client.Replay.Sessions.Create(ctx)
	if err != nil {
		return nil, err
	}
	
	ctxTimeout, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	
	result, err := client.Replay.Send(ctxTimeout, session.ID, ReplaySendOptions{Raw: raw, Connection: connection})
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			elapsedMs := int(time.Since(started).Milliseconds())
			return map[string]interface{}{
				"session_id": session.ID,
				"status":     "ERROR",
				"error":      "Caido replay dispatch did not complete within 30s — the target may be unroutable from the sandbox, or Caido's outbound HTTP client is stalled; check the target host/port and retry",
				"elapsed_ms": elapsedMs,
				"response_raw": nil,
			}, nil
		}
		return nil, err
	}
	
	elapsedMs := int(time.Since(started).Milliseconds())
	var responseRaw []byte
	if result.Entry != nil && result.Entry.Response != nil {
		responseRaw = result.Entry.Response.Raw
	}
	
	return map[string]interface{}{
		"session_id":   session.ID,
		"status":       result.Status,
		"error":        result.Error,
		"elapsed_ms":   elapsedMs,
		"response_raw": responseRaw,
	}, nil
}

func ScopeList(ctx context.Context, client *Client) ([]interface{}, error) {
	return client.Scope.List(ctx)
}

func ScopeGet(ctx context.Context, client *Client, scopeId string) (interface{}, error) {
	return client.Scope.Get(ctx, scopeId)
}

func ScopeCreate(ctx context.Context, client *Client, name string, allowlist []string, denylist []string) (interface{}, error) {
	if allowlist == nil {
		allowlist = []string{}
	}
	if denylist == nil {
		denylist = []string{}
	}
	return client.Scope.Create(ctx, CreateScopeOptions{Name: name, Allowlist: allowlist, Denylist: denylist})
}

func ScopeUpdate(ctx context.Context, client *Client, scopeId string, name string, allowlist []string, denylist []string) (interface{}, error) {
	if allowlist == nil {
		allowlist = []string{}
	}
	if denylist == nil {
		denylist = []string{}
	}
	return client.Scope.Update(ctx, scopeId, UpdateScopeOptions{Name: name, Allowlist: allowlist, Denylist: denylist})
}

func ScopeDelete(ctx context.Context, client *Client, scopeId string) error {
	return client.Scope.Delete(ctx, scopeId)
}

func ListRequests(ctx context.Context, httpqlFilter *string, first int, after *string, sortBy SortBy, sortOrder SortOrder, scopeId *string) (*Connection, error) {
	return CallWithClient(ctx, func(ctx context.Context, client *Client) (*Connection, error) {
		return ListRequestsWithClient(ctx, client, httpqlFilter, first, after, sortBy, sortOrder, scopeId)
	})
}

func ViewRequest(ctx context.Context, requestId string, part RequestPart) (*RequestResult, error) {
	return CallWithClient(ctx, func(ctx context.Context, client *Client) (*RequestResult, error) {
		return GetRequestWithClient(ctx, client, requestId, part)
	})
}

func RepeatRequest(ctx context.Context, requestId string, modifications map[string]interface{}) (map[string]interface{}, error) {
	if modifications == nil {
		modifications = make(map[string]interface{})
	}
	
	return CallWithClient(ctx, func(ctx context.Context, client *Client) (map[string]interface{}, error) {
		result, err := GetRequestWithClient(ctx, client, requestId, RequestPartRequest)
		if err != nil {
			return nil, err
		}
		if result == nil || result.Request == nil || len(result.Request.Raw) == 0 {
			return nil, fmt.Errorf("Request %s not found", requestId)
		}
		
		original := result.Request
		rawStr := string(result.Request.Raw)
		components, err := ParseRawRequest(rawStr)
		if err != nil {
			return nil, err
		}
		
		fullUrl := FullUrlFromComponents(original, components, modifications)
		modified := ApplyModifications(components, modifications, fullUrl)
		
		method, _ := modified["method"].(string)
		urlStr, _ := modified["url"].(string)
		headers, _ := modified["headers"].(map[string]string)
		body, _ := modified["body"].(string)
		
		connection, raw, err := BuildRawRequest(method, urlStr, headers, body)
		if err != nil {
			return nil, err
		}
		
		return ReplaySendRaw(ctx, client, raw, connection)
	})
}

func ScopeRules(ctx context.Context, action ScopeAction, allowlist []string, denylist []string, scopeId *string, scopeName *string) (interface{}, error) {
	return CallWithClient(ctx, func(ctx context.Context, client *Client) (interface{}, error) {
		switch action {
		case "list":
			return ScopeList(ctx, client)
		case "get":
			if scopeId == nil || *scopeId == "" {
				return nil, errors.New("scope_id required for get")
			}
			return ScopeGet(ctx, client, *scopeId)
		case "create":
			if scopeName == nil || *scopeName == "" {
				return nil, errors.New("scope_name required for create")
			}
			return ScopeCreate(ctx, client, *scopeName, allowlist, denylist)
		case "update":
			if scopeId == nil || *scopeId == "" || scopeName == nil || *scopeName == "" {
				return nil, errors.New("scope_id and scope_name required for update")
			}
			return ScopeUpdate(ctx, client, *scopeId, *scopeName, allowlist, denylist)
		case "delete":
			if scopeId == nil || *scopeId == "" {
				return nil, errors.New("scope_id required for delete")
			}
			err := ScopeDelete(ctx, client, *scopeId)
			if err != nil {
				return nil, err
			}
			return map[string]string{"deleted": *scopeId}, nil
		default:
			return nil, fmt.Errorf("Unknown action: %s", action)
		}
	})
}

var sitemapRootsQuery = `
query GetSitemapRoots($scopeId: ID) {
    sitemapRootEntries(scopeId: $scopeId) {
        edges { node {
            id kind label hasDescendants
            metadata { ... on SitemapEntryMetadataDomain { isTls port } }
            request { method path response { statusCode } }
        } }
        count { value }
    }
}
`

var sitemapDescendantsQuery = `
query GetSitemapDescendants($parentId: ID!, $depth: SitemapDescendantsDepth!) {
    sitemapDescendantEntries(parentId: $parentId, depth: $depth) {
        edges { node {
            id kind label hasDescendants
            request { method path response { statusCode } }
        } }
        count { value }
    }
}
`

var sitemapEntryQuery = `
query GetSitemapEntry($id: ID!) {
    sitemapEntry(id: $id) {
        id kind label hasDescendants
        metadata { ... on SitemapEntryMetadataDomain { isTls port } }
        request { method path response { statusCode length roundtripTime } }
        requests(first: 30, order: {by: CREATED_AT, ordering: DESC}) {
            edges { node { method path response { statusCode length } } }
            count { value }
        }
    }
}
`

func cleanSitemapMetadata(node map[string]interface{}) map[string]interface{} {
	cleaned := map[string]interface{}{
		"id":              node["id"],
		"kind":            node["kind"],
		"label":           node["label"],
		"has_descendants": node["hasDescendants"],
	}
	
	if meta, ok := node["metadata"].(map[string]interface{}); ok {
		metaOut := make(map[string]interface{})
		if isTls, hasTls := meta["isTls"]; hasTls && isTls != nil {
			metaOut["is_tls"] = isTls
		}
		if port, hasPort := meta["port"]; hasPort && port != nil {
			metaOut["port"] = port
		}
		if len(metaOut) > 0 {
			cleaned["metadata"] = metaOut
		}
	}
	return cleaned
}

func cleanSitemapRequestSummary(req map[string]interface{}) map[string]interface{} {
	if req == nil {
		return nil
	}
	out := make(map[string]interface{})
	if method, ok := req["method"]; ok && method != nil {
		out["method"] = method
	}
	if path, ok := req["path"]; ok && path != nil {
		out["path"] = path
	}
	
	if resp, ok := req["response"].(map[string]interface{}); ok && resp != nil {
		if code, hasCode := resp["statusCode"]; hasCode && code != nil {
			out["status_code"] = code
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func cleanSitemapResponse(resp map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{})
	if code, ok := resp["statusCode"]; ok && code != nil {
		out["status_code"] = code
	}
	if length, ok := resp["length"]; ok && length != nil {
		out["length"] = length
	}
	if roundtrip, ok := resp["roundtripTime"]; ok && roundtrip != nil {
		out["roundtrip_ms"] = roundtrip
	}
	return out
}

func ListSitemapWithClient(ctx context.Context, client *Client, scopeId *string, parentId *string, depth SitemapDepth, page int, pageSize int) (map[string]interface{}, error) {
	var raw map[string]interface{}
	var err error
	var data map[string]interface{}
	
	if parentId != nil && *parentId != "" {
		raw, err = client.GraphQL.Query(ctx, sitemapDescendantsQuery, map[string]interface{}{
			"parentId": *parentId,
			"depth":    string(depth),
		})
		if err == nil && raw != nil {
			if d, ok := raw["sitemapDescendantEntries"].(map[string]interface{}); ok {
				data = d
			}
		}
	} else {
		vars := map[string]interface{}{}
		if scopeId != nil && *scopeId != "" {
			vars["scopeId"] = *scopeId
		}
		raw, err = client.GraphQL.Query(ctx, sitemapRootsQuery, vars)
		if err == nil && raw != nil {
			if d, ok := raw["sitemapRootEntries"].(map[string]interface{}); ok {
				data = d
			}
		}
	}
	
	if err != nil {
		return nil, err
	}
	if data == nil {
		data = make(map[string]interface{})
	}
	
	edgesIface, _ := data["edges"].([]interface{})
	countData, _ := data["count"].(map[string]interface{})
	total := 0
	if val, ok := countData["value"].(float64); ok {
		total = int(val)
	}
	
	skip := (page - 1) * pageSize
	if skip < 0 {
		skip = 0
	}
	
	var sliced []map[string]interface{}
	for i, edgeIface := range edgesIface {
		if i >= skip && i < skip+pageSize {
			if edge, ok := edgeIface.(map[string]interface{}); ok {
				if node, ok := edge["node"].(map[string]interface{}); ok {
					sliced = append(sliced, node)
				}
			}
		}
	}
	
	cleaned := []map[string]interface{}{}
	for _, node := range sliced {
		entry := cleanSitemapMetadata(node)
		if reqIface, ok := node["request"].(map[string]interface{}); ok {
			summary := cleanSitemapRequestSummary(reqIface)
			if summary != nil {
				entry["request"] = summary
			}
		}
		cleaned = append(cleaned, entry)
	}
	
	totalPages := 0
	if total > 0 {
		totalPages = (total + pageSize - 1) / pageSize
	}
	
	return map[string]interface{}{
		"success":     true,
		"entries":     cleaned,
		"page":        page,
		"page_size":   pageSize,
		"total_pages": totalPages,
		"total_count": total,
		"has_more":    page < totalPages,
	}, nil
}

func ViewSitemapEntryWithClient(ctx context.Context, client *Client, entryId string) (map[string]interface{}, error) {
	raw, err := client.GraphQL.Query(ctx, sitemapEntryQuery, map[string]interface{}{"id": entryId})
	if err != nil {
		return nil, err
	}
	
	entry, ok := raw["sitemapEntry"].(map[string]interface{})
	if !ok || entry == nil {
		return map[string]interface{}{"success": false, "error": fmt.Sprintf("Sitemap entry %s not found", entryId)}, nil
	}
	
	cleaned := cleanSitemapMetadata(entry)
	if reqIface, ok := entry["request"].(map[string]interface{}); ok && reqIface != nil {
		primaryClean := make(map[string]interface{})
		if method, ok := reqIface["method"]; ok && method != nil {
			primaryClean["method"] = method
		}
		if path, ok := reqIface["path"]; ok && path != nil {
			primaryClean["path"] = path
		}
		if respIface, ok := reqIface["response"].(map[string]interface{}); ok && respIface != nil {
			primaryClean["response"] = cleanSitemapResponse(respIface)
		}
		if len(primaryClean) > 0 {
			cleaned["request"] = primaryClean
		}
	}
	
	related, _ := entry["requests"].(map[string]interface{})
	relatedEdges, _ := related["edges"].([]interface{})
	var relatedClean []map[string]interface{}
	
	for _, edgeIface := range relatedEdges {
		if edge, ok := edgeIface.(map[string]interface{}); ok {
			if node, ok := edge["node"].(map[string]interface{}); ok {
				if summary := cleanSitemapRequestSummary(node); summary != nil {
					relatedClean = append(relatedClean, summary)
				}
			}
		}
	}
	
	totalCount := 0
	if related != nil {
		if countData, ok := related["count"].(map[string]interface{}); ok {
			if val, ok := countData["value"].(float64); ok {
				totalCount = int(val)
			}
		}
	}
	
	cleaned["related_requests"] = map[string]interface{}{
		"requests":    relatedClean,
		"total_count": totalCount,
	}
	
	return map[string]interface{}{
		"success": true,
		"entry":   cleaned,
	}, nil
}

func ListSitemap(ctx context.Context, scopeId *string, parentId *string, depth SitemapDepth, page int, pageSize int) (map[string]interface{}, error) {
	return CallWithClient(ctx, func(ctx context.Context, client *Client) (map[string]interface{}, error) {
		return ListSitemapWithClient(ctx, client, scopeId, parentId, depth, page, pageSize)
	})
}

func ViewSitemapEntry(ctx context.Context, entryId string) (map[string]interface{}, error) {
	return CallWithClient(ctx, func(ctx context.Context, client *Client) (map[string]interface{}, error) {
		return ViewSitemapEntryWithClient(ctx, client, entryId)
	})
}
