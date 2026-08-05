package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync"
)

var (
	caidoCallLock sync.Mutex
)

func ctxClient(ctx *RunContextWrapper) *Client {
	if ctx == nil || ctx.Context == nil {
		return nil
	}
	if client, ok := ctx.Context["caido_client"].(*Client); ok {
		return client
	}
	return nil
}

func callClient[T any](client *Client, fn func(*Client) (T, error)) (T, error) {
	caidoCallLock.Lock()
	defer caidoCallLock.Unlock()
	return fn(client)
}

func noClient() string {
	payload := map[string]interface{}{
		"success": false,
		"error":   "Caido client not available in run context",
	}
	b, _ := json.Marshal(payload)
	return string(b)
}

func errJson(name string, err error) string {
	log.Printf("%s failed: %v", name, err)
	payload := map[string]interface{}{
		"success": false,
		"error":   fmt.Sprintf("%s failed: %v", name, err),
	}
	b, _ := json.Marshal(payload)
	return string(b)
}

func ListRequestsTool(
	ctx *RunContextWrapper,
	httpqlFilter *string,
	first int,
	after *string,
	sortBy SortBy,
	sortOrder SortOrder,
	scopeId *string,
) string {
	if first == 0 {
		first = 50
	}
	if sortBy == "" {
		sortBy = SortByTimestamp
	}
	if sortOrder == "" {
		sortOrder = "desc"
	}

	client := ctxClient(ctx)
	if client == nil {
		return noClient()
	}

	connection, err := callClient(client, func(c *Client) (*Connection, error) {
		return ListRequestsWithClient(context.Background(), c, httpqlFilter, first, after, sortBy, sortOrder, scopeId)
	})
	if err != nil {
		return errJson("list_requests", err)
	}

	var entries []map[string]interface{}
	for _, edge := range connection.Edges {
		req := edge.Node.Request
		resp := edge.Node.Response
		
		var responsePayload map[string]interface{}
		if resp != nil {
			responsePayload = map[string]interface{}{
				"id":          resp.ID,
				"status_code": resp.StatusCode,
				"length":      resp.Length,
				"created_at":  resp.CreatedAt.UTC().Format("2006-01-02T15:04:05.000000+00:00"),
			}
			if resp.RoundtripTime > 0 {
				responsePayload["roundtrip_ms"] = resp.RoundtripTime
			}
		}
		
		reqPayload := map[string]interface{}{
			"id":         req.ID,
			"host":       req.Host,
			"port":       req.Port,
			"method":     req.Method,
			"path":       req.Path,
			"query":      req.Query,
			"is_tls":     req.IsTLS,
			"created_at": req.CreatedAt.UTC().Format("2006-01-02T15:04:05.000000+00:00"),
		}
		
		entries = append(entries, map[string]interface{}{
			"cursor":   edge.Cursor,
			"request":  reqPayload,
			"response": responsePayload,
		})
	}

	result := map[string]interface{}{
		"success": true,
		"entries": entries,
		"page_info": map[string]interface{}{
			"has_next_page":     connection.PageInfo.HasNextPage,
			"has_previous_page": connection.PageInfo.HasPreviousPage,
			"start_cursor":      connection.PageInfo.StartCursor,
			"end_cursor":        connection.PageInfo.EndCursor,
		},
	}
	b, _ := json.Marshal(result)
	return string(b)
}

func formatSearchHits(content string, pattern string) map[string]interface{} {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return map[string]interface{}{"success": false, "error": fmt.Sprintf("Invalid regex: %v", err)}
	}

	matches := re.FindAllStringIndex(content, 20)
	var hits []map[string]interface{}
	for _, match := range matches {
		start, end := match[0], match[1]
		
		beforeStart := start - 40
		if beforeStart < 0 {
			beforeStart = 0
		}
		before := content[beforeStart:start]
		
		afterEnd := end + 40
		if afterEnd > len(content) {
			afterEnd = len(content)
		}
		after := content[end:afterEnd]
		
		hits = append(hits, map[string]interface{}{
			"match":    content[start:end],
			"position": start,
			"before":   before,
			"after":    after,
		})
	}

	return map[string]interface{}{
		"success":    true,
		"hits":       hits,
		"total_hits": len(hits),
	}
}

func formatTextPage(content string, page int, pageSize int) map[string]interface{} {
	lines := strings.Split(content, "\n")
	for i := range lines {
		lines[i] = strings.TrimRight(lines[i], "\r")
	}
	
	start := (page - 1) * pageSize
	if start < 0 {
		start = 0
	}
	
	end := start + pageSize
	if start > len(lines) {
		start = len(lines)
	}
	if end > len(lines) {
		end = len(lines)
	}
	
	hasMore := end < len(lines)
	pageContent := strings.Join(lines[start:end], "\n")
	
	return map[string]interface{}{
		"success":     true,
		"content":     pageContent,
		"page":        page,
		"page_size":   pageSize,
		"total_lines": len(lines),
		"has_more":    hasMore,
	}
}

func ViewRequestTool(
	ctx *RunContextWrapper,
	requestId string,
	part RequestPart,
	searchPattern *string,
	page int,
	pageSize int,
) string {
	if part == "" {
		part = RequestPartRequest
	}
	if page == 0 {
		page = 1
	}
	if pageSize == 0 {
		pageSize = 50
	}

	client := ctxClient(ctx)
	if client == nil {
		return noClient()
	}

	result, err := callClient(client, func(c *Client) (*RequestResult, error) {
		return GetRequestWithClient(context.Background(), c, requestId, part)
	})
	if err != nil {
		return errJson("view_request", err)
	}
	if result == nil {
		payload := map[string]interface{}{"success": false, "error": fmt.Sprintf("Request %s not found", requestId)}
		b, _ := json.Marshal(payload)
		return string(b)
	}

	var rawBytes []byte
	if part == RequestPartRequest && result.Request != nil {
		rawBytes = result.Request.Raw
	} else if part == RequestPartResponse && result.Response != nil {
		rawBytes = result.Response.Raw
	}
	
	if len(rawBytes) == 0 {
		payload := map[string]interface{}{"success": false, "error": fmt.Sprintf("No raw %s for %s", part, requestId)}
		b, _ := json.Marshal(payload)
		return string(b)
	}
	
	content := string(rawBytes)
	
	var res map[string]interface{}
	if searchPattern != nil && *searchPattern != "" {
		res = formatSearchHits(content, *searchPattern)
	} else {
		res = formatTextPage(content, page, pageSize)
	}
	
	b, _ := json.Marshal(res)
	return string(b)
}

func formatReplayToolResult(replay map[string]interface{}) string {
	var response interface{}
	if raw, ok := replay["response_raw"].([]byte); ok && len(raw) > 0 {
		response = ParseRawResponse(raw)
	}
	
	status, _ := replay["status"].(string)
	success := status == "DONE"
	
	payload := map[string]interface{}{
		"success":    success,
		"status":     status,
		"session_id": replay["session_id"],
		"elapsed_ms": replay["elapsed_ms"],
		"response":   response,
	}
	
	if errStr, ok := replay["error"].(string); ok && errStr != "" {
		payload["error"] = errStr
	}
	
	b, _ := json.Marshal(payload)
	return string(b)
}

func RepeatRequestTool(
	ctx *RunContextWrapper,
	requestId string,
	modifications map[string]interface{},
) string {
	client := ctxClient(ctx)
	if client == nil {
		return noClient()
	}
	if modifications == nil {
		modifications = make(map[string]interface{})
	}

	replay, err := callClient(client, func(c *Client) (map[string]interface{}, error) {
		res, err := GetRequestWithClient(context.Background(), c, requestId, RequestPartRequest)
		if err != nil || res == nil || res.Request == nil || len(res.Request.Raw) == 0 {
			return nil, nil
		}
		
		original := res.Request
		rawStr := string(res.Request.Raw)
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
		
		return ReplaySendRaw(context.Background(), c, raw, connection)
	})
	
	if err != nil {
		return errJson("repeat_request", err)
	}
	if replay == nil {
		payload := map[string]interface{}{"success": false, "error": fmt.Sprintf("Request %s not found", requestId)}
		b, _ := json.Marshal(payload)
		return string(b)
	}
	
	return formatReplayToolResult(replay)
}

func ListSitemapTool(
	ctx *RunContextWrapper,
	scopeId *string,
	parentId *string,
	depth SitemapDepth,
	page int,
) string {
	if depth == "" {
		depth = SitemapDepthDirect
	}
	if page == 0 {
		page = 1
	}

	client := ctxClient(ctx)
	if client == nil {
		return noClient()
	}

	payload, err := callClient(client, func(c *Client) (map[string]interface{}, error) {
		return ListSitemapWithClient(context.Background(), c, scopeId, parentId, depth, page, SitemapPageSize)
	})
	if err != nil {
		return errJson("list_sitemap", err)
	}

	b, _ := json.Marshal(payload)
	return string(b)
}

func ViewSitemapEntryTool(
	ctx *RunContextWrapper,
	entryId string,
) string {
	client := ctxClient(ctx)
	if client == nil {
		return noClient()
	}

	payload, err := callClient(client, func(c *Client) (map[string]interface{}, error) {
		return ViewSitemapEntryWithClient(context.Background(), c, entryId)
	})
	if err != nil {
		return errJson("view_sitemap_entry", err)
	}
	
	b, _ := json.Marshal(payload)
	return string(b)
}

func toToolJson(v interface{}) interface{} {
	return v
}

func ScopeRulesTool(
	ctx *RunContextWrapper,
	action ScopeAction,
	allowlist []string,
	denylist []string,
	scopeId *string,
	scopeName *string,
) string {
	client := ctxClient(ctx)
	if client == nil {
		return noClient()
	}

	res, err := callClient(client, func(c *Client) (interface{}, error) {
		switch action {
		case "list":
			scopes, err := ScopeList(context.Background(), c)
			if err != nil {
				return nil, err
			}
			return map[string]interface{}{"success": true, "scopes": scopes}, nil
		case "get":
			if scopeId == nil || *scopeId == "" {
				return map[string]interface{}{"success": false, "error": "Scope_id is required for action='get'"}, nil
			}
			scope, err := ScopeGet(context.Background(), c, *scopeId)
			if err != nil {
				return nil, err
			}
			return map[string]interface{}{"success": true, "scope": scope}, nil
		case "create":
			if scopeName == nil || *scopeName == "" {
				return map[string]interface{}{"success": false, "error": "Scope_name is required for action='create'"}, nil
			}
			scope, err := ScopeCreate(context.Background(), c, *scopeName, allowlist, denylist)
			if err != nil {
				return nil, err
			}
			return map[string]interface{}{"success": true, "scope": scope}, nil
		case "update":
			if scopeId == nil || *scopeId == "" || scopeName == nil || *scopeName == "" {
				return map[string]interface{}{"success": false, "error": "Scope_id and scope_name are required for action='update'"}, nil
			}
			scope, err := ScopeUpdate(context.Background(), c, *scopeId, *scopeName, allowlist, denylist)
			if err != nil {
				return nil, err
			}
			return map[string]interface{}{"success": true, "scope": scope}, nil
		case "delete":
			if scopeId == nil || *scopeId == "" {
				return map[string]interface{}{"success": false, "error": "Scope_id is required for action='delete'"}, nil
			}
			err := ScopeDelete(context.Background(), c, *scopeId)
			if err != nil {
				return nil, err
			}
			return map[string]interface{}{
				"success": true,
				"deleted": *scopeId,
				"message": fmt.Sprintf("Scope %s deleted", *scopeId),
			}, nil
		default:
			return map[string]interface{}{"success": false, "error": fmt.Sprintf("Unknown action: %s", action)}, nil
		}
	})
	
	if err != nil {
		return errJson("scope_rules", err)
	}
	
	b, _ := json.Marshal(res)
	return string(b)
}
