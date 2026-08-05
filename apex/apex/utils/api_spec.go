package utils

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

var SpecExtensions = map[string]bool{
	".json": true,
	".yaml": true,
	".yml":  true,
}

const maxPostmanDepth = 25
const PostmanApiBase = "https://api.getpostman.com"
const postmanFetchTimeout = 30 * time.Second

type SpecParseError struct {
	Message string
	Err     error
}

func (e *SpecParseError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func WriteFetchedCollection(raw map[string]interface{}, uid string) string {
	b, _ := json.Marshal(raw)
	path := filepath.Join(os.TempDir(), fmt.Sprintf("postman_collection_%s.json", uid))
	os.WriteFile(path, b, 0644)
	return path
}

func LoadSpec(path string) (map[string]interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &SpecParseError{Message: fmt.Sprintf("Cannot read spec %s", path), Err: err}
	}

	var dataIf interface{}
	err = json.Unmarshal(data, &dataIf)
	if err != nil {
		errYaml := yaml.Unmarshal(data, &dataIf)
		if errYaml != nil {
			return nil, &SpecParseError{Message: fmt.Sprintf("%s is not valid JSON or YAML", path), Err: errYaml}
		}
	}

	result, ok := dataIf.(map[string]interface{})
	if !ok {
		return nil, &SpecParseError{Message: fmt.Sprintf("%s does not contain a mapping at the top level", path)}
	}
	return result, nil
}

func ClassifySpec(raw map[string]interface{}) string {
	if _, ok := raw["openapi"].(string); ok {
		return "openapi"
	}
	if swagger, ok := raw["swagger"]; ok {
		if strings.HasPrefix(fmt.Sprintf("%v", swagger), "2") {
			return "swagger"
		}
	}
	info, hasInfo := raw["info"].(map[string]interface{})
	_, hasItem := raw["item"]

	hasPostmanId := false
	if hasInfo {
		_, hasPostmanId = info["_postman_id"]
	}

	if hasInfo && (hasPostmanId || hasItem) {
		return "postman"
	}
	return ""
}

func DetectSpecFormat(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	if !SpecExtensions[ext] {
		return ""
	}
	raw, err := LoadSpec(path)
	if err != nil {
		return ""
	}
	return ClassifySpec(raw)
}

func SpecTitle(raw map[string]interface{}) string {
	info, ok := raw["info"].(map[string]interface{})
	if !ok {
		return "API"
	}
	name := ""
	if title := info["title"]; title != nil && fmt.Sprintf("%v", title) != "" {
		name = fmt.Sprintf("%v", title)
	} else if n := info["name"]; n != nil && fmt.Sprintf("%v", n) != "" {
		name = fmt.Sprintf("%v", n)
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return "API"
	}
	return name
}

func absoluteURLs(candidates []string) []string {
	var urls []string
	seen := make(map[string]bool)
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		parsed, err := url.Parse(candidate)
		if err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != "" {
			u := strings.TrimRight(candidate, "/")
			if !seen[u] {
				urls = append(urls, u)
				seen[u] = true
			}
		}
	}
	return urls
}

var serverVarPattern = regexp.MustCompile(`\{([^{}/]+)\}`)

func resolveServerURL(urlStr string, variables interface{}) string {
	if !strings.Contains(urlStr, "{") {
		return urlStr
	}
	vars, ok := variables.(map[string]interface{})
	if !ok {
		return urlStr
	}
	defaults := make(map[string]string)
	for name, spec := range vars {
		specMap, ok := spec.(map[string]interface{})
		if ok && specMap["default"] != nil {
			defaults[name] = fmt.Sprintf("%v", specMap["default"])
		}
	}
	return serverVarPattern.ReplaceAllStringFunc(urlStr, func(m string) string {
		key := m[1 : len(m)-1]
		if val, ok := defaults[key]; ok {
			return val
		}
		return m
	})
}

func openapiBaseURLs(raw map[string]interface{}) []string {
	servers, ok := raw["servers"].([]interface{})
	if !ok {
		return nil
	}
	var candidates []string
	for _, s := range servers {
		server, ok := s.(map[string]interface{})
		if !ok {
			continue
		}
		if u := server["url"]; u != nil {
			urlStr := fmt.Sprintf("%v", u)
			if urlStr != "" {
				candidates = append(candidates, resolveServerURL(urlStr, server["variables"]))
			}
		}
	}
	return absoluteURLs(candidates)
}

func swaggerBaseURLs(raw map[string]interface{}) []string {
	host := ""
	if h := raw["host"]; h != nil {
		host = strings.TrimSpace(fmt.Sprintf("%v", h))
	}
	if host == "" {
		return nil
	}
	basePath := ""
	if b := raw["basePath"]; b != nil {
		basePath = strings.TrimSpace(fmt.Sprintf("%v", b))
	}

	schemesRaw, ok := raw["schemes"].([]interface{})
	var schemes []string
	if ok {
		for _, s := range schemesRaw {
			if str, ok := s.(string); ok {
				schemes = append(schemes, str)
			}
		}
	}
	if len(schemes) == 0 {
		schemes = []string{"https"}
	}

	var candidates []string
	for _, scheme := range schemes {
		candidates = append(candidates, fmt.Sprintf("%s://%s%s", scheme, host, basePath))
	}
	return absoluteURLs(candidates)
}

var postmanVarPattern = regexp.MustCompile(`\{\{\s*([^}]+?)\s*\}\}`)

func postmanVariables(raw map[string]interface{}) map[string]string {
	variables := make(map[string]string)
	entries, ok := raw["variable"].([]interface{})
	if !ok {
		return variables
	}
	for _, entry := range entries {
		entryMap, ok := entry.(map[string]interface{})
		if ok && entryMap["key"] != nil {
			key := fmt.Sprintf("%v", entryMap["key"])
			val := ""
			if v := entryMap["value"]; v != nil {
				val = fmt.Sprintf("%v", v)
			}
			variables[key] = val
		}
	}
	return variables
}

func resolvePostmanVars(text string, variables map[string]string) string {
	if len(variables) == 0 || !strings.Contains(text, "{{") {
		return text
	}
	return postmanVarPattern.ReplaceAllStringFunc(text, func(m string) string {
		match := postmanVarPattern.FindStringSubmatch(m)
		if len(match) > 1 {
			if val, ok := variables[match[1]]; ok {
				return val
			}
		}
		return m
	})
}

func postmanRequestURL(urlObj interface{}, variables map[string]string) string {
	var raw string
	switch u := urlObj.(type) {
	case string:
		raw = u
	case map[string]interface{}:
		if r, ok := u["raw"].(string); ok && r != "" {
			raw = r
		} else if host, ok := u["host"].([]interface{}); ok {
			var parts []string
			for _, h := range host {
				parts = append(parts, fmt.Sprintf("%v", h))
			}
			raw = strings.Join(parts, ".")
		} else if u["host"] != nil {
			raw = fmt.Sprintf("%v", u["host"])
		}
	default:
		return ""
	}
	return resolvePostmanVars(raw, variables)
}

func walkPostmanHosts(items interface{}, variables map[string]string, hosts *[]string, depth int) {
	if depth > maxPostmanDepth {
		return
	}
	itemList, ok := items.([]interface{})
	if !ok {
		return
	}
	for _, nodeObj := range itemList {
		node, ok := nodeObj.(map[string]interface{})
		if !ok {
			continue
		}
		if _, ok := node["item"].([]interface{}); ok {
			walkPostmanHosts(node["item"], variables, hosts, depth+1)
			continue
		}
		request, ok := node["request"].(map[string]interface{})
		if !ok {
			continue
		}
		urlStr := postmanRequestURL(request["url"], variables)
		parsed, err := url.Parse(urlStr)
		if err == nil && parsed.Scheme != "" && parsed.Host != "" {
			*hosts = append(*hosts, fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host))
		}
	}
}

func postmanBaseURLs(raw map[string]interface{}, extraVariables map[string]string) []string {
	variables := postmanVariables(raw)
	for k, v := range extraVariables {
		variables[k] = v
	}
	var hosts []string
	walkPostmanHosts(raw["item"], variables, &hosts, 0)

	// Sort and deduplicate
	sort.Strings(hosts)
	return absoluteURLs(hosts)
}

func SpecBaseURLs(raw map[string]interface{}, extraVariables map[string]string) ([]string, error) {
	specFormat := ClassifySpec(raw)
	if specFormat == "openapi" {
		return openapiBaseURLs(raw), nil
	}
	if specFormat == "swagger" {
		return swaggerBaseURLs(raw), nil
	}
	if specFormat == "postman" {
		return postmanBaseURLs(raw, extraVariables), nil
	}
	return nil, &SpecParseError{Message: "File is not a recognized OpenAPI, Swagger, or Postman spec"}
}

func postmanAPIJSON(urlStr, apiKey, label string) (map[string]interface{}, error) {
	if apiKey == "" {
		return nil, &SpecParseError{Message: "POSTMAN_API_KEY is not set. Export a Postman API key (PMAK-…) to fetch from the Postman API, or pass a local collection file instead."}
	}

	client := &http.Client{Timeout: postmanFetchTimeout}
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return nil, &SpecParseError{Message: fmt.Sprintf("Failed to reach the Postman API: %v", err), Err: err}
	}
	req.Header.Set("X-Api-Key", apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, &SpecParseError{Message: fmt.Sprintf("Failed to reach the Postman API: %v", err), Err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return nil, &SpecParseError{Message: "Postman API rejected the key (401). Check POSTMAN_API_KEY."}
	}
	if resp.StatusCode == 404 {
		return nil, &SpecParseError{Message: fmt.Sprintf("Postman %s not found (404). Check the id and that the key can access it.", label)}
	}
	if resp.StatusCode != 200 {
		return nil, &SpecParseError{Message: fmt.Sprintf("Postman API returned HTTP %d for %s.", resp.StatusCode, label)}
	}

	var payload map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, &SpecParseError{Message: fmt.Sprintf("Postman API returned non-JSON for %s", label), Err: err}
	}
	return payload, nil
}

func FetchPostmanCollection(collectionUID, apiKey string) (map[string]interface{}, error) {
	urlStr := fmt.Sprintf("%s/collections/%s", PostmanApiBase, collectionUID)
	payload, err := postmanAPIJSON(urlStr, apiKey, fmt.Sprintf("collection %s", collectionUID))
	if err != nil {
		return nil, err
	}

	collection := payload
	if c, ok := payload["collection"].(map[string]interface{}); ok {
		collection = c
	}
	if len(collection) == 0 {
		return nil, &SpecParseError{Message: fmt.Sprintf("Postman collection %s came back empty", collectionUID)}
	}
	return collection, nil
}

func FetchPostmanEnvironment(environmentUID, apiKey string) (map[string]string, error) {
	urlStr := fmt.Sprintf("%s/environments/%s", PostmanApiBase, environmentUID)
	payload, err := postmanAPIJSON(urlStr, apiKey, fmt.Sprintf("environment %s", environmentUID))
	if err != nil {
		return nil, err
	}

	environment := payload
	if e, ok := payload["environment"].(map[string]interface{}); ok {
		environment = e
	}

	valuesRaw, ok := environment["values"].([]interface{})
	if !ok {
		return make(map[string]string), nil
	}

	values := make(map[string]string)
	for _, valObj := range valuesRaw {
		valMap, ok := valObj.(map[string]interface{})
		if !ok {
			continue
		}
		if keyVal := valMap["key"]; keyVal != nil {
			key := fmt.Sprintf("%v", keyVal)
			if key != "" {
				enabled := true
				if e, ok := valMap["enabled"].(bool); ok {
					enabled = e
				}
				if enabled {
					v := ""
					if valObj := valMap["value"]; valObj != nil {
						v = fmt.Sprintf("%v", valObj)
					}
					values[key] = v
				}
			}
		}
	}
	return values, nil
}
