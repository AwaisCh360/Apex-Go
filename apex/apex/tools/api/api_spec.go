package api

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type SpecParseError struct {
	Message string
}

func (e *SpecParseError) Error() string {
	return e.Message
}

var SPEC_EXTENSIONS = map[string]bool{
	".json": true,
	".yaml": true,
	".yml":  true,
}

func LoadSpec(path string) (map[string]interface{}, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, &SpecParseError{Message: fmt.Sprintf("Cannot read spec %s: %v", path, err)}
	}

	var result interface{}
	err = json.Unmarshal(data, &result)
	if err != nil {
		err = yaml.Unmarshal(data, &result)
		if err != nil {
			return nil, &SpecParseError{Message: fmt.Sprintf("%s is not valid JSON or YAML: %v", path, err)}
		}
	}
	if resultMap, ok := result.(map[string]interface{}); ok {
		// Convert map[interface{}]interface{} to map[string]interface{} recursively if needed for YAML.
		// However, yaml.v3 unmarshals to map[string]interface{} for interface{} if keys are strings.
		return resultMap, nil
	}
	
	// yaml.v3 might unmarshal maps to map[string]interface{} or map[interface{}]interface{}
	// Let's do a more robust type assertion for yaml maps
	if mapIface, ok := result.(map[interface{}]interface{}); ok {
		resultMap := make(map[string]interface{})
		for k, v := range mapIface {
			resultMap[fmt.Sprintf("%v", k)] = v
		}
		return resultMap, nil
	}

	return nil, &SpecParseError{Message: fmt.Sprintf("%s does not contain a mapping at the top level", path)}
}

func ClassifySpec(raw map[string]interface{}) string {
	if _, ok := raw["openapi"]; ok {
		return "openapi"
	}
	if swg, ok := raw["swagger"]; ok {
		if strings.HasPrefix(fmt.Sprintf("%v", swg), "2") {
			return "swagger"
		}
	}
	if info, ok := raw["info"].(map[string]interface{}); ok {
		if _, hasPostmanID := info["_postman_id"]; hasPostmanID {
			return "postman"
		}
	}
	if _, hasItem := raw["item"]; hasItem {
		if _, ok := raw["info"].(map[string]interface{}); ok {
			return "postman"
		}
	}
	return ""
}

func DetectSpecFormat(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	if !SPEC_EXTENSIONS[ext] {
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
	if title, ok := info["title"].(string); ok && title != "" {
		name = title
	} else if n, ok := info["name"].(string); ok && n != "" {
		name = n
	} else {
		return "API"
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
	for _, c := range candidates {
		c = strings.TrimSpace(c)
		u, err := url.Parse(c)
		if err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" {
			c = strings.TrimRight(c, "/")
			if !seen[c] {
				urls = append(urls, c)
				seen[c] = true
			}
		}
	}
	return urls
}

var serverVarPattern = regexp.MustCompile(`\{([^{}/]+)\}`)

func resolveServerURL(u string, variables interface{}) string {
	if !strings.Contains(u, "{") {
		return u
	}
	vars, ok := variables.(map[string]interface{})
	if !ok {
		return u
	}
	defaults := make(map[string]string)
	for name, spec := range vars {
		if s, ok := spec.(map[string]interface{}); ok {
			if def, hasDef := s["default"]; hasDef && def != nil {
				defaults[name] = fmt.Sprintf("%v", def)
			}
		}
	}
	return serverVarPattern.ReplaceAllStringFunc(u, func(match string) string {
		name := match[1 : len(match)-1]
		if val, ok := defaults[name]; ok {
			return val
		}
		return match
	})
}

func openapiBaseURLs(raw map[string]interface{}) []string {
	servers, ok := raw["servers"].([]interface{})
	if !ok {
		return []string{}
	}
	var candidates []string
	for _, srv := range servers {
		if serverMap, ok := srv.(map[string]interface{}); ok {
			if u, hasURL := serverMap["url"].(string); hasURL && u != "" {
				candidates = append(candidates, resolveServerURL(u, serverMap["variables"]))
			}
		}
	}
	return absoluteURLs(candidates)
}

func swaggerBaseURLs(raw map[string]interface{}) []string {
	host := ""
	if h, ok := raw["host"].(string); ok {
		host = strings.TrimSpace(h)
	}
	if host == "" {
		return []string{}
	}
	basePath := ""
	if bp, ok := raw["basePath"].(string); ok {
		basePath = strings.TrimSpace(bp)
	}
	schemes := []string{"https"}
	if s, ok := raw["schemes"].([]interface{}); ok && len(s) > 0 {
		schemes = []string{}
		for _, sch := range s {
			if strSch, ok := sch.(string); ok {
				schemes = append(schemes, strSch)
			}
		}
	}
	var candidates []string
	for _, scheme := range schemes {
		candidates = append(candidates, fmt.Sprintf("%s://%s%s", scheme, host, basePath))
	}
	return absoluteURLs(candidates)
}

func postmanVariables(raw map[string]interface{}) map[string]string {
	vars := make(map[string]string)
	if entries, ok := raw["variable"].([]interface{}); ok {
		for _, entry := range entries {
			if e, ok := entry.(map[string]interface{}); ok {
				if key, ok := e["key"].(string); ok && key != "" {
					val := ""
					if v, ok := e["value"]; ok && v != nil {
						val = fmt.Sprintf("%v", v)
					}
					vars[key] = val
				}
			}
		}
	}
	return vars
}

var postmanVarPattern = regexp.MustCompile(`\{\{\s*([^}]+?)\s*\}\}`)

func resolvePostmanVars(text string, variables map[string]string) string {
	if len(variables) == 0 || !strings.Contains(text, "{{") {
		return text
	}
	return postmanVarPattern.ReplaceAllStringFunc(text, func(match string) string {
		name := match[2 : len(match)-2]
		name = strings.TrimSpace(name)
		if val, ok := variables[name]; ok {
			return val
		}
		return match
	})
}

func postmanRequestURL(urlObj interface{}, variables map[string]string) string {
	raw := ""
	if strURL, ok := urlObj.(string); ok {
		raw = strURL
	} else if u, ok := urlObj.(map[string]interface{}); ok {
		if rawStr, ok := u["raw"].(string); ok && rawStr != "" {
			raw = rawStr
		} else {
			if hostArr, ok := u["host"].([]interface{}); ok {
				var hostParts []string
				for _, h := range hostArr {
					hostParts = append(hostParts, fmt.Sprintf("%v", h))
				}
				raw = strings.Join(hostParts, ".")
			} else if hostStr, ok := u["host"].(string); ok {
				raw = hostStr
			}
		}
	} else {
		return ""
	}
	return resolvePostmanVars(raw, variables)
}

func walkPostmanHosts(items interface{}, variables map[string]string, hosts *[]string, depth int) {
	if depth > 25 {
		return
	}
	arr, ok := items.([]interface{})
	if !ok {
		return
	}
	for _, nodeObj := range arr {
		if node, ok := nodeObj.(map[string]interface{}); ok {
			if itemObj, hasItem := node["item"]; hasItem {
				if _, isArr := itemObj.([]interface{}); isArr {
					walkPostmanHosts(itemObj, variables, hosts, depth+1)
					continue
				}
			}
			if reqObj, hasReq := node["request"]; hasReq {
				if req, isDict := reqObj.(map[string]interface{}); isDict {
					u := postmanRequestURL(req["url"], variables)
					if u != "" {
						parsed, err := url.Parse(u)
						if err == nil && parsed.Scheme != "" && parsed.Host != "" {
							*hosts = append(*hosts, fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host))
						}
					}
				} else if reqStr, isStr := reqObj.(string); isStr {
					u := postmanRequestURL(reqStr, variables)
					if u != "" {
						parsed, err := url.Parse(u)
						if err == nil && parsed.Scheme != "" && parsed.Host != "" {
							*hosts = append(*hosts, fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host))
						}
					}
				}
			}
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
	
	sort.Strings(hosts)
	return absoluteURLs(hosts)
}

func SpecBaseURLs(raw map[string]interface{}, extraVariables map[string]string) ([]string, error) {
	format := ClassifySpec(raw)
	switch format {
	case "openapi":
		return openapiBaseURLs(raw), nil
	case "swagger":
		return swaggerBaseURLs(raw), nil
	case "postman":
		return postmanBaseURLs(raw, extraVariables), nil
	}
	return nil, &SpecParseError{Message: "File is not a recognized OpenAPI, Swagger, or Postman spec"}
}

var POSTMAN_API_BASE = "https://api.getpostman.com"
var HTTPClient = &http.Client{Timeout: 30 * time.Second} // exposed for testing

func postmanAPIJSON(url string, apiKey string, label string) (map[string]interface{}, error) {
	if apiKey == "" {
		return nil, &SpecParseError{Message: "POSTMAN_API_KEY is not set. Export a Postman API key (PMAK-…) to fetch from the Postman API, or pass a local collection file instead."}
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, &SpecParseError{Message: fmt.Sprintf("Failed to reach the Postman API: %v", err)}
	}
	req.Header.Set("X-Api-Key", apiKey)
	req.Header.Set("Accept", "application/json")
	
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return nil, &SpecParseError{Message: fmt.Sprintf("Failed to reach the Postman API: %v", err)}
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

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, &SpecParseError{Message: fmt.Sprintf("Failed to read Postman API response for %s", label)}
	}

	var payload map[string]interface{}
	err = json.Unmarshal(body, &payload)
	if err != nil {
		return nil, &SpecParseError{Message: fmt.Sprintf("Postman API returned non-JSON for %s", label)}
	}
	return payload, nil
}

func FetchPostmanCollection(uid string, apiKey string) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/collections/%s", POSTMAN_API_BASE, uid)
	payload, err := postmanAPIJSON(url, apiKey, fmt.Sprintf("collection %s", uid))
	if err != nil {
		return nil, err
	}
	if coll, ok := payload["collection"].(map[string]interface{}); ok {
		payload = coll
	}
	if len(payload) == 0 {
		return nil, &SpecParseError{Message: fmt.Sprintf("Postman collection %s came back empty", uid)}
	}
	return payload, nil
}

func FetchPostmanEnvironment(uid string, apiKey string) (map[string]string, error) {
	url := fmt.Sprintf("%s/environments/%s", POSTMAN_API_BASE, uid)
	payload, err := postmanAPIJSON(url, apiKey, fmt.Sprintf("environment %s", uid))
	if err != nil {
		return nil, err
	}
	if env, ok := payload["environment"].(map[string]interface{}); ok {
		payload = env
	}
	
	valuesObj := payload["values"]
	values, ok := valuesObj.([]interface{})
	if !ok {
		return map[string]string{}, nil
	}
	
	result := make(map[string]string)
	for _, vObj := range values {
		if v, ok := vObj.(map[string]interface{}); ok {
			key, okKey := v["key"].(string)
			if !okKey || key == "" {
				continue
			}
			enabled := true
			if en, okEn := v["enabled"].(bool); okEn {
				enabled = en
			}
			if enabled {
				val := ""
				if valObj, okVal := v["value"]; okVal && valObj != nil {
					val = fmt.Sprintf("%v", valObj)
				}
				result[key] = val
			}
		}
	}
	return result, nil
}
