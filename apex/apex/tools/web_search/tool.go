package web_search

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/AwaisCh360/Apex/apex/config"
)

var logger = log.New(os.Stdout, "[web_search] ", log.LstdFlags)

const systemPrompt = `You are assisting a cybersecurity agent specialized in vulnerability scanning
and security assessment running on Kali Linux. When responding to search queries:

1. Prioritize cybersecurity-relevant information including:
   - Vulnerability details (CVEs, CVSS scores, impact)
   - Security tools, techniques, and methodologies
   - Exploit information and proof-of-concepts
   - Security best practices and mitigations
   - Penetration testing approaches
   - Web application security findings

2. Provide technical depth appropriate for security professionals
3. Include specific versions, configurations, and technical details when available
4. Focus on actionable intelligence for security assessment
5. Cite reliable security sources (NIST, OWASP, CVE databases, security vendors)
6. When providing commands or installation instructions, prioritize Kali Linux compatibility
   and use apt package manager or tools pre-installed in Kali
7. Be detailed and specific - avoid general answers. Always include concrete code examples,
   command-line instructions, configuration snippets, or practical implementation steps
   when applicable

Structure your response to be comprehensive yet concise, emphasizing the most critical
security implications and details.`

// RunContextWrapper is a local stub for the Python RunContextWrapper.
type RunContextWrapper struct{}

// FunctionTool is a local stub for the Python @function_tool decorator.
func FunctionTool(timeout int) func(any) any {
	return func(fn any) any {
		return fn
	}
}

func doSearch(query string) map[string]any {
	if strings.TrimSpace(query) == "" {
		return map[string]any{"success": false, "error": "Query cannot be empty"}
	}

	settings := config.LoadSettings()
	apiKey := settings.Integrations.PerplexityAPIKey
	if apiKey == "" {
		logger.Println("WARNING: web_search invoked without PERPLEXITY_API_KEY configured")
		return map[string]any{
			"success": false,
			"error":   "Web search is not configured for this scan (operator needs to set PERPLEXITY_API_KEY). Proceed without it",
		}
	}

	logger.Printf("INFO: web_search query (len=%d): %s", len(query), truncateQueryForLog(query, 120))

	url := "https://api.perplexity.ai/chat/completions"
	payload := map[string]any{
		"model": "sonar-reasoning-pro",
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": query},
		},
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		logger.Printf("ERROR: web_search failed unexpectedly: %v", err)
		return map[string]any{"success": false, "error": "Web search failed unexpectedly"}
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(bodyBytes))
	if err != nil {
		logger.Printf("ERROR: web_search failed unexpectedly: %v", err)
		return map[string]any{"success": false, "error": "Web search failed unexpectedly"}
	}

	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 300 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		if os.IsTimeout(err) {
			logger.Println("WARNING: web_search timed out")
			return map[string]any{
				"success": false,
				"error":   "Web search timed out. Try again or shorten the query",
			}
		}
		logger.Printf("ERROR: web_search network error: %v", err)
		return map[string]any{
			"success": false,
			"error":   "Web search network error. Try again later",
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		logger.Printf("ERROR: web_search HTTP error status=%d", resp.StatusCode)
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			return map[string]any{
				"success": false,
				"error":   "Web search rejected the query. Refine it (more specific, shorter, no unusual characters) and retry",
			}
		}
		return map[string]any{
			"success": false,
			"error":   "Web search service is unavailable. Try again later",
		}
	}

	var result struct {
		Choices []struct {
			Message *struct {
				Content *string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil || len(result.Choices) == 0 || result.Choices[0].Message == nil || result.Choices[0].Message.Content == nil {
		logger.Printf("ERROR: web_search response shape unexpected: %v", err)
		return map[string]any{
			"success": false,
			"error":   "Web search returned an unexpected response. Try again",
		}
	}

	return map[string]any{
		"success": true,
		"query":   query,
		"content": *result.Choices[0].Message.Content,
	}
}

// WebSearch is a real-time web search via Perplexity — your primary research tool.
//
// Use it liberally for anything that's not in your training data:
//
// - Current CVEs, advisories, and 0-days for a specific
//   service/version (OpenSSH 9.6 RCE, Jenkins 2.401.3 auth bypass).
// - Latest WAF / EDR bypass techniques (Cloudflare WAF SQLi bypass 2025, CrowdStrike Falcon evasion).
// - Tool documentation, flag references, payload galleries.
// - Target reconnaissance / OSINT (company tech stack, leaked credentials, exposed assets).
// - Cloud-provider misconfiguration patterns (Azure/AWS/GCP-specific attack paths).
// - Bug-bounty writeups and security research papers.
// - Compliance frameworks and CWE/CVSS guidance.
// - Picking the right Python lib / Kali tool for a job (best 2025 lib for JWT alg-confusion).
// - When stuck — looking up the exact error message, Access denied quirks, kernel-specific local-privesc exploits.
//
// Be specific: include version numbers, error messages, target
// technology, and the exact problem you're stuck on. The more context
// in the query, the more actionable the answer. Vague queries get
// generic answers.
//
// A security-focused system prompt biases responses toward CVEs,
// exploits, Kali-compatible tooling, and concrete code/command
// examples.
//
// Good example queries (each is a full sentence, names a version/product, and asks one concrete thing):
//
// - "Found OpenSSH 7.4 on port 22 — any known RCE or privesc for this exact version?"
// - "Cloudflare WAF is blocking my sqlmap on a login form — what bypass techniques work in 2025?"
// - "Target runs WordPress 5.8.3 + WooCommerce 6.1.1 — current RCE chains for this combo?"
// - "Low-priv shell on Ubuntu 20.04 kernel 5.4.0-74-generic — what local privesc exploits hit this kernel?"
// - "Compromised domain user on Windows Server 2019 AD — quietest paths to Domain Admin without tripping EDR?"
// - "'Access denied' uploading a webshell to IIS 10.0 — alternate Windows IIS upload bypass techniques?"
// - "Discovered Jenkins 2.401.3 on staging — current authn-bypass and RCE exploits for this version?"
// - "Best 2025 Python lib for JWT algorithm-confusion + weak-secret cracking?"
//
// Args:
//     ctx: The RunContextWrapper (ignored in logic).
//     query: The search query — a full sentence with version numbers,
//         target tech, and the specific question. Treat it like a
//         ticket title for a senior security engineer.

func truncateQueryForLog(query string, limit int) string {
	runes := []rune(query)
	if len(runes) > limit {
		return string(runes[:limit])
	}
	return query
}

func toJSONString(v interface{}) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return `{"success":false,"error":"Failed to encode JSON response"}`
	}
	s := buf.String()
	if len(s) > 0 && s[len(s)-1] == '\n' {
		s = s[:len(s)-1]
	}
	return s
}

func WebSearch(ctx RunContextWrapper, query string) string {
	res := doSearch(query)
	return toJSONString(res)
}
