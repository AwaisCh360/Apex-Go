package config

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/AwaisCh360/Apex/apex/utils"
)

const (
	Provider     = "codex"
	ClientID     = "app_EMoamEEZ73f0CkXaXp7hrann"
	AuthorizeURL = "https://auth.openai.com/oauth/authorize"
	CallbackHost = "localhost"
	CallbackPort = 1455
	CallbackPath = "/auth/callback"
	Scope        = "openid profile email offline_access"
	CodexBaseURL = "https://chatgpt.com/backend-api/codex"
	Originator   = "codex_cli_rs"
	AccountClaim = "https://api.openai.com/auth"
	TokenTimeout = 30 * time.Second
	ExpirySkewS  = 300
)

var TokenURL = "https://auth.openai.com/oauth/token"

var (
	RedirectURI = fmt.Sprintf("http://%s:%d%s", CallbackHost, CallbackPort, CallbackPath)
	authPath    string
	refreshLock sync.Mutex
)

func init() {
	home, _ := os.UserHomeDir()
	authPath = filepath.Join(home, ".apex", "subscription-auth.json")
}

func SetAuthPathForTest(p string) {
	authPath = p
}

func readStore() map[string]interface{} {
	if _, err := os.Stat(authPath); os.IsNotExist(err) {
		return make(map[string]interface{})
	}
	b, err := os.ReadFile(authPath)
	if err != nil {
		return make(map[string]interface{})
	}
	var data map[string]interface{}
	if err := json.Unmarshal(b, &data); err != nil {
		return make(map[string]interface{})
	}
	return data
}

func writeStore(data map[string]interface{}) error {
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return utils.WriteSecretText(authPath, string(b))
}

func ReadRecord() map[string]interface{} {
	store := readStore()
	record, ok := store[Provider].(map[string]interface{})
	if !ok || record["type"] != "oauth" {
		return nil
	}
	if record["access"] == nil || record["refresh"] == nil || record["account_id"] == nil {
		return nil
	}
	return record
}

func IsAuthenticated() bool {
	return ReadRecord() != nil
}

func SaveRecord(record map[string]interface{}) error {
	store := readStore()
	store[Provider] = record
	return writeStore(store)
}

func Logout() error {
	store := readStore()
	if _, ok := store[Provider]; !ok {
		return nil
	}
	delete(store, Provider)
	if len(store) > 0 {
		return writeStore(store)
	}
	return os.Remove(authPath)
}

type CodexAuthError struct {
	Code    string
	Message string
}

func (e *CodexAuthError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return e.Code
}

func b64url(raw []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(raw), "=")
}

func GeneratePKCE() (string, string) {
	b := make([]byte, 64)
	rand.Read(b)
	verifier := b64url(b)
	hash := sha256.Sum256([]byte(verifier))
	challenge := b64url(hash[:])
	return verifier, challenge
}

func CreateState() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func BuildAuthorizeURL(challenge, state string) string {
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", ClientID)
	params.Set("redirect_uri", RedirectURI)
	params.Set("scope", Scope)
	params.Set("code_challenge", challenge)
	params.Set("code_challenge_method", "S256")
	params.Set("state", state)
	params.Set("id_token_add_organizations", "true")
	params.Set("codex_cli_simplified_flow", "true")
	params.Set("originator", Originator)
	return fmt.Sprintf("%s?%s", AuthorizeURL, params.Encode())
}

func ParseRedirectInput(value string) (string, string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", ""
	}
	if u, err := url.Parse(value); err == nil && u.Scheme != "" && u.RawQuery != "" {
		q := u.Query()
		return q.Get("code"), q.Get("state")
	}
	if strings.Contains(value, "#") {
		parts := strings.SplitN(value, "#", 2)
		return parts[0], parts[1]
	}
	if strings.Contains(value, "code=") {
		q, _ := url.ParseQuery(value)
		return q.Get("code"), q.Get("state")
	}
	return value, ""
}

var postForm = defaultPostForm

func defaultPostForm(payload url.Values) (map[string]interface{}, error) {
	client := &http.Client{Timeout: TokenTimeout}
	req, err := http.NewRequest("POST", TokenURL, strings.NewReader(payload.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, &CodexAuthError{Code: "unavailable", Message: err.Error()}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, &CodexAuthError{Code: "token_http_error", Message: fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(body)[:min(len(body), 300)])}
	}

	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, &CodexAuthError{Code: "bad_response", Message: "token endpoint returned non-object"}
	}
	return data, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func accountIDFromJWT(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	payloadB64 := parts[1]
	if pad := len(payloadB64) % 4; pad != 0 {
		payloadB64 += strings.Repeat("=", 4-pad)
	}
	payloadBytes, err := base64.URLEncoding.DecodeString(payloadB64)
	if err != nil {
		return ""
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return ""
	}

	if auth, ok := payload[AccountClaim].(map[string]interface{}); ok {
		if id, ok := auth["chatgpt_account_id"].(string); ok && id != "" {
			return id
		}
	}
	if orgs, ok := payload["organizations"].([]interface{}); ok && len(orgs) > 0 {
		if org, ok := orgs[0].(map[string]interface{}); ok {
			if id, ok := org["id"].(string); ok && id != "" {
				return id
			}
		}
	}
	return ""
}

func recordFromTokenResponse(data map[string]interface{}, refreshFallback string) (map[string]interface{}, error) {
	access, ok := data["access_token"].(string)
	if !ok || access == "" {
		return nil, &CodexAuthError{Code: "bad_response", Message: "token response missing access_token"}
	}
	refresh, ok := data["refresh_token"].(string)
	if !ok || refresh == "" {
		refresh = refreshFallback
	}
	if refresh == "" {
		return nil, &CodexAuthError{Code: "bad_response", Message: "token response missing refresh_token"}
	}

	idToken, _ := data["id_token"].(string)
	accountID := accountIDFromJWT(access)
	if accountID == "" {
		accountID = accountIDFromJWT(idToken)
	}
	if accountID == "" {
		return nil, &CodexAuthError{Code: "no_account_id", Message: "could not read chatgpt_account_id from token"}
	}

	ttl := 3600.0
	if exp, ok := data["expires_in"].(float64); ok {
		ttl = exp
	}

	return map[string]interface{}{
		"type":       "oauth",
		"provider":   Provider,
		"access":     access,
		"refresh":    refresh,
		"account_id": accountID,
		"expires_at": float64(time.Now().Unix()) + ttl,
	}, nil
}

func ExchangeCode(code, verifier string) (map[string]interface{}, error) {
	payload := url.Values{}
	payload.Set("grant_type", "authorization_code")
	payload.Set("client_id", ClientID)
	payload.Set("code", code)
	payload.Set("code_verifier", verifier)
	payload.Set("redirect_uri", RedirectURI)

	data, err := postForm(payload)
	if err != nil {
		return nil, err
	}
	return recordFromTokenResponse(data, "")
}

func RefreshTokens(refreshToken string) (map[string]interface{}, error) {
	payload := url.Values{}
	payload.Set("grant_type", "refresh_token")
	payload.Set("client_id", ClientID)
	payload.Set("refresh_token", refreshToken)

	data, err := postForm(payload)
	if err != nil {
		return nil, err
	}
	return recordFromTokenResponse(data, refreshToken)
}

func nearExpiry(record map[string]interface{}) bool {
	exp, ok := record["expires_at"].(float64)
	if !ok {
		return true
	}
	return exp-ExpirySkewS <= float64(time.Now().Unix())
}

func refreshGuard(callback func() error) error {
	refreshLock.Lock()
	defer refreshLock.Unlock()

	lockPath := strings.TrimSuffix(authPath, filepath.Ext(authPath)) + ".lock"
	os.MkdirAll(filepath.Dir(lockPath), 0755)
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_WRONLY, 0600)
	if err == nil {
		defer f.Close()
		if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err == nil {
			defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		}
	}
	return callback()
}

func GetValidToken() (string, string, error) {
	record := ReadRecord()
	if record == nil {
		return "", "", errors.New("not signed in; run: apex auth login")
	}
	if !nearExpiry(record) {
		return record["access"].(string), record["account_id"].(string), nil
	}

	var access, account string
	err := refreshGuard(func() error {
		r := ReadRecord()
		if r == nil {
			return errors.New("not signed in; run: apex auth login")
		}
		if !nearExpiry(r) {
			access = r["access"].(string)
			account = r["account_id"].(string)
			return nil
		}

		refreshed, err := RefreshTokens(r["refresh"].(string))
		if err != nil {
			latest := ReadRecord()
			if latest != nil && latest["refresh"] != r["refresh"] && !nearExpiry(latest) {
				access = latest["access"].(string)
				account = latest["account_id"].(string)
				return nil
			}
			return err
		}
		SaveRecord(refreshed)
		access = refreshed["access"].(string)
		account = refreshed["account_id"].(string)
		return nil
	})
	return access, account, err
}

// Subscription Client Structs (Mocks for OpenAI SDK since it's not present natively)
type AsyncOpenAI struct {
	APIKey         string
	BaseURL        string
	HTTPClient     *http.Client
	DefaultHeaders map[string]string
}

type authHookTransport struct {
	RoundTripper http.RoundTripper
}

func (t *authHookTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	access, account, err := GetValidToken()
	if err == nil {
		req.Header.Set("Authorization", "Bearer "+access)
		req.Header.Set("chatgpt-account-id", account)
	}
	return t.RoundTripper.RoundTrip(req)
}

func BuildOpenAIClient() *AsyncOpenAI {
	GetValidToken() // fail fast

	client := &http.Client{
		Timeout: 600 * time.Second,
		Transport: &authHookTransport{
			RoundTripper: http.DefaultTransport,
		},
	}

	return &AsyncOpenAI{
		APIKey:     "apex-codex-oauth",
		BaseURL:    CodexBaseURL,
		HTTPClient: client,
		DefaultHeaders: map[string]string{
			"OpenAI-Beta": "responses=experimental",
			"originator":  Originator,
		},
	}
}

var subscriptionClient *AsyncOpenAI
var subscriptionClientOnce sync.Once

func GetSubscriptionClient() *AsyncOpenAI {
	subscriptionClientOnce.Do(func() {
		subscriptionClient = BuildOpenAIClient()
	})
	return subscriptionClient
}

func SubscriptionModel(modelName string) string {
	name := strings.TrimSpace(modelName)
	if !strings.HasPrefix(strings.ToLower(name), "chatgpt/") {
		return ""
	}
	return name[len("chatgpt/"):]
}

func AuthMode(modelName string) string {
	if SubscriptionModel(modelName) != "" {
		return "subscription"
	}
	return "api_key"
}

type CodexContentGuardrailError struct {
	Model string
	Err   error
}

func (e *CodexContentGuardrailError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return "content guardrail error"
}

func IsContentGuardrailError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "This content was flagged for possible cybersecurity risk.")
}
