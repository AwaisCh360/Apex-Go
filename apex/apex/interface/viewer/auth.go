package viewer

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var logger = log.New(os.Stderr, "[viewer] ", log.LstdFlags)

var AuthPath string

const (
	otpTimeout  = 15 * time.Second
	sendTimeout = 30 * time.Second
)

func init() {
	home, _ := os.UserHomeDir()
	AuthPath = filepath.Join(home, ".apex", "viewer-auth.json")
}

// RelayError represents a failure in a relay call. Code is a stable, machine-readable reason.
type RelayError struct {
	Code    string
	Message string
}

func (e *RelayError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return e.Code
}

func NewRelayError(code string, msg ...string) *RelayError {
	m := ""
	if len(msg) > 0 {
		m = msg[0]
	}
	return &RelayError{Code: code, Message: m}
}

// --- local state ------------------------------------------------------------

type AuthRecord struct {
	Email      string      `json:"email"`
	Token      string      `json:"token"`
	VerifiedAt interface{} `json:"verified_at,omitempty"`
}

// ReadAuth returns the stored auth record, or nil if none or invalid.
func ReadAuth() *AuthRecord {
	b, err := os.ReadFile(AuthPath)
	if err != nil {
		return nil
	}
	var record map[string]interface{}
	if err := json.Unmarshal(b, &record); err != nil {
		return nil
	}
	email, ok1 := record["email"].(string)
	token, ok2 := record["token"].(string)
	if !ok1 || email == "" || !ok2 || token == "" {
		return nil
	}
	return &AuthRecord{
		Email:      email,
		Token:      token,
		VerifiedAt: record["verified_at"],
	}
}

// ParseExpiry parses a relay expires_at value into a UTC time.Time pointer.
func ParseExpiry(raw interface{}) *time.Time {
	if raw == nil {
		return nil
	}
	switch v := raw.(type) {
	case bool:
		return nil
	case float64:
		return fromEpoch(v)
	case int:
		return fromEpoch(float64(v))
	case int64:
		return fromEpoch(float64(v))
	case string:
		if v == "" {
			return nil
		}
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return fromEpoch(f)
		}

		v = strings.ReplaceAll(v, "Z", "+00:00")
		layouts := []string{
			time.RFC3339Nano,
			time.RFC3339,
			"2006-01-02T15:04:05-07:00",
			"2006-01-02 15:04:05-07:00",
			"2006-01-02T15:04:05",
			"2006-01-02 15:04:05",
		}
		for _, layout := range layouts {
			if t, err := time.Parse(layout, v); err == nil {
				utc := t.UTC()
				return &utc
			}
		}
		return nil
	default:
		return nil
	}
}

func fromEpoch(seconds float64) *time.Time {
	// Simple bounds to prevent overflow issues similar to Python's datetime.fromtimestamp
	if seconds < -62135596800 || seconds > 253402300799 {
		return nil
	}
	sec := int64(seconds)
	nsec := int64((seconds - float64(sec)) * 1e9)
	t := time.Unix(sec, nsec).UTC()
	return &t
}

// IsVerified returns true when a usable email + token record with a valid future expiry exists.
func IsVerified() bool {
	record := ReadAuth()
	if record == nil {
		return false
	}
	expiry := ParseExpiry(record.VerifiedAt)
	if expiry != nil && expiry.After(time.Now().UTC()) {
		return true
	}
	return false
}

// WriteAuth atomically persists the auth record with 0600 permissions.
func WriteAuth(email, token, verifiedAt string) error {
	payload := map[string]interface{}{
		"email":       email,
		"token":       token,
		"verified_at": verifiedAt,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	tmpFile := AuthPath + ".tmp"
	if err := os.WriteFile(tmpFile, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmpFile, AuthPath)
}

// Forget deletes the stored auth record. No-op if it is absent.
func Forget() {
	_ = os.Remove(AuthPath)
}

// --- relay client -----------------------------------------------------------

func appURL() string {
	url := os.Getenv("APEX_APP_URL")
	if url == "" {
		url = "http://localhost:8000" // Fallback
	}
	return strings.TrimRight(url, "/")
}

func postJSON(path string, payload map[string]interface{}, timeout time.Duration) (int, map[string]interface{}, error) {
	url := appURL() + path
	b, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, NewRelayError("unavailable")
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(b))
	if err != nil {
		return 0, nil, NewRelayError("unavailable")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		logger.Printf("relay request to %s failed: %v", path, err)
		return 0, nil, NewRelayError("unavailable")
	}
	defer resp.Body.Close()

	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		data = make(map[string]interface{})
	}
	if data == nil {
		data = make(map[string]interface{})
	}

	return resp.StatusCode, data, nil
}

// OtpStart asks the relay to email a verification code. Returns RelayError on failure.
func OtpStart(email string) error {
	status, data, err := postJSON("/api/oss/otp/start", map[string]interface{}{"email": email}, otpTimeout)
	if err != nil {
		return err
	}
	if status == 200 {
		return nil
	}
	if status == 429 {
		return NewRelayError("rate_limited")
	}
	if status == 400 {
		if errStr, ok := data["error"].(string); ok && errStr == "work_email_required" {
			return NewRelayError("work_email_required")
		}
		return NewRelayError("invalid_email")
	}
	return NewRelayError("unavailable")
}

// OtpVerify verifies a code. Returns map with {token, email, expires_at} or raises RelayError.
func OtpVerify(email, code string) (map[string]interface{}, error) {
	status, data, err := postJSON("/api/oss/otp/verify", map[string]interface{}{"email": email, "code": code}, otpTimeout)
	if err != nil {
		return nil, err
	}

	token, hasToken := data["token"].(string)
	if status == 200 && hasToken && token != "" {
		if ParseExpiry(data["expires_at"]) == nil {
			return nil, NewRelayError("unavailable")
		}
		return data, nil
	}
	if status == 403 {
		return nil, NewRelayError("invalid_code")
	}
	return nil, NewRelayError("unavailable")
}

// FeedbackSubmit relays a feedback message + email to Apex. No verification is required.
func FeedbackSubmit(email, message string) error {
	status, data, err := postJSON("/api/oss/feedback", map[string]interface{}{"email": email, "message": message}, otpTimeout)
	if err != nil {
		return err
	}
	if status == 200 {
		return nil
	}
	if status == 429 {
		return NewRelayError("rate_limited")
	}
	if status == 400 {
		if code, ok := data["error"].(string); ok && (code == "invalid_email" || code == "invalid_message") {
			return NewRelayError(code)
		}
		return NewRelayError("invalid_message")
	}
	return NewRelayError("unavailable")
}

// ReportSend forwards the encrypted PDF to the relay for delivery.
func ReportSend(token string, pdfBytes []byte, filename, runName, target string) error {
	payload := map[string]interface{}{
		"token":      token,
		"pdf_base64": base64.StdEncoding.EncodeToString(pdfBytes),
		"filename":   filename,
		"run_name":   runName,
		"target":     target,
	}
	status, _, err := postJSON("/api/oss/report/send", payload, sendTimeout)
	if err != nil {
		return err
	}
	if status == 200 {
		return nil
	}
	if status == 401 {
		return NewRelayError("reverify")
	}
	if status == 413 {
		return NewRelayError("too_large")
	}
	if status == 403 {
		return NewRelayError("forbidden")
	}
	return NewRelayError("unavailable")
}
