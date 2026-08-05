package viewer

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// SessionCookiePrefix is the prefix of the cookie carrying the per-process session capability.
const SessionCookiePrefix = "apex_viewer_session"

// viewerState corresponds to the _ViewerState class in Python.
type viewerState struct {
	runDir       string
	assetsDir    string
	baseDir      string
	steerHandler func(string, string) bool
	sessionToken string
	cookieName   string
}

// BundleDir returns the directory holding the committed, prebuilt SPA.
func BundleDir() string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return "static"
	}
	return filepath.Join(filepath.Dir(filename), "static")
}

// BundleIsBuilt checks if the bundle is built.
func BundleIsBuilt() bool {
	info, err := os.Stat(filepath.Join(BundleDir(), "index.html"))
	return err == nil && !info.IsDir()
}

// iterRunDirs returns every run directory under baseDir, newest first by record mtime.
func iterRunDirs(baseDir string) []string {
	info, err := os.Stat(baseDir)
	if err != nil || !info.IsDir() {
		return nil
	}

	entries, err := os.ReadDir(baseDir)
	if err != nil {
		return nil
	}

	type runInfo struct {
		path  string
		mtime time.Time
	}
	var runs []runInfo

	for _, entry := range entries {
		child := filepath.Join(baseDir, entry.Name())
		recordPath := RunRecordPath(child)
		recordInfo, err := os.Stat(recordPath)
		if err == nil && !recordInfo.IsDir() {
			runs = append(runs, runInfo{
				path:  child,
				mtime: recordInfo.ModTime(),
			})
		}
	}

	sort.Slice(runs, func(i, j int) bool {
		return runs[i].mtime.After(runs[j].mtime) // Reverse order (newest first)
	})

	var result []string
	for _, r := range runs {
		result = append(result, r.path)
	}
	return result
}

// runListEntry returns a compact summary of a single run for the history list.
func runListEntry(runDir string) map[string]interface{} {
	record := ReadRunSummary(runDir)
	name, _ := record["run_name"].(string)
	if name == "" {
		name = filepath.Base(runDir)
	}

	var finished bool
	if fin, ok := record["finished"].(bool); ok {
		finished = fin
	}

	targetStr := "unknown target"
	if t := PrimaryTarget(record); t != nil {
		targetStr = *t
	}

	return map[string]interface{}{
		"name":            name,
		"target":          targetStr,
		"scan_mode":       record["scan_mode"],
		"status":          record["status"],
		"start_time":      record["start_time"],
		"end_time":        record["end_time"],
		"finished":        finished,
		"severity_counts": SeverityCounts(ReadVulnerabilities(runDir)),
	}
}

// buildRunsPayload builds the /api/runs payload.
func buildRunsPayload(baseDir string, verified bool) map[string]interface{} {
	runDirs := iterRunDirs(baseDir)
	count := len(runDirs)

	if !verified {
		return map[string]interface{}{
			"locked": true,
			"count":  count,
			"runs":   []interface{}{},
		}
	}

	var runs []interface{}
	for _, d := range runDirs {
		runs = append(runs, runListEntry(d))
	}
	// ensure not nil
	if runs == nil {
		runs = []interface{}{}
	}

	return map[string]interface{}{
		"locked": false,
		"count":  count,
		"runs":   runs,
	}
}

func isSubPath(base, child string) bool {
	basePath := filepath.Clean(base)
	childPath := filepath.Clean(child)
	rel, err := filepath.Rel(basePath, childPath)
	if err != nil {
		return false
	}
	return !strings.HasPrefix(rel, "..") && rel != ".."
}

// resolveRunDir resolves a ?run= value to a real run directory under baseDir.
func resolveRunDir(baseDir string, runParam string, defaultRunDir string) *string {
	if runParam == "" {
		return &defaultRunDir
	}

	base, err := filepath.Abs(baseDir)
	if err != nil {
		return nil
	}

	candidate, err := filepath.Abs(filepath.Join(base, runParam))
	if err != nil {
		return nil
	}

	if filepath.Dir(candidate) != base {
		return nil
	}

	recordInfo, err := os.Stat(RunRecordPath(candidate))
	if err != nil || recordInfo.IsDir() {
		return nil
	}

	return &candidate
}

// generateToken generates a random URL-safe base64 token.
func generateToken(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b)
}

func makeHandler(state *viewerState) http.Handler {
	mux := http.NewServeMux()

	emailEvents := map[string]bool{
		"email_submitted":     true,
		"email_verified":      true,
		"report_sent":         true,
		"work_email_required": true,
	}

	sendJSON := func(w http.ResponseWriter, status int, payload interface{}) {
		body, err := json.Marshal(payload)
		if err != nil {
			http.Error(w, `{"error": "internal error"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
		w.WriteHeader(status)
		w.Write(body)
	}

	hasSession := func(r *http.Request) bool {
		cookie, err := r.Cookie(state.cookieName)
		if err != nil || cookie.Value == "" {
			return false
		}
		return subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(state.sessionToken)) == 1
	}

	tokenPresented := func(r *http.Request) bool {
		supplied := r.URL.Query().Get("token")
		if supplied == "" {
			return false
		}
		return subtle.ConstantTimeCompare([]byte(supplied), []byte(state.sessionToken)) == 1
	}

	sendRelayError := func(w http.ResponseWriter, err error) {
		statusByCode := map[string]int{
			"rate_limited":        http.StatusTooManyRequests,
			"invalid_email":       http.StatusBadRequest,
			"invalid_message":     http.StatusBadRequest,
			"work_email_required": http.StatusBadRequest,
			"invalid_code":        http.StatusForbidden,
			"reverify":            http.StatusUnauthorized,
			"forbidden":           http.StatusForbidden,
			"too_large":           http.StatusRequestEntityTooLarge,
			"unavailable":         http.StatusBadGateway,
		}

		code := "unavailable"
		if relayErr, ok := err.(*RelayError); ok {
			code = relayErr.Code
		}

		status, ok := statusByCode[code]
		if !ok {
			status = http.StatusBadGateway
		}
		sendJSON(w, status, map[string]string{"error": code})
	}

	readBody := func(r *http.Request) map[string]interface{} {
		body := make(map[string]interface{})
		if r.Body != nil {
			defer r.Body.Close()
			dec := json.NewDecoder(r.Body)
			if err := dec.Decode(&body); err != nil {
				return map[string]interface{}{}
			}
		}
		return body
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		if r.Method == http.MethodGet {
			if strings.HasPrefix(path, "/api/") {
				if path == "/api/runs" {
					unlocked := hasSession(r) && IsVerified()
					payload := buildRunsPayload(state.baseDir, unlocked)
					sendJSON(w, http.StatusOK, payload)
					return
				}
				if path == "/api/capabilities" {
					sendJSON(w, http.StatusOK, map[string]interface{}{"can_steer": state.steerHandler != nil})
					return
				}
				if path == "/api/auth/status" {
					if !hasSession(r) {
						sendJSON(w, http.StatusOK, map[string]interface{}{"verified": false, "email": nil})
						return
					}
					record := ReadAuth()
					var email interface{}
					if record != nil {
						email = record.Email
					}
					sendJSON(w, http.StatusOK, map[string]interface{}{
						"verified": IsVerified(),
						"email":    email,
					})
					return
				}

				runParam := r.URL.Query().Get("run")
				runDirPtr := resolveRunDir(state.baseDir, runParam, state.runDir)
				if runDirPtr == nil {
					sendJSON(w, http.StatusNotFound, map[string]string{"error": "unknown run"})
					return
				}
				runDir := *runDirPtr

				stateRunDirAbs, _ := filepath.Abs(state.runDir)
				runDirAbs, _ := filepath.Abs(runDir)

				if runDirAbs != stateRunDirAbs {
					if !hasSession(r) {
						sendJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
						return
					}
					if !IsVerified() {
						sendJSON(w, http.StatusUnauthorized, map[string]string{"error": "unverified"})
						return
					}
				}

				switch path {
				case "/api/run":
					sendJSON(w, http.StatusOK, ReadRunSummary(runDir))
				case "/api/vulnerabilities":
					sendJSON(w, http.StatusOK, ReadVulnerabilities(runDir))
				case "/api/report":
					sendJSON(w, http.StatusOK, map[string]string{"markdown": ReadReportMarkdown(runDir)})
				case "/api/transcript":
					sendJSON(w, http.StatusOK, BuildRunState(runDir))
				default:
					sendJSON(w, http.StatusNotFound, map[string]string{"error": "unknown endpoint"})
				}
				return
			}

			// Handle static files
			relPath, err := url.PathUnescape(path)
			if err != nil {
				relPath = path
			}
			relPath = strings.TrimLeft(relPath, "/")

			var target string
			if relPath == "" || strings.HasSuffix(relPath, "/") {
				target = ""
			} else {
				root, _ := filepath.Abs(state.assetsDir)
				candidate, _ := filepath.Abs(filepath.Join(root, relPath))
				if isSubPath(root, candidate) {
					info, err := os.Stat(candidate)
					if err == nil && !info.IsDir() {
						target = candidate
					}
				}
			}

			if target == "" {
				target = filepath.Join(state.assetsDir, "index.html")
			}

			isIndex := filepath.Base(target) == "index.html"

			info, err := os.Stat(target)
			if err != nil || info.IsDir() {
				sendJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
				return
			}

			content, err := os.ReadFile(target)
			if err != nil {
				sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
				return
			}

			ext := filepath.Ext(target)
			contentType := mime.TypeByExtension(ext)
			if contentType == "" {
				contentType = "application/octet-stream"
			}

			w.Header().Set("Content-Type", contentType)
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))

			if isIndex && tokenPresented(r) {
				cookieVal := fmt.Sprintf("%s=%s; Path=/; HttpOnly; SameSite=Strict", state.cookieName, state.sessionToken)
				w.Header().Set("Set-Cookie", cookieVal)
			}

			w.WriteHeader(http.StatusOK)
			w.Write(content)
			return
		}

		if r.Method == http.MethodPost {
			switch path {
			case "/api/event":
				body := readBody(r)
				event, _ := body["event"].(string)

				if event == "cta_clicked" {
					cta, ok := body["cta"].(string)
					if !ok || cta == "" {
						cta = "unknown"
					}
					var surface string
					if s, ok := body["surface"].(string); ok {
						surface = s
					}
					ViewerCtaClicked(cta, surface)
				} else if emailEvents[event] {
					var purpose string
					if p, ok := body["purpose"].(string); ok {
						purpose = p
					}
					ViewerEmailEvent(event, purpose)
				} else if event == "agent_steered" {
					ViewerAgentSteered()
				}
				w.WriteHeader(http.StatusNoContent)

			case "/api/auth/otp/start":
				if !hasSession(r) {
					sendJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
					return
				}
				body := readBody(r)
				email, _ := body["email"].(string)
				email = strings.TrimSpace(email)
				if email == "" {
					sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_email"})
					return
				}
				if err := OtpStart(email); err != nil {
					sendRelayError(w, err)
					return
				}
				sendJSON(w, http.StatusOK, map[string]bool{"ok": true})

			case "/api/auth/otp/verify":
				if !hasSession(r) {
					sendJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
					return
				}
				body := readBody(r)
				email, _ := body["email"].(string)
				email = strings.TrimSpace(email)
				code, _ := body["code"].(string)
				code = strings.TrimSpace(code)

				if email == "" || code == "" {
					sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_code"})
					return
				}

				result, err := OtpVerify(email, code)
				if err != nil {
					sendRelayError(w, err)
					return
				}

				resEmail, _ := result["email"].(string)
				if resEmail == "" {
					resEmail = email
				}
				token, _ := result["token"].(string)
				expiresAt, _ := result["expires_at"].(string)

				WriteAuth(resEmail, token, expiresAt)
				sendJSON(w, http.StatusOK, map[string]interface{}{"verified": true, "email": resEmail})

			case "/api/auth/forget":
				if !hasSession(r) {
					sendJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
					return
				}
				Forget()
				sendJSON(w, http.StatusOK, map[string]bool{"ok": true})

			case "/api/report/send":
				if !hasSession(r) {
					sendJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
					return
				}
				record := ReadAuth()
				if record == nil {
					sendJSON(w, http.StatusUnauthorized, map[string]string{"error": "unverified"})
					return
				}

				body := readBody(r)
				runParam, _ := body["run"].(string)
				runDirPtr := resolveRunDir(state.baseDir, runParam, state.runDir)
				if runDirPtr == nil {
					sendJSON(w, http.StatusNotFound, map[string]string{"error": "unknown run"})
					return
				}
				runDir := *runDirPtr

				summary := ReadRunSummary(runDir)
				finished, _ := summary["finished"].(bool)
				if !finished {
					sendJSON(w, http.StatusConflict, map[string]string{"error": "run_not_finished"})
					return
				}

				pdfBytes, password, filename, err := BuildEncryptedReport(runDir)
				if err != nil {
					sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "pdf_generation_failed"})
					return
				}

				runName, _ := summary["run_name"].(string)
				if runName == "" {
					runName = filepath.Base(runDir)
				}
				var targetStr string
				target := PrimaryTarget(summary)
				if target == nil {
					targetStr = "unknown target"
				} else {
					targetStr = *target
				}

				token := record.Token
				err = ReportSend(token, pdfBytes, filename, runName, targetStr)
				if err != nil {
					sendRelayError(w, err)
					return
				}
				sendJSON(w, http.StatusOK, map[string]interface{}{
					"ok":       true,
					"password": password,
					"filename": filename,
				})

			case "/api/feedback":
				if !hasSession(r) {
					sendJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
					return
				}
				body := readBody(r)
				email, _ := body["email"].(string)
				email = strings.TrimSpace(email)
				message, _ := body["message"].(string)
				message = strings.TrimSpace(message)

				if email == "" {
					sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_email"})
					return
				}
				if message == "" {
					sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_message"})
					return
				}
				if len(message) > 5000 {
					message = message[:5000]
				}

				if err := FeedbackSubmit(email, message); err != nil {
					sendRelayError(w, err)
					return
				}

				ViewerFeedbackSubmitted()
				sendJSON(w, http.StatusOK, map[string]bool{"ok": true})

			case "/api/agents/steer":
				if !hasSession(r) {
					sendJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
					return
				}
				body := readBody(r)
				agentID, ok1 := body["agent_id"].(string)
				message, ok2 := body["message"].(string)

				if !ok1 || strings.TrimSpace(agentID) == "" {
					sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_agent_id"})
					return
				}
				if !ok2 || strings.TrimSpace(message) == "" || len(message) > 4000 {
					sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_message"})
					return
				}

				if state.steerHandler == nil {
					sendJSON(w, http.StatusForbidden, map[string]string{"error": "steering_unavailable"})
					return
				}

				delivered := state.steerHandler(agentID, message)
				if delivered {
					sendJSON(w, http.StatusOK, map[string]bool{"ok": true})
				} else {
					sendJSON(w, http.StatusOK, map[string]interface{}{"ok": false, "error": "not_delivered"})
				}

			default:
				sendJSON(w, http.StatusNotFound, map[string]string{"error": "unknown endpoint"})
			}
			return
		}

		sendJSON(w, http.StatusNotFound, map[string]string{"error": "unknown endpoint"})
	})

	return mux
}

// AuthorizedUrl returns the URL that bootstraps the viewer session for the operator.
func AuthorizedUrl(baseUrl string, token string) string {
	return fmt.Sprintf("%s/?token=%s", baseUrl, url.QueryEscape(token))
}

// Serve starts the viewer server on a background thread; returns (server, url, token).
func Serve(
	runDir string,
	host string,
	port int,
	openBrowser bool,
	steerHandler func(string, string) bool,
) (*http.Server, string, string) {
	assetsDir := BundleDir()
	sessionToken := generateToken(32)
	
	state := &viewerState{
		runDir:       runDir,
		assetsDir:    assetsDir,
		baseDir:      filepath.Dir(runDir),
		steerHandler: steerHandler,
		sessionToken: sessionToken,
		cookieName:   SessionCookiePrefix,
	}

	handler := makeHandler(state)

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		if port == 0 {
			panic(err)
		}
		log.Printf("viewer port %d unavailable, falling back to an ephemeral port", port)
		listener, err = net.Listen("tcp", fmt.Sprintf("%s:0", host))
		if err != nil {
			panic(err)
		}
	}

	boundPort := listener.Addr().(*net.TCPAddr).Port
	state.cookieName = fmt.Sprintf("%s_%d", SessionCookiePrefix, boundPort)
	serverUrl := fmt.Sprintf("http://%s:%d", host, boundPort)

	srv := &http.Server{Handler: handler}
	
	go func() {
		if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("viewer server failed: %v", err)
		}
	}()

	if openBrowser {
		openURL(AuthorizedUrl(serverUrl, sessionToken))
	}

	return srv, serverUrl, sessionToken
}

func openURL(url string) {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start"}
	case "darwin":
		cmd = "open"
	default:
		cmd = "xdg-open"
	}
	args = append(args, url)
	err := exec.Command(cmd, args...).Start()
	if err != nil {
		log.Printf("could not open browser for %s: %v", url, err)
	}
}

// =====================================================================
// Telemetry stubs (To be implemented when telemetry is ported)
// =====================================================================

func ViewerCtaClicked(cta, surface string) {
}

func ViewerEmailEvent(event, purpose string) {
}

func ViewerAgentSteered() {
}

func ViewerFeedbackSubmitted() {
}

