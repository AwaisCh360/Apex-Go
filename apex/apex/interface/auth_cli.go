package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/AwaisCh360/Apex/apex/config"
)

const loginProvider = "chatgpt"

var usage = `Usage:
  apex auth login chatgpt [--manual]
  apex auth status
  apex auth logout`

var (
	runOAuthFlowFunc = runOAuthFlow
	exchangeCodeFunc = config.ExchangeCode
)

func RunAuth(argv []string) int {
	subcommand := "login"
	if len(argv) > 0 {
		subcommand = argv[0]
	}
	var rest []string
	if len(argv) > 1 {
		rest = argv[1:]
	}

	if subcommand == "-h" || subcommand == "--help" || subcommand == "help" {
		fmt.Println(usage)
		return 0
	}

	switch subcommand {
	case "login":
		return runLogin(rest)
	case "status":
		return runStatus()
	case "logout":
		return runLogout()
	default:
		fmt.Printf("Unknown auth command: %s\n\n%s\n", subcommand, usage)
		return 2
	}
}

func runLogin(argv []string) int {
	provider := loginProvider
	manual := false

	for i := 0; i < len(argv); i++ {
		if argv[i] == "--manual" {
			manual = true
		} else {
			provider = argv[i]
		}
	}

	if strings.ToLower(provider) != loginProvider && strings.ToLower(provider) != "codex" {
		fmt.Printf("Unsupported provider: %s. Only '%s' (ChatGPT subscription) is supported.\n", provider, loginProvider)
		return 2
	}

	verifier, challenge := config.GeneratePKCE()
	state := config.CreateState()
	authorizeURL := config.BuildAuthorizeURL(challenge, state)

	fmt.Println()
	fmt.Println("Signing in with ChatGPT (provider: chatgpt)")
	fmt.Println("This uses your ChatGPT Plus/Pro plan for inference instead of a metered API key.")
	fmt.Println()

	record, err := runOAuthFlowFunc(authorizeURL, verifier, state, manual)
	if err != nil {
		if err.Error() == "cancelled" {
			fmt.Println("\nSign-in cancelled.")
			return 130
		}
		var authErr *config.CodexAuthError
		if errors.As(err, &authErr) {
			fmt.Printf("\nSIGN-IN FAILED\n\n%s\n\n", authErr.Message)
		} else {
			fmt.Printf("\nSIGN-IN FAILED\n\n%v\n\n", err)
		}
		return 1
	}

	config.SaveRecord(record)
	printSuccess()
	return 0
}

func runOAuthFlow(authorizeURL, verifier, state string, manual bool) (map[string]interface{}, error) {
	fmt.Println("Open this URL in your browser to authorize:")
	fmt.Println(authorizeURL)
	fmt.Println()

	if !manual {
		openBrowser(authorizeURL)
	}

	if !manual {
		code, returnedState, err := runCallbackServer()
		if err == nil {
			return finishOAuth(code, returnedState, verifier, state, true)
		}
		fmt.Println("Timed out or failed waiting for the browser. Falling back to manual paste.")
	}

	fmt.Println()
	fmt.Print("Paste the full redirect URL (or code#state): ")
	reader := bufio.NewReader(os.Stdin)
	pasted, err := reader.ReadString('\n')
	if err != nil {
		return nil, &config.CodexAuthError{Code: "no_input", Message: "no redirect URL provided"}
	}
	pasted = strings.TrimSpace(pasted)

	code, returnedState := config.ParseRedirectInput(pasted)
	return finishOAuth(code, returnedState, verifier, state, false)
}

func openBrowser(url string) {
	var err error
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	}
	if err != nil {
		fmt.Printf("could not open browser: %v\n", err)
	}
}

func runCallbackServer() (string, string, error) {
	result := make(chan struct {
		code  string
		state string
		err   string
	})

	srv := &http.Server{Addr: fmt.Sprintf("127.0.0.1:%d", config.CallbackPort)}
	http.HandleFunc(config.CallbackPath, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		code := q.Get("code")
		state := q.Get("state")
		errMsg := q.Get("error_description")
		if errMsg == "" {
			errMsg = q.Get("error")
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(renderCallbackHTML()))

		result <- struct {
			code  string
			state string
			err   string
		}{code, state, errMsg}
	})

	go func() {
		srv.ListenAndServe()
	}()
	defer srv.Shutdown(context.Background())

	select {
	case res := <-result:
		if res.err != "" {
			return "", "", &config.CodexAuthError{Code: "oauth_error", Message: res.err}
		}
		return res.code, res.state, nil
	case <-time.After(300 * time.Second):
		return "", "", errors.New("timeout")
	}
}

func logoImgTag() string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return ""
	}
	logoPath := filepath.Join(filepath.Dir(filename), "..", "viewer", "static", "logo.png")
	data, err := os.ReadFile(logoPath)
	if err != nil {
		return ""
	}
	encoded := base64.StdEncoding.EncodeToString(data)
	return fmt.Sprintf(`<img class="logo" src="data:image/png;base64,%s" alt="" />`, encoded)
}

func renderCallbackHTML() string {
	return strings.ReplaceAll(callbackHTML, "<!--LOGO-->", logoImgTag())
}

var callbackHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Apex — signed in</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; padding: 24px;
    font-family: 'Geist', 'Geist Sans', ui-sans-serif, system-ui, -apple-system,
      "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    -webkit-font-smoothing: antialiased; -moz-osx-font-smoothing: grayscale;
    background: #000; color: #ededed;
    display: flex; flex-direction: column; align-items: center; justify-content: center;
  }
  .topbar {
    position: absolute; top: 20px; left: 22px;
    display: flex; align-items: center; gap: 6px; text-decoration: none;
  }
  .topbar .logo { width: 40px; height: 40px; display: block; }
  .topbar span {
    font-size: 1.1rem; font-weight: 600; letter-spacing: -.01em; color: #fff;
    transition: color .15s ease;
  }
  .topbar:hover span { color: #c9c9c9; }
  .brand {
    font-size: 2.1rem; font-weight: 700; letter-spacing: -.02em; color: #fff;
    text-align: center; margin: 0 0 10px;
  }
  h1 {
    font-size: 1.35rem; font-weight: 600; letter-spacing: -.01em; color: #f5f5f5;
    text-align: center; margin: 0 0 28px;
  }
  .card {
    width: 100%; max-width: 430px; text-align: center;
    background: #171717; border: 1px solid rgba(255, 255, 255, .06);
    border-radius: 24px; padding: 40px 40px 34px;
  }
  .badge {
    margin: 0 auto 22px; width: 52px; height: 52px; border-radius: 50%;
    display: flex; align-items: center; justify-content: center; font-size: 23px; color: #fff;
    background: rgba(255, 255, 255, .05); border: 1px solid rgba(255, 255, 255, .14);
  }
  .msg { margin: 0 auto; max-width: 34ch; color: #b5b5b5; line-height: 1.6; font-size: .98rem; }
  .rule { height: 1px; background: rgba(255, 255, 255, .07); margin: 26px 0 0; }
  .tagline { margin: 22px 0 0; color: #7c7c7c; font-size: .9rem; line-height: 1.55; }
  .tagline b { color: #ededed; font-weight: 500; }
  .links {
    margin-top: 18px; display: flex; gap: 8px; justify-content: center;
    align-items: center; flex-wrap: wrap; font-size: .84rem;
  }
  .links a { color: #a3a3a3; text-decoration: none; transition: color .15s ease; }
  .links a:hover { color: #fff; }
  .links .dot { color: #3a3a3a; }
  .close { margin: 24px 0 0; color: #5a5a5a; font-size: .78rem; text-align: center; }
</style></head>
<body>
  <a class="topbar" href="https://apex.ai" target="_blank" rel="noopener"
     aria-label="Apex — apex.ai">
    <!--LOGO-->
    <span>Apex</span>
  </a>
  <div class="brand">Apex</div>
  <h1>You're signed in</h1>
  <main class="card">
    <div class="badge">✓</div>
    <p class="msg">Apex is connected to your ChatGPT subscription. Head back to your
      terminal — your security test runs there.</p>
    <div class="rule"></div>
    <p class="tagline">Autonomous AI hackers that <b>find and fix</b> your app's
      vulnerabilities.</p>
    <nav class="links">
      <a href="https://apex.ai" target="_blank" rel="noopener">apex.ai</a>
      <span class="dot">·</span>
      <a href="https://docs.apex.ai" target="_blank" rel="noopener">docs</a>
      <span class="dot">·</span>
      <a href="https://discord.gg/apex-ai" target="_blank" rel="noopener">community</a>
    </nav>
  </main>
  <p class="close">You can close this tab.</p>
</body></html>`

func finishOAuth(code, returnedState, verifier, expectedState string, requireState bool) (map[string]interface{}, error) {
	if code == "" {
		return nil, &config.CodexAuthError{Code: "no_code", Message: "no authorization code found in the redirect"}
	}
	if requireState && returnedState == "" {
		return nil, &config.CodexAuthError{Code: "state_mismatch", Message: "missing state in callback; possible CSRF"}
	}
	if returnedState != "" && returnedState != expectedState {
		return nil, &config.CodexAuthError{Code: "state_mismatch", Message: "state did not match; possible CSRF"}
	}
	return exchangeCodeFunc(code, verifier)
}

func runStatus() int {
	record := config.ReadRecord()
	if record == nil {
		fmt.Println("Not signed in. Run 'apex auth login chatgpt' to sign in.")
		return 1
	}
	settings := config.LoadSettings()
	fmt.Println("Signed in with a ChatGPT subscription.")
	fmt.Printf("  Account: %v\n", record["account_id"])
	if config.SubscriptionModel(settings.Llm.Model) != "" {
		fmt.Printf("  Runs use the subscription (APEX_LLM=%s).\n", settings.Llm.Model)
	} else {
		fmt.Println("  Note: set APEX_LLM to e.g. chatgpt/gpt-5.4 to run on the subscription.")
	}
	return 0
}

func runLogout() int {
	config.Logout()
	fmt.Println("Signed out. Stored subscription credentials removed.")
	return 0
}

func printSuccess() {
	fmt.Println("Signed in with your ChatGPT subscription")
	fmt.Println("Set APEX_LLM to a chatgpt/ model (e.g. chatgpt/gpt-5.4) — runs are billed to your ChatGPT plan.")
	fmt.Println("Run a scan as usual, e.g. apex --target https://example.com")
}
