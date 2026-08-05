package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/AwaisCh360/Apex/apex/config"
	"github.com/AwaisCh360/Apex/apex/core"
	"github.com/AwaisCh360/Apex/apex/report"
	"github.com/AwaisCh360/Apex/apex/telemetry"
)

func exceptionMessages(err error) []string {
	var msgs []string
	for err != nil {
		msgs = append(msgs, err.Error())
		if u, ok := err.(interface{ Unwrap() error }); ok {
			err = u.Unwrap()
		} else {
			break
		}
	}
	return msgs
}

func providerImportHint(err error, model string) string {
	msgs := exceptionMessages(err)
	modelName := strings.ToLower(model)

	hasBedrockErr := false
	for _, m := range msgs {
		if strings.Contains(m, "No module named 'boto3'") {
			hasBedrockErr = true
		}
	}
	if hasBedrockErr && strings.HasPrefix(modelName, "bedrock/") {
		return "Bedrock support is optional. Install it with: pipx install \"apex-agent[bedrock]\""
	}

	hasVertexErr := false
	for _, m := range msgs {
		if strings.Contains(m, "No module named 'google") {
			hasVertexErr = true
		}
	}
	if hasVertexErr && strings.Contains(modelName, "vertex") {
		return "Vertex AI support is optional. Install it with: pipx install \"apex-agent[vertex]\""
	}
	return ""
}

func subscriptionErrorHint(err error) string {
	settings := config.LoadSettings()
	if config.SubscriptionModel(settings.Llm.Model) == "" {
		return ""
	}
	joined := strings.ToLower(strings.Join(exceptionMessages(err), " "))
	if strings.Contains(joined, "not supported when using codex with a chatgpt account") {
		return "This model isn't available on your ChatGPT subscription. Set APEX_LLM to a model your plan includes (e.g. chatgpt/gpt-5.4)."
	}
	if strings.Contains(joined, "error code: 401") || strings.Contains(joined, "http 401") || strings.Contains(joined, "unauthorized") || strings.Contains(joined, "invalid_grant") {
		return "Your ChatGPT sign-in has expired or was revoked. Sign in again:\n  apex auth login chatgpt"
	}
	return ""
}

func WarmUpLlm(showModelWarning bool) error {
	logger.Println("Warming up Llm connection")
	settings := config.LoadSettings()
	config.ConfigureSdkModelDefaults(settings)

	rawModel := strings.TrimSpace(settings.Llm.Model)

	if rawModel != "" && !strings.Contains(rawModel, "/") && !config.IsKnownOpenAIBareModel(rawModel) && settings.Llm.APIBase == "" {
		fmt.Printf("\n[UNKNOWN MODEL NAME]\n\n'%s' is not a known OpenAI model. Bare names route to OpenAI by default.\nIf you meant a non-OpenAI provider, use the '<provider>/<model>' form, e.g. 'anthropic/claude-opus-4-7'.\n\n", rawModel)
		os.Exit(1)
	}

	if showModelWarning && rawModel != "" && !config.IsRecommendedOrFrontierModel(rawModel) {
		recommended := []string{
			"openai/gpt-4o",
			"anthropic/claude-3-5-sonnet-20241022",
			"google/gemini-2.0-pro-exp",
		}
		fmt.Printf("\n[MODEL QUALITY WARNING]\n\n'%s' is not a recommended frontier model for Apex.\nSecurity scans work best with:\n", rawModel)
		for _, m := range recommended {
			fmt.Printf("• %s\n", m)
		}
		fmt.Println("\nYou can continue, but weaker models may miss vulnerabilities or produce lower-quality findings.")
	}

	err := PreflightModelConnection(rawModel, settings)
	if err != nil {
		logger.Printf("Llm warm-up failed: %v", err)
		return &ModelConnectionError{ModelName: rawModel, Cause: err}
	}

	/* if settings.Dedupe.Model != "" {
		dedupeModel := strings.TrimSpace(settings.Dedupe.Model)

		// In Go, since agents package is not fully imported here, we simulate the exact
		// dedicated provider instantiation by wrapping it in PreflightModelConnection with
		// the dedupe settings isolated, including headers and extra args.
		dedupeSettings := *settings
		dedupeSettings.Llm.Model = dedupeModel
		dedupeSettings.Llm.ExtraHeaders = settings.Dedupe.ExtraHeaders
		dedupeSettings.Llm.ExtraArgs = settings.Dedupe.ExtraArgs

		err = PreflightModelConnection(dedupeModel, &dedupeSettings)
		if err != nil {
			logger.Printf("LLM warm-up failed for dedupe model: %v", err)
			return &ModelConnectionError{ModelName: dedupeModel, Cause: err}
		}
		logger.Printf("LLM warm-up succeeded for dedupe model %s", dedupeModel)
	} */

	logger.Printf("LLM warm-up succeeded for model %s", rawModel)
	return nil
}

func DisplayCompletionMessage(args *CliArgs, resultsPath string) {
	fmt.Println()
	rs := report.GetGlobalReportState()
	scanCompleted := false
	if rs != nil {
		scanCompleted = rs.RunRecord["status"].(string) == "completed"
	}

	if scanCompleted {
		fmt.Println("[Penetration test completed]")
	} else {
		fmt.Println("Run record status:")
		// fmt.Println(rs.Status())
	}
	fmt.Println()

	targetsText := ""
	if len(args.TargetsInfo) == 1 {
		if orig, ok := args.TargetsInfo[0]["original"].(string); ok {
			targetsText = orig
		}
	} else {
		targetsText = fmt.Sprintf("%d targets", len(args.TargetsInfo))
		for _, t := range args.TargetsInfo {
			if orig, ok := t["original"].(string); ok {
				targetsText += "\n        " + orig
			}
		}
	}
	fmt.Printf("Target  %s\n", targetsText)

	if rs != nil {
		// fmt.Println(BuildFinalStatsText(rs))
		statsText := ""
		if statsText != "" {
			fmt.Printf("\n%s", statsText)
		}
	}

	fmt.Printf("\nOutput  %s\n", resultsPath)

	if args.RunName != nil {
		fmt.Printf("\nView    apex view %s\n", *args.RunName)
		if !scanCompleted {
			fmt.Printf("\nResume  apex --resume %s\n", *args.RunName)
		}
	}

	fmt.Println("\napex.ai  ·  docs.apex.ai  ·  discord.gg/apex-ai")

	if !args.NonInteractive {
		NotifyUpdate()
	}
}

func printErrorPanel(title, message string) {
	fmt.Printf("\n[%s]\n\n%s\n\n", title, message)
}

func printModelConnectionError(err error, modelName string) {
	subHint := subscriptionErrorHint(err)
	if subHint != "" {
		fmt.Printf("\n[MODEL NOT AVAILABLE ON SUBSCRIPTION]\n\n%s\n\nDetails: %v\n\n", subHint, err)
	} else {
		fmt.Printf("\n[LLM CONNECTION FAILED]\n\nCould not establish connection to the language model.\nPlease check your configuration and try again.\n")
		hint := providerImportHint(err, modelName)
		if hint != "" {
			fmt.Printf("\n%s\n", hint)
		}
		fmt.Printf("\nError: %v\n\n", err)
	}
}

func BootstrapScan(args *CliArgs) {
	ValidateEnvironment()
	if !args.NonInteractive {
		return
	}
	err := error(nil) // WarmUpLLM(ctx)
	if err != nil {
		if mcErr, ok := err.(*ModelConnectionError); ok {
			printModelConnectionError(mcErr.Cause, mcErr.ModelName)
		} else {
			printModelConnectionError(err, "")
		}
		os.Exit(1)
	}
	config.PersistCurrent()
	err = PrepareRun(args)
	if err != nil {
		printErrorPanel("SCAN PREPARATION FAILED", err.Error())
		os.Exit(1)
	}
	TelemetryStart(args)
}

// Subcommand Run stubs
func RunView(args []string) {
	fmt.Println("Viewer starting...")
}



func main() {
	telemetry.ConfigureDependencyLogging()

	if len(os.Args) > 1 && os.Args[1] == "view" {
		RunView(os.Args[2:])
		return
	}

	if len(os.Args) > 1 && os.Args[1] == "auth" {
		os.Exit(RunAuth(os.Args[2:]))
	}

	args, err := ParseArguments(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing arguments: %v\n", err)
		os.Exit(1)
	}

	StartBackgroundCheck()
	if !args.NonInteractive && PromptUpdateIfAvailable() {
		if IsBinaryInstall() {
			err := syscall.Exec(os.Args[0], os.Args, os.Environ())
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to restart process: %v\n", err)
				os.Exit(1)
			}
		}
		os.Exit(0)
	}

	CheckDockerInstalled()
	PullDockerImage()

	if !args.NeedsSetup {
		BootstrapScan(args)
	}

	exitReason := "user_exit"

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		rs := report.GetGlobalReportState()
		if rs != nil {
			rs.Cleanup("interrupted")
		}
		telemetry.End(rs, "interrupted")
		os.Exit(1)
	}()

	if args.NonInteractive {
		err = RunCLI(args)
	} else {
		err = RunTUI(args)
	}

	if err != nil {
		if _, ok := err.(*InteractiveSetupUnavailableError); ok {
			exitReason = "error"
			printErrorPanel("INTERACTIVE SETUP UNAVAILABLE", err.Error())
			telemetry.End(nil, "error")
			os.Exit(1)
		} else {
			exitReason = "error"
		}
	}

	rs := report.GetGlobalReportState()
	if rs != nil {
		status := "stopped"
		if exitReason == "interrupted" {
			status = "interrupted"
		}
		if exitReason == "error" {
			status = "failed"
		}
		rs.Cleanup(status)
	}
	telemetry.End(rs, exitReason)

	if args.RunName == nil {
		return
	}

	resultsPath := filepath.Join(core.RunDirFor(*args.RunName, ""))
	DisplayCompletionMessage(args, resultsPath)

	if args.NonInteractive {
		if true { // if rs.HasVulnerabilities() {
			os.Exit(2)
		}
	}
}
