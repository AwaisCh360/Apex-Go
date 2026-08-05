package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/AwaisCh360/Apex/apex/config"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/jsonmessage"
)

func ValidateEnvironment() {
	logger.Println("Validating environment")
	settings := config.LoadSettings()

	if config.SubscriptionModel(settings.Llm.Model) != "" {
		if config.ReadRecord() == nil {
			fmt.Printf("\n[red]APEX_LLM=%s uses your ChatGPT subscription, but you're not signed in.[/] Run [cyan]apex auth login chatgpt[/] first.\n", settings.Llm.Model)
			os.Exit(1)
		}
		logger.Println("Environment OK (ChatGPT subscription)")
		return
	}

	var missingRequired []string
	var missingOptional []string

	if settings.Llm.Model == "" {
		missingRequired = append(missingRequired, "APEX_LLM")
	}
	if settings.Llm.APIKey == "" {
		missingOptional = append(missingOptional, "LLM_API_KEY")
	}
	if settings.Llm.APIBase == "" {
		missingOptional = append(missingOptional, "LLM_API_BASE")
	}
	if settings.Integrations.PerplexityAPIKey == "" {
		missingOptional = append(missingOptional, "PERPLEXITY_API_KEY")
	}

	if len(missingRequired) > 0 {
		fmt.Println("\nMISSING REQUIRED ENVIRONMENT VARIABLES")
		for _, v := range missingRequired {
			fmt.Printf("• %s is not set\n", v)
		}

		if len(missingOptional) > 0 {
			fmt.Println("\nOptional environment variables:")
			for _, v := range missingOptional {
				fmt.Printf("• %s is not set\n", v)
			}
		}

		fmt.Println("\nRequired environment variables:")
		for _, v := range missingRequired {
			if v == "APEX_LLM" {
				fmt.Println("• APEX_LLM - Model name to use (e.g., 'openai/gpt-5.4' or 'anthropic/claude-opus-4-7')")
			}
		}

		if len(missingOptional) > 0 {
			fmt.Println("\nOptional environment variables:")
			for _, v := range missingOptional {
				if v == "LLM_API_BASE" {
					fmt.Println("• LLM_API_BASE - Custom API base URL if using local models (e.g., Ollama, LMStudio)")
				} else if v == "PERPLEXITY_API_KEY" {
					fmt.Println("• PERPLEXITY_API_KEY - API key for Perplexity AI web search (enables real-time research)")
				}
			}
		}

		fmt.Println("\nExample setup:")
		fmt.Println("export APEX_LLM='openai/gpt-5.4'")

		if len(missingOptional) > 0 {
			for _, v := range missingOptional {
				if v == "LLM_API_BASE" {
					fmt.Println("export LLM_API_BASE='http://localhost:11434'  # needed for local models only")
				} else if v == "PERPLEXITY_API_KEY" {
					fmt.Println("export PERPLEXITY_API_KEY='your-perplexity-key-here'")
				}
			}
		}

		fmt.Println()
		os.Exit(1)
	}

	logger.Printf("Environment OK (optional missing: %v)", missingOptional)
}

func CheckDockerInstalled() {
	if _, err := exec.LookPath("docker"); err != nil {
		logger.Println("Docker CLI not found in PATH")
		printErrorPanelEnv("DOCKER NOT INSTALLED", "The 'docker' CLI was not found in your PATH.\nPlease install Docker and ensure the 'docker' command is available.")
		os.Exit(1)
	}
	logger.Println("Docker CLI present")
}

func PullDockerImage() {
	settings := config.LoadSettings()
	img := settings.Runtime.Image
	if img == "" {
		return
	}

	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		printDockerDaemonError()
		os.Exit(1)
	}
	defer cli.Close()

	if _, err := cli.Ping(ctx); err != nil {
		printDockerDaemonError()
		os.Exit(1)
	}

	_, _, err = cli.ImageInspectWithRaw(ctx, img)
	if err == nil {
		logger.Printf("Docker image already present locally: %s\n", img)
		return
	}

	logger.Printf("Pulling docker image: %s\n", img)
	fmt.Println()
	fmt.Printf("Pulling image %s\n", img)
	fmt.Println("This only happens on first run and may take a few minutes...")

	out, err := cli.ImagePull(ctx, img, types.ImagePullOptions{})
	if err != nil {
		logger.Printf("Failed to initiate docker pull for %s: %v\n", img, err)
		printDockerPullError(img, err)
		os.Exit(1)
	}
	defer out.Close()

	err = jsonmessage.DisplayJSONMessagesStream(out, os.Stdout, os.Stdout.Fd(), true, nil)
	if err != nil {
		logger.Printf("Failed to complete docker pull for %s: %v\n", img, err)
		printDockerPullError(img, err)
		os.Exit(1)
	}

	logger.Printf("Docker image %s ready\n", img)
	fmt.Println("\nDocker image ready")
}

func printErrorPanelEnv(title, message string) {
	fmt.Printf("\n[%s]\n\n%s\n\n", title, message)
}

func printDockerDaemonError() {
	logger.Println("Cannot connect to Docker daemon")
	printErrorPanelEnv("DOCKER NOT AVAILABLE", "Cannot connect to Docker daemon.\n\nPlease ensure Docker Desktop is installed and running, and try running apex again.")
}

func printDockerPullError(image string, err error) {
	logger.Printf("Docker pull failed for %s: %v", image, err)
	msg := fmt.Sprintf("Could not download: %s\n\n%v", image, err)
	printErrorPanelEnv("FAILED TO PULL IMAGE", msg)
}
