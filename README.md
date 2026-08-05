# Apex-Go

Apex-Go is a powerful, autonomous AI-driven security scanner and vulnerability assessment tool written in Go. It acts as an intelligent agent that can reason about target systems, discover attack vectors, and automatically report vulnerabilities. The project features a robust core execution engine paired with an interactive Terminal User Interface (TUI) for real-time monitoring of the AI's thought processes and actions.

## 🚀 Features

- **Autonomous AI Scanning:** Supply a target and an instruction, and Apex will autonomously navigate, investigate, and analyze the target for security weaknesses.
- **Interactive TUI:** A beautiful, terminal-based interface powered by Bubble Tea that provides real-time updates on agent state, budget usage, and vulnerabilities found.
- **Pluggable LLM Backends:** Supports multiple LLM providers (e.g., Mistral, OpenAI, Anthropic).
- **Docker Integration:** Seamlessly utilizes Docker for sandboxed execution and environment management during assessments.
- **Comprehensive Reporting:** Automatically aggregates findings and generates detailed vulnerability reports at the end of a scan.

## 📋 Prerequisites

Before you begin, ensure you have the following installed:
- **Go 1.21+**: [Download and install Go](https://golang.org/doc/install)
- **Docker**: Required for local sandboxing and tool execution ([Download Docker](https://docs.docker.com/get-docker/))
- **Make**: For using the provided `Makefile` (optional but recommended)

## 🛠️ Installation

Clone the repository and install the CLI locally:

```bash
git clone https://github.com/AwaisCh360/Apex-Go.git
cd Apex-Go/apex
make install
```

This will build the `apex` binary and install it to your `$GOPATH/bin` directory. Make sure your `$GOPATH/bin` is in your system's `$PATH`.

## ⚙️ Configuration

Apex relies on environment variables to configure its AI capabilities. Set the following environment variables before running a scan:

```bash
# Set your preferred LLM provider and model (e.g., mistral-large-latest, gpt-4o, claude-3-5-sonnet)
export APEX_LLM="mistral/mistral-large-latest"

# Provide the API key for your chosen LLM provider
export LLM_API_KEY="your-api-key-here"

# (Optional) Set an API base URL if using a custom endpoint
export LLM_API_BASE="https://api.yourprovider.com/v1"
```

## 🎮 Usage

You can run Apex via the CLI by passing a target and specific instructions.

### Basic Scan
To start an interactive scan on a specific target:

```bash
apex -target http://example.com -instruction "Explore the application and look for common vulnerabilities like XSS or SQLi."
```

### Advanced Scan with Budget Limits
You can limit the amount of money the AI agent is allowed to spend during its execution:

```bash
apex -target http://example.com -instruction "Perform a deep scan" -max-budget-usd 5.0
```

### TUI Experience
When launched, Apex will open its interactive TUI. You will be able to see:
- **Agent State:** The current thoughts and actions of the AI coordinator.
- **Budget Tracking:** Real-time tracking of token usage and costs.
- **Vulnerabilities:** Real-time feed of identified vulnerabilities as they are discovered.

## 🏗️ Architecture

Apex-Go is heavily modularized to decouple the TUI frontend from the AI execution backend:
- `apex/core`: Contains the main `AgentCoordinator`, `RunApexScan` orchestration, and agent lifecycle management.
- `apex/report`: Handles the collection, state management, and output formatting of vulnerability reports.
- `apex/interface`: The CLI entrypoint that parses arguments and launches the application.
- `apex/interface/tui`: The Bubble Tea frontend and IPC backend that synchronizes state from the `core` into a visual interface.

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! 
Feel free to check the [issues page](https://github.com/AwaisCh360/Apex-Go/issues).

## 📝 License

This project is licensed under the MIT License.
