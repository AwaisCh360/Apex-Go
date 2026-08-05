package main

import (

	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/AwaisCh360/Apex/apex/config"
	"github.com/AwaisCh360/Apex/apex/core"
)

type CliArgs struct {
	Version         bool
	Update          bool
	Targets         []string
	TargetLists     []string
	Instruction     *string
	InstructionFile *string
	NonInteractive  bool
	ScanMode        string
	ScopeMode       string
	DiffBase        *string
	Config          *string
	MaxBudgetUSD    *float64
	MaxTurns        int
	Resume          *string

	NeedsSetup              bool
	TargetsInfo             []map[string]interface{}
	LocalSources            []map[string]interface{}
	DiffScope               map[string]interface{}
	RunName                 *string
	UserExplicitInstruction *string
	UserInstruction         *string
	WorkspaceMount          *string
}

type StringSliceFlag []string

func (i *StringSliceFlag) String() string {
	return fmt.Sprintf("%v", *i)
}
func (i *StringSliceFlag) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func GetVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "0.0.0-dev"
}

// Stubs for functions in other files
func ValidateConfigFile(path string) string                             { return "" }
func CheckMountableDir(path string) error                                               { return nil }
func ReadRunRecord(runDir string) (map[string]interface{}, error) {
	b, err := os.ReadFile(filepath.Join(runDir, "run.json"))
	if err != nil {
		return nil, err
	}
	var res map[string]interface{}
	json.Unmarshal(b, &res)
	return res, nil
}
func ParseArguments(osArgs []string) (*CliArgs, error) {
	fs := flag.NewFlagSet("apex", flag.ContinueOnError)

	args := &CliArgs{
		TargetsInfo:  []map[string]interface{}{},
		LocalSources: []map[string]interface{}{},
		DiffScope:    map[string]interface{}{"active": false},
	}

	fs.BoolVar(&args.Version, "v", false, "version")
	fs.BoolVar(&args.Version, "version", false, "version")

	fs.BoolVar(&args.Update, "update", false, "Update apex to the latest version and exit.")

	var targets StringSliceFlag
	fs.Var(&targets, "t", "Target to test")
	fs.Var(&targets, "target", "Target to test")

	var targetLists StringSliceFlag
	fs.Var(&targetLists, "target-list", "Path to a file containing targets")

	instruction := fs.String("instruction", "", "Custom instructions")
	instructionFile := fs.String("instruction-file", "", "Path to a file containing instructions")

	fs.BoolVar(&args.NonInteractive, "n", false, "Run in non-interactive mode")
	fs.BoolVar(&args.NonInteractive, "non-interactive", false, "Run in non-interactive mode")

	fs.StringVar(&args.ScanMode, "m", "deep", "Scan mode")
	fs.StringVar(&args.ScanMode, "scan-mode", "deep", "Scan mode")

	fs.StringVar(&args.ScopeMode, "scope-mode", "auto", "Scope mode for code targets")

	diffBase := fs.String("diff-base", "", "Target branch or commit")
	configFile := fs.String("config", "", "Path to custom config file")

	maxBudget := fs.String("max-budget", "", "Maximum LLM cost in USD")
	maxBudgetUSD := fs.String("max-budget-usd", "", "Maximum LLM cost in USD")

	fs.IntVar(&args.MaxTurns, "max-turns", 30, "Maximum turns per agent")

	resume := fs.String("resume", "", "Resume a prior scan by its run name")

	err := fs.Parse(osArgs)
	if err != nil {
		if err == flag.ErrHelp {
			os.Exit(0)
		}
		return nil, err
	}

	if args.Version {
		fmt.Printf("apex %s\n", GetVersion())
		os.Exit(0)
	}

	args.Targets = targets
	args.TargetLists = targetLists

	if *instruction != "" {
		args.Instruction = instruction
	}
	if *instructionFile != "" {
		args.InstructionFile = instructionFile
	}
	if *diffBase != "" {
		args.DiffBase = diffBase
	}
	if *configFile != "" {
		args.Config = configFile
	}
	if *resume != "" {
		args.Resume = resume
	}

	var budgetStr string
	if *maxBudget != "" {
		budgetStr = *maxBudget
	}
	if *maxBudgetUSD != "" {
		budgetStr = *maxBudgetUSD
	}
	if budgetStr != "" {
		b, err := strconv.ParseFloat(budgetStr, 64)
		if err != nil || !math.IsInf(b, 0) == false || b <= 0 {
			return nil, fmt.Errorf("invalid max budget: must be finite number > 0")
		}
		args.MaxBudgetUSD = &b
	}

	if args.MaxTurns <= 0 {
		return nil, fmt.Errorf("max-turns must be an integer greater than 0")
	}

	if args.Config != nil {
		config.ApplyConfigOverride(ValidateConfigFile(*args.Config))
	}

	if args.Update {
		if SelfUpdate("") {
			os.Exit(0)
		} else {
			os.Exit(1)
		}
	}

	if args.Instruction != nil && args.InstructionFile != nil {
		return nil, fmt.Errorf("Cannot specify both --instruction and --instruction-file")
	}

	if args.InstructionFile != nil {
		b, err := os.ReadFile(*args.InstructionFile)
		if err != nil {
			return nil, fmt.Errorf("Failed to read instruction file: %v", err)
		}
		s := strings.TrimSpace(string(b))
		if s == "" {
			return nil, fmt.Errorf("Instruction file is empty")
		}
		args.Instruction = &s
	}

	if args.Resume != nil {
		args.UserExplicitInstruction = args.Instruction
	} else {
		args.UserExplicitInstruction = nil
	}

	args.UserInstruction = args.Instruction

	if args.Resume != nil {
		if len(args.Targets) > 0 || len(args.TargetLists) > 0 {
			return nil, fmt.Errorf("Cannot combine --resume with --target/--target-list")
		}
		err := loadResumeState(args)
		if err != nil {
			return nil, err
		}

		agentsPath := filepath.Join(core.RuntimeStateDir(core.RunDirFor(*args.Resume, "")), "agents.json")
		if _, err := os.Stat(agentsPath); err != nil {
			return nil, fmt.Errorf("--resume %s: missing %s", *args.Resume, agentsPath)
		}
	} else {
		if len(args.Targets) == 0 && len(args.TargetLists) == 0 {
			if args.NonInteractive {
				return nil, fmt.Errorf("the following arguments are required: -t/--target or --target-list")
			}
			args.NeedsSetup = true
			return args, nil
		}

		err := BuildTargetsInfo(args)
		if err != nil {
			return nil, err
		}
	}

	return args, nil
}

func loadResumeState(args *CliArgs) error {
	runDir := core.RunDirFor(*args.Resume, "")
	statePath := filepath.Join(runDir, "run.json")
	if _, err := os.Stat(statePath); err != nil {
		return fmt.Errorf("--resume %s: no such run", *args.Resume)
	}

	state, err := ReadRunRecord(runDir)
	if err != nil {
		return fmt.Errorf("--resume %s: run.json unreadable: %v", *args.Resume, err)
	}

	if tinfo, ok := state["targets_info"].([]interface{}); ok {
		for _, t := range tinfo {
			if m, ok := t.(map[string]interface{}); ok {
				args.TargetsInfo = append(args.TargetsInfo, m)
			}
		}
	}

	workspaceMount, _ := state["workspace_mount"].(string)
	if len(args.TargetsInfo) == 0 && workspaceMount == "" {
		return fmt.Errorf("--resume %s: run.json has no targets_info", *args.Resume)
	}

	for _, target := range args.TargetsInfo {
		details, _ := target["details"].(map[string]interface{})
		typ, _ := target["type"].(string)

		if typ == "local_code" {
			if tp, ok := details["target_path"].(string); ok {
				if err := CheckMountableDir(tp); err != nil {
					return fmt.Errorf("--resume %s: %v", *args.Resume, err)
				}
			}
			continue
		}
		if typ != "repository" {
			continue
		}

		cloned, _ := details["cloned_repo_path"].(string)
		if cloned == "" {
			continue
		}
		if _, err := os.Stat(cloned); err != nil {
			return fmt.Errorf("--resume %s: cloned repo missing at %s", *args.Resume, cloned)
		}
	}

	if args.Instruction == nil {
		if inst, ok := state["instruction"].(string); ok && inst != "" {
			args.Instruction = &inst
		}
	}
	if args.UserInstruction == nil {
		if ui, ok := state["user_instruction"].(string); ok && ui != "" {
			args.UserInstruction = &ui
		}
	}

	args.LocalSources = CollectLocalSources(args.TargetsInfo)
	if workspaceMount != "" {
		args.WorkspaceMount = &workspaceMount
		if s, err := os.Stat(workspaceMount); err != nil || !s.IsDir() {
			return fmt.Errorf("--resume %s: working directory %s missing", *args.Resume, workspaceMount)
		}
		AttachWorkspaceMount(args)
	}

	if ds, ok := state["diff_scope"].(map[string]interface{}); ok {
		args.DiffScope = ds
	}

	if psm, ok := state["scan_mode"].(string); ok && psm != "" {
		if args.ScanMode == "deep" {
			args.ScanMode = psm
		}
	}

	return nil
}
