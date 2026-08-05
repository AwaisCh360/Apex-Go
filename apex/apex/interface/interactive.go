package main

import (
	"fmt"

	"github.com/useapex/apex/tui"
	"github.com/AwaisCh360/Apex/apex/config"
	"github.com/AwaisCh360/Apex/apex/core"
)

type InteractiveSetupUnavailableError struct {
	Message string
}

func (e *InteractiveSetupUnavailableError) Error() string {
	return e.Message
}

func runGoTUI(args *CliArgs) error {
	runName := ""
	if args.RunName != nil {
		runName = *args.RunName
	}
	instr := ""
	if args.Instruction != nil {
		instr = *args.Instruction
	}
	diffBase := ""
	if args.DiffBase != nil {
		diffBase = *args.DiffBase
	}
	userExp := ""
	if args.UserExplicitInstruction != nil {
		userExp = *args.UserExplicitInstruction
	}
	wsMount := ""
	if args.WorkspaceMount != nil {
		wsMount = *args.WorkspaceMount
	}
	maxBudget := 0.0
	if args.MaxBudgetUSD != nil {
		maxBudget = *args.MaxBudgetUSD
	}

	diffScope := ""
	if args.DiffScope != nil {
		diffScope = fmt.Sprintf("%v", args.DiffScope)
	}

	var targetList []interface{}
	for _, t := range args.TargetLists {
		targetList = append(targetList, t)
	}

	tuiArgs := &tui.Namespace{
		RunName:                 runName,
		TargetsInfo:             args.TargetsInfo,
		Instruction:             instr,
		DiffScope:               diffScope,
		ScanMode:                args.ScanMode,
		LocalSources:            nil,
		ScopeMode:               args.ScopeMode,
		DiffBase:                diffBase,
		UserExplicitInstruction: userExp,
		WorkspaceMount:          wsMount,
		WorkspaceSubdir:         "",
		MaxBudgetUSD:            maxBudget,
		MaxTurns:                args.MaxTurns,
		UserInstruction:         args.UserInstruction,
		Target:                  args.Targets,
		TargetList:              targetList,
	}
	tui.GlobalCallbacks = &tui.Callbacks{
		LoadSettings: func() (string, string) {
			s := config.LoadSettings()
			return s.Llm.Model, s.Runtime.Image
		},
		PreflightModelConnection: func(model string) error {
			return PreflightModelConnection(model, config.LoadSettings())
		},
		BuildTargetsInfo: func(ns *tui.Namespace) {
			argsCopy := *args
			argsCopy.TargetsInfo = ns.TargetsInfo
			BuildTargetsInfo(&argsCopy)
			ns.TargetsInfo = argsCopy.TargetsInfo
		},
		PrepareRun: func(ns *tui.Namespace) {
			argsCopy := *args
			argsCopy.TargetsInfo = ns.TargetsInfo
			PrepareRun(&argsCopy)
			ns.TargetsInfo = argsCopy.TargetsInfo
			ns.LocalSources = argsCopy.LocalSources
		},
		TelemetryStart: func(ns *tui.Namespace) {
			TelemetryStart(args)
		},
		PersistCurrent: func() {
		},
		RunApexScan: func(config map[string]interface{}, id, image string, localSources []map[string]interface{}, coord *core.AgentCoordinator, interactive bool, maxTurns int, maxBudget float64, eventSink func(string, interface{})) error {
			var scanID *string
			if id != "" {
				scanID = &id
			}
			var maxBudgetUSD *float64
			if maxBudget > 0 {
				maxBudgetUSD = &maxBudget
			}
			_, err := core.RunApexScan(config, scanID, image, localSources, coord, interactive, maxTurns, maxBudgetUSD, nil, false, eventSink, nil, nil, nil)
			return err
		},
	}

	return tui.RunGoTui(tuiArgs)
}

func RunTUI(args *CliArgs) error {
	err := runGoTUI(args)
	if err != nil {
		return &InteractiveSetupUnavailableError{
			Message: fmt.Sprintf("The interactive interface could not start: %v", err),
		}
	}
	return nil
}
