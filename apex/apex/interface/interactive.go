package main

import (
	"fmt"

	"github.com/useapex/apex/tui"
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
