package main

import (
	"fmt"
	"time"

	"github.com/AwaisCh360/Apex/apex/config"
	"github.com/AwaisCh360/Apex/apex/core"
	"github.com/AwaisCh360/Apex/apex/telemetry"
	"github.com/AwaisCh360/Apex/apex/utils"
)

type ModelConnectionError struct {
	ModelName string
	Cause     error
}

func (e *ModelConnectionError) Error() string {
	return e.Cause.Error()
}

func PreflightModelConnection(modelName string, settings *config.Settings) error {
	return nil
}

func BuildTargetsInfo(args *CliArgs) error {
	args.TargetsInfo = []map[string]interface{}{}
	var targets []string
	targets = append(targets, args.Targets...)
	for _, targetListPath := range args.TargetLists {
		listTargets, err := ReadTargetListFile(targetListPath)
		if err == nil {
			targets = append(targets, listTargets...)
		}
	}

	for _, target := range targets {
		targetType, targetDict, err := InferTargetType(target)
		if err != nil {
			return fmt.Errorf("Invalid target '%s': %v", target, err)
		}

		displayTarget := target
		if targetType == "local_code" {
			if tp, ok := targetDict["target_path"].(string); ok {
				displayTarget = tp
			}
		}

		if targetType == "api_spec" {
			err = resolveApiSpec(target, targetDict)
			if err != nil {
				return err
			}
		}

		args.TargetsInfo = append(args.TargetsInfo, map[string]interface{}{
			"type":     targetType,
			"details":  targetDict,
			"original": displayTarget,
		})
	}

	args.TargetsInfo = DedupeLocalTargets(args.TargetsInfo)
	AssignWorkspaceSubdirs(args.TargetsInfo)
	RewriteLocalhostTargets(args.TargetsInfo, "host.docker.internal")
	return nil
}

func resolveApiSpec(target string, details map[string]interface{}) error {
	var raw map[string]interface{}
	var extraVariables map[string]string

	source, _ := details["source"].(string)
	if source == "postman_api" {
		collectionUID, _ := details["collection_uid"].(string)
		settings := config.LoadSettings()
		apiKey := settings.Integrations.PostmanAPIKey

		fetched, err := utils.FetchPostmanCollection(collectionUID, apiKey)
		if err != nil {
			return fmt.Errorf("Invalid API spec '%s': %v", target, err)
		}
		raw = fetched

		envUID, ok := details["environment_uid"].(string)
		if ok && envUID != "" {
			envVars, err := utils.FetchPostmanEnvironment(envUID, apiKey)
			if err != nil {
				return fmt.Errorf("Invalid API spec '%s': %v", target, err)
			}
			extraVariables = envVars
		}

		details["target_spec"] = utils.WriteFetchedCollection(raw, collectionUID)
	} else {
		targetSpec, _ := details["target_spec"].(string)
		fetched, err := utils.LoadSpec(targetSpec)
		if err != nil {
			return fmt.Errorf("Invalid API spec '%s': %v", target, err)
		}
		raw = fetched
		extraVariables = nil
	}

	baseUrls, err := utils.SpecBaseURLs(raw, extraVariables)
	if err != nil {
		return fmt.Errorf("Invalid API spec '%s': %v", target, err)
	}

	details["spec_title"] = utils.SpecTitle(raw)
	details["base_urls"] = baseUrls

	return nil
}

func PrepareRun(args *CliArgs) error {
	if args.RunName == nil {
		name := GenerateRunName(args.TargetsInfo)
		args.RunName = &name
	}

	if args.Resume != nil {
		return nil
	}

	for _, targetInfo := range args.TargetsInfo {
		if targetInfo["type"] == "repository" {
			details := targetInfo["details"].(map[string]interface{})
			repoUrl, _ := details["target_repo"].(string)
			destName, _ := details["workspace_subdir"].(string)
			clonedPath, err := CloneRepository(repoUrl, *args.RunName, destName)
			if err != nil {
				return err
			}
			targetInfo["details"].(map[string]interface{})["cloned_repo_path"] = clonedPath
		}
	}

	args.LocalSources = CollectLocalSources(args.TargetsInfo)
	args.LocalSources = append(args.LocalSources, StageApiSpecs(args.TargetsInfo, *args.RunName)...)

	diffScope, err := ResolveDiffScopeContext(args.LocalSources, args.ScopeMode, args.DiffBase, args.NonInteractive)
	if err != nil {
		return err
	}
	args.DiffScope = diffScope.Metadata

	if diffScope.InstructionBlock != "" {
		if args.Instruction != nil {
			inst := fmt.Sprintf("%s\n\n%s", diffScope.InstructionBlock, *args.Instruction)
			args.Instruction = &inst
		} else {
			inst := diffScope.InstructionBlock
			args.Instruction = &inst
		}
	}

	AttachWorkspaceMount(args)
	PersistRunRecord(args)
	return nil
}

func AttachWorkspaceMount(args *CliArgs) {
	if args.WorkspaceMount == nil || *args.WorkspaceMount == "" {
		return
	}
	mount := *args.WorkspaceMount
	wsSubdir := DeriveLocalBaseName(mount)

	args.LocalSources = append(args.LocalSources, map[string]interface{}{
		"source_path":      mount,
		"workspace_subdir": wsSubdir,
		"protect_metadata": true,
	})
}

func codexAuthMode(model string) string {
	if config.SubscriptionModel(model) != "" {
		record := config.ReadRecord()
		if record != nil {
			if am, ok := record["auth_mode"].(string); ok && am != "" {
				return am
			}
		}
	}
	return "api_key"
}

func isWhiteboxScan(targetsInfo []map[string]interface{}) bool {
	for _, t := range targetsInfo {
		if tType, _ := t["type"].(string); tType == "repository" || tType == "local_code" {
			return true
		}
	}
	return false
}

func TelemetryStart(args *CliArgs) {
	settings := config.LoadSettings()
	model := settings.Llm.Model

	interactive := !args.NonInteractive
	hasInstructions := args.Instruction != nil && *args.Instruction != ""

	// The telemetry module is now imported. We pass the exact kwargs required.
	// Since python uses telemetry.start(...), we will call telemetry.Start if it exists.
	// We'll create telemetry.Start inside telemetry package to wire it fully.
	telemetry.Start(
		model,
		args.ScanMode,
		isWhiteboxScan(args.TargetsInfo),
		interactive,
		hasInstructions,
		codexAuthMode(model),
	)
}

func PersistRunRecord(args *CliArgs) {
	runDir := core.RunDirFor(*args.RunName, "")

	runRecord := map[string]interface{}{
		"run_id":           *args.RunName,
		"run_name":         *args.RunName,
		"status":           "running",
		"start_time":       time.Now().UTC().Format(time.RFC3339),
		"end_time":         nil,
		"targets_info":     args.TargetsInfo,
		"scan_mode":        args.ScanMode,
		"instruction":      args.Instruction,
		"user_instruction": args.UserInstruction,
		"non_interactive":  args.NonInteractive,
		"local_sources":    args.LocalSources,
		"workspace_mount":  args.WorkspaceMount,
		"diff_scope":       args.DiffScope,
		"scope_mode":       args.ScopeMode,
		"diff_base":        args.DiffBase,
	}

	WriteRunRecord(runDir, runRecord)
}
