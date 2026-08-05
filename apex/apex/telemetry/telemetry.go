package telemetry

import (
	"github.com/AwaisCh360/Apex/apex/report"
)

func Start(model string, scanMode string, isWhitebox bool, interactive bool, hasInstructions bool, authMode string) {
	PosthogStart(model, scanMode, isWhitebox, interactive, hasInstructions, authMode)
	ScarfStart(model, scanMode, isWhitebox, interactive, hasInstructions, authMode)
}

func End(reportState *report.ReportState, exitReason string) {
	if reportState == nil {
		return
	}
	PosthogEnd(reportState, exitReason)
	ScarfEnd(reportState, exitReason)
}

func Finding(severity string, cwe string, isCve bool) {
	PosthogFinding(severity, cwe, isCve)
	ScarfFinding(severity, cwe, isCve)
}

func SkillLoaded(skillName string) {
	PosthogSkillLoaded(skillName)
	ScarfSkillLoaded(skillName)
}

func Error(errorType string) {
	PosthogError(errorType)
	ScarfError(errorType)
}

func ViewerOpened(source string, live bool) {
	PosthogViewerOpened(source, live)
}

func ViewerCtaClicked(cta string, surface string) {
	PosthogViewerCtaClicked(cta, surface)
}

func ViewerEmailEvent(step string, purpose string) {
	PosthogViewerEmailEvent(step, purpose)
}

func ViewerFeedbackSubmitted() {
	PosthogViewerFeedbackSubmitted()
}

func ViewerAgentSteered() {
	PosthogViewerAgentSteered()
}
