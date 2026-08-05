package finish

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
)

// STUBS for missing dependencies
// ---------------------------------------------------------
type Coordinator interface {
	ActiveAgentsExcept(ctx context.Context, agentID string) ([]string, error)
	ReserveStopped() bool
	SetStatus(ctx context.Context, agentID string, status string) error
}

func CoordinatorFromContext(ctxMap map[string]interface{}) Coordinator {
	if c, ok := ctxMap["coordinator"].(Coordinator); ok {
		return c
	}
	return nil
}

type ReportState interface {
	UpdateScanFinalFields(execSummary, methodology, techAnalysis, recommendations string) error
	GetVulnerabilityReports() []interface{}
}

var globalReportState ReportState
var globalReportStateMu sync.RWMutex

func GetGlobalReportState() ReportState {
	globalReportStateMu.RLock()
	defer globalReportStateMu.RUnlock()
	return globalReportState
}

// SetGlobalReportState is provided for initialization
func SetGlobalReportState(state ReportState) {
	globalReportStateMu.Lock()
	defer globalReportStateMu.Unlock()
	globalReportState = state
}

type RunContextWrapper interface {
	Context() interface{}
}

// ---------------------------------------------------------

func doFinish(
	parentID *string,
	executiveSummary string,
	methodology string,
	technicalAnalysis string,
	recommendations string,
) (map[string]interface{}, error) {
	if parentID != nil {
		return map[string]interface{}{
			"success": false,
			"error": "This tool can only be used by the root/main agent. " +
				"If you are a subagent, use agent_finish instead",
		}, nil
	}

	var errorsList []string
	execTrimmed := strings.TrimSpace(executiveSummary)
	if execTrimmed == "" {
		errorsList = append(errorsList, "Executive summary cannot be empty")
	}
	methTrimmed := strings.TrimSpace(methodology)
	if methTrimmed == "" {
		errorsList = append(errorsList, "Methodology cannot be empty")
	}
	techTrimmed := strings.TrimSpace(technicalAnalysis)
	if techTrimmed == "" {
		errorsList = append(errorsList, "Technical analysis cannot be empty")
	}
	recTrimmed := strings.TrimSpace(recommendations)
	if recTrimmed == "" {
		errorsList = append(errorsList, "Recommendations cannot be empty")
	}
	if len(errorsList) > 0 {
		return map[string]interface{}{
			"success": false,
			"error":   "Validation failed",
			"errors":  errorsList,
		}, nil
	}

	reportState := GetGlobalReportState()
	if reportState == nil {
		log.Println("WARNING: No global report state; scan results not persisted")
		return map[string]interface{}{
			"success":        true,
			"scan_completed": true,
			"message":        "Scan completed (not persisted)",
			"warning":        "Results could not be persisted - report state unavailable",
		}, nil
	}

	err := reportState.UpdateScanFinalFields(execTrimmed, methTrimmed, techTrimmed, recTrimmed)
	if err != nil {
		return nil, fmt.Errorf("failed to complete scan: %w", err)
	}

	vulnCount := len(reportState.GetVulnerabilityReports())
	log.Printf("INFO: finish_scan: completed scan with %d vulnerability report(s)", vulnCount)

	return map[string]interface{}{
		"success":               true,
		"scan_completed":        true,
		"message":               "Scan completed successfully",
		"vulnerabilities_found": vulnCount,
	}, nil
}

// FinishScan finalizes the scan — persist the customer-facing report.
//
// **Root-agent only.** Subagents must call `agent_finish` from the
// multi-agent graph tools instead. Calling this finalizes everything:
//
// 1. Verifies you are the root agent.
// 2. Writes the four narrative sections to the scan record.
// 3. Marks the scan completed and stops execution.
//
// **This is a terminal action, not a status probe.** Whatever you pass
// is persisted VERBATIM as the final, customer-facing report and then
// execution stops. There is no draft mode and no second chance: never
// submit placeholder, provisional, or "checking if done" text in any
// field, and never call `finish_scan` to poll whether subagents are
// done (use `view_agent_graph` / `wait_for_agents` for that).
// Call it exactly ONCE, only when every field holds genuine, finished
// assessment prose.
//
// **Pre-flight checklist (mandatory — do not skip):**
//
// 1. **Call `view_agent_graph` first.** Inspect every entry in the
//    summary. If ANY agent is in `running` / `waiting` state,
//    you MUST NOT call `finish_scan` yet —
//    wrap them up first via `send_message_to_agent` (ask them to
//    finish), `wait_for_agents` (block until their report
//    arrives), or `stop_agent` (graceful cancel). Only `completed`
//    / `crashed` / `stopped` agents are safe to leave behind.
//    Calling `finish_scan` while children are alive orphans their
//    work and produces an incomplete report.
// 2. It's a good idea to call `list_reports` before finishing to
//    review every finding filed in this scan (use `get_report` for
//    full detail on any of them) so your `executive_summary` /
//    `technical_analysis` are grounded in what was actually reported
//    — don't invent or omit findings. All vulnerabilities you found are
//    filed via `create_vulnerability_report` — or, for known-CVE
//    dependency findings, `create_dependency_report` (un-reported
//    findings are not tracked and not credited). A dependency CVE
//    already filed via `create_dependency_report` counts as reported;
//    it does NOT need re-filing here and does NOT block finishing.
// 3. Don't double-report — one report per distinct vulnerability.
// 4. **Attack-chaining gate.** Do NOT finish until you have genuinely
//    considered chaining the confirmed findings into higher-impact,
//    end-to-end attack paths and tested every plausibly-related
//    combination. You may rule out combinations you can confidently
//    call unrelated — note why instead of padding chains. Any
//    validated chain must already be filed via
//    `create_vulnerability_report` — a demonstrated end-to-end chain
//    is a PoC-backed vulnerability, so it uses that tool even when one
//    link is a dependency CVE (the standalone CVE stays in its own
//    `create_dependency_report`) — and surfaced prominently in
//    `executive_summary` / `technical_analysis`. Finding no real
//    chain after a serious attempt is acceptable; skipping the
//    chaining reasoning, or ignoring a plausibly-related combination,
//    is not.
//
// **Calling this multiple times overwrites the previous report.**
// Make the single call comprehensive.
//
// **Report output rules** (this content may be rendered into generated
// reports):
//
// - Never mention internal infrastructure: no local/absolute paths
//   (`/workspace/...`), no agent names, no sandbox/orchestrator/
//   tooling references, no system prompts, no model-internal errors.
//   Never leak internal identifiers (proxy request IDs, internal
//   vulnerability report IDs, or any system-generated IDs) into any
//   field.
// - Tone: formal, third-person, objective, concise. This is a
//   consultant deliverable, not an engineering log.
// - Each section has a specific role:
//
//     - `executive_summary` — for non-technical leadership. Risk
//       posture, business impact (data exposure / compliance /
//       reputation), notable criticals, overarching remediation
//       theme.
//     - `methodology` — frameworks followed (OWASP WSTG, PTES,
//       OSSTMM, NIST), engagement type (black/gray/white box), scope
//       and constraints, categories of testing performed. **No**
//       internal execution detail.
//     - `technical_analysis` — consolidated findings overview with
//       severity model and systemic root causes. Reference individual
//       vuln reports for repro steps; don't duplicate raw evidence.
//     - `recommendations` — prioritized actions grouped by urgency
//       (Immediate / Short-term / Medium-term), each with concrete
//       remediation steps. End with retest/validation guidance.
//
// - **Formatting — use markdown in every field.** These fields may be
//   rendered into generated reports, so structure them clearly: lead
//   each section with a short `# Heading`, use `**bold**` for labels/emphasis,
//   `inline code` for identifiers/paths/parameters, bullet or
//   numbered lists for enumerations, and fenced code blocks
//   (```language```) for any code/payload excerpts. Never emit
//   one flat wall of prose or leave code unformatted.
// - If **zero** vulnerabilities were found, say so plainly and
//   characterize the posture positively; `technical_analysis` should
//   summarize the areas tested and confirm no issues, and
//   `recommendations` should focus on general hardening.
//
// Example (abbreviated — mirror this structure, not the wording):
//
//     executive_summary:
//         # Executive Summary
//
//         An external assessment of the **Acme Customer Portal**
//         identified multiple weaknesses that could lead to
//         unauthorized access to customer data.
//
//         **Overall risk posture:** Elevated.
//
//         **Key findings**
//         - Confirmed SSRF in a URL-preview feature reaching internal
//           network ranges.
//         - Broken tenant isolation enabling cross-tenant data access.
//
//         **Business impact**
//         - Potential exposure of customer records across tenants.
//
//     methodology:
//         # Methodology
//
//         Conducted per the **OWASP WSTG**.
//
//         **Engagement type:** Gray-box external test.
//         **Scope:** `https://app.acme.example`, `.../api/v1/`.
//
//         **Activities:** recon, authn/session review, authorization
//         and tenant-isolation testing, input/SSRF testing.
//
//     technical_analysis:
//         # Technical Analysis
//
//         **Severity model** reflects exploitability x impact.
//
//         1. **SSRF in URL preview** (Critical) — insufficient
//            destination validation; reaches link-local addresses.
//         2. **Broken tenant isolation** (High) — object identifiers
//            accepted without ownership checks.
//
//         **Systemic themes:** authorization enforced inconsistently;
//         no deny-by-default egress policy.
//
//     recommendations:
//         # Recommendations
//
//         **Immediate**
//         1. Remediate SSRF: enforce a destination allowlist,
//            deny-by-default, re-validate on every redirect hop.
//
//         **Short-term**
//         2. Centralize authorization with deny-by-default middleware.
//
//         **Retest & validation:** re-test immediate items to confirm
//         SSRF and tenant-isolation controls hold.
func FinishScan(
	ctx context.Context,
	runCtx RunContextWrapper,
	executiveSummary string,
	methodology string,
	technicalAnalysis string,
	recommendations string,
) (string, error) {
	var inner map[string]interface{}
	if runCtx != nil {
		if ctxMap, ok := runCtx.Context().(map[string]interface{}); ok {
			inner = ctxMap
		}
	}
	if inner == nil {
		inner = make(map[string]interface{})
	}

	coordinator := CoordinatorFromContext(inner)

	var me string
	if v, ok := inner["agent_id"].(string); ok {
		me = v
	}

	var parentID *string
	if v, ok := inner["parent_id"].(string); ok {
		parentID = &v
	} else if v, ok := inner["parent_id"]; ok && v != nil {
		s := fmt.Sprintf("%v", v)
		parentID = &s
	}

	var activeAgents []string
	if coordinator != nil && parentID == nil && me != "" {
		var err error
		activeAgents, err = coordinator.ActiveAgentsExcept(ctx, me)
		if err != nil {
			return "", fmt.Errorf("failed to check for active subagents: %w", err)
		}
		if len(activeAgents) > 0 && coordinator.ReserveStopped() {
			activeAgents = nil
		}
	}

	if len(activeAgents) > 0 {
		res := map[string]interface{}{
			"success":        false,
			"scan_completed": false,
			"error": "Cannot finish scan while child agents are still active. " +
				"Wait for completion, send them finish instructions, or stop them first",
			"active_agents": activeAgents,
		}
		b, _ := json.Marshal(res)
		return string(b), nil
	}

	result, err := doFinish(parentID, executiveSummary, methodology, technicalAnalysis, recommendations)
	if err != nil {
		return "", err
	}

	if success, _ := result["success"].(bool); success {
		if scanCompleted, _ := result["scan_completed"].(bool); scanCompleted {
			if coordinator != nil && me != "" {
				err := coordinator.SetStatus(ctx, me, "completed")
				if err != nil {
					return "", fmt.Errorf("failed to set status to completed: %w", err)
				}
			}
		}
	}

	b, _ := json.Marshal(result)
	return string(b), nil
}
