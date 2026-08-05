package live_view

// TuiLiveView is a placeholder for apex.interface.tui.live_view.TuiLiveView.
type TuiLiveView struct {
	Agents map[string]any
	Events []any
}

func NewTuiLiveView() *TuiLiveView {
	return &TuiLiveView{
		Agents: make(map[string]any),
		Events: make([]any, 0),
	}
}

func (t *TuiLiveView) HydrateFromRunDir(runDir string) {
	// Stub implementation
}
