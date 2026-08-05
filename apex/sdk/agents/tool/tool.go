package tool

import "context"

type Tool interface {
	GetName() string
}

type FunctionTool struct {
	Name             string
	Description      string
	ParamsJSONSchema map[string]interface{}
	OnInvokeTool     func(ctx context.Context, rawInput string) (interface{}, error)
	StrictJSONSchema bool
	NeedsApproval    bool
	ApexBounded      bool
	ApexCoerced      bool
}

func (t *FunctionTool) GetName() string {
	return t.Name
}

type CustomTool struct {
	Name          string
	Description   string
	NeedsApproval bool
	OnInvokeTool  func(ctx context.Context, input string) (interface{}, error)
}

func (t *CustomTool) GetName() string {
	return t.Name
}
