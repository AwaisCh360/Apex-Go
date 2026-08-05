package tool

import "context"

type CustomTool struct {
	Name          string
	Description   string
	NeedsApproval bool
	OnInvokeTool  func(context.Context, string) (interface{}, error)
}

func (t *CustomTool) GetName() string { return t.Name }

type FunctionTool struct {
	Name             string
	Description      string
	ParamsJSONSchema map[string]interface{}
	StrictJSONSchema bool
	NeedsApproval    bool
	ApexBounded      bool
	ApexCoerced      bool
	OnInvokeTool     func(context.Context, string) (interface{}, error)
}

func (t *FunctionTool) GetName() string { return t.Name }

type Tool interface {
	GetName() string
}
