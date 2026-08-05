package capabilities

import "github.com/AwaisCh360/Apex/sdk/agents/tool"

type Capability interface{}

type FilesystemToolset struct {
	Tools map[string]tool.Tool
}

type ShellToolset struct {
	Tools map[string]interface{}
}

type Filesystem struct {
	ConfigureTools func(*FilesystemToolset)
}

type Shell struct {
	ConfigureTools func(*ShellToolset)
}
