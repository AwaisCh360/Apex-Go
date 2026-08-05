package capabilities

type FilesystemToolset struct {
	Tools map[string]interface{}
}

type ShellToolset struct {
	Tools map[string]interface{}
}

type Capability interface{}

type Filesystem struct {
	ConfigureTools func(*FilesystemToolset)
}

type Shell struct {
	ConfigureTools func(*ShellToolset)
}
