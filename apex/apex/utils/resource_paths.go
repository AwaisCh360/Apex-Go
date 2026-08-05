package utils

import (
	"os"
	"path/filepath"
	"runtime"
)

// GetApexResourcePath resolves the absolute path to a resource.
// Note on Python vs Go conversion:
// The Python implementation uses `getattr(sys, "_MEIPASS", None)` to detect if it
// is running as a frozen PyInstaller binary, falling back to the `__file__` path.
// Go does not use PyInstaller. It compiles to a native binary. Therefore, we use
// `os.Executable()` to determine the binary's directory as the exact equivalent
// of finding the bundled assets, falling back to `runtime.Caller` to emulate `__file__`.
func GetApexResourcePath(parts ...string) string {
	// 1. Try PyInstaller equivalent (executable directory)
	exePath, err := os.Executable()
	if err == nil {
		base := filepath.Join(filepath.Dir(exePath), "apex")
		if stat, err := os.Stat(base); err == nil && stat.IsDir() {
			paths := append([]string{base}, parts...)
			return filepath.Join(paths...)
		}
	}

	// 2. Fallback equivalent to __file__.resolve().parent.parent
	_, file, _, ok := runtime.Caller(0)
	if ok {
		// file is /.../Apex/apex/apex/utils/resource_paths.go
		// parent is utils, parent.parent is apex
		base := filepath.Dir(filepath.Dir(file))
		paths := append([]string{base}, parts...)
		return filepath.Join(paths...)
	}

	// Ultimate fallback if runtime.Caller fails
	base, _ := os.Getwd()
	paths := append([]string{base}, parts...)
	return filepath.Join(paths...)
}
