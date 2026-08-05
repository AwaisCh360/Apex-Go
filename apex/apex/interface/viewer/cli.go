package viewer

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
)

// Local stubs for core package
const runsDirName = "runs"

func runsBaseDir() string {
	cwd, _ := os.Getwd()
	return filepath.Join(cwd, runsDirName)
}

func runDirFor(run string) string {
	return filepath.Join(runsBaseDir(), run)
}

func latestRunDir() string {
	base := runsBaseDir()
	entries, err := os.ReadDir(base)
	if err != nil {
		return ""
	}
	var dirs []os.DirEntry
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, e)
		}
	}
	if len(dirs) == 0 {
		return ""
	}
	sort.Slice(dirs, func(i, j int) bool {
		iInfo, _ := dirs[i].Info()
		jInfo, _ := dirs[j].Info()
		return iInfo.ModTime().After(jInfo.ModTime())
	})
	return filepath.Join(base, dirs[0].Name())
}

// Local stub for telemetry
func viewerOpened(source string, live bool) {}

// RunView serves a run's viewer UI locally.
func RunView(argv []string) {
	fs := flag.NewFlagSet("apex view", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Open a local web view of a Apex run (live or finished).\n\n")
		fmt.Fprintf(os.Stderr, "Usage: apex view [run] [options]\n\n")
		fs.PrintDefaults()
	}

	port := fs.Int("port", 0, "Port to serve on (default: an available ephemeral port).")
	host := fs.String("host", "127.0.0.1", "Host to serve on")
	noOpen := fs.Bool("no-open", false, "Do not open the browser automatically.")

	if err := fs.Parse(argv); err != nil {
		os.Exit(1)
	}

	var run string
	if fs.NArg() > 0 {
		run = fs.Arg(0)
	}

	if !BundleIsBuilt() {
		fmt.Println("\033[1;31mViewer UI is not built.\033[0m")
		fmt.Println("Build it with: \033[36mcd apex/interface/viewer/frontend && npm ci && npm run build\033[0m")
		os.Exit(1)
	}

	runDir := cliResolveRunDir(run)

	httpd, url, token := Serve(runDir, *host, *port, !*noOpen, nil)
	openUrl := AuthorizedUrl(url, token)

	runName := filepath.Base(runDir)
	summary := ReadRunSummary(runDir)

	live := true
	if fin, ok := summary["finished"].(bool); ok && fin {
		live = false
	} else if fin, ok := summary["finished"].(string); ok && fin == "true" {
		live = false
	}

	viewerOpened("cli", live)

	stateLabel := "\033[38;5;220mlive\033[0m" // #eab308
	if !live {
		stateLabel = "\033[38;5;77mfinished\033[0m" // #22c55e
	}

	fmt.Println()
	fmt.Printf("Serving \033[1;37m%s\033[0m (%s) at:\n", runName, stateLabel)
	fmt.Printf("  \033[38;5;75m%s\033[0m\n", openUrl)
	fmt.Println("\033[2mThis link authorizes the browser; anyone you share it with can steer\033[0m")
	fmt.Println("\033[2ma live scan and browse history. Press Ctrl-C to stop the viewer.\033[0m")
	fmt.Println()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c

	fmt.Println("\n\033[2mViewer stopped.\033[0m")
	if httpd != nil {
		httpd.Shutdown(context.Background())
		httpd.Close()
	}
}

func cliResolveRunDir(run string) string {
	if run != "" {
		runDir := runDirFor(run)
		info, err := os.Stat(RunRecordPath(runDir))
		if err != nil || info.IsDir() {
			failNoRun(&run)
		}
		return runDir
	}

	latest := latestRunDir()
	if latest == "" {
		failNoRun(nil)
	}
	return latest
}

func failNoRun(requested *string) {
	base := runsBaseDir()
	var available []string

	if info, err := os.Stat(base); err == nil && info.IsDir() {
		entries, _ := os.ReadDir(base)
		for _, entry := range entries {
			child := filepath.Join(base, entry.Name())
			recInfo, err := os.Stat(RunRecordPath(child))
			if err == nil && !recInfo.IsDir() {
				available = append(available, entry.Name())
			}
		}
		sort.Slice(available, func(i, j int) bool {
			return available[i] > available[j]
		})
	}

	if requested != nil {
		fmt.Printf("\033[1;31mNo run named '%s' under ./%s.\033[0m\n", *requested, runsDirName)
	} else {
		fmt.Printf("\033[1;31mNo runs found under ./%s.\033[0m\n", runsDirName)
	}

	if len(available) > 0 {
		fmt.Println("Available runs:")
		limit := 20
		if len(available) < limit {
			limit = len(available)
		}
		for _, name := range available[:limit] {
			fmt.Printf("  \033[36m%s\033[0m\n", name)
		}
	}
	os.Exit(1)
}
