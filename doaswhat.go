// doaswhat - Fast doas permission enumerator (Go version)
// Build: GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o doaswhat-go doaswhat.go

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const version = "v2.0"

type Result int

const (
	ResultNone   Result = iota
	ResultNopass        // exit code 0, no password needed
	ResultPass          // timed out, password required
)

type CommandResult struct {
	Command string
	Result  Result
}

var (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorGray   = "\033[90m"
	colorBold   = "\033[1m"
)

func setupColors() {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("CLICOLOR") == "0" {
		colorReset = ""
		colorRed = ""
		colorGreen = ""
		colorYellow = ""
		colorGray = ""
		colorBold = ""
	}
}

func banner() {
	fmt.Printf("doaswhat %s  %sSublarge%s  %shttps://github.com/yanxinwu946/doaswhat%s\n",
		version, colorBold, colorReset, colorGray, colorReset)
}

func showHelp() {
	banner()
	fmt.Println()
	fmt.Println("Usage: doaswhat [-u user] [-h]")
	fmt.Println()
	fmt.Println("Enumerate doas permission rules by probing every")
	fmt.Println("executable in $PATH. Each command is tested twice -- by")
	fmt.Println("full path and by basename -- to match both exact and")
	fmt.Println("pattern-based rules in doas.conf.")
	fmt.Println()
	fmt.Println("Flags:")
	fmt.Println("  -u user  test permissions for a given user (default: current user)")
	fmt.Println("  -h       show this help")
}

func findDoas() (string, error) {
	path, err := exec.LookPath("doas")
	if err != nil {
		return "", fmt.Errorf("doas not found in PATH")
	}
	return path, nil
}

func getExecutables() []struct{ FullPath, BaseName string } {
	var result []struct{ FullPath, BaseName string }
	seen := make(map[string]bool)

	pathEnv := os.Getenv("PATH")
	for _, dir := range filepath.SplitList(pathEnv) {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			continue
		}

		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			fullPath := filepath.Join(dir, entry.Name())
			if seen[fullPath] {
				continue
			}
			info, err := entry.Info()
			if err != nil {
				continue
			}
			if info.Mode()&0111 != 0 && !info.IsDir() {
				seen[fullPath] = true
				result = append(result, struct{ FullPath, BaseName string }{
					FullPath: fullPath,
					BaseName: entry.Name(),
				})
			}
		}
	}
	return result
}

func processConfig(file string) {
	data, err := os.ReadFile(file)
	if err != nil {
		return
	}
	content := strings.TrimSpace(string(data))
	if content == "" {
		return
	}

	fmt.Printf("%s[+]%s %s\n", colorGreen, colorReset, file)
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fmt.Printf("    %s\n", line)
	}
}

func testCommand(ctx context.Context, doasPath, user, command string) Result {
	args := []string{}
	if user != "" {
		args = append(args, "-u", user)
	}
	args = append(args, command, "--help")

	timeoutCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	cmd := exec.CommandContext(timeoutCtx, doasPath, args...)
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil

	cmd.Stdin = nil

	err := cmd.Run()
	if err != nil {
		if timeoutCtx.Err() != nil {
			return ResultPass
		}
		return ResultNone
	}
	return ResultNopass
}

func main() {
	var user string
	showHelpFlag := false

	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "-u":
			i++
			if i < len(os.Args) {
				user = os.Args[i]
			}
		case "-h":
			showHelpFlag = true
		default:
			showHelp()
			os.Exit(1)
		}
	}

	setupColors()

	if showHelpFlag {
		showHelp()
		return
	}

	banner()
	fmt.Println()

	// Find doas binary
	doasPath, err := findDoas()
	if err != nil {
		fmt.Printf("%s!%s %s\n", colorRed, colorReset, err)
		os.Exit(1)
	}

	fmt.Printf("%s[*]%s binary\n", colorBold, colorReset)

	info, err := os.Stat(doasPath)
	if err == nil {
		mode := info.Mode()
		modeStr := mode.String()
		if mode&os.ModeSetuid != 0 && len(modeStr) > 3 && modeStr[3] == 'x' {
			modeStr = modeStr[:3] + "s" + modeStr[4:]
		}
		if mode&os.ModeSetgid != 0 && len(modeStr) > 6 && modeStr[6] == 'x' {
			modeStr = modeStr[:6] + "s" + modeStr[7:]
		}

		userName := "root"
		groupName := "root"
		fmt.Printf("%s %d %s %s %5d %s\n",
			modeStr, 1, userName, groupName, info.Size(), doasPath)
	} else {
		fmt.Println(doasPath)
	}
	fmt.Println()

	if user != "" {
		fmt.Printf("%s[*]%s user\n", colorBold, colorReset)
		fmt.Println(user)
		fmt.Println()
	}

	fmt.Printf("%s[*]%s configs\n", colorBold, colorReset)
	processConfig("/etc/doas.conf")
	processConfig("/usr/local/etc/doas.conf")

	if entries, err := os.ReadDir("/etc/doas.d"); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".conf") {
				processConfig(filepath.Join("/etc/doas.d", entry.Name()))
			}
		}
	}

	// Get executables
	exes := getExecutables()

	fmt.Println()
	fmt.Printf("%s[*]%s probing %d commands...\n",
		colorBold, colorReset, len(exes))

	// Setup signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)

	var wg sync.WaitGroup
	var mu sync.Mutex
	seen := make(map[string]bool)
	var nopassCmds, passCmds []string
	completed := 0

	maxConcurrent := 50
	sem := make(chan struct{}, maxConcurrent)

	ctx, cancelAll := context.WithCancel(context.Background())
	defer cancelAll()

	for _, exe := range exes {
		wg.Add(2)

		go func(cmd string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			select {
			case <-ctx.Done():
				return
			default:
			}

			result := testCommand(ctx, doasPath, user, cmd)

			mu.Lock()
			if result != ResultNone && !seen[cmd] {
				seen[cmd] = true
				if result == ResultNopass {
					nopassCmds = append(nopassCmds, cmd)
				} else {
					passCmds = append(passCmds, cmd)
				}
			}
			completed++
			fmt.Printf("\r%s[%d/%d]%s testing...",
				colorGray, completed/2, len(exes), colorReset)
			mu.Unlock()
		}(exe.FullPath)

		go func(name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			select {
			case <-ctx.Done():
				return
			default:
			}

			result := testCommand(ctx, doasPath, user, name)

			mu.Lock()
			if result != ResultNone && !seen[name] {
				seen[name] = true
				if result == ResultNopass {
					nopassCmds = append(nopassCmds, name)
				} else {
					passCmds = append(passCmds, name)
				}
			}
			mu.Unlock()
		}(exe.BaseName)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-sigCh:
		cancelAll()
		wg.Wait()
		fmt.Println()
	}

	fmt.Println()

	fmt.Printf("%s[*]%s analyzing results...\n", colorBold, colorReset)

	if len(nopassCmds) == 0 && len(passCmds) == 0 {
		fmt.Printf("%s!%s no commands allowed via doas\n", colorRed, colorReset)
		return
	}

	prefix := "doas"
	if user != "" {
		prefix = "doas -u " + user
	}

	sort.Strings(nopassCmds)
	sort.Strings(passCmds)

	if len(nopassCmds) > 0 {
		fmt.Println()
		fmt.Printf("%s[+]%s you can run these without a password:\n",
			colorGreen, colorReset)
		for _, cmd := range nopassCmds {
			fmt.Printf("    %s %s\n", prefix, cmd)
		}
	}

	if len(passCmds) > 0 {
		fmt.Println()
		fmt.Printf("%s[!]%s these require a password:\n",
			colorYellow, colorReset)
		for _, cmd := range passCmds {
			fmt.Printf("    %s %s\n", prefix, cmd)
		}
	}

	fmt.Println()
}
